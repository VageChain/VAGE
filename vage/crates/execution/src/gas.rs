use anyhow::{bail, Result};
use primitive_types::U256;
use vage_types::{Account, Transaction};

pub const INTRINSIC_GAS: u64 = 210;
pub const VALUE_TRANSFER_GAS: u64 = 210;
pub const STORAGE_READ_GAS: u64 = 48; // Verkle storage access cost
pub const STORAGE_WRITE_GAS: u64 = 200;
pub const CALLDATA_GAS: u64 = 1; // Per non-zero byte

#[derive(Clone, Debug, Default)]
pub struct GasMeter {
    pub gas_limit: u64,
    pub gas_used: u64,
}

impl GasMeter {
    pub fn new(limit: u64) -> Self {
        Self {
            gas_limit: limit,
            gas_used: 0,
        }
    }

    pub fn consume(&mut self, amount: u64) -> Result<()> {
        let next = self.gas_used.saturating_add(amount);
        if next > self.gas_limit {
            bail!(
                "out of gas: attempted to use {}, limit {}",
                next,
                self.gas_limit
            );
        }
        self.gas_used = next;
        Ok(())
    }

    pub fn remaining(&self) -> u64 {
        self.gas_limit.saturating_sub(self.gas_used)
    }

    pub fn refund(&mut self, amount: u64) {
        self.gas_used = self.gas_used.saturating_sub(amount);
    }

    pub fn out_of_gas(&self) -> bool {
        self.gas_used >= self.gas_limit
    }

    pub fn reset(&mut self) {
        self.gas_used = 0;
    }

    pub fn gas_price(&self, tx: &Transaction) -> U256 {
        tx.gas_price
    }

    pub fn calculate_fee(&self, tx: &Transaction) -> U256 {
        self.gas_price(tx).saturating_mul(U256::from(self.gas_used))
    }

    pub fn deduct_fee(&mut self, account: &mut Account, tx: &Transaction) -> Result<U256> {
        let prepaid = self
            .gas_price(tx)
            .saturating_mul(U256::from(self.gas_limit));
        account.decrease_balance(prepaid)?;
        Ok(prepaid)
    }

    pub fn refund_unused(&self, account: &mut Account, tx: &Transaction) -> U256 {
        let prepaid = self
            .gas_price(tx)
            .saturating_mul(U256::from(self.gas_limit));
        let used_fee = self.calculate_fee(tx);
        let refund = prepaid.saturating_sub(used_fee);
        if refund > U256::zero() {
            account.increase_balance(refund);
        }
        refund
    }

    pub fn gas_cost_transfer(&self) -> u64 {
        VALUE_TRANSFER_GAS
    }

    pub fn gas_cost_storage_read(&self) -> u64 {
        STORAGE_READ_GAS
    }

    pub fn gas_cost_storage_write(&self) -> u64 {
        STORAGE_WRITE_GAS
    }

    pub fn gas_cost_contract_call(&self) -> u64 {
        INTRINSIC_GAS + self.gas_cost_storage_read() + self.gas_cost_storage_write()
    }
}

pub fn calculate_intrinsic_gas(data: &[u8]) -> u64 {
    let mut gas = INTRINSIC_GAS;
    for &byte in data {
        if byte != 0 {
            gas += CALLDATA_GAS;
        } else {
            gas += 4;
        }
    }
    gas
}

#[cfg(test)]
mod tests {
    use super::{GasMeter, INTRINSIC_GAS, STORAGE_READ_GAS, STORAGE_WRITE_GAS, VALUE_TRANSFER_GAS, CALLDATA_GAS, calculate_intrinsic_gas};
    use primitive_types::U256;
    use vage_types::{Account, Address, Transaction};

    #[test]
    fn gas_meter_supports_limits_fees_refunds_and_cost_helpers() {
        let tx = Transaction::new_transfer(Address([1u8; 32]), Address([2u8; 32]), U256::from(1u64), 0);
        // Use a generous fixed limit so consume() does not exceed it.
        let gas_limit = 10_000u64;
        let mut meter = GasMeter::new(gas_limit);
        let mut account = Account::new(Address([3u8; 32]));
        account.balance = U256::from(100_000u64);

        meter.consume(500).expect("consume should succeed");
        assert_eq!(meter.remaining(), gas_limit - 500);
        assert!(!meter.out_of_gas());
        assert_eq!(meter.gas_price(&tx), tx.gas_price);
        assert_eq!(meter.calculate_fee(&tx), U256::from(500u64));
        assert_eq!(meter.gas_cost_transfer(), VALUE_TRANSFER_GAS);
        assert_eq!(meter.gas_cost_storage_read(), STORAGE_READ_GAS);
        assert_eq!(meter.gas_cost_storage_write(), STORAGE_WRITE_GAS);
        assert_eq!(meter.gas_cost_contract_call(), INTRINSIC_GAS + STORAGE_READ_GAS + STORAGE_WRITE_GAS);

        // Build a transaction whose gas_limit matches the meter limit for fee checks.
        let fee_tx = {
            let mut t = Transaction::new_transfer(Address([1u8; 32]), Address([2u8; 32]), U256::from(1u64), 0);
            t.gas_limit = gas_limit;
            t
        };
        let prepaid = meter.deduct_fee(&mut account, &fee_tx).expect("fee deduction should succeed");
        assert_eq!(prepaid, fee_tx.gas_cost());
        let refund = meter.refund_unused(&mut account, &fee_tx);
        assert_eq!(refund, fee_tx.gas_cost() - U256::from(500u64));

        meter.refund(250);
        assert_eq!(meter.gas_used, 250);
        meter.reset();
        assert_eq!(meter.gas_used, 0);
    }

    #[test]
    fn calculate_intrinsic_gas_accounts_for_zero_and_non_zero_bytes() {
        // Zero byte costs 4 gas; non-zero byte costs CALLDATA_GAS (VageChain reduced schedule).
        assert_eq!(calculate_intrinsic_gas(&[]), INTRINSIC_GAS);
        assert_eq!(
            calculate_intrinsic_gas(&[0u8, 1u8, 2u8]),
            INTRINSIC_GAS + 4 + CALLDATA_GAS + CALLDATA_GAS
        );
    }
}
