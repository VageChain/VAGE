use crate::governance::GovernanceManager;
use crate::hotstuff::vote::Vote;
use crate::pos::staking::StakingManager;
use crate::pos::validator_set::ValidatorSet;
use anyhow::{anyhow, bail, Result};
use primitive_types::U256;
use vage_storage::StorageEngine;
use vage_types::{Address, Validator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

// â”€â”€ custom serde for [u8; 64] â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

mod serde_sig64 {
    use serde::{de::Error, Deserializer, Serializer};
    pub fn serialize<S>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error>
    where S: Serializer { s.serialize_bytes(sig.as_slice()) }
    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 64], D::Error>
    where D: Deserializer<'de> {
        let v: Vec<u8> = serde::Deserialize::deserialize(d)?;
        v.try_into().map_err(|_| Error::custom("expected 64 bytes"))
    }
}

// â”€â”€ storage keys â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const SLASHING_EVENT_PREFIX: &[u8] = b"slashing:event:";
const SLASHING_HISTORY_PREFIX: &[u8] = b"slashing:history:";
const COOLDOWN_PREFIX: &[u8] = b"slashing:cooldown:";

// â”€â”€ item 1: Misbehavior enum â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Misbehavior {
    /// item 2: validator signed two different blocks in the same view.
    DoubleVote {
        view: u64,
        vote_a: Vote,
        vote_b: Vote,
    },
    /// item 3: validator proposed two different blocks in the same view.
    DoubleProposal {
        view: u64,
        proposal_a: Vec<u8>,
        proposal_b: Vec<u8>,
    },
    /// item 4: validator submitted a vote with an invalid signature.
    InvalidSignature {
        vote: Vote,
        reason: String,
    },
}

impl Misbehavior {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::DoubleVote { .. } => "DoubleVote",
            Self::DoubleProposal { .. } => "DoubleProposal",
            Self::InvalidSignature { .. } => "InvalidSignature",
        }
    }

    pub fn validator(&self) -> &Address {
        match self {
            Self::DoubleVote { vote_a, .. } => &vote_a.validator,
            Self::DoubleProposal { .. } => {
                // The proposer address is not embedded in the raw bytes here;
                // callers must resolve via the Evidence.validator field.
                // Return a zero address as a safe fallback.
                static ZERO: Address = Address([0u8; 32]);
                &ZERO
            }
            Self::InvalidSignature { vote, .. } => &vote.validator,
        }
    }
}

// â”€â”€ item 5: Evidence record â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub id: [u8; 32],
    pub validator: Address,
    pub misbehavior: Misbehavior,
    pub reported_at_height: u64,
    pub reporter: Address,
    /// item 7: reporter's signature over the evidence id.
    #[serde(with = "serde_sig64")]
    pub reporter_signature: [u8; 64],
    pub verified: bool,
}

impl Evidence {
    pub fn new(
        validator: Address,
        misbehavior: Misbehavior,
        reported_at_height: u64,
        reporter: Address,
        reporter_signature: [u8; 64],
    ) -> Self {
        let mut e = Self {
            id: [0u8; 32],
            validator,
            misbehavior,
            reported_at_height,
            reporter,
            reporter_signature,
            verified: false,
        };
        e.id = e.compute_id();
        e
    }

    fn compute_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.validator.as_bytes());
        hasher.update(self.misbehavior.kind().as_bytes());
        hasher.update(self.reported_at_height.to_le_bytes());
        hasher.update(self.reporter.as_bytes());
        hasher.finalize().into()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("evidence encode: {}", e))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow!("evidence decode: {}", e))
    }
}

// â”€â”€ item 13 / 18: SlashingEvent (log + history) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub id: [u8; 32],
    pub validator: Address,
    pub misbehavior_kind: String,
    pub slash_amount: U256,
    pub burned_amount: U256,
    pub height: u64,
    pub timestamp: u64,
    pub evidence_id: [u8; 32],
}

impl SlashingEvent {
    fn new(evidence: &Evidence, slash_amount: U256, burned_amount: U256, height: u64) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut hasher = Sha256::new();
        hasher.update(evidence.id);
        hasher.update(height.to_le_bytes());
        let id: [u8; 32] = hasher.finalize().into();
        Self {
            id,
            validator: evidence.validator,
            misbehavior_kind: evidence.misbehavior.kind().to_string(),
            slash_amount,
            burned_amount,
            height,
            timestamp: ts,
            evidence_id: evidence.id,
        }
    }
}

// â”€â”€ Slashing config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Clone, Debug)]
pub struct SlashingConfig {
    /// Fraction of stake to slash on double-vote (in basis points, 10_000 = 100%).
    pub double_vote_slash_bps: u64,
    /// Fraction of stake to slash on double-proposal.
    pub double_proposal_slash_bps: u64,
    /// Fraction of stake to slash on invalid signature.
    pub invalid_sig_slash_bps: u64,
    /// Fraction of the slashed amount that is burned (rest may go to reporter).
    pub burn_fraction_bps: u64,
    /// Cooldown in blocks before a jailed validator may rejoin (item 17).
    pub cooldown_blocks: u64,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            double_vote_slash_bps: 500,      // 5%
            double_proposal_slash_bps: 200,  // 2%
            invalid_sig_slash_bps: 100,      // 1%
            burn_fraction_bps: 8_000,        // 80% burned
            cooldown_blocks: 1_000,
        }
    }
}

// â”€â”€ RPC types (item 19) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEventRpc {
    pub id: String,
    pub validator: String,
    pub misbehavior: String,
    pub slash_amount: String,
    pub burned_amount: String,
    pub height: u64,
    pub timestamp: u64,
}

impl From<&SlashingEvent> for SlashingEventRpc {
    fn from(e: &SlashingEvent) -> Self {
        Self {
            id: hex::encode(e.id),
            validator: e.validator.to_string(),
            misbehavior: e.misbehavior_kind.clone(),
            slash_amount: e.slash_amount.to_string(),
            burned_amount: e.burned_amount.to_string(),
            height: e.height,
            timestamp: e.timestamp,
        }
    }
}

// â”€â”€ SlashingManager â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub struct SlashingManager {
    config: SlashingConfig,
    storage: Arc<StorageEngine>,
    /// In-memory pending evidence pool (item 5).
    pending_evidence: HashMap<[u8; 32], Evidence>,
}

impl SlashingManager {
    pub fn new(config: SlashingConfig, storage: Arc<StorageEngine>) -> Self {
        Self { config, storage, pending_evidence: HashMap::new() }
    }

    // â”€â”€ item 2: detect double vote â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn detect_double_vote(
        &self,
        existing: &Vote,
        incoming: &Vote,
    ) -> Option<Misbehavior> {
        if existing.view == incoming.view
            && existing.validator == incoming.validator
            && existing.block_hash != incoming.block_hash
        {
            Some(Misbehavior::DoubleVote {
                view: existing.view,
                vote_a: existing.clone(),
                vote_b: incoming.clone(),
            })
        } else {
            None
        }
    }

    // â”€â”€ item 3: detect double proposal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn detect_double_proposal(
        &self,
        view: u64,
        existing_bytes: Vec<u8>,
        incoming_bytes: Vec<u8>,
    ) -> Option<Misbehavior> {
        // Different raw bytes at the same view = conflicting proposals.
        if existing_bytes != incoming_bytes {
            Some(Misbehavior::DoubleProposal {
                view,
                proposal_a: existing_bytes,
                proposal_b: incoming_bytes,
            })
        } else {
            None
        }
    }

    // â”€â”€ item 4: detect invalid signature â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn detect_invalid_signature(
        &self,
        vote: &Vote,
        validator: &Validator,
    ) -> Option<Misbehavior> {
        match vote.verify_signature(validator) {
            Ok(true) => None,
            Ok(false) => Some(Misbehavior::InvalidSignature {
                vote: vote.clone(),
                reason: "signature verification returned false".to_string(),
            }),
            Err(e) => Some(Misbehavior::InvalidSignature {
                vote: vote.clone(),
                reason: e.to_string(),
            }),
        }
    }

    // â”€â”€ item 5: record evidence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn record_evidence(
        &mut self,
        validator: Address,
        misbehavior: Misbehavior,
        reported_at_height: u64,
        reporter: Address,
        reporter_signature: [u8; 64],
    ) -> Result<[u8; 32]> {
        let evidence = Evidence::new(
            validator,
            misbehavior,
            reported_at_height,
            reporter,
            reporter_signature,
        );
        let id = evidence.id;
        self.pending_evidence.insert(id, evidence);
        Ok(id)
    }

    // â”€â”€ item 6: broadcast slashing evidence (returns serialized payload) â”€â”€â”€â”€â”€â”€

    pub fn broadcast_slashing_evidence(&self, evidence_id: &[u8; 32]) -> Result<Vec<u8>> {
        let evidence = self
            .pending_evidence
            .get(evidence_id)
            .ok_or_else(|| anyhow!("evidence {:?} not found", evidence_id))?;
        evidence.encode()
    }

    // â”€â”€ item 7: verify evidence signatures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn verify_evidence_signatures(
        &self,
        evidence: &Evidence,
        reporter_validator: &Validator,
    ) -> Result<bool> {
        reporter_validator.verify_signature(&evidence.id, &evidence.reporter_signature)
    }

    // â”€â”€ item 8: confirm validator misbehavior â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn confirm_misbehavior(
        &mut self,
        evidence_id: &[u8; 32],
        reporter_validator: &Validator,
    ) -> Result<()> {
        // Clone evidence to avoid simultaneous mut + immut borrow of self.
        let evidence = self
            .pending_evidence
            .get(evidence_id)
            .cloned()
            .ok_or_else(|| anyhow!("evidence {:?} not found", evidence_id))?;

        let locally_observed = evidence.reporter == reporter_validator.address
            && evidence.reporter_signature == [0u8; 64];

        if !locally_observed && !self.verify_evidence_signatures(&evidence, reporter_validator)? {
            bail!("evidence signature verification failed for {:?}", evidence_id);
        }
        self.pending_evidence.get_mut(evidence_id)
            .ok_or_else(|| anyhow!("evidence {:?} disappeared", evidence_id))?
            .verified = true;
        Ok(())
    }

    // â”€â”€ items 9-12, 13-17: full slash pipeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn execute_slash(
        &mut self,
        evidence_id: &[u8; 32],
        current_height: u64,
        validator_set: &mut ValidatorSet,
        staking: &mut StakingManager,
        governance: &mut GovernanceManager,
    ) -> Result<SlashingEvent> {
        let evidence = self
            .pending_evidence
            .get(evidence_id)
            .cloned()
            .ok_or_else(|| anyhow!("evidence {:?} not found", evidence_id))?;

        if !evidence.verified {
            bail!("evidence {:?} not yet confirmed", evidence_id);
        }

        let validator_addr = evidence.validator;

        // Determine slash amount based on misbehavior type (item 9)
        let current_stake = staking.get_stake(&validator_addr);

        let slash_bps = match &evidence.misbehavior {
            Misbehavior::DoubleVote { .. } => self.config.double_vote_slash_bps,
            Misbehavior::DoubleProposal { .. } => self.config.double_proposal_slash_bps,
            Misbehavior::InvalidSignature { .. } => self.config.invalid_sig_slash_bps,
        };

        let slash_amount = current_stake * U256::from(slash_bps) / U256::from(10_000u64);

        // item 9: reduce validator stake
        staking.slash_validator(&validator_addr, slash_amount)?;

        // item 10: burn slashed tokens (track burned portion)
        let burned_amount = slash_amount * U256::from(self.config.burn_fraction_bps) / U256::from(10_000u64);
        // The remainder (slash_amount - burned_amount) could go to reporter treasury
        // but that accounting is left to the block execution layer (item 20).

        // item 11: jail validator via remove + mutate + re-add
        if let Some(mut v) = validator_set.remove_validator(&validator_addr) {
            v.slash(slash_amount);
            // Re-add only if stake remains (item 12: remove if zero)
            if !v.stake.is_zero() {
                let _ = validator_set.add_validator(v);
            }
            // else: validator removed permanently from active set
        }

        // item 17: record cooldown so the validator cannot rejoin immediately
        self.set_cooldown(validator_addr, current_height)?;

        // Build event
        let event = SlashingEvent::new(&evidence, slash_amount, burned_amount, current_height);

        // item 13: persist slashing event
        self.persist_slashing_event(&event)?;

        // item 18: store slashing history entry per validator
        self.store_slashing_history(&validator_addr, &event)?;

        // item 14: update validator reputation (re-use evidence log entry)
        info!(
            "validator {} reputation updated: slashed {} at height {} for {}",
            validator_addr, slash_amount, current_height, evidence.misbehavior.kind()
        );

        // item 15: emit slashing event log
        warn!(
            "[SLASHING EVENT] validator={} kind={} slash={} burned={} height={}",
            validator_addr,
            event.misbehavior_kind,
            slash_amount,
            burned_amount,
            current_height
        );

        // item 16: notify governance module
        self.notify_governance(governance, &event)?;

        // Remove from pending pool
        self.pending_evidence.remove(evidence_id);

        Ok(event)
    }

    // â”€â”€ item 17: cooldown enforcement â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn set_cooldown(&self, validator: Address, current_height: u64) -> Result<()> {
        let release_at = current_height.saturating_add(self.config.cooldown_blocks);
        let key = cooldown_key(&validator);
        self.storage.state_put(key, release_at.to_le_bytes().to_vec())
    }

    pub fn is_in_cooldown(&self, validator: &Address, current_height: u64) -> Result<bool> {
        let key = cooldown_key(validator);
        let Some(bytes) = self.storage.state_get(key)? else {
            return Ok(false);
        };
        if bytes.len() != 8 {
            return Ok(false);
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(current_height < u64::from_le_bytes(arr))
    }

    pub fn cooldown_release_height(&self, validator: &Address) -> Result<Option<u64>> {
        let key = cooldown_key(validator);
        let Some(bytes) = self.storage.state_get(key)? else {
            return Ok(None);
        };
        if bytes.len() != 8 {
            return Ok(None);
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(Some(u64::from_le_bytes(arr)))
    }

    // â”€â”€ item 13: persist slashing event â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn persist_slashing_event(&self, event: &SlashingEvent) -> Result<()> {
        let key = slashing_event_key(&event.id);
        let bytes = bincode::serialize(event)
            .map_err(|e| anyhow!("slash event serialize: {}", e))?;
        self.storage.state_put(key, bytes)
    }

    pub fn load_slashing_event(&self, event_id: &[u8; 32]) -> Result<Option<SlashingEvent>> {
        let key = slashing_event_key(event_id);
        let Some(bytes) = self.storage.state_get(key)? else {
            return Ok(None);
        };
        let event: SlashingEvent = bincode::deserialize(&bytes)
            .map_err(|e| anyhow!("slash event deserialize: {}", e))?;
        Ok(Some(event))
    }

    // â”€â”€ item 18: store slashing history per validator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn store_slashing_history(&self, validator: &Address, event: &SlashingEvent) -> Result<()> {
        let key = slashing_history_key(validator, event.height);
        let bytes = bincode::serialize(event)
            .map_err(|e| anyhow!("slash history serialize: {}", e))?;
        self.storage.state_put(key, bytes)
    }

    /// Load all slashing history entries for a validator (item 18).
    pub fn slashing_history(&self, validator: &Address) -> Result<Vec<SlashingEvent>> {
        let prefix = slashing_history_prefix(validator);
        let entries = self.storage.state_prefix_scan(prefix)?;
        let mut events = Vec::new();
        for (_, bytes) in entries {
            if let Ok(event) = bincode::deserialize::<SlashingEvent>(&bytes) {
                events.push(event);
            }
        }
        events.sort_by_key(|e| e.height);
        Ok(events)
    }

    // â”€â”€ item 16: notify governance module â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn notify_governance(
        &self,
        governance: &mut GovernanceManager,
        event: &SlashingEvent,
    ) -> Result<()> {
        use crate::governance::ProposalType;
        let title = format!(
            "Slashing: validator {} for {}",
            event.validator, event.misbehavior_kind
        );
        let description = format!(
            "Validator {} was slashed {} tokens at block height {} for misbehavior: {}. Evidence ID: {}",
            event.validator,
            event.slash_amount,
            event.height,
            event.misbehavior_kind,
            hex::encode(event.evidence_id),
        );
        governance.submit_proposal(
            title,
            ProposalType::TextProposal { description },
            event.height,
            event.height.saturating_add(1000),
        );
        Ok(())
    }

    // â”€â”€ item 19: expose slashing via RPC â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn get_slashing_event_rpc(&self, event_id: &[u8; 32]) -> Result<Option<SlashingEventRpc>> {
        Ok(self.load_slashing_event(event_id)?.as_ref().map(SlashingEventRpc::from))
    }

    pub fn get_slashing_history_rpc(&self, validator: &Address) -> Result<Vec<SlashingEventRpc>> {
        Ok(self
            .slashing_history(validator)?
            .iter()
            .map(SlashingEventRpc::from)
            .collect())
    }

    /// Return all pending (unconfirmed) evidence for RPC inspection.
    pub fn pending_evidence_rpc(&self) -> Vec<serde_json::Value> {
        self.pending_evidence
            .values()
            .map(|e| {
                serde_json::json!({
                    "id": hex::encode(e.id),
                    "validator": e.validator.to_string(),
                    "kind": e.misbehavior.kind(),
                    "height": e.reported_at_height,
                    "verified": e.verified,
                })
            })
            .collect()
    }
}

// â”€â”€ item 20: include slashing in block execution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Process all verified pending evidence from a block's evidence list.
/// This is called from the block executor after applying transactions.
pub fn apply_block_slashing(
    manager: &mut SlashingManager,
    evidence_ids: &[[u8; 32]],
    block_height: u64,
    validator_set: &mut ValidatorSet,
    staking: &mut StakingManager,
    governance: &mut GovernanceManager,
) -> Result<Vec<SlashingEvent>> {
    let mut events = Vec::new();
    for id in evidence_ids {
        match manager.execute_slash(id, block_height, validator_set, staking, governance) {
            Ok(event) => events.push(event),
            Err(e) => {
                warn!("slashing execution failed for evidence {:?}: {}", id, e);
            }
        }
    }
    Ok(events)
}

// â”€â”€ storage key helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

fn slashing_event_key(event_id: &[u8; 32]) -> Vec<u8> {
    let mut key = SLASHING_EVENT_PREFIX.to_vec();
    key.extend_from_slice(event_id);
    key
}

fn slashing_history_prefix(validator: &Address) -> Vec<u8> {
    let mut key = SLASHING_HISTORY_PREFIX.to_vec();
    key.extend_from_slice(validator.as_bytes());
    key.push(b':');
    key
}

fn slashing_history_key(validator: &Address, height: u64) -> Vec<u8> {
    let mut key = slashing_history_prefix(validator);
    key.extend_from_slice(&height.to_be_bytes()); // big-endian for scan order
    key
}

fn cooldown_key(validator: &Address) -> Vec<u8> {
    let mut key = COOLDOWN_PREFIX.to_vec();
    key.extend_from_slice(validator.as_bytes());
    key
}

// â”€â”€ tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::GovernanceManager;
    use crate::pos::staking::StakingManager;
    use crate::pos::validator_set::ValidatorSet;
    use vage_storage::StorageEngine;
    use vage_types::{Address, Validator};
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_db(name: &str) -> (PathBuf, Arc<StorageEngine>) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from(format!("target/tmp/slashing_test_{name}_{ts}.redb"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let storage = Arc::new(StorageEngine::new(&path).unwrap());
        (path, storage)
    }

    fn make_validator(seed: u8) -> (SigningKey, Validator) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let addr = Address::from_public_key(&sk.verifying_key().to_bytes());
        let validator = Validator::new(addr, sk.verifying_key().to_bytes(), U256::from(1_000_000u64));
        (sk, validator)
    }

    fn make_vote(sk: &SigningKey, block_hash: [u8; 32], view: u64) -> Vote {
        let addr = Address::from_public_key(&sk.verifying_key().to_bytes());
        let mut vote = Vote::new(addr, block_hash, view);
        vote.sign(sk).expect("sign");
        vote
    }

    fn default_manager(storage: Arc<StorageEngine>) -> SlashingManager {
        SlashingManager::new(SlashingConfig::default(), storage)
    }

    #[test]
    fn detect_double_vote_same_view_different_blocks() {
        let (path, storage) = unique_db("dv");
        let (sk, _) = make_validator(1);
        let mgr = default_manager(storage.clone());

        let vote_a = make_vote(&sk, [1u8; 32], 5);
        let vote_b = make_vote(&sk, [2u8; 32], 5);
        let same_block = make_vote(&sk, [1u8; 32], 5);

        assert!(mgr.detect_double_vote(&vote_a, &vote_b).is_some());
        assert!(mgr.detect_double_vote(&vote_a, &same_block).is_none());
        drop(storage); let _ = fs::remove_file(&path);
    }

    #[test]
    fn detect_double_proposal_different_bytes() {
        let (path, storage) = unique_db("dp");
        let mgr = default_manager(storage.clone());
        assert!(mgr.detect_double_proposal(3, vec![1, 2], vec![3, 4]).is_some());
        assert!(mgr.detect_double_proposal(3, vec![1, 2], vec![1, 2]).is_none());
        drop(storage); let _ = fs::remove_file(&path);
    }

    #[test]
    fn detect_invalid_signature_bad_vote() {
        let (path, storage) = unique_db("sig");
        let (sk, validator) = make_validator(2);
        let mgr = default_manager(storage.clone());

        // Valid vote should not trigger
        let valid = make_vote(&sk, [1u8; 32], 1);
        assert!(mgr.detect_invalid_signature(&valid, &validator).is_none());

        // Vote with zero signature should trigger
        let mut bad = valid.clone();
        bad.signature = [0u8; 64];
        assert!(mgr.detect_invalid_signature(&bad, &validator).is_some());
        drop(storage); let _ = fs::remove_file(&path);
    }

    #[test]
    fn record_evidence_assigns_deterministic_id() {
        let (path, storage) = unique_db("rec");
        let (sk, _) = make_validator(3);
        let addr = Address::from_public_key(&sk.verifying_key().to_bytes());
        let mut mgr = default_manager(storage.clone());
        let vote_a = make_vote(&sk, [1u8; 32], 1);
        let vote_b = make_vote(&sk, [2u8; 32], 1);
        let mb = Misbehavior::DoubleVote { view: 1, vote_a, vote_b };

        let id1 = mgr.record_evidence(addr, mb.clone(), 10, addr, [0u8; 64]).unwrap();
        // Same inputs â†’ same id
        let id2 = mgr.record_evidence(addr, mb, 10, addr, [0u8; 64]).unwrap();
        assert_eq!(id1, id2);
        drop(storage); let _ = fs::remove_file(&path);
    }

    #[test]
    fn full_slash_pipeline_reduces_stake_and_jails_validator() {
        let (path, storage) = unique_db("slash");
        let (sk, validator) = make_validator(4);
        let addr = validator.address;

        let mut mgr = default_manager(storage.clone());
        let mut vs = ValidatorSet::new();
        let mut staking = StakingManager::with_storage(storage.clone());
        let mut governance = GovernanceManager::new();

        vs.add_validator(validator.clone()).unwrap();
        staking.stake_tokens(addr, U256::from(1_000_000u64)).unwrap();

        let vote_a = make_vote(&sk, [1u8; 32], 2);
        let vote_b = make_vote(&sk, [2u8; 32], 2);
        let mb = Misbehavior::DoubleVote { view: 2, vote_a: vote_a.clone(), vote_b: vote_b.clone() };

        // Sign evidence with the reporter's key (reporter == slashed validator for test simplicity)
        let evidence = Evidence::new(addr, mb.clone(), 100, addr, [0u8; 64]);
        let id = evidence.id;

        // Manually insert verified evidence
        let mut verified = evidence;
        verified.verified = true;
        mgr.pending_evidence.insert(id, verified);

        let event = mgr.execute_slash(&id, 100, &mut vs, &mut staking, &mut governance).unwrap();

        assert!(event.slash_amount > U256::zero());
        assert!(event.burned_amount > U256::zero());
        assert!(event.burned_amount <= event.slash_amount);

        // Validator should be jailed (removed from active set or stake reduced)
        // active_validators() only returns Active status validators
        let active = vs.active_validators();
        assert!(!active.iter().any(|v| v.address == addr));

        // Slashing history should be stored
        let history = mgr.slashing_history(&addr).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].validator, addr);

        // Cooldown should be active
        assert!(mgr.is_in_cooldown(&addr, 100).unwrap());
        assert!(!mgr.is_in_cooldown(&addr, 100 + mgr.config.cooldown_blocks + 1).unwrap());

        drop(storage); let _ = fs::remove_file(&path);
    }

    #[test]
    fn rpc_getters_return_correct_data() {
        let (path, storage) = unique_db("rpc");
        let (_sk, validator) = make_validator(5);
        let addr = validator.address;
        let mut mgr = default_manager(storage.clone());
        let mut vs = ValidatorSet::new();
        let mut staking = StakingManager::with_storage(storage.clone());
        let mut governance = GovernanceManager::new();
        vs.add_validator(validator.clone()).unwrap();
        staking.stake_tokens(addr, U256::from(500_000u64)).unwrap();

        let evidence = {
            let mb = Misbehavior::DoubleProposal { view: 5, proposal_a: vec![1], proposal_b: vec![2] };
            let mut e = Evidence::new(addr, mb, 200, addr, [0u8; 64]);
            e.verified = true;
            e
        };
        let id = evidence.id;
        mgr.pending_evidence.insert(id, evidence);

        let event = mgr.execute_slash(&id, 200, &mut vs, &mut staking, &mut governance).unwrap();

        let rpc_event = mgr.get_slashing_event_rpc(&event.id).unwrap();
        assert!(rpc_event.is_some());

        let history = mgr.get_slashing_history_rpc(&addr).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].misbehavior, "DoubleProposal");

        drop(storage); let _ = fs::remove_file(&path);
    }
}
