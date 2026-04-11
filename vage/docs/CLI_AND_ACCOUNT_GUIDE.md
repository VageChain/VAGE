# VageChain CLI & Account Management Guide

This comprehensive guide covers CLI operations, account workflows, and documentation for maintainers of the VageChain CLI.

---

## 🛠️ CLI Reference

The VageChain CLI provides commands for managing accounts, submitting transactions, querying state, and controlling nodes.

### Account Commands
- `account generate`
- `account list-devnet`
- `account import`
- `account derive`

### Transaction Commands
- `transaction send`
- `transaction status`
- `transaction pending`

### Query Commands
- `query balance`
- `query nonce`
- `query state-root`

### Node Commands
- `node start`
- `node status`
- `node peers`

*Tip: Use the quickstart for the shortest path to a running node.*

---

## 👤 Account Operations

This section covers the common account workflows in VageChain.

### Common Tasks
- List the pre-funded DevNet accounts
- Generate a new local account
- Import an existing key
- Check balance and nonce
- Submit a transfer transaction

### Security Notes
- **Use the funded validator accounts only for DevNet testing.**
- **Keep private keys out of source control.**

---

## 💸 First Transfer Tutorial

Here is the quickest end-to-end flow for sending a transfer on DevNet.

### Steps
1. Start the node using the launcher script (`devnet_start.ps1` or `devnet_start.sh`).
2. Confirm the RPC endpoint is reachable.
3. List the pre-funded accounts using `account list-devnet`.
4. Submit a transfer from one funded account to a fresh address using `transaction send`.
5. Query the transaction status and the recipient balance to confirm.

### Reminders
- Use DevNet keys only for local testing.
- Confirm the account nonce before submitting repeated transfers.

---

## 🏗️ CLI Implementation Notes

This section is for maintainers to understand the CLI structure.

### Architecture
- Command parsing and dispatch
- RPC request construction
- Account and transaction helpers
- Output formatting and error handling

### Maintenance Notes
- Keep command names stable where possible
- Prefer consistent JSON-RPC responses
- Update the command reference when CLI behavior changes
