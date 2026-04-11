# 🎯 VageSocial Web3 Setup & Developer Guide

Welcome to the complete setup and developer guide for the VageSocial Web3 application. This guide walks you through setting up the VageChain DevNet, launching the backend API, running the React frontend, and configuring MetaMask for testing.

---

## 📋 Prerequisites

Before starting, ensure you have the following installed:
- ✅ **Rust** (for blockchain & backend)
- ✅ **Node.js** (for frontend)
- ✅ **MetaMask** browser extension
- ✅ **Git**
- ✅ **~20GB disk space** (for Rust builds)

---

## 🚀 Quick Start: Running the Network

You need to run all three services in separate terminals.

### 1. Start VageChain DevNet
The blockchain foundation must start first.
```bash
# Terminal 1
cd d:\VAGE
# Windows
.\devnet_start.ps1
# Mac/Linux
./devnet_start.sh
```
*(Wait for `RPC endpoint: http://127.0.0.1:8080/rpc` and `Chain ID: vage_devnet_1`)*

### 2. Start Backend API (Indexer)
```powershell
# Terminal 2
cd d:\VAGE\vage-indexer
cargo run
```
*(Wait for `API server listening on http://127.0.0.1:8888`)*

### 3. Start Frontend Web UI
```powershell
# Terminal 3
cd d:\VAGE\vage-web
npm run dev
```
*(Wait for `➜  Local:   http://localhost:3001/`)*

---

## 🦊 MetaMask Configuration

To interact with VageSocial, MetaMask needs to be configured for the VageChain DevNet.

### 1. Add VageChain Network

1. Open **MetaMask** and click the network dropdown (top left).
2. Click **"Add Network"** or **"Add a custom network"**.
3. Fill in the following details:

| Setting | Value |
|---------|-------|
| **Network Name** | VageChain DevNet |
| **RPC URL** | `http://127.0.0.1:8080/rpc` |
| **Chain ID** | `2018131581` (or `0x78637a7d`) |
| **Currency Symbol** | `VAGE` |
| **Block Explorer URL** | *(leave empty)* |

4. Click **"Save"**.

### 2. Import a Test Account

VageChain provides pre-funded test accounts (1,000,000 VAGE each). View them via:
```bash
./target/release/vage-cli account list-devnet
```

**Output:**
```text
📋 DEVNET PRE-FUNDED ACCOUNTS
═══════════════════════════════════════════════════════════

Validator #1
───────────────────────────────────────────────────────────
Address:     0x0000000000000000000000000000000000000000000000000000000000000001
Public Key:  0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
Balance:     1000000000000000000000000000 vc (1000000000.000000 tokens)
```
*(Import private key `0x0000000000000000000000000000000000000000000000000000000000000001` into MetaMask for Validator #1).*

> [!CAUTION]
> **A Code of Honor for DevNet Test Tokens**
> These pre-funded assets are strictly for development, stress-testing, and breaking the boundaries of what is possible on VageChain. **They hold absolutely zero real-world value.** Any attempt to sell, misuse, or scam users with these testnet tokens is a direct violation of the builder ethos. 
> 
> Real greatness is forged in the code you write, the systems you architect, and the problems you solve—not in exploiting test networks. VageChain is built by and for true innovators. Take pride in your work, honor the open-source rules, and execute with absolute integrity.

**To import:**
1. Click the MetaMask **account icon** (top right) → **"Import Account"**.
2. Paste one of the **Private Keys** above.
3. Click **"Import"**. Check that your account shows a large VAGE balance.

---

## 🔐 Sign Up & Authentication

VageSocial uses Web3 wallet signatures for authentication.

### Testing Sign Up
1. Visit **http://localhost:3001** in your browser.
2. Go to the **Sign Up** page and click **"Connect Wallet"**.
3. Approve the connection in MetaMask.
4. Enter a **Username** (3-20 chars) and **Display Name**.
5. Click **"Create Account"**. MetaMask will prompt you to **Sign** a message.
6. Click **Sign** to complete registration and log in!

### Testing Sign In
1. Log out from your profile.
2. On the login page, click **"Connect Wallet"** → **"Sign & Login"**.
3. Approve the signature request in MetaMask to log back in.

*(Note: The backend implements `/api/auth/register`, `/api/auth/verify-signature`, and `/api/auth/logout` handlers using basic signature verification and token issuance).*

---

## 💻 CLI Tools & Verification

Verify the DevNet using basic CLI commands or cURL.

**Verify Node Status:**
```bash
curl -X POST http://127.0.0.1:8080/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1}'
# Expected result: {"jsonrpc":"2.0","result":"0x78637a7d","id":1}
```

**Common `vage-cli` Commands:**
```powershell
vage-cli account list-devnet
vage-cli account generate
vage-cli query balance 0x0000000000000000000000000000000000000000000000000000000000000001
vage-cli transaction send --from <address> --to <address> --value <amount> --private-key <key>
vage-cli transaction pending
vage-cli node status
```

---

## 🗺️ System Architecture

```text
┌─────────────────────────────────────┐
│    Your Browser (Port 3001)         │
│  - VageSocial Frontend (React)      │
│  - MetaMask Extension               │
└──────────────┬──────────────────────┘
               │
    ┌──────────┼──────────┐
    ▼          ▼          ▼
 Frontend   Backend    Blockchain
 (Port 3001) (8888)    (Port 8080)
 React       Rust       VageChain
 TypeScript  Axum       DevNet
 Vite        SQLite     
```

### Database Tables (SQLite)
- **Users**: `address`, `username`, `display_name`, `bio`, `avatar_url`, `follower_count`, `following_count`
- **Follows**: `follower_address`, `following_address`, `followed_at`

---

## 🛠️ Troubleshooting

| Issue | Potential Cause / Solution |
|-------|----------------------------|
| **DevNet won't start/build** | From `d:\VAGE\vage`, run `cargo clean` then `cargo build --release`. |
| **MetaMask won't connect** | Ensure DevNet is running. Check RPC URL (`http://127.0.0.1:8080/rpc`) and Port 8080. |
| **"No Accounts Found"** | Check if MetaMask network is DevNet. Manually import private key if needed. |
| **Port Conflicts** | Run `netstat -ano \| findstr :8080` (or `8888`, `3001`) to clear lingering processes. |
| **CORS Errors** | Verify Vite dev server is on port 3001 and API server is on 8888. Restart both. |
