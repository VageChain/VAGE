# RPC API Architecture

VageChain is built to completely abstract its underlying computational complexity from the developers, presenting an identical interface to traditional EVM environments.

## 1. EIP-1474 / EVM API Compliance
The JSON-RPC interface fully implements standard web3 specifications, allowing immediate compatibility without requiring custom SDKs.
Supported namespaces include:
- `eth_` (Core chain querying, gas estimation, log reading)
- `net_` (Peer-to-peer and network configuration endpoints)
- `web3_` (Client utility endpoints)

## 2. Middleware Mapping & Storage Indexing
VageChain runs a highly concurrent `vage-indexer` process connected via WebSockets and local IPC to the core runtime.
When a standard request like `eth_getLogs` is executed, the query doesn't stall the parallel EVM executing native tasks. Instead, it hits an isolated, read-replica SQLite/RocksDB indexing cache optimized precisely for generic EVM historical filters.

## 3. Handling Commit-Reveal Injections
Behind the scenes, when `eth_sendRawTransaction` is fired from MetaMask, the VageChain RPC node automatically intercepts it:
1. It natively encrypts the standard payload.
2. It pushes the Commitment phase natively to the mempool.
3. It operates a background relayer process to submit the Reveal phase immediately after the consensus engine acknowledges the block ordering.

The user perfectly interacts via legacy Web3 protocols, while the VageChain RPC automatically envelopes the MEV-protection flow on their behalf.
