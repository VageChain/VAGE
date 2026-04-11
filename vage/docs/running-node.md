# Node Runtime & Network Operations 

VageChain optimizes client footprint. Because the state is verified via succinct proofs (Verkle Trees) and execution logic runs concurrently, the node topology is distinct.

## 1. Network Subsystem
VageChain builds on `libp2p` for generic transports, noise encryption, and Kademlia DHT routing. The network distinguishes between two primary streams:
- **Consensus Stream:** High-priority, latency-sensitive HotStuff message passing.
- **Mempool / Sync Stream:** High-bandwidth, eventual-consistency state proofs and historical block synchronization.

## 2. Fast Sync & Snapshots
Because of the mathematical properties of Verkle state proofs, a new node bootstrapping onto the network does not need to replay execution vectors from Genesis. 
- It downloads the recent Vector Commitments and the associated polynomial proofs. 
- Validation of state root takes milliseconds.
- A node joins the actively participating BFT replica set almost instantly, relying on archived nodes only if deep historical EVM tracing logic is explicitly queried.

## 3. Hardware Requirements
| Resource | Minimum (Stateless Light Node) | Recommended (Full Validator) |
|----------|--------------------------------|------------------------------|
| **CPU** | 4 Cores (Sequential processing)| 16+ Cores (Parallel execution)|
| **RAM** | 8 GB | 32 GB |
| **Disk** | 100 GB SSD | 1 TB NVMe |
| **Net** | 20 Mbps | 1 Gbps |

## 4. Diagnostic & Debug Configurations
Running via Cargo embeds massive debug capabilities:
```bash
cargo run --release -- --config configs/devnet.json --log-level debug --metrics-port 9090
```
This spawns integrated Prometheus metric scraping and localized Jaeger telemetry profiling to identify exactly how parallel STMs scale against local workloads.
