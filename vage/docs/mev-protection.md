# Native MEV Protection: Commit-Reveal Cryptography

Maximal Extractable Value (MEV) represents billions of dollars drained continuously by sophisticated searchers and builders operating on probabilistic mempools. VageChain neutralizes toxic MEV at the protocol level.

## 1. The MEV Attack Surface
In standard blockchains, validators and public mempool operators have pre-execution visibility. 
- **Sandwich Attacks:** Identifying an AMM swap and placing a buy (frontrun) and a sell (backrun) around it.
- **Censorship / Extortion:** Delaying execution based on unencrypted transaction contents.

## 2. The Commit-Reveal Architecture
VageChain employs a strict bipartite transaction lifecycle:

### Phase 1: Cryptographic Commitment
Users broadcast $C(Tx, r)$ where $C$ is a secure commitment scheme (e.g., a hash function like SHA-256 or Poseidon) over the transaction data $Tx$ and a random blinding factor $r$. 
- The mempool only propagates $C(Tx, r)$. 
- The HotStuff consensus engine sequences $C(Tx, r)$ into a block with absolute finality. No validator knows what $Tx$ implies.

### Phase 2: Execution Reveal
Once ordered natively at Block $H$, users (or delegated relayer networks) reveal $(Tx, r)$ for Block $H+1$.
- The protocol verifies that $C(Tx, r) == \text{Commitment}$.
- The transaction executes exactly at the pre-determined index.

## 3. Information Asymmetry Elimination
Because the transaction ordering happens strictly *before* the transaction contents are revealed, searchers have zero data to calculate arbitrage. They cannot inject sandwich transactions because they literally do not know if the user is buying or selling, what token they are swapping, or the slippage parameters until the transactions are already immutably chained.

## 4. Handling Reveal Failures
If a user fails to reveal $r$, the committed transaction inherently fails to execute and is permanently skipped, but a base fee is confiscated algorithmically from the user's previously staked balance to prevent denial-of-service (DoS) spam of the blockchain.
