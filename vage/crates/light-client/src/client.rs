use anyhow::Result;
use libp2p::PeerId;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};
use vage_block::BlockHeader;
use vage_networking::{
    P2PNetwork, RpcStateProofQuery, RpcStateProofRequest, RpcStateProofValue, RpcSyncClient,
    RpcVerifiedHeaderEnvelope,
};
use vage_types::{Account, Address, BlockHeight, Hash, Validator};

use crate::header_sync::HeaderSync;
use crate::proofs::ProofVerifier;

/// A lightweight client for the VageChain blockchain that verifies block headers
/// and maintains a trusted view of the chain without storing the full state.
pub struct LightClient {
    /// The most recent header that has been cryptographically verified.
    latest_header: Arc<RwLock<Option<BlockHeader>>>,
    /// Networking handle used for request-response header discovery.
    networking: Arc<Mutex<P2PNetwork>>,
    /// The primary peer used for fetching new headers.
    peer: Arc<RwLock<PeerId>>,
    /// A trusted block height used as a synchronization anchor (checkpoint).
    trusted_checkpoint: Option<BlockHeight>,
    /// The underlying synchronization engine.
    sync_engine: Arc<RwLock<HeaderSync>>,
}

impl LightClient {
    /// Creates a new light client instance anchored at a trusted height.
    pub fn new(
        networking: Arc<Mutex<P2PNetwork>>,
        peer: PeerId,
        trusted_header: BlockHeader,
    ) -> Self {
        Self::new_with_validator_set(networking, peer, trusted_header, Vec::new())
    }

    pub fn new_with_validator_set(
        networking: Arc<Mutex<P2PNetwork>>,
        peer: PeerId,
        trusted_header: BlockHeader,
        validator_set: Vec<Validator>,
    ) -> Self {
        info!(
            "Initializing VageChain light client... Primary peer: {}, Trusted Checkpoint: {}",
            peer, trusted_header.height
        );

        Self {
            latest_header: Arc::new(RwLock::new(None)),
            networking,
            peer: Arc::new(RwLock::new(peer)),
            trusted_checkpoint: Some(trusted_header.height),
            sync_engine: Arc::new(RwLock::new(HeaderSync::new_with_validator_set(
                peer,
                trusted_header,
                validator_set,
            ))),
        }
    }

    /// Returns the height and hash of the latest verified block header.
    pub async fn get_chain_tip(&self) -> (BlockHeight, Option<Hash>) {
        let header_guard = self.latest_header.read().await;
        if let Some(header) = &*header_guard {
            (header.height, Some(header.hash()))
        } else {
            (self.trusted_checkpoint.unwrap_or(0), None)
        }
    }

    /// Detects the target network height from the primary peer.
    pub async fn detect_network_head(&self) -> Result<BlockHeight> {
        let peer = *self.peer.read().await;
        info!("Detecting latest chain head from primary peer: {}", peer);

        let mut network = self.networking.lock().await;
        let remote_height = network.request_latest_block_height(peer).await?;

        info!("Peer {} reported network height {}", peer, remote_height);
        Ok(remote_height)
    }

    /// LC Step 1 â€” Light client downloads block headers and verifies them.
    ///
    /// Full sync pipeline:
    /// 1. Detect the network head from the primary peer.
    /// 2. Download the missing header range via `HeaderSync`.
    /// 3. `process_pending_batches` (called inside `receive_headers`) verifies
    ///    each header's linkage, proposer signature, and ZK validity proof
    ///    (LC steps 2 and 3).
    /// 4. Accept the block and advance the trusted tip (LC step 4).
    pub async fn run_sync_loop(&self) -> Result<()> {
        info!("Initiating light client synchronization sequence...");
        let peer = *self.peer.read().await;

        // LC Step 1a â€” detect network head height from the primary peer.
        let target_height = self.detect_network_head().await?;
        let (current_height, _) = self.get_chain_tip().await;

        if target_height <= current_height {
            info!(
                "Light client is already at the network tip (height={})",
                current_height
            );
            return Ok(());
        }

        // LC Step 1b â€” download missing headers with validator-signature bundles.
        info!(
            "Sync gap detected: local={}, network={}. Fetching verified header range...",
            current_height, target_height
        );
        let headers = {
            let mut network = self.networking.lock().await;
            network
                .request_headers(peer, current_height.saturating_add(1), target_height)
                .await?
        }
        .unwrap_or_default();

        let mut sync_guard = self.sync_engine.write().await;
        sync_guard.update_peer(peer);
        sync_guard.sync_to_latest_peer_height(target_height).await?;
        sync_guard.receive_verified_headers(
            headers
                .into_iter()
                .map(Self::to_verified_header_envelope)
                .collect(),
        )?;

        // LC Step 4 â€” accept block: advance the trusted tip to the latest
        // verified header so future queries reflect the new chain state.
        if let Some(header) = sync_guard.latest_verified_header() {
            let mut header_guard = self.latest_header.write().await;
            *header_guard = Some(header.clone());
            info!(
                "Trusted state updated to height {}: Hash={}",
                header.height,
                hex::encode(header.hash())
            );
        }

        Ok(())
    }

    fn to_verified_header_envelope(
        envelope: RpcVerifiedHeaderEnvelope,
    ) -> crate::header_sync::VerifiedHeaderEnvelope {
        let consensus_signatures = envelope
            .consensus_signatures
            .into_iter()
            .filter_map(|(address, signature)| {
                let signature: Result<[u8; 64], _> = signature.try_into();
                signature.ok().map(|signature| (address, signature))
            })
            .collect();

        crate::header_sync::VerifiedHeaderEnvelope {
            header: envelope.header,
            consensus_signatures,
        }
    }

    /// Proactively updates the light client state with a new batch of headers from the network.
    pub async fn update_headers(&self, headers: Vec<BlockHeader>) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        let mut sync_guard = self.sync_engine.write().await;
        sync_guard.receive_headers(headers)?;

        if let Some(header) = sync_guard.latest_verified_header() {
            let mut header_guard = self.latest_header.write().await;
            *header_guard = Some(header.clone());
        }

        Ok(())
    }

    pub async fn verify_account_state(
        &self,
        address: &Address,
        account: &Account,
        proof: &vage_state::VerkleProof,
    ) -> Result<bool> {
        let header = self
            .latest_header
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow::anyhow!("light client has no verified header"))?;
        ProofVerifier::verify_account_state(proof, address, account, header.state_root)
    }

    pub async fn verify_storage_state(
        &self,
        address: &Address,
        storage_key: [u8; 32],
        storage_value: [u8; 32],
        proof: &vage_state::VerkleProof,
    ) -> Result<bool> {
        let header = self
            .latest_header
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow::anyhow!("light client has no verified header"))?;
        ProofVerifier::verify_contract_storage(
            proof,
            address,
            storage_key,
            storage_value,
            header.state_root,
        )
    }

    pub async fn request_account_state_at_height(
        &self,
        height: BlockHeight,
        address: Address,
        max_depth: usize,
    ) -> Result<(Account, vage_state::RpcVerkleProof)> {
        let peer = *self.peer.read().await;
        let response = {
            let mut network = self.networking.lock().await;
            network
                .request_state_proof(
                    peer,
                    RpcStateProofRequest {
                        height,
                        max_depth,
                        query: RpcStateProofQuery::Account { address },
                    },
                )
                .await?
        }
        .ok_or_else(|| anyhow::anyhow!("peer did not return an account state proof"))?;

        let header = self
            .verified_header_at_height(height)
            .await
            .ok_or_else(|| anyhow::anyhow!("light client has not synced header {}", height))?;

        if response.proof.root != header.state_root {
            anyhow::bail!(
                "state proof root mismatch for height {}: expected 0x{}, got 0x{}",
                height,
                hex::encode(header.state_root),
                hex::encode(response.proof.root)
            );
        }

        let RpcStateProofValue::Account(account) = response.value else {
            anyhow::bail!("peer returned non-account proof value for account query");
        };

        if !ProofVerifier::verify_rpc_account_proof(&response.proof, &address, &account)? {
            anyhow::bail!(
                "account state proof verification failed at height {}",
                height
            );
        }

        Ok((account, response.proof))
    }

    /// Returns the current trusted checkpoint height.
    pub fn trusted_checkpoint(&self) -> Option<BlockHeight> {
        self.trusted_checkpoint
    }

    /// Returns the PeerId of the node this light client is tracking.
    pub async fn tracking_peer(&self) -> PeerId {
        *self.peer.read().await
    }

    pub async fn update_tracking_peer(&self, peer: PeerId) {
        *self.peer.write().await = peer;
        self.sync_engine.write().await.update_peer(peer);
    }

    /// Verifies if the current state of the light client is consistent with the chain.
    pub async fn verify_state_integrity(&self) -> Result<bool> {
        let (height, hash) = self.get_chain_tip().await;
        if hash.is_none() && height > 0 {
            warn!("Light client state is uninitialized at height {}", height);
            return Ok(false);
        }

        info!("Light client state integrity verified at height {}", height);
        Ok(true)
    }

    async fn verified_header_at_height(&self, height: BlockHeight) -> Option<BlockHeader> {
        if self
            .latest_header
            .read()
            .await
            .as_ref()
            .map(|header| header.height)
            == Some(height)
        {
            return self.latest_header.read().await.clone();
        }

        let sync_guard = self.sync_engine.read().await;
        sync_guard
            .verified_headers
            .iter()
            .find(|header| header.height == height)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::LightClient;
    use anyhow::Result;
    use ed25519_dalek::{Signer, SigningKey};
    use libp2p::{identity::Keypair, Multiaddr, PeerId};
    use primitive_types::U256;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;
    use vage_block::{BlockBody, BlockHeader};
    use vage_networking::{
        L1Response, P2PConfig, P2PNetwork, RpcStateProofResponse, RpcStateProofValue,
        RpcVerifiedHeaderEnvelope,
    };
    use vage_state::{VerkleProof, VerkleTree};
    use vage_types::{validator::ValidatorStatus, Account, Address, Validator};

    fn test_config() -> P2PConfig {
        P2PConfig {
            local_key: Keypair::generate_ed25519(),
            bootstrap_peers: Vec::new(),
            discovery_interval: Duration::from_millis(25),
            discovery_backoff: Duration::from_millis(10),
            max_peers: 8,
        }
    }

    fn tcp_addr(port: u16) -> Multiaddr {
        format!("/ip4/127.0.0.1/tcp/{port}")
            .parse()
            .expect("tcp multiaddr should parse")
    }

    fn expected_sp1_commitment(public_inputs: &[u8]) -> Vec<u8> {
        let verification_key = vec![0u8; 128];
        let mut hasher = Sha256::new();
        hasher.update(b"sp1:trace");
        hasher.update(&verification_key);
        hasher.update(public_inputs);
        let execution_trace = hasher.finalize_reset();

        hasher.update(b"sp1:pk");
        hasher.update(&verification_key);
        let proving_key = hasher.finalize_reset();

        hasher.update(proving_key);
        hasher.update(execution_trace);
        hasher.update(public_inputs);
        hasher.finalize().to_vec()
    }

    #[tokio::test]
    async fn run_sync_loop_accepts_qc_backed_verified_headers() -> Result<()> {
        let signer = SigningKey::from_bytes(&[0u8; 32]);
        let proposer_pubkey = signer.verifying_key().to_bytes();
        let proposer = Address::from_public_key(&proposer_pubkey);

        let mut validator = Validator::new(proposer, proposer_pubkey, U256::from(10u64.pow(18)));
        validator.status = ValidatorStatus::Active;
        validator.voting_power = 1;
        let validator_set = vec![validator.clone()];

        let genesis = BlockHeader::genesis();
        let mut header = BlockHeader::new(genesis.hash(), 1);
        header.proposer = proposer;
        header.timestamp = genesis.timestamp + 1;
        header.validator_root = BlockBody::compute_validator_root(&validator_set);
        let unsigned_hash = header.hash();
        header.zk_proof = Some(expected_sp1_commitment(&unsigned_hash));
        let header_hash = header.hash();
        header.signature = Some(signer.sign(&header_hash).to_bytes());

        let envelope = RpcVerifiedHeaderEnvelope {
            header: header.clone(),
            consensus_signatures: vec![(proposer, signer.sign(&header_hash).to_bytes().to_vec())],
        };

        let peer_id = PeerId::random();
        let mut network = P2PNetwork::new(test_config()).await?;
        network
            .peer_store
            .add_peer(vage_networking::Peer::new(peer_id, tcp_addr(22000)));
        network.queue_mock_rpc_response(L1Response::respond_latest_block_height(Some(1)));
        network.queue_mock_rpc_response(L1Response::respond_headers(Some(vec![envelope])));

        let client = LightClient::new_with_validator_set(
            Arc::new(Mutex::new(network)),
            peer_id,
            genesis,
            validator_set,
        );

        client.run_sync_loop().await?;

        let (height, hash) = client.get_chain_tip().await;
        assert_eq!(height, 1);
        assert_eq!(hash, Some(header.hash()));

        Ok(())
    }

    #[tokio::test]
    async fn light_client_requests_account_state_proof_against_synced_header() -> Result<()> {
        let signer = SigningKey::from_bytes(&[1u8; 32]);
        let proposer_pubkey = signer.verifying_key().to_bytes();
        let proposer = Address::from_public_key(&proposer_pubkey);

        let mut validator = Validator::new(proposer, proposer_pubkey, U256::from(10u64.pow(18)));
        validator.status = ValidatorStatus::Active;
        validator.voting_power = 1;
        let validator_set = vec![validator.clone()];

        let account = {
            let mut account = Account::new(proposer);
            account.increase_balance(U256::from(777u64));
            account
        };
        let mut tree = VerkleTree::new();
        tree.insert(*proposer.as_bytes(), account.hash())?;
        let rpc_account_proof = VerkleProof::generate_account_proof(&tree, &proposer)?
            .export_for_rpc(tree.root_commitment());

        let genesis = BlockHeader::genesis();
        let mut header = BlockHeader::new(genesis.hash(), 1);
        header.proposer = proposer;
        header.timestamp = genesis.timestamp + 1;
        header.validator_root = BlockBody::compute_validator_root(&validator_set);
        header.state_root = tree.root_commitment();
        let unsigned_hash = header.hash();
        header.zk_proof = Some(expected_sp1_commitment(&unsigned_hash));
        let header_hash = header.hash();
        header.signature = Some(signer.sign(&header_hash).to_bytes());

        let envelope = RpcVerifiedHeaderEnvelope {
            header: header.clone(),
            consensus_signatures: vec![(proposer, signer.sign(&header_hash).to_bytes().to_vec())],
        };

        let peer_id = PeerId::random();
        let mut network = P2PNetwork::new(test_config()).await?;
        network
            .peer_store
            .add_peer(vage_networking::Peer::new(peer_id, tcp_addr(22001)));
        network.queue_mock_rpc_response(L1Response::respond_latest_block_height(Some(1)));
        network.queue_mock_rpc_response(L1Response::respond_headers(Some(vec![envelope])));
        network.queue_mock_rpc_response(L1Response::respond_state_proof(Some(
            RpcStateProofResponse {
                height: 1,
                proof: rpc_account_proof,
                value: RpcStateProofValue::Account(account.clone()),
            },
        )));

        let client = LightClient::new_with_validator_set(
            Arc::new(Mutex::new(network)),
            peer_id,
            genesis,
            validator_set,
        );
        client.run_sync_loop().await?;

        let (proved_account, proof) = client
            .request_account_state_at_height(1, proposer, 32)
            .await?;

        assert_eq!(proved_account.balance, U256::from(777u64));
        assert_eq!(proof.root, header.state_root);
        Ok(())
    }

    #[tokio::test]
    async fn update_tracking_peer_preserves_verified_tip() -> Result<()> {
        let signer = SigningKey::from_bytes(&[2u8; 32]);
        let proposer_pubkey = signer.verifying_key().to_bytes();
        let proposer = Address::from_public_key(&proposer_pubkey);
        let mut validator = Validator::new(proposer, proposer_pubkey, U256::from(10u64.pow(18)));
        validator.status = ValidatorStatus::Active;
        validator.voting_power = 1;
        let validator_set = vec![validator.clone()];

        let peer_id = PeerId::random();
        let replacement_peer = PeerId::random();
        let mut network = P2PNetwork::new(test_config()).await?;
        let genesis = BlockHeader::genesis();
        let mut header = BlockHeader::new(genesis.hash(), 1);
        header.proposer = proposer;
        header.timestamp = genesis.timestamp + 1;
        header.validator_root = BlockBody::compute_validator_root(&validator_set);
        let unsigned_hash = header.hash();
        header.zk_proof = Some(expected_sp1_commitment(&unsigned_hash));
        let header_hash = header.hash();
        header.signature = Some(signer.sign(&header_hash).to_bytes());

        let envelope = RpcVerifiedHeaderEnvelope {
            header: header.clone(),
            consensus_signatures: vec![(proposer, signer.sign(&header_hash).to_bytes().to_vec())],
        };

        network
            .peer_store
            .add_peer(vage_networking::Peer::new(peer_id, tcp_addr(22002)));
        network.queue_mock_rpc_response(L1Response::respond_latest_block_height(Some(1)));
        network.queue_mock_rpc_response(L1Response::respond_headers(Some(vec![envelope])));

        let client = LightClient::new_with_validator_set(
            Arc::new(Mutex::new(network)),
            peer_id,
            genesis,
            validator_set,
        );
        client.run_sync_loop().await?;

        client.update_tracking_peer(replacement_peer).await;

        let (height, hash) = client.get_chain_tip().await;
        assert_eq!(client.tracking_peer().await, replacement_peer);
        assert_eq!(height, 1);
        assert_eq!(hash, Some(header.hash()));

        Ok(())
    }
}
