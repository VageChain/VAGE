use anyhow::{Result, bail};
use vage_block::BlockBody;
use vage_block::BlockHeader;
use vage_types::Validator;
use vage_types::{BlockHeight, Hash};
use tracing::{info, warn, error};
use crate::verifier::HeaderVerifier;
use std::collections::VecDeque;
use libp2p::PeerId;

#[derive(Clone, Debug)]
pub struct VerifiedHeaderEnvelope {
    pub header: BlockHeader,
    pub consensus_signatures: Vec<(vage_types::Address, [u8; 64])>,
}

/// Orchestrates the synchronization of block headers from a peer to the local light client state.
pub struct HeaderSync {
    /// The libp2p PeerId of the full node providing headers.
    pub peer: PeerId,
    /// The current height of the local verified chain.
    pub current_height: BlockHeight,
    /// The append-only store of headers that have passed all cryptographic checks.
    pub verified_headers: Vec<BlockHeader>,
    /// Temporary queue for batches received from the network awaiting validation.
    pub pending_batches: VecDeque<Vec<BlockHeader>>,
    /// Cached ZK verification key for block state transitions.
    pub zk_verification_key: Vec<u8>,
    /// Active validator set used for aggregated signature checks.
    pub validator_set: Vec<Validator>,
}

impl HeaderSync {
    /// Creates a new synchronization instance starting from a trusted checkpoint header.
    pub fn new(peer: PeerId, trusted_header: BlockHeader) -> Self {
        Self::new_with_validator_set(peer, trusted_header, Vec::new())
    }

    pub fn new_with_validator_set(
        peer: PeerId,
        trusted_header: BlockHeader,
        validator_set: Vec<Validator>,
    ) -> Self {
        let zk_verification_key = HeaderVerifier::load_zk_verification_key().unwrap_or_else(|_| vec![0u8; 128]);
        let current_height = trusted_header.height;
        
        Self {
            peer,
            current_height,
            verified_headers: vec![trusted_header],
            pending_batches: VecDeque::new(),
            zk_verification_key,
            validator_set,
        }
    }

    /// High-level entry point for initiating a sync to a peer's latest height.
    pub async fn sync_to_latest_peer_height(&mut self, peer_height: BlockHeight) -> Result<()> {
        if peer_height <= self.current_height {
            info!("Local chain tip (height={}) is already up to date with peer {}.", self.current_height, self.peer);
            return Ok(());
        }

        let missing_count = peer_height - self.current_height;
        info!("Detecting {} missing headers to sync from peer {}...", missing_count, self.peer);

        // Request the missing range of headers in chunks if necessary.
        // This payload would be sent via libp2p Request-Response protocol.
        let _request_payload = self.request_headers(self.current_height + 1, peer_height)?;
        
        Ok(())
    }

    /// Construct a formal request for a range of block headers to be sent to a full node.
    pub fn request_headers(&self, start: BlockHeight, end: BlockHeight) -> Result<Vec<u8>> {
        info!("Constructing header request for range [{}, {}] from peer {}...", start, end, self.peer);
        // The serializable request format used by the VageChain P2P protocol.
        let request = (start, end);
        Ok(bincode::serialize(&request)?)
    }

    /// Entry point for blocks/headers received from the network swarm.
    pub fn receive_headers(&mut self, headers: Vec<BlockHeader>) -> Result<()> {
        let envelopes = headers
            .into_iter()
            .map(|header| VerifiedHeaderEnvelope {
                header,
                consensus_signatures: Vec::new(),
            })
            .collect();
        self.receive_verified_headers(envelopes)
    }

    pub fn receive_verified_headers(&mut self, headers: Vec<VerifiedHeaderEnvelope>) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        info!("Received batch of {} headers from peer {}.", headers.len(), self.peer);
        
        // Ensure the batch is sorted by height before processing.
        let mut sorted_headers = headers;
        sorted_headers.sort_by_key(|h| h.header.height);
        
        self.process_verified_batch(sorted_headers)?;
        Ok(())
    }

    fn process_verified_batch(&mut self, batch: Vec<VerifiedHeaderEnvelope>) -> Result<()> {
        for envelope in batch {
            let header = envelope.header;
            if header.height != self.current_height + 1 {
                warn!("Received out-of-order header: height={}, expected={}", header.height, self.current_height + 1);
                bail!("Invalid header height sequence: expected {}, got {}", self.current_height + 1, header.height);
            }

            let parent = self.verified_headers.last().ok_or_else(|| anyhow::anyhow!("Internal error: missing parent for linkage verification"))?;
            let proposer_pk = self
                .validator_set
                .iter()
                .find(|validator| validator.address == header.proposer)
                .map(|validator| validator.pubkey)
                .unwrap_or([0u8; 32]);

            HeaderVerifier::validate_header_full(
                &header,
                parent,
                &proposer_pk,
                &self.zk_verification_key,
            )?;

            if !self.validator_set.is_empty() {
                let expected_validator_root = BlockBody::compute_validator_root(&self.validator_set);
                if header.validator_root != expected_validator_root {
                    bail!("validator root mismatch at height {}", header.height);
                }

                HeaderVerifier::verify_consensus_signatures(
                    header.hash(),
                    &envelope.consensus_signatures,
                    &self.validator_set,
                )?;
            }

            self.current_height = header.height;
            self.verified_headers.push(header);
        }

        info!("Header sync progress: successfully verified up to height {}.", self.current_height);
        Ok(())
    }

    /// Iteratively validates and commits all pending header batches to the local verified store.
    #[allow(dead_code)]
    fn process_pending_batches(&mut self) -> Result<()> {
        while let Some(batch) = self.pending_batches.pop_front() {
            for header in batch {
                // 1. Verify height sequence (monotonicity and continuity)
                if header.height != self.current_height + 1 {
                    warn!("Received out-of-order header: height={}, expected={}", header.height, self.current_height + 1);
                    bail!("Invalid header height sequence: expected {}, got {}", self.current_height + 1, header.height);
                }

                // 2. Retrieve the parent to establish linkage. 
                // Since verified_headers is initialized with a checkpoint, this is guaranteed to exist.
                let parent = self.verified_headers.last().ok_or_else(|| anyhow::anyhow!("Internal error: missing parent for linkage verification"))?;

                // 3. Perform exhaustive cryptographic and structural validation.
                // This call includes parent hash linkage, timestamp monotonicity, and ZK-proof verification.
                let proposer_pk = self
                    .validator_set
                    .iter()
                    .find(|validator| validator.address == header.proposer)
                    .map(|validator| validator.pubkey)
                    .unwrap_or([0u8; 32]);

                if let Err(e) = HeaderVerifier::validate_header_full(
                    &header,
                    parent,
                    &proposer_pk,
                    &self.zk_verification_key,
                ) {
                    error!("Validation failed for block at height {}: {:?}", header.height, e);
                    bail!("Light client header verification failed: {:?}", e);
                }

                // 4. Commit the verified header.
                self.current_height = header.height;
                self.verified_headers.push(header);
            }
        }
        
        info!("Header sync progress: successfully verified up to height {}.", self.current_height);
        Ok(())
    }

    pub fn update_validator_set(&mut self, validator_set: Vec<Validator>) {
        self.validator_set = validator_set;
    }

    pub fn update_peer(&mut self, peer: PeerId) {
        self.peer = peer;
    }

    /// Returns the current trusted tip of the light client's synced chain.
    pub fn current_chain_tip(&self) -> (BlockHeight, Option<Hash>) {
        let last_header = self.latest_verified_header();
        (self.current_height, last_header.map(|h| h.hash()))
    }

    /// Retrieve the current verified head of the synced header chain.
    pub fn latest_verified_header(&self) -> Option<&BlockHeader> {
        self.verified_headers.last()
    }
}
