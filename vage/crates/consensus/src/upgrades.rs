use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use vage_types::BlockHeight;

/// Represents a distinct protocol version for the VageChain network.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl ProtocolVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

/// A formal proposal for a network-wide protocol upgrade (hard fork).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpgradeProposal {
    pub name: String,
    pub target_version: ProtocolVersion,
    pub activation_height: BlockHeight,
    pub description: String,
    pub votes: u64,
}

/// Manages the governance and scheduling of network upgrades.
pub struct UpgradeManager {
    current_version: ProtocolVersion,
    pending_upgrades: Vec<UpgradeProposal>,
}

impl UpgradeManager {
    pub fn new(initial_version: ProtocolVersion) -> Self {
        Self {
            current_version: initial_version,
            pending_upgrades: Vec::new(),
        }
    }

    /// Submit a new upgrade proposal for validator voting.
    pub fn submit_proposal(&mut self, proposal: UpgradeProposal) -> Result<()> {
        if proposal.activation_height == 0 {
            bail!("Activation height must be greater than current height");
        }
        self.pending_upgrades.push(proposal);
        Ok(())
    }

    /// Record a validator's vote for a specific proposal.
    pub fn record_vote(&mut self, proposal_name: &str, weight: u64) -> Result<()> {
        let proposal = self
            .pending_upgrades
            .iter_mut()
            .find(|p| p.name == proposal_name)
            .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_name))?;

        proposal.votes = proposal.votes.saturating_add(weight);
        Ok(())
    }

    /// Checks if a protocol version change is active at the given height.
    pub fn get_active_version(&self, height: BlockHeight) -> ProtocolVersion {
        let mut version = self.current_version;
        for p in &self.pending_upgrades {
            if height >= p.activation_height {
                // In a simplified model, we take the highest version that reached height
                if p.target_version > version {
                    version = p.target_version;
                }
            }
        }
        version
    }

    /// Schedules an upgrade height once quorum is reached.
    pub fn schedule_upgrade(&mut self, proposal_name: &str, height: BlockHeight) -> Result<()> {
        let proposal = self
            .pending_upgrades
            .iter_mut()
            .find(|p| p.name == proposal_name)
            .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_name))?;

        proposal.activation_height = height;
        Ok(())
    }
}
