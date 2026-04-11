use anyhow::{bail, Result};
use vage_types::{Address, BlockHeight};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Types of governance proposals supported by VageChain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProposalType {
    ParameterChange { key: String, value: String },
    TextProposal { description: String },
    SoftwareUpgrade { version: String, height: BlockHeight },
    CommunityFundSpend { recipient: Address, amount: U256 },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, std::hash::Hash)]
pub enum VoteOption {
    Yes,
    No,
    Abstain,
    NoWithVeto,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub id: u64,
    pub title: String,
    pub proposal_type: ProposalType,
    pub status: ProposalStatus,
    pub submit_time: u64,
    pub voting_start_height: BlockHeight,
    pub voting_end_height: BlockHeight,
    pub total_votes: HashMap<VoteOption, U256>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalStatus {
    DepositPeriod,
    VotingPeriod,
    Passed,
    Rejected,
    Failed,
}

pub struct GovernanceManager {
    proposals: HashMap<u64, Proposal>,
    votes: HashMap<(u64, Address), VoteOption>,
    next_id: u64,
}

impl GovernanceManager {
    pub fn new() -> Self {
        Self {
            proposals: HashMap::new(),
            votes: HashMap::new(),
            next_id: 1,
        }
    }

    /// Submit a new governance proposal to the network.
    pub fn submit_proposal(
        &mut self, 
        title: String, 
        p_type: ProposalType, 
        start: BlockHeight, 
        end: BlockHeight
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let proposal = Proposal {
            id,
            title,
            proposal_type: p_type,
            status: ProposalStatus::VotingPeriod,
            submit_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            voting_start_height: start,
            voting_end_height: end,
            total_votes: HashMap::new(),
        };

        self.proposals.insert(id, proposal);
        id
    }

    /// Cast a vote on an active proposal.
    /// voting_power should be calculated by the caller (likely via StakingManager).
    pub fn cast_vote(&mut self, proposal_id: u64, voter: Address, option: VoteOption, power: U256) -> Result<()> {
        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_id))?;

        if proposal.status != ProposalStatus::VotingPeriod {
            bail!("Proposal is not in voting period");
        }

        // Handle double voting by removing previous weight if any.
        if let Some(previous_option) = self.votes.get(&(proposal_id, voter)) {
             let weight = proposal.total_votes.entry(previous_option.clone()).or_insert(U256::zero());
             *weight = weight.saturating_sub(power);
        }

        self.votes.insert((proposal_id, voter), option.clone());
        let weight = proposal.total_votes.entry(option).or_insert(U256::zero());
        *weight = weight.saturating_add(power);

        Ok(())
    }

    /// Tally the votes and determine the outcome of a proposal.
    pub fn tally_proposal(&mut self, proposal_id: u64, quorum: U256, pass_threshold: f64) -> Result<ProposalStatus> {
        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_id))?;

        let total_power = proposal.total_votes.values().fold(U256::zero(), |acc, x| acc.saturating_add(*x));
        if total_power < quorum {
             proposal.status = ProposalStatus::Failed;
             return Ok(ProposalStatus::Failed);
        }

        let yes_votes = proposal.total_votes.get(&VoteOption::Yes).cloned().unwrap_or(U256::zero());
        let ratio = (yes_votes.as_u128() as f64) / (total_power.as_u128() as f64);

        if ratio >= pass_threshold {
            proposal.status = ProposalStatus::Passed;
        } else {
            proposal.status = ProposalStatus::Rejected;
        }

        Ok(proposal.status)
    }

    /// Returns the current state of a proposal for the explorer and RPC.
    pub fn get_proposal(&self, id: u64) -> Option<&Proposal> {
        self.proposals.get(&id)
    }
}
