use crate::eth::{BlockNumberOrTag, EthError, Filter as EthFilter, Log as EthLog, Provider};
use crate::hyperware::process::dao_cacher::{
    DaoCacherRequest, DaoCacherResponse, DaoCacherStatus, DaoGetLogsByRangeOkResponse,
    DaoGetLogsByRangeRequest, DaoLogsMetadata, DaoManifest, DaoManifestItem,
};
use crate::sign;
use crate::{print_to_terminal, Address as HyperAddress, Request};
use alloy::hex;
use alloy::rpc::types::request::{TransactionInput, TransactionRequest};
use alloy_primitives::{keccak256, Address, Bytes, FixedBytes, B256, U256};
use alloy_sol_macro::sol;
use alloy_sol_types::{SolCall, SolEvent};
use serde::{
    self,
    de::{self, MapAccess, Visitor},
    ser::{SerializeMap, SerializeStruct},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{fmt, str::FromStr};

#[cfg(not(feature = "simulation-mode"))]
pub const DAO_CHAIN_ID: u64 = 8453; // Base
#[cfg(feature = "simulation-mode")]
pub const DAO_CHAIN_ID: u64 = 31337; // Anvil / fakenet
#[cfg(not(feature = "simulation-mode"))]
pub const DAO_TIMELOCK_ADDRESS: &str = "0x0000000000c3442cbc1E194BBD6f74713816e51B";
#[cfg(feature = "simulation-mode")]
pub const DAO_TIMELOCK_ADDRESS: &str = "0x322D23640D57f36aE058FCc43e02C2A307678166";

#[cfg(not(feature = "simulation-mode"))]
pub const DAO_GOVERNOR_ADDRESS: &str = "0x000000000048395579c3C60f2F8Cb2DECa457550";
#[cfg(feature = "simulation-mode")]
pub const DAO_GOVERNOR_ADDRESS: &str = "0x45d8B75bb9A961E88486C470bcf8aa13E506Ec9B";

#[cfg(not(feature = "simulation-mode"))]
pub const DAO_VOTES_TOKEN_ADDRESS: &str = "0x00000000004a50Daa1B759C47Ebf4239163aE5be";
#[cfg(feature = "simulation-mode")]
pub const DAO_VOTES_TOKEN_ADDRESS: &str = "0xec48905Bb1714bbf3B6f56E49a8FA2299Bfa55f5";

// First block to start caching DAO events from (can be refined later)
#[cfg(not(feature = "simulation-mode"))]
pub const DAO_FIRST_BLOCK: u64 = 40_000_000;
#[cfg(feature = "simulation-mode")]
pub const DAO_FIRST_BLOCK: u64 = 0;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogCache {
    pub metadata: DaoLogsMetadata,
    pub logs: Vec<EthLog>,
}

const CACHER_REQUEST_TIMEOUT_S: u64 = 15;

sol! {
    /// Minimal voting token interface (IVotes).
    #[allow(non_camel_case_types)]
    contract IVotes {
        function getPastVotes(address account, uint256 blockNumber) external view returns (uint256);
    }

    /// Minimal TimelockController interface.
    #[allow(non_camel_case_types)]
    contract TimelockController {
        function getMinDelay() external view returns (uint256);
        function hasRole(bytes32 role, address account) external view returns (bool);
        function PROPOSER_ROLE() external view returns (bytes32);
        function EXECUTOR_ROLE() external view returns (bytes32);
        function CANCELLER_ROLE() external view returns (bytes32);
        function schedule(
            address target,
            uint256 value,
            bytes data,
            bytes32 predecessor,
            bytes32 salt,
            uint256 delay
        ) external;
        function execute(
            address target,
            uint256 value,
            bytes data,
            bytes32 predecessor,
            bytes32 salt
        ) external payable;
        function cancel(bytes32 id) external;
        function hashOperation(
            address target,
            uint256 value,
            bytes data,
            bytes32 predecessor,
            bytes32 salt
        ) external view returns (bytes32);
    }

    /// Minimal Governor interface.
    #[allow(non_camel_case_types)]
    contract HyperwareGovernor {
        function propose(
            address[] targets,
            uint256[] values,
            bytes[] calldatas,
            string description
        ) external returns (uint256);
        function hashProposal(
            address[] targets,
            uint256[] values,
            bytes[] calldatas,
            bytes32 descriptionHash
        ) external view returns (uint256);
        function state(uint256 proposalId) external view returns (uint8);
        function proposalSnapshot(uint256 proposalId) external view returns (uint256);
        function proposalDeadline(uint256 proposalId) external view returns (uint256);
        function proposalEta(uint256 proposalId) external view returns (uint256);
        function quorum(uint256 blockNumber) external view returns (uint256);
        function getPastVotes(address account, uint256 blockNumber) external view returns (uint256);
        function castVoteWithReason(uint256 proposalId, uint8 support, string reason) external returns (uint256);

        /// Standard OZ ProposalCreated event layout
        event ProposalCreated(
            uint256 proposalId,
            address proposer,
            address[] targets,
            uint256[] values,
            string[] signatures,
            bytes[] calldatas,
            uint256 startBlock,
            uint256 endBlock,
            string description
        );

        /// ProposalQueued event (includes eta).
        event ProposalQueued(uint256 proposalId, uint256 eta);

        /// ProposalCanceled event.
        event ProposalCanceled(uint256 proposalId);

        /// Standard OZ VoteCast event layout.
        event VoteCast(
            address indexed voter,
            uint256 proposalId,
            uint8 support,
            uint256 weight,
            string reason
        );
        /// ProposalExecuted event
        event ProposalExecuted(uint256 proposalId);
    }
}

/// Convenience wrapper for Timelock/Governor interactions.
#[derive(Clone, Debug)]
pub struct DaoContracts {
    pub provider: Provider,
    pub timelock: Address,
    pub governor: Address,
    pub votes_token: Address,
}

impl DaoContracts {
    pub fn new(provider: Provider) -> Self {
        let timelock =
            Address::from_str(DAO_TIMELOCK_ADDRESS).expect("invalid DAO_TIMELOCK_ADDRESS constant");
        let governor =
            Address::from_str(DAO_GOVERNOR_ADDRESS).expect("invalid DAO_GOVERNOR_ADDRESS constant");
        let votes_token = Address::from_str(DAO_VOTES_TOKEN_ADDRESS)
            .expect("invalid DAO_VOTES_TOKEN_ADDRESS constant");
        Self {
            provider,
            timelock,
            governor,
            votes_token,
        }
    }

    fn call_view<Call>(&self, target: Address, call: Call) -> Result<Call::Return, EthError>
    where
        Call: SolCall,
    {
        let tx_req = TransactionRequest::default()
            .to(target)
            .input(TransactionInput::new(Bytes::from(call.abi_encode())));
        let res_bytes = self.provider.call(tx_req, None)?;
        Call::abi_decode_returns(&res_bytes, false).map_err(|_| EthError::RpcMalformedResponse)
    }

    /// Return the timelock's minimum delay.
    pub fn timelock_delay(&self) -> Result<U256, EthError> {
        let res = self.call_view(self.timelock, TimelockController::getMinDelayCall {})?;
        Ok(res._0)
    }

    /// Fetch role IDs from the timelock.
    pub fn roles(&self) -> Result<(FixedBytes<32>, FixedBytes<32>, FixedBytes<32>), EthError> {
        let proposer = self
            .call_view(self.timelock, TimelockController::PROPOSER_ROLECall {})?
            ._0;
        let executor = self
            .call_view(self.timelock, TimelockController::EXECUTOR_ROLECall {})?
            ._0;
        let canceller = self
            .call_view(self.timelock, TimelockController::CANCELLER_ROLECall {})?
            ._0;
        Ok((proposer, executor, canceller))
    }

    /// Check if an account has a specific timelock role.
    pub fn has_role(&self, role: FixedBytes<32>, account: Address) -> Result<bool, EthError> {
        let res = self.call_view(
            self.timelock,
            TimelockController::hasRoleCall { role, account },
        )?;
        Ok(res._0)
    }

    /// Build a schedule tx for a single operation.
    pub fn build_schedule_tx(
        &self,
        target: Address,
        value: U256,
        data: Bytes,
        predecessor: FixedBytes<32>,
        salt: FixedBytes<32>,
        delay: U256,
    ) -> TransactionRequest {
        let call = TimelockController::scheduleCall {
            target,
            value,
            data,
            predecessor,
            salt,
            delay,
        };
        TransactionRequest::default()
            .to(self.timelock)
            .input(TransactionInput::new(Bytes::from(call.abi_encode())))
    }

    /// Build an execute tx for a scheduled operation.
    pub fn build_execute_tx(
        &self,
        target: Address,
        value: U256,
        data: Bytes,
        predecessor: FixedBytes<32>,
        salt: FixedBytes<32>,
    ) -> TransactionRequest {
        let call = TimelockController::executeCall {
            target,
            value,
            data,
            predecessor,
            salt,
        };
        TransactionRequest::default()
            .to(self.timelock)
            .input(TransactionInput::new(Bytes::from(call.abi_encode())))
    }

    /// Build a cancel tx for an operation id (hashOperation output).
    pub fn build_cancel_tx(&self, operation_id: FixedBytes<32>) -> TransactionRequest {
        let call = TimelockController::cancelCall { id: operation_id };
        TransactionRequest::default()
            .to(self.timelock)
            .input(TransactionInput::new(Bytes::from(call.abi_encode())))
    }

    /// Build a propose tx on the governor.
    pub fn build_propose_tx(
        &self,
        targets: Vec<Address>,
        values: Vec<U256>,
        calldatas: Vec<Bytes>,
        description: String,
    ) -> TransactionRequest {
        let call = HyperwareGovernor::proposeCall {
            targets,
            values,
            calldatas,
            description,
        };
        TransactionRequest::default()
            .to(self.governor)
            .input(TransactionInput::new(Bytes::from(call.abi_encode())))
    }

    /// Compute the proposal id off-chain using the governor's hashProposal view.
    /// (OZ proposalId = keccak256(abi.encode(targets, values, calldatas, descriptionHash))).
    pub fn hash_proposal(
        &self,
        targets: Vec<Address>,
        values: Vec<U256>,
        calldatas: Vec<Bytes>,
        description: &str,
    ) -> Result<U256, EthError> {
        let description_hash = keccak256(description.as_bytes());
        let res = self.call_view(
            self.governor,
            HyperwareGovernor::hashProposalCall {
                targets,
                values,
                calldatas,
                descriptionHash: description_hash,
            },
        )?;
        Ok(res._0)
    }

    /// Build a castVoteWithReason tx (support: 0=Against,1=For,2=Abstain in OZ Governor).
    pub fn build_vote_tx(
        &self,
        proposal_id: U256,
        support: u8,
        reason: String,
    ) -> TransactionRequest {
        let call = HyperwareGovernor::castVoteWithReasonCall {
            proposalId: proposal_id,
            support,
            reason,
        };
        TransactionRequest::default()
            .to(self.governor)
            .input(TransactionInput::new(Bytes::from(call.abi_encode())))
    }

    /// Governor state (OZ enum: 0 Pending, 1 Active, 2 Canceled, 3 Defeated, 4 Succeeded, 5 Queued, 6 Expired, 7 Executed).
    pub fn proposal_state(&self, proposal_id: U256) -> Result<u8, EthError> {
        let res = self.call_view(
            self.governor,
            HyperwareGovernor::stateCall {
                proposalId: proposal_id,
            },
        )?;
        Ok(res._0)
    }

    /// Proposal snapshot block.
    pub fn proposal_snapshot(&self, proposal_id: U256) -> Result<U256, EthError> {
        let res = self.call_view(
            self.governor,
            HyperwareGovernor::proposalSnapshotCall {
                proposalId: proposal_id,
            },
        )?;
        Ok(res._0)
    }

    /// Proposal deadline block.
    pub fn proposal_deadline(&self, proposal_id: U256) -> Result<U256, EthError> {
        let res = self.call_view(
            self.governor,
            HyperwareGovernor::proposalDeadlineCall {
                proposalId: proposal_id,
            },
        )?;
        Ok(res._0)
    }

    /// Proposal ETA (ready time) if queued; zero otherwise.
    pub fn proposal_eta(&self, proposal_id: U256) -> Result<U256, EthError> {
        let res = self.call_view(
            self.governor,
            HyperwareGovernor::proposalEtaCall {
                proposalId: proposal_id,
            },
        )?;
        Ok(res._0)
    }

    /// Governor quorum at a given block.
    pub fn quorum_at(&self, block_number: U256) -> Result<U256, EthError> {
        let res = self.call_view(
            self.governor,
            HyperwareGovernor::quorumCall {
                blockNumber: block_number,
            },
        )?;
        Ok(res._0)
    }

    /// Voter weight at a given block using the votes token.
    pub fn past_votes(&self, voter: Address, block_number: U256) -> Result<U256, EthError> {
        let res = self.call_view(
            self.votes_token,
            IVotes::getPastVotesCall {
                account: voter,
                blockNumber: block_number,
            },
        )?;
        Ok(res._0)
    }

    /// Fetch ProposalCreated events within a block range.
    pub fn fetch_proposals_created(
        &self,
        from_block: Option<BlockNumberOrTag>,
        to_block: Option<BlockNumberOrTag>,
    ) -> Result<Vec<ProposalCreatedEvent>, EthError> {
        let topic0 = HyperwareGovernor::ProposalCreated::SIGNATURE_HASH;
        let mut filter = EthFilter::new()
            .address(self.governor)
            .event_signature(B256::from(topic0));
        if let Some(fb) = from_block {
            filter = filter.from_block(fb);
        }
        if let Some(tb) = to_block {
            filter = filter.to_block(tb);
        }
        let logs = self.provider.get_logs(&filter)?;
        let mut out = Vec::new();
        for log in logs {
            let prim_log = log.inner.clone();
            if let Ok(decoded) = HyperwareGovernor::ProposalCreated::decode_log(&prim_log, true) {
                out.push(ProposalCreatedEvent {
                    proposal_id: decoded.proposalId,
                    proposer: decoded.proposer,
                    targets: decoded.targets.clone(),
                    values: decoded.values.clone(),
                    signatures: decoded.signatures.clone(),
                    calldatas: decoded.calldatas.clone(),
                    start_block: decoded.startBlock,
                    end_block: decoded.endBlock,
                    description: decoded.description.clone(),
                });
            }
        }
        Ok(out)
    }

    /// Fetch ProposalExecuted events within a block range.
    pub fn fetch_proposals_executed(
        &self,
        from_block: Option<BlockNumberOrTag>,
        to_block: Option<BlockNumberOrTag>,
    ) -> Result<Vec<ProposalExecutedEvent>, EthError> {
        let topic0 = HyperwareGovernor::ProposalExecuted::SIGNATURE_HASH;
        let mut filter = EthFilter::new()
            .address(self.governor)
            .event_signature(B256::from(topic0));
        if let Some(fb) = from_block {
            filter = filter.from_block(fb);
        }
        if let Some(tb) = to_block {
            filter = filter.to_block(tb);
        }
        let logs = self.provider.get_logs(&filter)?;
        let mut out = Vec::new();
        for log in logs {
            if let Ok(decoded) = HyperwareGovernor::ProposalExecuted::decode_log(&log.inner, true) {
                if let Some(bn) = log.block_number {
                    out.push(ProposalExecutedEvent {
                        proposal_id: decoded.proposalId,
                        block_number: bn,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Fetch ProposalQueued events within a block range.
    pub fn fetch_proposals_queued(
        &self,
        from_block: Option<BlockNumberOrTag>,
        to_block: Option<BlockNumberOrTag>,
    ) -> Result<Vec<ProposalQueuedEvent>, EthError> {
        let topic0 = HyperwareGovernor::ProposalQueued::SIGNATURE_HASH;
        let mut filter = EthFilter::new()
            .address(self.governor)
            .event_signature(B256::from(topic0));
        if let Some(fb) = from_block {
            filter = filter.from_block(fb);
        }
        if let Some(tb) = to_block {
            filter = filter.to_block(tb);
        }
        let logs = self.provider.get_logs(&filter)?;
        let mut out = Vec::new();
        for log in logs {
            if let Ok(decoded) = HyperwareGovernor::ProposalQueued::decode_log(&log.inner, true) {
                if let Some(bn) = log.block_number {
                    out.push(ProposalQueuedEvent {
                        proposal_id: decoded.proposalId,
                        eta: decoded.eta,
                        block_number: bn,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Fetch ProposalCanceled events within a block range.
    pub fn fetch_proposals_canceled(
        &self,
        from_block: Option<BlockNumberOrTag>,
        to_block: Option<BlockNumberOrTag>,
    ) -> Result<Vec<ProposalCanceledEvent>, EthError> {
        let topic0 = HyperwareGovernor::ProposalCanceled::SIGNATURE_HASH;
        let mut filter = EthFilter::new()
            .address(self.governor)
            .event_signature(B256::from(topic0));
        if let Some(fb) = from_block {
            filter = filter.from_block(fb);
        }
        if let Some(tb) = to_block {
            filter = filter.to_block(tb);
        }
        let logs = self.provider.get_logs(&filter)?;
        let mut out = Vec::new();
        for log in logs {
            if let Ok(decoded) = HyperwareGovernor::ProposalCanceled::decode_log(&log.inner, true) {
                if let Some(bn) = log.block_number {
                    out.push(ProposalCanceledEvent {
                        proposal_id: decoded.proposalId,
                        block_number: bn,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Fetch the timestamp for a block number.
    pub fn block_timestamp(&self, block_number: u64) -> Result<u64, EthError> {
        let block = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number), false)?;
        let Some(b) = block else {
            return Err(EthError::RpcMalformedResponse);
        };
        Ok(b.header.timestamp)
    }

    /// Compute quorum progress (basis points) for a proposal: (for+abstain) / quorum * 10_000.
    /// Returns a tuple of (basis_points, votes_counted, quorum_required) to avoid precision loss.
    pub fn quorum_progress_bps(&self, proposal_id: U256) -> Result<(u128, U256, U256), String> {
        // Grab snapshot; if unavailable (e.g., pending and governor reverts, or RPC missing), fall back to latest-1.
        let snapshot = match self.proposal_snapshot(proposal_id) {
            Ok(s) => s,
            Err(_) => {
                println!(
                    "has_power_at_snapshot: snapshot lookup failed for proposal {}, chain {}",
                    proposal_id, self.provider.chain_id
                );
                let latest_block = self.provider.get_block_number().map_err(|e| {
                    println!(
                        "has_power_at_snapshot: block number error for chain {}: {:?}",
                        self.provider.chain_id, e
                    );
                    format!("block number error: {e:?}")
                })?;
                if latest_block > 0 {
                    U256::from(latest_block.saturating_sub(1))
                } else {
                    U256::ZERO
                }
            }
        };
        // First try quorum at the snapshot; if it errors (e.g., snapshot in the future), fall back to latest-1.
        let quorum = match self.quorum_at(snapshot) {
            Ok(q) => q,
            Err(_) => {
                let latest_block = self
                    .provider
                    .get_block_number()
                    .map_err(|e| format!("block number error: {e:?}"))?;
                let fallback_block = if latest_block > 0 {
                    U256::from(latest_block.saturating_sub(1))
                } else {
                    U256::ZERO
                };
                self.quorum_at(fallback_block)
                    .map_err(|e| format!("quorum error: {e:?}"))?
            }
        };
        let votes = self
            .fetch_votes(proposal_id, Some(BlockNumberOrTag::Earliest), None)
            .map_err(|e| format!("votes error: {e:?}"))?;
        let mut counted: U256 = U256::ZERO;
        for vote in votes {
            // HyperGovernor (OZ counting) considers For + Abstain toward quorum; Against does not count.
            if vote.support == 1 || vote.support == 2 {
                counted = counted.saturating_add(vote.weight);
            }
        }
        if quorum.is_zero() {
            return Ok((0, counted, quorum));
        }
        // basis points: counted * 10_000 / quorum
        let numerator = counted.saturating_mul(U256::from(10_000u64));
        let bps = (numerator / quorum)
            .try_into()
            .map_err(|_| "bps overflow".to_string())?;
        Ok((bps, counted, quorum))
    }

    /// Check whether a voter had any voting power at the proposal snapshot (or fallback block if needed).
    pub fn has_power_at_snapshot(&self, proposal_id: U256, voter: Address) -> Result<bool, String> {
        // Determine snapshot; fallback to latest-1 if snapshot lookup fails.
        let snapshot = match self.proposal_snapshot(proposal_id) {
            Ok(s) => s,
            Err(_) => {
                let latest_block = self
                    .provider
                    .get_block_number()
                    .map_err(|e| format!("block number error: {e:?}"))?;
                if latest_block > 0 {
                    U256::from(latest_block.saturating_sub(1))
                } else {
                    U256::ZERO
                }
            }
        };
        // Try to read past votes at snapshot; if that fails (e.g., snapshot in future), fallback to latest-1.
        let weight = match self.past_votes(voter, snapshot) {
            Ok(w) => w,
            Err(_) => {
                println!(
                    "has_power_at_snapshot: past_votes failed at snapshot {} for voter {}, chain {}; trying fallback",
                    snapshot, voter, self.provider.chain_id
                );
                let latest_block = self.provider.get_block_number().map_err(|e| {
                    println!(
                        "has_power_at_snapshot: block number error (fallback) for chain {}: {:?}",
                        self.provider.chain_id, e
                    );
                    format!("block number error: {e:?}")
                })?;
                let fallback_block = if latest_block > 0 {
                    U256::from(latest_block.saturating_sub(1))
                } else {
                    U256::ZERO
                };
                match self.past_votes(voter, fallback_block) {
                    Ok(w) => w,
                    Err(_) => {
                        // If we still can't determine weight, assume non-zero to avoid false negatives.
                        println!(
                            "has_power_at_snapshot: past_votes failed at fallback {} for voter {}, chain {}; assuming true",
                            fallback_block, voter, self.provider.chain_id
                        );
                        return Ok(true);
                    }
                }
            }
        };
        Ok(!weight.is_zero())
    }

    /// Fetch VoteCast events for a proposal within a block range.
    /// Note: proposalId is not indexed in OZ Governor, so filtering occurs post-decode.
    pub fn fetch_votes(
        &self,
        proposal_id: U256,
        from_block: Option<BlockNumberOrTag>,
        to_block: Option<BlockNumberOrTag>,
    ) -> Result<Vec<VoteCastEvent>, EthError> {
        let topic0 = HyperwareGovernor::VoteCast::SIGNATURE_HASH;
        let mut filter = EthFilter::new()
            .address(self.governor)
            .event_signature(B256::from(topic0));
        if let Some(fb) = from_block {
            filter = filter.from_block(fb);
        }
        if let Some(tb) = to_block {
            filter = filter.to_block(tb);
        }
        let logs = self.provider.get_logs(&filter)?;
        let mut out = Vec::new();
        for log in logs {
            let prim_log = log.inner.clone();
            if let Ok(decoded) = HyperwareGovernor::VoteCast::decode_log(&prim_log, true) {
                if decoded.proposalId == proposal_id {
                    out.push(VoteCastEvent {
                        voter: decoded.voter,
                        proposal_id: decoded.proposalId,
                        support: decoded.support,
                        weight: decoded.weight,
                        reason: decoded.reason.clone(),
                    });
                }
            }
        }
        Ok(out)
    }

    /// Hash a timelock operation (matches timelock.hashOperation).
    pub fn hash_operation(
        &self,
        target: Address,
        value: U256,
        data: Bytes,
        predecessor: FixedBytes<32>,
        salt: FixedBytes<32>,
    ) -> Result<FixedBytes<32>, EthError> {
        let res = self.call_view(
            self.timelock,
            TimelockController::hashOperationCall {
                target,
                value,
                data,
                predecessor,
                salt,
            },
        )?;
        Ok(res._0)
    }
}

/// Parsed ProposalCreated event.
#[derive(Clone, Debug)]
pub struct ProposalCreatedEvent {
    pub proposal_id: U256,
    pub proposer: Address,
    pub targets: Vec<Address>,
    pub values: Vec<U256>,
    pub signatures: Vec<String>,
    pub calldatas: Vec<Bytes>,
    pub start_block: U256,
    pub end_block: U256,
    pub description: String,
}

/// Parsed VoteCast event.
#[derive(Clone, Debug)]
pub struct VoteCastEvent {
    pub voter: Address,
    pub proposal_id: U256,
    pub support: u8,
    pub weight: U256,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct ProposalExecutedEvent {
    pub proposal_id: U256,
    pub block_number: u64,
}

/// Parsed ProposalQueued event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalQueuedEvent {
    pub proposal_id: U256,
    pub eta: U256,
    pub block_number: u64,
}

/// Parsed ProposalCanceled event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalCanceledEvent {
    pub proposal_id: U256,
    pub block_number: u64,
}

impl Serialize for DaoCacherRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            DaoCacherRequest::GetManifest => serializer.serialize_str("GetManifest"),
            DaoCacherRequest::GetLogCacheContent(path) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("GetLogCacheContent", path)?;
                map.end()
            }
            DaoCacherRequest::GetStatus => serializer.serialize_str("GetStatus"),
            DaoCacherRequest::GetLogsByRange(request) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("GetLogsByRange", request)?;
                map.end()
            }
            DaoCacherRequest::StartProviding => serializer.serialize_str("StartProviding"),
            DaoCacherRequest::StopProviding => serializer.serialize_str("StopProviding"),
            DaoCacherRequest::SetNodes(nodes) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("SetNodes", nodes)?;
                map.end()
            }
            DaoCacherRequest::Reset(nodes) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("Reset", nodes)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for DaoCacherRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DaoCacherRequestVisitor;

        impl<'de> Visitor<'de> for DaoCacherRequestVisitor {
            type Value = DaoCacherRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string for unit variants or a map for other variants")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    "GetManifest" => Ok(DaoCacherRequest::GetManifest),
                    "GetStatus" => Ok(DaoCacherRequest::GetStatus),
                    "StartProviding" => Ok(DaoCacherRequest::StartProviding),
                    "StopProviding" => Ok(DaoCacherRequest::StopProviding),
                    _ => Err(de::Error::unknown_variant(
                        value,
                        &[
                            "GetManifest",
                            "GetLogCacheContent",
                            "GetStatus",
                            "GetLogsByRange",
                            "StartProviding",
                            "StopProviding",
                            "SetNodes",
                            "Reset",
                        ],
                    )),
                }
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let entry = map
                    .next_entry::<String, serde_json::Value>()?
                    .ok_or_else(|| de::Error::custom("expected a map entry"))?;
                match entry.0.as_str() {
                    "GetLogCacheContent" => {
                        let path: String =
                            serde_json::from_value(entry.1).map_err(de::Error::custom)?;
                        Ok(DaoCacherRequest::GetLogCacheContent(path))
                    }
                    "GetLogsByRange" => {
                        let req: DaoGetLogsByRangeRequest =
                            serde_json::from_value(entry.1).map_err(de::Error::custom)?;
                        Ok(DaoCacherRequest::GetLogsByRange(req))
                    }
                    "SetNodes" => {
                        let nodes: Vec<String> =
                            serde_json::from_value(entry.1).map_err(de::Error::custom)?;
                        Ok(DaoCacherRequest::SetNodes(nodes))
                    }
                    "Reset" => {
                        let nodes: Option<Vec<String>> =
                            serde_json::from_value(entry.1).map_err(de::Error::custom)?;
                        Ok(DaoCacherRequest::Reset(nodes))
                    }
                    other => Err(de::Error::unknown_variant(
                        other,
                        &[
                            "GetManifest",
                            "GetLogCacheContent",
                            "GetStatus",
                            "GetLogsByRange",
                            "StartProviding",
                            "StopProviding",
                            "SetNodes",
                            "Reset",
                        ],
                    )),
                }
            }
        }

        deserializer.deserialize_any(DaoCacherRequestVisitor)
    }
}

impl Serialize for DaoGetLogsByRangeRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("DaoGetLogsByRangeRequest", 2)?;
        state.serialize_field("from_block", &self.from_block)?;
        state.serialize_field("to_block", &self.to_block)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for DaoGetLogsByRangeRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            FromBlock,
            ToBlock,
        }

        struct GetLogsByRangeRequestVisitor;

        impl<'de> Visitor<'de> for GetLogsByRangeRequestVisitor {
            type Value = DaoGetLogsByRangeRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct DaoGetLogsByRangeRequest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut from_block = None;
                let mut to_block = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::FromBlock => {
                            if from_block.is_some() {
                                return Err(de::Error::duplicate_field("from_block"));
                            }
                            from_block = Some(map.next_value()?);
                        }
                        Field::ToBlock => {
                            if to_block.is_some() {
                                return Err(de::Error::duplicate_field("to_block"));
                            }
                            to_block = Some(map.next_value()?);
                        }
                    }
                }

                let from_block =
                    from_block.ok_or_else(|| de::Error::missing_field("from_block"))?;

                Ok(DaoGetLogsByRangeRequest {
                    from_block,
                    to_block,
                })
            }
        }

        deserializer.deserialize_struct(
            "DaoGetLogsByRangeRequest",
            &["from_block", "to_block"],
            GetLogsByRangeRequestVisitor,
        )
    }
}

impl Serialize for DaoCacherResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            DaoCacherResponse::GetManifest(manifest) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("GetManifest", manifest)?;
                map.end()
            }
            DaoCacherResponse::GetLogCacheContent(result) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("GetLogCacheContent", result)?;
                map.end()
            }
            DaoCacherResponse::GetStatus(status) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("GetStatus", status)?;
                map.end()
            }
            DaoCacherResponse::GetLogsByRange(result) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("GetLogsByRange", result)?;
                map.end()
            }
            DaoCacherResponse::StartProviding(result) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("StartProviding", result)?;
                map.end()
            }
            DaoCacherResponse::StopProviding(result) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("StopProviding", result)?;
                map.end()
            }
            DaoCacherResponse::SetNodes(result) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("SetNodes", result)?;
                map.end()
            }
            DaoCacherResponse::Reset(result) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("Reset", result)?;
                map.end()
            }
            DaoCacherResponse::Rejected => serializer.serialize_str("Rejected"),
            DaoCacherResponse::IsStarting => serializer.serialize_str("IsStarting"),
        }
    }
}

impl<'de> Deserialize<'de> for DaoCacherResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DaoCacherResponseVisitor;

        impl<'de> Visitor<'de> for DaoCacherResponseVisitor {
            type Value = DaoCacherResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string for unit variants or a map for other variants")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    "Rejected" => Ok(DaoCacherResponse::Rejected),
                    "IsStarting" => Ok(DaoCacherResponse::IsStarting),
                    _ => Err(de::Error::unknown_variant(
                        value,
                        &[
                            "GetManifest",
                            "GetLogCacheContent",
                            "GetStatus",
                            "GetLogsByRange",
                            "StartProviding",
                            "StopProviding",
                            "SetNodes",
                            "Reset",
                            "Rejected",
                            "IsStarting",
                        ],
                    )),
                }
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let entry = map
                    .next_entry::<String, serde_json::Value>()?
                    .ok_or_else(|| de::Error::custom("expected a map entry"))?;
                match entry.0.as_str() {
                    "GetManifest" => {
                        let val: Option<DaoManifest> =
                            serde_json::from_value(entry.1).map_err(de::Error::custom)?;
                        Ok(DaoCacherResponse::GetManifest(val))
                    }
                    "GetLogCacheContent" => {
                        let val: Result<Option<String>, String> =
                            serde_json::from_value(entry.1).map_err(de::Error::custom)?;
                        Ok(DaoCacherResponse::GetLogCacheContent(val))
                    }
                    "GetStatus" => {
                        let val: DaoCacherStatus =
                            serde_json::from_value(entry.1).map_err(de::Error::custom)?;
                        Ok(DaoCacherResponse::GetStatus(val))
                    }
                    "GetLogsByRange" => {
                        let val: Result<DaoGetLogsByRangeOkResponse, String> =
                            serde_json::from_value(entry.1).map_err(de::Error::custom)?;
                        Ok(DaoCacherResponse::GetLogsByRange(val))
                    }
                    "StartProviding" => {
                        let val: Result<String, String> =
                            serde_json::from_value(entry.1).map_err(de::Error::custom)?;
                        Ok(DaoCacherResponse::StartProviding(val))
                    }
                    "StopProviding" => {
                        let val: Result<String, String> =
                            serde_json::from_value(entry.1).map_err(de::Error::custom)?;
                        Ok(DaoCacherResponse::StopProviding(val))
                    }
                    "SetNodes" => {
                        let val: Result<String, String> =
                            serde_json::from_value(entry.1).map_err(de::Error::custom)?;
                        Ok(DaoCacherResponse::SetNodes(val))
                    }
                    "Reset" => {
                        let val: Result<String, String> =
                            serde_json::from_value(entry.1).map_err(de::Error::custom)?;
                        Ok(DaoCacherResponse::Reset(val))
                    }
                    other => Err(de::Error::unknown_variant(
                        other,
                        &[
                            "GetManifest",
                            "GetLogCacheContent",
                            "GetStatus",
                            "GetLogsByRange",
                            "StartProviding",
                            "StopProviding",
                            "SetNodes",
                            "Reset",
                            "Rejected",
                            "IsStarting",
                        ],
                    )),
                }
            }
        }

        deserializer.deserialize_any(DaoCacherResponseVisitor)
    }
}

impl Serialize for DaoCacherStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("DaoCacherStatus", 8)?;
        state.serialize_field("last_cached_block", &self.last_cached_block)?;
        state.serialize_field("chain_id", &self.chain_id)?;
        state.serialize_field("protocol_version", &self.protocol_version)?;
        state.serialize_field(
            "next_cache_attempt_in_seconds",
            &self.next_cache_attempt_in_seconds,
        )?;
        state.serialize_field("manifest_filename", &self.manifest_filename)?;
        state.serialize_field("log_files_count", &self.log_files_count)?;
        state.serialize_field("our_address", &self.our_address)?;
        state.serialize_field("is_providing", &self.is_providing)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for DaoCacherStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            LastCachedBlock,
            ChainId,
            ProtocolVersion,
            NextCacheAttemptInSeconds,
            ManifestFilename,
            LogFilesCount,
            OurAddress,
            IsProviding,
        }

        struct CacherStatusVisitor;

        impl<'de> Visitor<'de> for CacherStatusVisitor {
            type Value = DaoCacherStatus;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct DaoCacherStatus")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut last_cached_block = None;
                let mut chain_id = None;
                let mut protocol_version = None;
                let mut next_cache_attempt_in_seconds = None;
                let mut manifest_filename = None;
                let mut log_files_count = None;
                let mut our_address = None;
                let mut is_providing = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::LastCachedBlock => {
                            if last_cached_block.is_some() {
                                return Err(de::Error::duplicate_field("last_cached_block"));
                            }
                            last_cached_block = Some(map.next_value()?);
                        }
                        Field::ChainId => {
                            if chain_id.is_some() {
                                return Err(de::Error::duplicate_field("chain_id"));
                            }
                            chain_id = Some(map.next_value()?);
                        }
                        Field::ProtocolVersion => {
                            if protocol_version.is_some() {
                                return Err(de::Error::duplicate_field("protocol_version"));
                            }
                            protocol_version = Some(map.next_value()?);
                        }
                        Field::NextCacheAttemptInSeconds => {
                            if next_cache_attempt_in_seconds.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "next_cache_attempt_in_seconds",
                                ));
                            }
                            next_cache_attempt_in_seconds = Some(map.next_value()?);
                        }
                        Field::ManifestFilename => {
                            if manifest_filename.is_some() {
                                return Err(de::Error::duplicate_field("manifest_filename"));
                            }
                            manifest_filename = Some(map.next_value()?);
                        }
                        Field::LogFilesCount => {
                            if log_files_count.is_some() {
                                return Err(de::Error::duplicate_field("log_files_count"));
                            }
                            log_files_count = Some(map.next_value()?);
                        }
                        Field::OurAddress => {
                            if our_address.is_some() {
                                return Err(de::Error::duplicate_field("our_address"));
                            }
                            our_address = Some(map.next_value()?);
                        }
                        Field::IsProviding => {
                            if is_providing.is_some() {
                                return Err(de::Error::duplicate_field("is_providing"));
                            }
                            is_providing = Some(map.next_value()?);
                        }
                    }
                }

                let last_cached_block = last_cached_block
                    .ok_or_else(|| de::Error::missing_field("last_cached_block"))?;
                let chain_id = chain_id.ok_or_else(|| de::Error::missing_field("chain_id"))?;
                let protocol_version =
                    protocol_version.ok_or_else(|| de::Error::missing_field("protocol_version"))?;
                let manifest_filename = manifest_filename
                    .ok_or_else(|| de::Error::missing_field("manifest_filename"))?;
                let log_files_count =
                    log_files_count.ok_or_else(|| de::Error::missing_field("log_files_count"))?;
                let our_address =
                    our_address.ok_or_else(|| de::Error::missing_field("our_address"))?;
                let is_providing =
                    is_providing.ok_or_else(|| de::Error::missing_field("is_providing"))?;

                Ok(DaoCacherStatus {
                    last_cached_block,
                    chain_id,
                    protocol_version,
                    next_cache_attempt_in_seconds,
                    manifest_filename,
                    log_files_count,
                    our_address,
                    is_providing,
                })
            }
        }

        deserializer.deserialize_struct(
            "DaoCacherStatus",
            &[
                "last_cached_block",
                "chain_id",
                "protocol_version",
                "next_cache_attempt_in_seconds",
                "manifest_filename",
                "log_files_count",
                "our_address",
                "is_providing",
            ],
            CacherStatusVisitor,
        )
    }
}

impl Serialize for DaoLogsMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("DaoLogsMetadata", 6)?;
        state.serialize_field("chainId", &self.chain_id)?;
        state.serialize_field("fromBlock", &self.from_block)?;
        state.serialize_field("toBlock", &self.to_block)?;
        state.serialize_field("timeCreated", &self.time_created)?;
        state.serialize_field("createdBy", &self.created_by)?;
        state.serialize_field("signature", &self.signature)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for DaoLogsMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            ChainId,
            FromBlock,
            ToBlock,
            TimeCreated,
            CreatedBy,
            Signature,
        }

        struct LogsMetadataVisitor;

        impl<'de> Visitor<'de> for LogsMetadataVisitor {
            type Value = DaoLogsMetadata;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct DaoLogsMetadata")
            }

            fn visit_map<V>(self, mut map: V) -> Result<DaoLogsMetadata, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut chain_id = None;
                let mut from_block = None;
                let mut to_block = None;
                let mut time_created = None;
                let mut created_by = None;
                let mut signature = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::ChainId => {
                            if chain_id.is_some() {
                                return Err(de::Error::duplicate_field("chainId"));
                            }
                            chain_id = Some(map.next_value()?);
                        }
                        Field::FromBlock => {
                            if from_block.is_some() {
                                return Err(de::Error::duplicate_field("fromBlock"));
                            }
                            from_block = Some(map.next_value()?);
                        }
                        Field::ToBlock => {
                            if to_block.is_some() {
                                return Err(de::Error::duplicate_field("toBlock"));
                            }
                            to_block = Some(map.next_value()?);
                        }
                        Field::TimeCreated => {
                            if time_created.is_some() {
                                return Err(de::Error::duplicate_field("timeCreated"));
                            }
                            time_created = Some(map.next_value()?);
                        }
                        Field::CreatedBy => {
                            if created_by.is_some() {
                                return Err(de::Error::duplicate_field("createdBy"));
                            }
                            created_by = Some(map.next_value()?);
                        }
                        Field::Signature => {
                            if signature.is_some() {
                                return Err(de::Error::duplicate_field("signature"));
                            }
                            signature = Some(map.next_value()?);
                        }
                    }
                }

                let chain_id = chain_id.ok_or_else(|| de::Error::missing_field("chainId"))?;
                let from_block = from_block.ok_or_else(|| de::Error::missing_field("fromBlock"))?;
                let to_block = to_block.ok_or_else(|| de::Error::missing_field("toBlock"))?;
                let time_created =
                    time_created.ok_or_else(|| de::Error::missing_field("timeCreated"))?;
                let created_by = created_by.ok_or_else(|| de::Error::missing_field("createdBy"))?;
                let signature = signature.ok_or_else(|| de::Error::missing_field("signature"))?;

                Ok(DaoLogsMetadata {
                    chain_id,
                    from_block,
                    to_block,
                    time_created,
                    created_by,
                    signature,
                })
            }
        }

        deserializer.deserialize_struct(
            "DaoLogsMetadata",
            &[
                "chainId",
                "fromBlock",
                "toBlock",
                "timeCreated",
                "createdBy",
                "signature",
            ],
            LogsMetadataVisitor,
        )
    }
}

impl Serialize for DaoGetLogsByRangeOkResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            DaoGetLogsByRangeOkResponse::Logs(tuple) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("Logs", tuple)?;
                map.end()
            }
            DaoGetLogsByRangeOkResponse::Latest(block) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("Latest", block)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for DaoGetLogsByRangeOkResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct GetLogsByRangeOkResponseVisitor;

        impl<'de> Visitor<'de> for GetLogsByRangeOkResponseVisitor {
            type Value = DaoGetLogsByRangeOkResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("DaoGetLogsByRangeOkResponse")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let entry = map
                    .next_entry::<String, serde_json::Value>()?
                    .ok_or_else(|| de::Error::custom("expected map entry"))?;
                match entry.0.as_str() {
                    "Logs" => {
                        let tuple: (u64, String) =
                            serde_json::from_value(entry.1).map_err(de::Error::custom)?;
                        Ok(DaoGetLogsByRangeOkResponse::Logs(tuple))
                    }
                    "Latest" => {
                        let block: u64 =
                            serde_json::from_value(entry.1).map_err(de::Error::custom)?;
                        Ok(DaoGetLogsByRangeOkResponse::Latest(block))
                    }
                    other => Err(de::Error::unknown_variant(other, &["Logs", "Latest"])),
                }
            }
        }

        deserializer.deserialize_any(GetLogsByRangeOkResponseVisitor)
    }
}

impl Serialize for DaoManifestItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("DaoManifestItem", 4)?;
        state.serialize_field("metadata", &self.metadata)?;
        state.serialize_field("is_empty", &self.is_empty)?;
        state.serialize_field("file_hash", &self.file_hash)?;
        state.serialize_field("file_name", &self.file_name)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for DaoManifestItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Metadata,
            IsEmpty,
            FileHash,
            FileName,
        }

        struct ManifestItemVisitor;

        impl<'de> Visitor<'de> for ManifestItemVisitor {
            type Value = DaoManifestItem;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct DaoManifestItem")
            }

            fn visit_map<V>(self, mut map: V) -> Result<DaoManifestItem, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut metadata = None;
                let mut is_empty = None;
                let mut file_hash = None;
                let mut file_name = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Metadata => {
                            if metadata.is_some() {
                                return Err(de::Error::duplicate_field("metadata"));
                            }
                            metadata = Some(map.next_value()?);
                        }
                        Field::IsEmpty => {
                            if is_empty.is_some() {
                                return Err(de::Error::duplicate_field("is_empty"));
                            }
                            is_empty = Some(map.next_value()?);
                        }
                        Field::FileHash => {
                            if file_hash.is_some() {
                                return Err(de::Error::duplicate_field("file_hash"));
                            }
                            file_hash = Some(map.next_value()?);
                        }
                        Field::FileName => {
                            if file_name.is_some() {
                                return Err(de::Error::duplicate_field("file_name"));
                            }
                            file_name = Some(map.next_value()?);
                        }
                    }
                }

                let metadata = metadata.ok_or_else(|| de::Error::missing_field("metadata"))?;
                let is_empty = is_empty.ok_or_else(|| de::Error::missing_field("is_empty"))?;
                let file_hash = file_hash.ok_or_else(|| de::Error::missing_field("file_hash"))?;
                let file_name = file_name.ok_or_else(|| de::Error::missing_field("file_name"))?;

                Ok(DaoManifestItem {
                    metadata,
                    is_empty,
                    file_hash,
                    file_name,
                })
            }
        }

        deserializer.deserialize_struct(
            "DaoManifestItem",
            &["metadata", "is_empty", "file_hash", "file_name"],
            ManifestItemVisitor,
        )
    }
}

impl Serialize for DaoManifest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("DaoManifest", 4)?;
        state.serialize_field("items", &self.items)?;
        state.serialize_field("manifest_filename", &self.manifest_filename)?;
        state.serialize_field("chain_id", &self.chain_id)?;
        state.serialize_field("protocol_version", &self.protocol_version)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for DaoManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Items,
            ManifestFilename,
            ChainId,
            ProtocolVersion,
        }

        struct ManifestVisitor;

        impl<'de> Visitor<'de> for ManifestVisitor {
            type Value = DaoManifest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct DaoManifest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<DaoManifest, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut items = None;
                let mut manifest_filename = None;
                let mut chain_id = None;
                let mut protocol_version = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Items => {
                            if items.is_some() {
                                return Err(de::Error::duplicate_field("items"));
                            }
                            items = Some(map.next_value()?);
                        }
                        Field::ManifestFilename => {
                            if manifest_filename.is_some() {
                                return Err(de::Error::duplicate_field("manifest_filename"));
                            }
                            manifest_filename = Some(map.next_value()?);
                        }
                        Field::ChainId => {
                            if chain_id.is_some() {
                                return Err(de::Error::duplicate_field("chain_id"));
                            }
                            chain_id = Some(map.next_value()?);
                        }
                        Field::ProtocolVersion => {
                            if protocol_version.is_some() {
                                return Err(de::Error::duplicate_field("protocol_version"));
                            }
                            protocol_version = Some(map.next_value()?);
                        }
                    }
                }

                let items = items.ok_or_else(|| de::Error::missing_field("items"))?;
                let manifest_filename = manifest_filename
                    .ok_or_else(|| de::Error::missing_field("manifest_filename"))?;
                let chain_id = chain_id.ok_or_else(|| de::Error::missing_field("chain_id"))?;
                let protocol_version =
                    protocol_version.ok_or_else(|| de::Error::missing_field("protocol_version"))?;

                Ok(DaoManifest {
                    items,
                    manifest_filename,
                    chain_id,
                    protocol_version,
                })
            }
        }

        deserializer.deserialize_struct(
            "DaoManifest",
            &["items", "manifest_filename", "chain_id", "protocol_version"],
            ManifestVisitor,
        )
    }
}

impl DaoContracts {
    fn get_bootstrap_log_cache_inner(
        &self,
        cacher_request: &DaoCacherRequest,
        cacher_process_address: &HyperAddress,
        attempt: u64,
        request_from_block_val: u64,
        retry_delay_s: u64,
        retry_count: Option<u64>,
        chain: &Option<String>,
    ) -> anyhow::Result<Option<(u64, Vec<LogCache>)>> {
        let retry_count_str = retry_count
            .map(|r| r.to_string())
            .unwrap_or_else(|| "inf".to_string());
        print_to_terminal(
            2,
            &format!("Attempt {attempt}/{retry_count_str} to query local dao-cacher"),
        );

        let response_msg = match Request::to(cacher_process_address.clone())
            .body(serde_json::to_vec(cacher_request)?)
            .send_and_await_response(CACHER_REQUEST_TIMEOUT_S)
        {
            Ok(Ok(msg)) => msg,
            Ok(Err(e)) => {
                print_to_terminal(
                    1,
                    &format!(
                        "Error response from local dao-cacher (attempt {}): {:?}",
                        attempt, e
                    ),
                );
                if retry_count.is_none() || attempt < retry_count.unwrap() {
                    std::thread::sleep(std::time::Duration::from_secs(retry_delay_s));
                    return Ok(None);
                } else {
                    return Err(anyhow::anyhow!(
                        "Error response from local dao-cacher after {retry_count_str} attempts: {e:?}"
                    ));
                }
            }
            Err(e) => {
                print_to_terminal(
                    1,
                    &format!(
                        "Failed to send request to local dao-cacher (attempt {}): {:?}",
                        attempt, e
                    ),
                );
                if retry_count.is_none() || attempt < retry_count.unwrap() {
                    std::thread::sleep(std::time::Duration::from_secs(retry_delay_s));
                    return Ok(None);
                } else {
                    return Err(anyhow::anyhow!(
                        "Failed to send request to local dao-cacher after {retry_count_str} attempts: {e:?}"
                    ));
                }
            }
        };

        match serde_json::from_slice::<DaoCacherResponse>(response_msg.body())? {
            DaoCacherResponse::GetLogsByRange(res) => match res {
                Ok(DaoGetLogsByRangeOkResponse::Latest(block)) => Ok(Some((block, vec![]))),
                Ok(DaoGetLogsByRangeOkResponse::Logs((block, json))) => {
                    if json.is_empty() || json == "[]" {
                        print_to_terminal(
                            2,
                            &format!(
                                "Local dao-cacher returned no log caches for the range from block {}.",
                                request_from_block_val,
                            ),
                        );
                        return Ok(Some((block, vec![])));
                    }
                    match serde_json::from_str::<Vec<LogCache>>(&json) {
                        Ok(retrieved_caches) => {
                            let target_chain_id = chain
                                .clone()
                                .unwrap_or_else(|| self.provider.get_chain_id().to_string());
                            let mut filtered_caches = vec![];

                            for log_cache in retrieved_caches {
                                if log_cache.metadata.chain_id == target_chain_id {
                                    let cache_to =
                                        log_cache.metadata.to_block.parse::<u64>().unwrap_or(0);
                                    if cache_to >= request_from_block_val {
                                        filtered_caches.push(log_cache);
                                    } else {
                                        print_to_terminal(
                                            3,
                                            &format!(
                                                "Cache from local dao-cacher ({} to {}) does not meet request_from_block {}",
                                                log_cache.metadata.from_block,
                                                log_cache.metadata.to_block,
                                                request_from_block_val
                                            ),
                                        );
                                    }
                                } else {
                                    print_to_terminal(
                                        1,
                                        &format!(
                                            "LogCache from local dao-cacher has mismatched chain_id (expected {}, got {}). Skipping.",
                                            target_chain_id, log_cache.metadata.chain_id
                                        ),
                                    );
                                }
                            }

                            print_to_terminal(
                                2,
                                &format!(
                                    "Retrieved {} log caches from local dao-cacher.",
                                    filtered_caches.len(),
                                ),
                            );
                            Ok(Some((block, filtered_caches)))
                        }
                        Err(e) => Err(anyhow::anyhow!(
                            "Failed to deserialize Vec<LogCache> from local cacher: {:?}. JSON: {:.100}",
                            e,
                            json
                        )),
                    }
                }
                Err(e_str) => Err(anyhow::anyhow!(
                    "Local dao-cacher reported error for GetLogsByRange: {}",
                    e_str,
                )),
            },
            DaoCacherResponse::IsStarting => {
                print_to_terminal(
                    2,
                    &format!(
                        "Local dao-cacher is still starting (attempt {}/{}). Retrying in {}s...",
                        attempt, retry_count_str, retry_delay_s
                    ),
                );
                if retry_count.is_none() || attempt < retry_count.unwrap() {
                    std::thread::sleep(std::time::Duration::from_secs(retry_delay_s));
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!(
                        "Local dao-cacher is still starting after {retry_count_str} attempts"
                    ))
                }
            }
            DaoCacherResponse::Rejected => {
                Err(anyhow::anyhow!("Local dao-cacher rejected our request"))
            }
            _ => Err(anyhow::anyhow!(
                "Unexpected response type from local dao-cacher"
            )),
        }
    }

    pub fn get_bootstrap_log_cache(
        &self,
        from_block: Option<u64>,
        retry_params: Option<(u64, Option<u64>)>,
        chain: Option<String>,
    ) -> anyhow::Result<(u64, Vec<LogCache>)> {
        print_to_terminal(
            2,
            &format!(
                "get_bootstrap_log_cache (using local dao-cacher): from_block={:?}, retry_params={:?}, chain={:?}",
                from_block, retry_params, chain
            ),
        );

        let (retry_delay_s, retry_count) = retry_params.ok_or_else(|| {
            anyhow::anyhow!("IsStarted check requires retry parameters (delay_s, max_tries)")
        })?;

        let cacher_process_address =
            HyperAddress::new("our", ("dao-cacher", "hypermap-cacher", "sys"));

        print_to_terminal(
            2,
            &format!(
                "Querying local cacher with GetLogsByRange: {}",
                cacher_process_address.to_string(),
            ),
        );

        let request_from_block_val = from_block.unwrap_or(0);

        let get_logs_by_range_payload = DaoGetLogsByRangeRequest {
            from_block: request_from_block_val,
            to_block: None,
        };
        let cacher_request = DaoCacherRequest::GetLogsByRange(get_logs_by_range_payload);

        if let Some(retry_count) = retry_count {
            for attempt in 1..=retry_count {
                if let Some(return_vals) = self.get_bootstrap_log_cache_inner(
                    &cacher_request,
                    &cacher_process_address,
                    attempt,
                    request_from_block_val,
                    retry_delay_s,
                    Some(retry_count),
                    &chain,
                )? {
                    return Ok(return_vals);
                }
            }
        } else {
            let mut attempt = 1;
            loop {
                if let Some(return_vals) = self.get_bootstrap_log_cache_inner(
                    &cacher_request,
                    &cacher_process_address,
                    attempt,
                    request_from_block_val,
                    retry_delay_s,
                    None,
                    &chain,
                )? {
                    return Ok(return_vals);
                }
                attempt += 1;
            }
        }

        Err(anyhow::anyhow!(
            "Failed to get response from local dao-cacher after {retry_count:?} attempts"
        ))
    }

    #[cfg(not(feature = "hyperapp"))]
    pub fn validate_log_cache(&self, log_cache: &LogCache) -> anyhow::Result<bool> {
        let from_block = log_cache.metadata.from_block.parse::<u64>().map_err(|_| {
            anyhow::anyhow!(
                "Invalid from_block in metadata: {}",
                log_cache.metadata.from_block
            )
        })?;
        let to_block = log_cache.metadata.to_block.parse::<u64>().map_err(|_| {
            anyhow::anyhow!(
                "Invalid to_block in metadata: {}",
                log_cache.metadata.to_block
            )
        })?;

        let mut bytes_to_verify = serde_json::to_vec(&log_cache.logs)
            .map_err(|e| anyhow::anyhow!("Failed to serialize logs for validation: {:?}", e))?;
        bytes_to_verify.extend_from_slice(&from_block.to_be_bytes());
        bytes_to_verify.extend_from_slice(&to_block.to_be_bytes());
        let hashed_data = keccak256(&bytes_to_verify);

        let signature_hex = log_cache.metadata.signature.trim_start_matches("0x");
        let signature_bytes = hex::decode(signature_hex)
            .map_err(|e| anyhow::anyhow!("Failed to decode hex signature: {:?}", e))?;

        Ok(sign::net_key_verify(
            hashed_data.to_vec(),
            &log_cache.metadata.created_by.parse::<HyperAddress>()?,
            signature_bytes,
        )?)
    }

    #[cfg(feature = "hyperapp")]
    pub async fn validate_log_cache(&self, log_cache: &LogCache) -> anyhow::Result<bool> {
        let from_block = log_cache.metadata.from_block.parse::<u64>().map_err(|_| {
            anyhow::anyhow!(
                "Invalid from_block in metadata: {}",
                log_cache.metadata.from_block
            )
        })?;
        let to_block = log_cache.metadata.to_block.parse::<u64>().map_err(|_| {
            anyhow::anyhow!(
                "Invalid to_block in metadata: {}",
                log_cache.metadata.to_block
            )
        })?;

        let mut bytes_to_verify = serde_json::to_vec(&log_cache.logs)
            .map_err(|e| anyhow::anyhow!("Failed to serialize logs for validation: {:?}", e))?;
        bytes_to_verify.extend_from_slice(&from_block.to_be_bytes());
        bytes_to_verify.extend_from_slice(&to_block.to_be_bytes());
        let hashed_data = keccak256(&bytes_to_verify);

        let signature_hex = log_cache.metadata.signature.trim_start_matches("0x");
        let signature_bytes = hex::decode(signature_hex)
            .map_err(|e| anyhow::anyhow!("Failed to decode hex signature: {:?}", e))?;

        Ok(sign::net_key_verify(
            hashed_data.to_vec(),
            &log_cache.metadata.created_by.parse::<HyperAddress>()?,
            signature_bytes,
        )
        .await?)
    }

    pub fn get_bootstrap(
        &self,
        from_block: Option<u64>,
        retry_params: Option<(u64, Option<u64>)>,
        chain: Option<String>,
    ) -> anyhow::Result<(u64, Vec<EthLog>)> {
        print_to_terminal(
            2,
            &format!(
                "get_bootstrap: from_block={:?}, retry_params={:?}, chain={:?}",
                from_block, retry_params, chain,
            ),
        );

        let (block, log_caches) = self.get_bootstrap_log_cache(from_block, retry_params, chain)?;

        let mut combined_logs = vec![];
        for log_cache in log_caches {
            combined_logs.extend(log_cache.logs);
        }

        combined_logs.sort_by(|a, b| {
            let block_cmp = a.block_number.cmp(&b.block_number);
            if block_cmp == std::cmp::Ordering::Equal {
                std::cmp::Ordering::Equal
            } else {
                block_cmp
            }
        });

        let mut unique_logs = Vec::new();
        for log in combined_logs {
            if !unique_logs.contains(&log) {
                unique_logs.push(log);
            }
        }

        Ok((block, unique_logs))
    }
}
