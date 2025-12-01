use crate::eth::{BlockNumberOrTag, EthError, Filter as EthFilter, Provider};
use alloy::rpc::types::request::{TransactionInput, TransactionRequest};
use alloy_primitives::{Address, Bytes, FixedBytes, U256, B256, keccak256};
use alloy_sol_macro::sol;
use alloy_sol_types::{SolCall, SolEvent};

sol! {
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
    }
}

/// Convenience wrapper for Timelock/Governor interactions.
#[derive(Clone, Debug)]
pub struct DaoContracts {
    pub provider: Provider,
    pub timelock: Address,
    pub governor: Address,
}

impl DaoContracts {
    pub fn new(provider: Provider, timelock: Address, governor: Address) -> Self {
        Self {
            provider,
            timelock,
            governor,
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
        let proposer = self.call_view(self.timelock, TimelockController::PROPOSER_ROLECall {})?._0;
        let executor = self.call_view(self.timelock, TimelockController::EXECUTOR_ROLECall {})?._0;
        let canceller = self.call_view(self.timelock, TimelockController::CANCELLER_ROLECall {})?._0;
        Ok((proposer, executor, canceller))
    }

    /// Check if an account has a specific timelock role.
    pub fn has_role(&self, role: FixedBytes<32>, account: Address) -> Result<bool, EthError> {
        let res = self.call_view(
            self.timelock,
            TimelockController::hasRoleCall {
                role,
                account,
            },
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
            if let Ok(decoded) =
                HyperwareGovernor::ProposalCreated::decode_log(&prim_log, true)
            {
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
