use crate::eth::{
    BlockNumberOrTag, EthError, Filter as EthFilter, FilterBlockOption, Log as EthLog, Provider,
};
use crate::hyperware::process::binding_cacher::{
    BindingCacherRequest as CacherRequest, BindingCacherResponse as CacherResponse,
    BindingCacherStatus as CacherStatus,
    BindingGetLogsByRangeOkResponse as GetLogsByRangeOkResponse,
    BindingGetLogsByRangeRequest as GetLogsByRangeRequest, BindingLogsMetadata as LogsMetadata,
    BindingManifest as Manifest, BindingManifestItem as ManifestItem,
};
use crate::{print_to_terminal, Address as BindingAddress, Request};
use alloy::hex;
use alloy::rpc::types::request::{TransactionInput, TransactionRequest};
use alloy_primitives::{keccak256, Address, Bytes, FixedBytes, B256, U256};
use alloy_sol_types::{SolCall, SolEvent, SolValue};
use serde::{
    self,
    de::{self, MapAccess, Visitor},
    ser::{SerializeMap, SerializeStruct},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;
use std::str::FromStr;

/// bindings data deployment address on base
#[cfg(not(feature = "simulation-mode"))]
pub const BINDINGS_ADDRESS: &'static str = "0x0000000000e8d224B902632757d5dbc51a451456";
#[cfg(feature = "simulation-mode")]
pub const BINDINGS_ADDRESS: &'static str = "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6";
#[cfg(not(feature = "simulation-mode"))]
pub const BINDINGS_CHAIN_ID: u64 = 8453; // base
#[cfg(feature = "simulation-mode")]
pub const BINDINGS_CHAIN_ID: u64 = 31337; // fakenet
/// first block (minus one) of tokenregistry deployment on base
#[cfg(not(feature = "simulation-mode"))]
pub const BINDINGS_FIRST_BLOCK: u64 = 36_283_831;
#[cfg(feature = "simulation-mode")]
pub const BINDINGS_FIRST_BLOCK: u64 = 0;
/// the root hash of tokenregistry, empty bytes32
pub const BINDINGS_ROOT_HASH: &'static str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogCache {
    pub metadata: LogsMetadata,
    pub logs: Vec<EthLog>,
}

const CACHER_REQUEST_TIMEOUT_S: u64 = 15;

/// Sol structures for TokenRegistry requests/events.
pub mod contract {
    use alloy_sol_macro::sol;

    sol! {
        struct Bind {
            uint256 amount;
            uint256 endTime;
        }

        error InvalidAdmin();
        error InvalidAmount(uint256 amount, uint256 minRequiredAmount, uint256 maxAmount);
        error InvalidDuration(uint256 duration, uint256 minDuration, uint256 maxDuration);
        error NoLockExists();
        error LockExpired(uint256 endTime);
        error LockNotExpired(uint256 endTime);
        error InvalidParam(uint256 param);
        error UnsupportedToken(address token);
        error ZeroAmount();
        error SourceNotExpired(bytes32 namehash, uint256 endTime);
        error ZeroDurationForNewBind();
        error ZeroAmountForNewBind();
        error DefaultDestinationInvalidParams(uint256 amount, uint256 duration);
        error InsufficientLockAmount(uint256 currentlyLocked, uint256 requested);
        error OnlyGovernanceTokenCanCall();
        error GHyprAlreadySet();

        event TokensLocked(
            address indexed account,
            uint256 amount,
            uint256 duration,
            uint256 balance,
            uint256 endTime
        );

        event LockExtended(
            address indexed account,
            uint256 duration,
            uint256 balance,
            uint256 endTime
        );

        event TokensWithdrawn(
            address indexed user,
            uint256 amountWithdrawn,
            uint256 remainingAmount,
            uint256 endTime
        );

        event BindCreated(
            address indexed user,
            bytes32 indexed namehash,
            uint256 amount,
            uint256 endTime
        );

        event BindAmountIncreased(
            address indexed user,
            bytes32 indexed namehash,
            uint256 amount,
            uint256 endTime
        );

        event BindDurationExtended(
            address indexed user,
            bytes32 indexed namehash,
            uint256 amount,
            uint256 endTime
        );

        event TokensBound(
            address indexed user,
            bytes32 srcNamehash,
            bytes32 dstNamehash,
            uint256 amount
        );

        event ExpiredBindReclaimed(
            address indexed user,
            bytes32 indexed namehash,
            uint256 amount
        );

        event Initialized(address indexed hypr, address indexed admin);

        event GHyprSet(address indexed gHypr);

        function initialize(address _hypr, address _admin) external;

        function manageLock(uint256 _amount, uint256 _duration) external;

        function isLockExpired(address _account) external view returns (bool);

        function withdraw() external returns (bool);

        function getLockDetails(address _user)
            external
            view
            returns (uint256 amount, uint256 endTime, uint256 remainingTime);

        function getRegistrationDetails(bytes32 _namehash, address _user)
            external
            view
            returns (uint256 amount, uint256 endTime, uint256 remainingTime);

        function transferRegistration(
            bytes32 _srcNamehash,
            bytes32 _dstNamehash,
            uint256 _maxAmount,
            uint256 _duration
        ) external;

        function getUserBinds(address _user) external view returns (bytes32[] memory);

        function calculateVotingPower(uint256 _value, uint256 _lockDuration)
            external
            view
            returns (uint256);

        function getMultiplier(address _account, uint256 _timepoint)
            external
            view
            returns (uint256);

        function getUserUnlockStamp(address _account) external view returns (uint256);

        function getUserOrDelegatedUnlockStamp(address _account) external view returns (uint256);

        function updateDelegationMultipliers(
            uint256 _unlockTime,
            uint256 _movedVotes,
            address _sender,
            uint256 _senderVotesBefore,
            address _dst,
            uint256 _dstVotesBefore
        ) external;

        function calculateWeightedUnlockStamp(
            uint256 _remainingDuration,
            uint256 _currentBalance,
            uint256 _newLockDuration,
            uint256 _newLockAmount
        ) external view returns (uint256);

        function calculateNewLockDuration(
            uint256 _unlockStamp,
            uint256 _remainingDuration,
            uint256 _currentBalance,
            uint256 _newLockAmount
        ) external view returns (uint256);

        function hypr() external view returns (address);
    }
}

mod erc20 {
    use alloy_sol_macro::sol;

    sol! {
        interface IERC20 {
            function balanceOf(address account) external view returns (uint256);
            function allowance(address owner, address spender) external view returns (uint256);
        }
    }
}

/// Canonical helper used throughout to hash dotted Hypermap paths into bytes32.
pub fn namehash(name: &str) -> FixedBytes<32> {
    let mut node = B256::ZERO;
    let mut labels: Vec<&str> = name.split('.').collect();
    labels.reverse();

    for label in labels.iter() {
        let l = keccak256(label.as_bytes());
        node = keccak256((node, l).abi_encode_packed());
    }

    FixedBytes::from(node)
}

/// Details returned from `getLockDetails`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LockDetails {
    pub amount: U256,
    pub end_time: U256,
    pub remaining_time: U256,
}

/// Details returned from `getRegistrationDetails`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegistrationDetails {
    pub amount: U256,
    pub end_time: U256,
    pub remaining_time: U256,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DecodeBindingLogError {
    UnexpectedTopic(B256),
    MissingTopic(usize),
    DecodeError(String),
}

fn topic_as_address(topic: &B256) -> Address {
    let bytes = topic.as_slice();
    Address::from_slice(&bytes[12..32])
}

fn expect_topic(log: &EthLog, expected: B256) -> Result<(), DecodeBindingLogError> {
    match log.topics().first().copied() {
        Some(topic) if topic == expected => Ok(()),
        other => Err(DecodeBindingLogError::UnexpectedTopic(
            other.unwrap_or_default(),
        )),
    }
}

fn topic_at(log: &EthLog, idx: usize) -> Result<B256, DecodeBindingLogError> {
    log.topics()
        .get(idx)
        .copied()
        .ok_or(DecodeBindingLogError::MissingTopic(idx))
}

fn decode_data<T>(result: Result<T, alloy_sol_types::Error>) -> Result<T, DecodeBindingLogError> {
    result.map_err(|e| DecodeBindingLogError::DecodeError(e.to_string()))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokensLockedLog {
    pub account: Address,
    pub amount: U256,
    pub duration: U256,
    pub balance: U256,
    pub end_time: U256,
}

pub fn decode_tokens_locked_log(log: &EthLog) -> Result<TokensLockedLog, DecodeBindingLogError> {
    expect_topic(log, contract::TokensLocked::SIGNATURE_HASH)?;
    let account = topic_as_address(&topic_at(log, 1)?);
    let decoded = decode_data(contract::TokensLocked::decode_log_data(log.data(), true))?;
    Ok(TokensLockedLog {
        account,
        amount: decoded.amount,
        duration: decoded.duration,
        balance: decoded.balance,
        end_time: decoded.endTime,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LockExtendedLog {
    pub account: Address,
    pub duration: U256,
    pub balance: U256,
    pub end_time: U256,
}

pub fn decode_lock_extended_log(log: &EthLog) -> Result<LockExtendedLog, DecodeBindingLogError> {
    expect_topic(log, contract::LockExtended::SIGNATURE_HASH)?;
    let account = topic_as_address(&topic_at(log, 1)?);
    let decoded = decode_data(contract::LockExtended::decode_log_data(log.data(), true))?;
    Ok(LockExtendedLog {
        account,
        duration: decoded.duration,
        balance: decoded.balance,
        end_time: decoded.endTime,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokensWithdrawnLog {
    pub user: Address,
    pub amount_withdrawn: U256,
    pub remaining_amount: U256,
    pub end_time: U256,
}

pub fn decode_tokens_withdrawn_log(
    log: &EthLog,
) -> Result<TokensWithdrawnLog, DecodeBindingLogError> {
    expect_topic(log, contract::TokensWithdrawn::SIGNATURE_HASH)?;
    let user = topic_as_address(&topic_at(log, 1)?);
    let decoded = decode_data(contract::TokensWithdrawn::decode_log_data(log.data(), true))?;
    Ok(TokensWithdrawnLog {
        user,
        amount_withdrawn: decoded.amountWithdrawn,
        remaining_amount: decoded.remainingAmount,
        end_time: decoded.endTime,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BindLog {
    pub user: Address,
    pub namehash: FixedBytes<32>,
    pub amount: U256,
    pub end_time: U256,
}

pub fn decode_bind_created_log(log: &EthLog) -> Result<BindLog, DecodeBindingLogError> {
    expect_topic(log, contract::BindCreated::SIGNATURE_HASH)?;
    let user = topic_as_address(&topic_at(log, 1)?);
    let namehash = topic_at(log, 2)?;
    let decoded = decode_data(contract::BindCreated::decode_log_data(log.data(), true))?;
    Ok(BindLog {
        user,
        namehash,
        amount: decoded.amount,
        end_time: decoded.endTime,
    })
}

pub fn decode_bind_amount_increased_log(log: &EthLog) -> Result<BindLog, DecodeBindingLogError> {
    expect_topic(log, contract::BindAmountIncreased::SIGNATURE_HASH)?;
    let user = topic_as_address(&topic_at(log, 1)?);
    let namehash = topic_at(log, 2)?;
    let decoded = decode_data(contract::BindAmountIncreased::decode_log_data(
        log.data(),
        true,
    ))?;
    Ok(BindLog {
        user,
        namehash,
        amount: decoded.amount,
        end_time: decoded.endTime,
    })
}

pub fn decode_bind_duration_extended_log(log: &EthLog) -> Result<BindLog, DecodeBindingLogError> {
    expect_topic(log, contract::BindDurationExtended::SIGNATURE_HASH)?;
    let user = topic_as_address(&topic_at(log, 1)?);
    let namehash = topic_at(log, 2)?;
    let decoded = decode_data(contract::BindDurationExtended::decode_log_data(
        log.data(),
        true,
    ))?;
    Ok(BindLog {
        user,
        namehash,
        amount: decoded.amount,
        end_time: decoded.endTime,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokensBoundLog {
    pub user: Address,
    pub src_namehash: FixedBytes<32>,
    pub dst_namehash: FixedBytes<32>,
    pub amount: U256,
}

pub fn decode_tokens_bound_log(log: &EthLog) -> Result<TokensBoundLog, DecodeBindingLogError> {
    expect_topic(log, contract::TokensBound::SIGNATURE_HASH)?;
    let user = topic_as_address(&topic_at(log, 1)?);
    let decoded = decode_data(contract::TokensBound::decode_log_data(log.data(), true))?;
    Ok(TokensBoundLog {
        user,
        src_namehash: decoded.srcNamehash,
        dst_namehash: decoded.dstNamehash,
        amount: decoded.amount,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExpiredBindReclaimedLog {
    pub user: Address,
    pub namehash: FixedBytes<32>,
    pub amount: U256,
}

pub fn decode_expired_bind_reclaimed_log(
    log: &EthLog,
) -> Result<ExpiredBindReclaimedLog, DecodeBindingLogError> {
    expect_topic(log, contract::ExpiredBindReclaimed::SIGNATURE_HASH)?;
    let user = topic_as_address(&topic_at(log, 1)?);
    let namehash = topic_at(log, 2)?;
    let decoded = decode_data(contract::ExpiredBindReclaimed::decode_log_data(
        log.data(),
        true,
    ))?;
    Ok(ExpiredBindReclaimedLog {
        user,
        namehash,
        amount: decoded.amount,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InitializedLog {
    pub hypr: Address,
    pub admin: Address,
}

pub fn decode_initialized_log(log: &EthLog) -> Result<InitializedLog, DecodeBindingLogError> {
    expect_topic(log, contract::Initialized::SIGNATURE_HASH)?;
    let hypr = topic_as_address(&topic_at(log, 1)?);
    let admin = topic_as_address(&topic_at(log, 2)?);
    Ok(InitializedLog { hypr, admin })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GHyprSetLog {
    pub g_hypr: Address,
}

pub fn decode_ghypr_set_log(log: &EthLog) -> Result<GHyprSetLog, DecodeBindingLogError> {
    expect_topic(log, contract::GHyprSet::SIGNATURE_HASH)?;
    let g_hypr = topic_as_address(&topic_at(log, 1)?);
    Ok(GHyprSetLog { g_hypr })
}

/// Apply an ETH log filter to a set of logs (topic/address/block-range only).
pub fn eth_apply_filter(logs: &[EthLog], filter: &EthFilter) -> Vec<EthLog> {
    let mut matched_logs = Vec::new();

    let (filter_from_block, filter_to_block) = match filter.block_option {
        FilterBlockOption::Range {
            from_block,
            to_block,
        } => {
            let parse_block_num = |bn: Option<BlockNumberOrTag>| -> Option<u64> {
                match bn {
                    Some(BlockNumberOrTag::Number(n)) => Some(n),
                    _ => None,
                }
            };
            (parse_block_num(from_block), parse_block_num(to_block))
        }
        _ => (None, None),
    };

    for log in logs.iter() {
        let mut match_address = filter.address.is_empty();
        if !match_address && filter.address.matches(&log.address()) {
            match_address = true;
        }
        if !match_address {
            continue;
        }

        if let Some(log_bn) = log.block_number {
            if let Some(filter_from) = filter_from_block {
                if log_bn < filter_from {
                    continue;
                }
            }
            if let Some(filter_to) = filter_to_block {
                if log_bn > filter_to {
                    continue;
                }
            }
        } else if filter_from_block.is_some() || filter_to_block.is_some() {
            continue;
        }

        let mut match_topics = true;
        for (i, alts) in filter.topics.iter().enumerate() {
            if alts.is_empty() {
                continue;
            }
            let log_topic = log.topics().get(i);
            if !alts.iter().any(|t| Some(t) == log_topic) {
                match_topics = false;
                break;
            }
        }

        if match_topics {
            matched_logs.push(log.clone());
        }
    }
    matched_logs
}

/// Helper struct for reading binding data and local cacher bootstrap.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Bindings {
    pub provider: Provider,
    address: Address,
}

impl Bindings {
    /// Creates a new Bindings instance with a specified address.
    pub fn new(provider: Provider, address: Address) -> Self {
        Self { provider, address }
    }

    /// Creates a new Bindings instance with the default address and chain ID.
    pub fn default(timeout: u64) -> Self {
        let provider = Provider::new(BINDINGS_CHAIN_ID, timeout);
        Self::new(provider, Address::from_str(BINDINGS_ADDRESS).unwrap())
    }

    /// Returns the in-use Bindings contract address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    fn call_view<Call>(&self, call: Call) -> Result<Call::Return, EthError>
    where
        Call: SolCall,
    {
        self.call_view_at(self.address, call)
    }

    fn call_view_at<Call>(&self, target: Address, call: Call) -> Result<Call::Return, EthError>
    where
        Call: SolCall,
    {
        let tx_req = TransactionRequest::default()
            .to(target)
            .input(TransactionInput::new(Bytes::from(call.abi_encode())));
        let res_bytes = self.provider.call(tx_req, None)?;
        Call::abi_decode_returns(&res_bytes, false).map_err(|_| EthError::RpcMalformedResponse)
    }

    fn build_tx<Call>(&self, call: Call) -> TransactionRequest
    where
        Call: SolCall,
    {
        TransactionRequest::default()
            .to(self.address)
            .input(TransactionInput::new(Bytes::from(call.abi_encode())))
    }

    /// Whether a user's lock is expired.
    pub fn is_lock_expired(&self, account: Address) -> Result<bool, EthError> {
        let res = self.call_view(contract::isLockExpiredCall { _account: account })?;
        Ok(res._0)
    }

    /// Get the lock details for a user.
    pub fn get_lock_details(&self, user: Address) -> Result<LockDetails, EthError> {
        let res = self.call_view(contract::getLockDetailsCall { _user: user })?;
        Ok(LockDetails {
            amount: res.amount,
            end_time: res.endTime,
            remaining_time: res.remainingTime,
        })
    }

    /// Get registration details by an already hashed name.
    pub fn get_registration_details_by_hash(
        &self,
        namehash: FixedBytes<32>,
        user: Address,
    ) -> Result<RegistrationDetails, EthError> {
        let res = self.call_view(contract::getRegistrationDetailsCall {
            _namehash: namehash,
            _user: user,
        })?;
        Ok(RegistrationDetails {
            amount: res.amount,
            end_time: res.endTime,
            remaining_time: res.remainingTime,
        })
    }

    /// Get registration details using a dotted Hypermap label.
    pub fn get_registration_details(
        &self,
        name: &str,
        user: Address,
    ) -> Result<RegistrationDetails, EthError> {
        self.get_registration_details_by_hash(namehash(name), user)
    }

    /// Return all bind namehashes owned by a user.
    pub fn get_user_binds(&self, user: Address) -> Result<Vec<FixedBytes<32>>, EthError> {
        let res = self.call_view(contract::getUserBindsCall { _user: user })?;
        Ok(res._0)
    }

    /// Calculate voting power for a balance/duration.
    pub fn calculate_voting_power(
        &self,
        value: U256,
        lock_duration: U256,
    ) -> Result<U256, EthError> {
        let res = self.call_view(contract::calculateVotingPowerCall {
            _value: value,
            _lockDuration: lock_duration,
        })?;
        Ok(res._0)
    }

    /// Retrieve the multiplier for an account (or supply if account == zero) at a timepoint.
    pub fn get_multiplier(&self, account: Address, timepoint: U256) -> Result<U256, EthError> {
        let res = self.call_view(contract::getMultiplierCall {
            _account: account,
            _timepoint: timepoint,
        })?;
        Ok(res._0)
    }

    pub fn get_user_unlock_stamp(&self, account: Address) -> Result<U256, EthError> {
        let res = self.call_view(contract::getUserUnlockStampCall { _account: account })?;
        Ok(res._0)
    }

    pub fn get_user_or_delegated_unlock_stamp(&self, account: Address) -> Result<U256, EthError> {
        let res =
            self.call_view(contract::getUserOrDelegatedUnlockStampCall { _account: account })?;
        Ok(res._0)
    }

    pub fn calculate_weighted_unlock_stamp(
        &self,
        remaining_duration: U256,
        current_balance: U256,
        new_lock_duration: U256,
        new_lock_amount: U256,
    ) -> Result<U256, EthError> {
        let res = self.call_view(contract::calculateWeightedUnlockStampCall {
            _remainingDuration: remaining_duration,
            _currentBalance: current_balance,
            _newLockDuration: new_lock_duration,
            _newLockAmount: new_lock_amount,
        })?;
        Ok(res._0)
    }

    pub fn calculate_new_lock_duration(
        &self,
        unlock_stamp: U256,
        remaining_duration: U256,
        current_balance: U256,
        new_lock_amount: U256,
    ) -> Result<U256, EthError> {
        let res = self.call_view(contract::calculateNewLockDurationCall {
            _unlockStamp: unlock_stamp,
            _remainingDuration: remaining_duration,
            _currentBalance: current_balance,
            _newLockAmount: new_lock_amount,
        })?;
        Ok(res._0)
    }

    /// Returns the HYPR token address backing the registry.
    pub fn get_hypr_address(&self) -> Result<Address, EthError> {
        let res = self.call_view(contract::hyprCall {})?;
        Ok(res._0)
    }

    /// Returns the HYPR ERC20 balance for a given account.
    pub fn get_hypr_balance(&self, account: Address) -> Result<U256, EthError> {
        let hypr_address = self.get_hypr_address()?;
        let res = self.call_view_at(hypr_address, erc20::IERC20::balanceOfCall { account })?;
        Ok(res._0)
    }

    /// Returns the HYPR ERC20 allowance granted to the TokenRegistry for an account.
    pub fn get_hypr_allowance(&self, owner: Address) -> Result<U256, EthError> {
        let hypr_address = self.get_hypr_address()?;
        let res = self.call_view_at(
            hypr_address,
            erc20::IERC20::allowanceCall {
                owner,
                spender: self.address,
            },
        )?;
        Ok(res._0)
    }

    /// Build a transaction for `initialize`.
    pub fn build_initialize_tx(&self, hypr: Address, admin: Address) -> TransactionRequest {
        self.build_tx(contract::initializeCall {
            _hypr: hypr,
            _admin: admin,
        })
    }

    /// Build a transaction for `manageLock`.
    pub fn build_manage_lock_tx(&self, amount: U256, duration: U256) -> TransactionRequest {
        self.build_tx(contract::manageLockCall {
            _amount: amount,
            _duration: duration,
        })
    }

    /// Build a transaction for `withdraw`.
    pub fn build_withdraw_tx(&self) -> TransactionRequest {
        self.build_tx(contract::withdrawCall {})
    }

    /// Build a transaction for `transferRegistration` with pre-hashed names.
    pub fn build_transfer_registration_tx(
        &self,
        src_namehash: FixedBytes<32>,
        dst_namehash: FixedBytes<32>,
        max_amount: U256,
        duration: U256,
    ) -> TransactionRequest {
        self.build_tx(contract::transferRegistrationCall {
            _srcNamehash: src_namehash,
            _dstNamehash: dst_namehash,
            _maxAmount: max_amount,
            _duration: duration,
        })
    }

    /// Build a transaction for `transferRegistration` using dotted names.
    pub fn build_transfer_registration_by_name_tx(
        &self,
        src_name: &str,
        dst_name: &str,
        max_amount: U256,
        duration: U256,
    ) -> TransactionRequest {
        self.build_transfer_registration_tx(
            namehash(src_name),
            namehash(dst_name),
            max_amount,
            duration,
        )
    }

    /// Build a transaction for `updateDelegationMultipliers`.
    #[allow(clippy::too_many_arguments)]
    pub fn build_update_delegation_multipliers_tx(
        &self,
        unlock_time: U256,
        moved_votes: U256,
        sender: Address,
        sender_votes_before: U256,
        dst: Address,
        dst_votes_before: U256,
    ) -> TransactionRequest {
        self.build_tx(contract::updateDelegationMultipliersCall {
            _unlockTime: unlock_time,
            _movedVotes: moved_votes,
            _sender: sender,
            _senderVotesBefore: sender_votes_before,
            _dst: dst,
            _dstVotesBefore: dst_votes_before,
        })
    }

    fn event_filter(signature: &str, address: Address) -> EthFilter {
        EthFilter::new().address(address).event(signature)
    }

    /// Filter for `TokensLocked` events.
    pub fn tokens_locked_filter(&self) -> EthFilter {
        Self::event_filter(contract::TokensLocked::SIGNATURE, self.address)
    }

    /// Filter for `LockExtended` events.
    pub fn lock_extended_filter(&self) -> EthFilter {
        Self::event_filter(contract::LockExtended::SIGNATURE, self.address)
    }

    /// Filter for `TokensWithdrawn` events.
    pub fn tokens_withdrawn_filter(&self) -> EthFilter {
        Self::event_filter(contract::TokensWithdrawn::SIGNATURE, self.address)
    }

    /// Filter for `BindCreated` events.
    pub fn bind_created_filter(&self) -> EthFilter {
        Self::event_filter(contract::BindCreated::SIGNATURE, self.address)
    }

    /// Filter for `BindAmountIncreased` events.
    pub fn bind_amount_increased_filter(&self) -> EthFilter {
        Self::event_filter(contract::BindAmountIncreased::SIGNATURE, self.address)
    }

    /// Filter for `BindDurationExtended` events.
    pub fn bind_duration_extended_filter(&self) -> EthFilter {
        Self::event_filter(contract::BindDurationExtended::SIGNATURE, self.address)
    }

    /// Filter for `TokensBound` events.
    pub fn tokens_bound_filter(&self) -> EthFilter {
        Self::event_filter(contract::TokensBound::SIGNATURE, self.address)
    }

    /// Filter for `ExpiredBindReclaimed` events.
    pub fn expired_bind_reclaimed_filter(&self) -> EthFilter {
        Self::event_filter(contract::ExpiredBindReclaimed::SIGNATURE, self.address)
    }

    /// Filter for `GHyprSet` events.
    pub fn ghypr_set_filter(&self) -> EthFilter {
        Self::event_filter(contract::GHyprSet::SIGNATURE, self.address)
    }

    /// Filter for `Initialized` events.
    pub fn initialized_filter(&self) -> EthFilter {
        Self::event_filter(contract::Initialized::SIGNATURE, self.address)
    }

    /// Create a `BindCreated` filter scoped to specific namehashes.
    pub fn named_bind_filter(&self, namehashes: &[FixedBytes<32>]) -> EthFilter {
        self.bind_created_filter().topic2(
            namehashes
                .iter()
                .map(|h| B256::from(*h))
                .collect::<Vec<_>>(),
        )
    }

    fn get_bootstrap_log_cache_inner(
        &self,
        cacher_request: &CacherRequest,
        cacher_process_address: &BindingAddress,
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
            &format!("Attempt {attempt}/{retry_count_str} to query local binding-cacher"),
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
                        "Error response from local cacher (attempt {}): {:?}",
                        attempt, e
                    ),
                );
                if retry_count.is_none() || attempt < retry_count.unwrap() {
                    std::thread::sleep(std::time::Duration::from_secs(retry_delay_s));
                    return Ok(None);
                } else {
                    return Err(anyhow::anyhow!(
                        "Error response from local cacher after {retry_count_str} attempts: {e:?}"
                    ));
                }
            }
            Err(e) => {
                print_to_terminal(
                    1,
                    &format!(
                        "Failed to send request to local cacher (attempt {}): {:?}",
                        attempt, e
                    ),
                );
                if retry_count.is_none() || attempt < retry_count.unwrap() {
                    std::thread::sleep(std::time::Duration::from_secs(retry_delay_s));
                    return Ok(None);
                } else {
                    return Err(anyhow::anyhow!(
                        "Failed to send request to local cacher after {retry_count_str} attempts: {e:?}"
                    ));
                }
            }
        };

        match serde_json::from_slice::<CacherResponse>(response_msg.body())? {
            CacherResponse::GetLogsByRange(res) => match res {
                Ok(GetLogsByRangeOkResponse::Latest(block)) => Ok(Some((block, vec![]))),
                Ok(GetLogsByRangeOkResponse::Logs((block, json))) => {
                    if json.is_empty() || json == "[]" {
                        print_to_terminal(
                            2,
                            &format!(
                                "Local cacher returned no log caches for the range from block {}.",
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
                                                "Cache from local cacher ({} to {}) does not meet request_from_block {}",
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
                                            "LogCache from local cacher has mismatched chain_id (expected {}, got {}). Skipping.",
                                            target_chain_id, log_cache.metadata.chain_id
                                        ),
                                    );
                                }
                            }

                            print_to_terminal(
                                2,
                                &format!(
                                    "Retrieved {} log caches from local binding-cacher.",
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
                    "Local cacher reported error for GetLogsByRange: {}",
                    e_str,
                )),
            },
            CacherResponse::IsStarting => {
                print_to_terminal(
                    2,
                    &format!(
                        "Local binding-cacher is still starting (attempt {}/{}). Retrying in {}s...",
                        attempt, retry_count_str, retry_delay_s
                    ),
                );
                if retry_count.is_none() || attempt < retry_count.unwrap() {
                    std::thread::sleep(std::time::Duration::from_secs(retry_delay_s));
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!(
                        "Local binding-cacher is still starting after {retry_count_str} attempts"
                    ))
                }
            }
            CacherResponse::Rejected => {
                Err(anyhow::anyhow!("Local binding-cacher rejected our request"))
            }
            _ => Err(anyhow::anyhow!(
                "Unexpected response type from local binding-cacher"
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
                "get_bootstrap_log_cache (using local binding-cacher): from_block={:?}, retry_params={:?}, chain={:?}",
                from_block, retry_params, chain
            ),
        );

        let (retry_delay_s, retry_count) = retry_params.ok_or_else(|| {
            anyhow::anyhow!("IsStarted check requires retry parameters (delay_s, max_tries)")
        })?;

        let cacher_process_address =
            BindingAddress::new("our", ("binding-cacher", "hypermap-cacher", "sys"));

        print_to_terminal(
            2,
            &format!(
                "Querying local cacher with GetLogsByRange: {}",
                cacher_process_address.to_string(),
            ),
        );

        let request_from_block_val = from_block.unwrap_or(0);

        let get_logs_by_range_payload = GetLogsByRangeRequest {
            from_block: request_from_block_val,
            to_block: None,
        };
        let cacher_request = CacherRequest::GetLogsByRange(get_logs_by_range_payload);

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
            "Failed to get response from local binding-cacher after {retry_count:?} attempts"
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

        Ok(crate::sign::net_key_verify(
            hashed_data.to_vec(),
            &log_cache.metadata.created_by.parse::<BindingAddress>()?,
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

        Ok(crate::sign::net_key_verify(
            hashed_data.to_vec(),
            &log_cache.metadata.created_by.parse::<BindingAddress>()?,
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

        let mut all_valid_logs: Vec<EthLog> = Vec::new();
        let request_from_block_val = from_block.unwrap_or(0);

        for log_cache in log_caches {
            for log in log_cache.logs {
                if let Some(log_block_number) = log.block_number {
                    if log_block_number >= request_from_block_val {
                        all_valid_logs.push(log);
                    }
                } else if from_block.is_none() {
                    all_valid_logs.push(log);
                }
            }
        }

        all_valid_logs.sort_by(|a, b| {
            let block_cmp = a.block_number.cmp(&b.block_number);
            if block_cmp == std::cmp::Ordering::Equal {
                std::cmp::Ordering::Equal
            } else {
                block_cmp
            }
        });

        let mut unique_logs = Vec::new();
        for log in all_valid_logs {
            if !unique_logs.contains(&log) {
                unique_logs.push(log);
            }
        }

        print_to_terminal(
            2,
            &format!(
                "get_bootstrap: Consolidated {} unique logs.",
                unique_logs.len(),
            ),
        );
        Ok((block, unique_logs))
    }

    pub fn bootstrap(
        &self,
        from_block: Option<u64>,
        filters: Vec<EthFilter>,
        retry_params: Option<(u64, Option<u64>)>,
        chain: Option<String>,
    ) -> anyhow::Result<(u64, Vec<Vec<EthLog>>)> {
        print_to_terminal(
            2,
            &format!(
                "bootstrap: from_block={:?}, num_filters={}, retry_params={:?}, chain={:?}",
                from_block,
                filters.len(),
                retry_params,
                chain,
            ),
        );

        let (block, consolidated_logs) = self.get_bootstrap(from_block, retry_params, chain)?;

        if consolidated_logs.is_empty() {
            print_to_terminal(
                2,
                "bootstrap: No logs retrieved after consolidation. Returning empty results for filters.",
            );
            return Ok((block, filters.iter().map(|_| Vec::new()).collect()));
        }

        let mut results_per_filter: Vec<Vec<EthLog>> = Vec::new();
        for filter in filters {
            let filtered_logs = eth_apply_filter(&consolidated_logs, &filter);
            results_per_filter.push(filtered_logs);
        }

        print_to_terminal(
            2,
            &format!(
                "bootstrap: Applied {} filters to bootstrapped logs.",
                results_per_filter.len(),
            ),
        );
        Ok((block, results_per_filter))
    }
}

// ... existing code ...

impl Serialize for ManifestItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ManifestItem", 4)?;
        state.serialize_field("metadata", &self.metadata)?;
        state.serialize_field("is_empty", &self.is_empty)?;
        state.serialize_field("file_hash", &self.file_hash)?;
        state.serialize_field("file_name", &self.file_name)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ManifestItem {
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
            type Value = ManifestItem;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ManifestItem")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ManifestItem, V::Error>
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

                Ok(ManifestItem {
                    metadata,
                    is_empty,
                    file_hash,
                    file_name,
                })
            }
        }

        deserializer.deserialize_struct(
            "ManifestItem",
            &["metadata", "is_empty", "file_hash", "file_name"],
            ManifestItemVisitor,
        )
    }
}

impl Serialize for Manifest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Manifest", 4)?;
        state.serialize_field("items", &self.items)?;
        state.serialize_field("manifest_filename", &self.manifest_filename)?;
        state.serialize_field("chain_id", &self.chain_id)?;
        state.serialize_field("protocol_version", &self.protocol_version)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Manifest {
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
            type Value = Manifest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Manifest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Manifest, V::Error>
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

                Ok(Manifest {
                    items,
                    manifest_filename,
                    chain_id,
                    protocol_version,
                })
            }
        }

        deserializer.deserialize_struct(
            "Manifest",
            &["items", "manifest_filename", "chain_id", "protocol_version"],
            ManifestVisitor,
        )
    }
}

impl Serialize for GetLogsByRangeRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("GetLogsByRangeRequest", 2)?;
        state.serialize_field("from_block", &self.from_block)?;
        state.serialize_field("to_block", &self.to_block)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for GetLogsByRangeRequest {
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
            type Value = GetLogsByRangeRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct GetLogsByRangeRequest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<GetLogsByRangeRequest, V::Error>
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

                Ok(GetLogsByRangeRequest {
                    from_block,
                    to_block,
                })
            }
        }

        deserializer.deserialize_struct(
            "GetLogsByRangeRequest",
            &["from_block", "to_block"],
            GetLogsByRangeRequestVisitor,
        )
    }
}

impl Serialize for CacherStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CacherStatus", 8)?;
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

impl<'de> Deserialize<'de> for CacherStatus {
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
            type Value = CacherStatus;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct CacherStatus")
            }

            fn visit_map<V>(self, mut map: V) -> Result<CacherStatus, V::Error>
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

                Ok(CacherStatus {
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
            "CacherStatus",
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

impl Serialize for CacherRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            CacherRequest::GetManifest => serializer.serialize_str("GetManifest"),
            CacherRequest::GetLogCacheContent(path) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("GetLogCacheContent", path)?;
                map.end()
            }
            CacherRequest::GetStatus => serializer.serialize_str("GetStatus"),
            CacherRequest::GetLogsByRange(request) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("GetLogsByRange", request)?;
                map.end()
            }
            CacherRequest::StartProviding => serializer.serialize_str("StartProviding"),
            CacherRequest::StopProviding => serializer.serialize_str("StopProviding"),
            CacherRequest::SetNodes(nodes) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("SetNodes", nodes)?;
                map.end()
            }
            CacherRequest::Reset(nodes) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("Reset", nodes)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for CacherRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CacherRequestVisitor;

        impl<'de> Visitor<'de> for CacherRequestVisitor {
            type Value = CacherRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string for unit variants or a map for other variants")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    "GetManifest" => Ok(CacherRequest::GetManifest),
                    "GetStatus" => Ok(CacherRequest::GetStatus),
                    "StartProviding" => Ok(CacherRequest::StartProviding),
                    "StopProviding" => Ok(CacherRequest::StopProviding),
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
                let (variant, value) = map
                    .next_entry::<String, serde_json::Value>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                // Ensure there are no extra entries
                if map.next_entry::<String, serde_json::Value>()?.is_some() {
                    return Err(de::Error::custom("unexpected extra entries in map"));
                }

                match variant.as_str() {
                    "GetLogCacheContent" => {
                        let path = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(CacherRequest::GetLogCacheContent(path))
                    }
                    "GetLogsByRange" => {
                        let request = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(CacherRequest::GetLogsByRange(request))
                    }
                    "SetNodes" => {
                        let nodes = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(CacherRequest::SetNodes(nodes))
                    }
                    "Reset" => {
                        let nodes = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(CacherRequest::Reset(nodes))
                    }
                    _ => Err(de::Error::unknown_variant(
                        &variant,
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

        deserializer.deserialize_any(CacherRequestVisitor)
    }
}

impl Serialize for CacherResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            CacherResponse::GetManifest(manifest) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("GetManifest", manifest)?;
                map.end()
            }
            CacherResponse::GetLogCacheContent(result) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("GetLogCacheContent", result)?;
                map.end()
            }
            CacherResponse::GetStatus(status) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("GetStatus", status)?;
                map.end()
            }
            CacherResponse::GetLogsByRange(result) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("GetLogsByRange", result)?;
                map.end()
            }
            CacherResponse::StartProviding(result) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("StartProviding", result)?;
                map.end()
            }
            CacherResponse::StopProviding(result) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("StopProviding", result)?;
                map.end()
            }
            CacherResponse::Rejected => serializer.serialize_str("Rejected"),
            CacherResponse::IsStarting => serializer.serialize_str("IsStarting"),
            CacherResponse::SetNodes(result) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("SetNodes", result)?;
                map.end()
            }
            CacherResponse::Reset(result) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("Reset", result)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for CacherResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CacherResponseVisitor;

        impl<'de> Visitor<'de> for CacherResponseVisitor {
            type Value = CacherResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string for unit variants or a map for other variants")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    "Rejected" => Ok(CacherResponse::Rejected),
                    "IsStarting" => Ok(CacherResponse::IsStarting),
                    _ => Err(de::Error::unknown_variant(
                        value,
                        &[
                            "GetManifest",
                            "GetLogCacheContent",
                            "GetStatus",
                            "GetLogsByRange",
                            "StartProviding",
                            "StopProviding",
                            "Rejected",
                            "IsStarting",
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
                let (variant, value) = map
                    .next_entry::<String, serde_json::Value>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                // Ensure there are no extra entries
                if map.next_entry::<String, serde_json::Value>()?.is_some() {
                    return Err(de::Error::custom("unexpected extra entries in map"));
                }

                match variant.as_str() {
                    "GetManifest" => {
                        let manifest = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(CacherResponse::GetManifest(manifest))
                    }
                    "GetLogCacheContent" => {
                        let result = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(CacherResponse::GetLogCacheContent(result))
                    }
                    "GetStatus" => {
                        let status = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(CacherResponse::GetStatus(status))
                    }
                    "GetLogsByRange" => {
                        let result = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(CacherResponse::GetLogsByRange(result))
                    }
                    "StartProviding" => {
                        let result = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(CacherResponse::StartProviding(result))
                    }
                    "StopProviding" => {
                        let result = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(CacherResponse::StopProviding(result))
                    }
                    "SetNodes" => {
                        let result = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(CacherResponse::SetNodes(result))
                    }
                    "Reset" => {
                        let result = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(CacherResponse::Reset(result))
                    }
                    _ => Err(de::Error::unknown_variant(
                        &variant,
                        &[
                            "GetManifest",
                            "GetLogCacheContent",
                            "GetStatus",
                            "GetLogsByRange",
                            "StartProviding",
                            "StopProviding",
                            "Rejected",
                            "IsStarting",
                            "SetNodes",
                            "Reset",
                        ],
                    )),
                }
            }
        }

        deserializer.deserialize_any(CacherResponseVisitor)
    }
}

impl Serialize for LogsMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("LogsMetadata", 6)?;
        state.serialize_field("chainId", &self.chain_id)?;
        state.serialize_field("fromBlock", &self.from_block)?;
        state.serialize_field("toBlock", &self.to_block)?;
        state.serialize_field("timeCreated", &self.time_created)?;
        state.serialize_field("createdBy", &self.created_by)?;
        state.serialize_field("signature", &self.signature)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for LogsMetadata {
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
            type Value = LogsMetadata;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct LogsMetadata")
            }

            fn visit_map<V>(self, mut map: V) -> Result<LogsMetadata, V::Error>
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

                Ok(LogsMetadata {
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
            "LogsMetadata",
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

impl Serialize for GetLogsByRangeOkResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            GetLogsByRangeOkResponse::Logs(tuple) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("Logs", tuple)?;
                map.end()
            }
            GetLogsByRangeOkResponse::Latest(block) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("Latest", block)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for GetLogsByRangeOkResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct GetLogsByRangeOkResponseVisitor;

        impl<'de> Visitor<'de> for GetLogsByRangeOkResponseVisitor {
            type Value = GetLogsByRangeOkResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "a map with a single key representing the GetLogsByRangeOkResponse variant",
                )
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let (variant, value) = map
                    .next_entry::<String, serde_json::Value>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                match variant.as_str() {
                    "Logs" => {
                        let tuple = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(GetLogsByRangeOkResponse::Logs(tuple))
                    }
                    "Latest" => {
                        let block = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(GetLogsByRangeOkResponse::Latest(block))
                    }
                    _ => Err(de::Error::unknown_variant(&variant, &["Logs", "Latest"])),
                }
            }
        }

        deserializer.deserialize_map(GetLogsByRangeOkResponseVisitor)
    }
}
