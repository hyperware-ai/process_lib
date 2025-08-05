//! Shared types for the Hyperwallet protocol, used by both the client and the server.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub type ProcessAddress = crate::Address;
pub type WalletAddress = String;
pub type ChainId = u64;
pub type SessionId = String;
pub type UserOperationHash = String;
pub type Signature = Vec<u8>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Operation {
    Handshake,
    UnlockWallet,
    RegisterProcess, // Deprecated
    UpdateSpendingLimits,
    CreateWallet,
    ImportWallet,
    DeleteWallet,
    RenameWallet,
    ExportWallet,
    EncryptWallet,
    DecryptWallet,
    GetWalletInfo,
    ListWallets,
    SetWalletLimits,
    SendEth,
    SendToken,
    ApproveToken,
    CallContract,
    SignTransaction,
    SignMessage,
    ExecuteViaTba,
    CheckTbaOwnership,
    SetupTbaDelegation,
    BuildAndSignUserOperationForPayment,
    SubmitUserOperation,
    BuildUserOperation,
    SignUserOperation,
    BuildAndSignUserOperation,
    EstimateUserOperationGas,
    GetUserOperationReceipt,
    ConfigurePaymaster,
    ResolveIdentity,
    CreateNote,
    ReadNote,
    SetupDelegation,
    VerifyDelegation,
    MintEntry,
    GetBalance,
    GetTokenBalance,
    GetTransactionHistory,
    EstimateGas,
    GetGasPrice,
    GetTransactionReceipt,
    BatchOperations,
    ScheduleOperation,
    CancelOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OperationCategory {
    System,
    ProcessManagement,
    WalletManagement,
    Ethereum,
    TokenBoundAccount,
    ERC4337,
    Hypermap,
    Query,
    Advanced,
}

impl Operation {
    pub fn all() -> Vec<Operation> {
        vec![
            Operation::Handshake,
            Operation::UnlockWallet,
            Operation::RegisterProcess,
            Operation::UpdateSpendingLimits,
            Operation::CreateWallet,
            Operation::ImportWallet,
            Operation::DeleteWallet,
            Operation::RenameWallet,
            Operation::ExportWallet,
            Operation::EncryptWallet,
            Operation::DecryptWallet,
            Operation::GetWalletInfo,
            Operation::ListWallets,
            Operation::SetWalletLimits,
            Operation::SendEth,
            Operation::SendToken,
            Operation::ApproveToken,
            Operation::CallContract,
            Operation::SignTransaction,
            Operation::SignMessage,
            Operation::ExecuteViaTba,
            Operation::CheckTbaOwnership,
            Operation::SetupTbaDelegation,
            Operation::BuildAndSignUserOperationForPayment,
            Operation::SubmitUserOperation,
            Operation::BuildUserOperation,
            Operation::SignUserOperation,
            Operation::BuildAndSignUserOperation,
            Operation::EstimateUserOperationGas,
            Operation::GetUserOperationReceipt,
            Operation::ConfigurePaymaster,
            Operation::ResolveIdentity,
            Operation::CreateNote,
            Operation::ReadNote,
            Operation::SetupDelegation,
            Operation::VerifyDelegation,
            Operation::MintEntry,
            Operation::GetBalance,
            Operation::GetTokenBalance,
            Operation::GetTransactionHistory,
            Operation::EstimateGas,
            Operation::GetGasPrice,
            Operation::GetTransactionReceipt,
            Operation::BatchOperations,
            Operation::ScheduleOperation,
            Operation::CancelOperation,
        ]
    }

    pub fn category(&self) -> OperationCategory {
        match self {
            Operation::Handshake | Operation::UnlockWallet => OperationCategory::System,

            Operation::RegisterProcess | Operation::UpdateSpendingLimits => {
                OperationCategory::ProcessManagement
            }

            Operation::CreateWallet
            | Operation::ImportWallet
            | Operation::DeleteWallet
            | Operation::RenameWallet
            | Operation::ExportWallet
            | Operation::EncryptWallet
            | Operation::DecryptWallet
            | Operation::GetWalletInfo
            | Operation::ListWallets
            | Operation::SetWalletLimits => OperationCategory::WalletManagement,

            Operation::SendEth
            | Operation::SendToken
            | Operation::ApproveToken
            | Operation::CallContract
            | Operation::SignTransaction
            | Operation::SignMessage
            | Operation::GetBalance
            | Operation::GetTokenBalance
            | Operation::GetTransactionHistory
            | Operation::EstimateGas
            | Operation::GetGasPrice
            | Operation::GetTransactionReceipt => OperationCategory::Ethereum,

            Operation::ExecuteViaTba
            | Operation::CheckTbaOwnership
            | Operation::SetupTbaDelegation => OperationCategory::TokenBoundAccount,

            Operation::BuildAndSignUserOperationForPayment
            | Operation::SubmitUserOperation
            | Operation::BuildUserOperation
            | Operation::SignUserOperation
            | Operation::BuildAndSignUserOperation
            | Operation::EstimateUserOperationGas
            | Operation::GetUserOperationReceipt
            | Operation::ConfigurePaymaster => OperationCategory::ERC4337,

            Operation::ResolveIdentity
            | Operation::CreateNote
            | Operation::ReadNote
            | Operation::SetupDelegation
            | Operation::VerifyDelegation
            | Operation::MintEntry => OperationCategory::Hypermap,

            Operation::BatchOperations
            | Operation::ScheduleOperation
            | Operation::CancelOperation => OperationCategory::Advanced,
        }
    }
}

#[derive(Debug)]
pub struct HandshakeConfig {
    pub(crate) required_operations: HashSet<Operation>,
    pub(crate) spending_limits: Option<SpendingLimits>,
    pub(crate) client_name: Option<String>,
    pub(crate) initial_chain_id: ChainId,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            required_operations: HashSet::new(),
            spending_limits: None,
            client_name: None,
            initial_chain_id: 8453, // Default to Base mainnet
        }
    }
}

impl HandshakeConfig {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_operations(mut self, operations: &[Operation]) -> Self {
        self.required_operations.extend(operations.iter().cloned());
        self
    }

    pub fn require_category(mut self, category: OperationCategory) -> Self {
        self.required_operations.extend(
            Operation::all()
                .into_iter()
                .filter(|op| op.category() == category),
        );
        self
    }

    pub fn with_spending_limits(mut self, limits: SpendingLimits) -> Self {
        self.spending_limits = Some(limits);
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.client_name = Some(name.into());
        self
    }

    pub fn with_initial_chain(mut self, chain_id: ChainId) -> Self {
        self.initial_chain_id = chain_id;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub server_version: String,
    pub session_id: SessionId,
    pub registered_permissions: ProcessPermissions,
    pub initial_chain_id: ChainId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "step")]
pub enum HandshakeStep {
    ClientHello {
        client_version: String,
        client_name: String,
    },
    ServerWelcome {
        server_version: String,
        supported_operations: Vec<Operation>,
        supported_chains: Vec<u64>,
        features: Vec<String>,
    },
    Register {
        required_operations: Vec<Operation>,
        spending_limits: Option<SpendingLimits>,
    },
    Complete {
        registered_permissions: ProcessPermissions,
        session_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperwalletMessage {
    pub request: HyperwalletRequest,
    pub session_id: SessionId,
}

/// Typed message enum for type-safe communication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation")]
pub enum HyperwalletRequest {
    // Session Management (Unauthenticated)
    Handshake(HandshakeStep),

    // Session Management (Authenticated)
    UnlockWallet(UnlockWalletRequest),

    // Wallet Lifecycle Management
    CreateWallet(CreateWalletRequest),
    ImportWallet(ImportWalletRequest),
    DeleteWallet(DeleteWalletRequest),
    RenameWallet(RenameWalletRequest),
    ExportWallet(ExportWalletRequest),
    ListWallets,
    GetWalletInfo(GetWalletInfoRequest),

    // Ethereum Operations
    SendEth(SendEthRequest),
    SendToken(SendTokenRequest),
    ApproveToken(ApproveTokenRequest),
    GetBalance(GetBalanceRequest),
    GetTokenBalance(GetTokenBalanceRequest),
    CallContract(CallContractRequest),
    SignTransaction(SignTransactionRequest),
    SignMessage(SignMessageRequest),
    GetTransactionHistory(GetTransactionHistoryRequest),
    EstimateGas(EstimateGasRequest),
    GetGasPrice,
    GetTransactionReceipt(GetTransactionReceiptRequest),

    // Token Bound Account Operations
    ExecuteViaTba(ExecuteViaTbaRequest),
    CheckTbaOwnership(CheckTbaOwnershipRequest),
    SetupTbaDelegation(SetupTbaDelegationRequest),

    // Account Abstraction (ERC-4337)
    BuildAndSignUserOperationForPayment(BuildAndSignUserOperationForPaymentRequest),
    SubmitUserOperation(SubmitUserOperationRequest),
    GetUserOperationReceipt(GetUserOperationReceiptRequest),
    BuildUserOperation(BuildUserOperationRequest),
    SignUserOperation(SignUserOperationRequest),
    BuildAndSignUserOperation(BuildAndSignUserOperationRequest),
    EstimateUserOperationGas(EstimateUserOperationGasRequest),
    ConfigurePaymaster(ConfigurePaymasterRequest),

    // Hypermap Operations
    ResolveIdentity(ResolveIdentityRequest),
    CreateNote(CreateNoteRequest),
    ReadNote(ReadNoteRequest),
    SetupDelegation(SetupDelegationRequest),
    VerifyDelegation(VerifyDelegationRequest),
    MintEntry(MintEntryRequest),

    // Process Management (Legacy)
    UpdateSpendingLimits(UpdateSpendingLimitsRequest),
}

impl HyperwalletMessage {
    /// Get the operation type for this message - used for permission checking and routing
    pub fn operation_type(&self) -> Operation {
        match self.request {
            // Session Management
            HyperwalletRequest::Handshake(_) => Operation::Handshake,
            HyperwalletRequest::UnlockWallet(_) => Operation::UnlockWallet,

            // Wallet Lifecycle Management
            HyperwalletRequest::CreateWallet(_) => Operation::CreateWallet,
            HyperwalletRequest::ImportWallet(_) => Operation::ImportWallet,
            HyperwalletRequest::DeleteWallet(_) => Operation::DeleteWallet,
            HyperwalletRequest::RenameWallet(_) => Operation::RenameWallet,
            HyperwalletRequest::ExportWallet(_) => Operation::ExportWallet,
            HyperwalletRequest::ListWallets => Operation::ListWallets,
            HyperwalletRequest::GetWalletInfo(_) => Operation::GetWalletInfo,

            // Ethereum Operations
            HyperwalletRequest::SendEth(_) => Operation::SendEth,
            HyperwalletRequest::SendToken(_) => Operation::SendToken,
            HyperwalletRequest::ApproveToken(_) => Operation::ApproveToken,
            HyperwalletRequest::GetBalance(_) => Operation::GetBalance,
            HyperwalletRequest::GetTokenBalance(_) => Operation::GetTokenBalance,
            HyperwalletRequest::CallContract(_) => Operation::CallContract,
            HyperwalletRequest::SignTransaction(_) => Operation::SignTransaction,
            HyperwalletRequest::SignMessage(_) => Operation::SignMessage,
            HyperwalletRequest::GetTransactionHistory(_) => Operation::GetTransactionHistory,
            HyperwalletRequest::EstimateGas(_) => Operation::EstimateGas,
            HyperwalletRequest::GetGasPrice => Operation::GetGasPrice,
            HyperwalletRequest::GetTransactionReceipt(_) => Operation::GetTransactionReceipt,

            // Token Bound Account Operations
            HyperwalletRequest::ExecuteViaTba(_) => Operation::ExecuteViaTba,
            HyperwalletRequest::CheckTbaOwnership(_) => Operation::CheckTbaOwnership,
            HyperwalletRequest::SetupTbaDelegation(_) => Operation::SetupTbaDelegation,

            // Account Abstraction (ERC-4337)
            HyperwalletRequest::BuildAndSignUserOperationForPayment(_) => {
                Operation::BuildAndSignUserOperationForPayment
            }
            HyperwalletRequest::SubmitUserOperation(_) => Operation::SubmitUserOperation,
            HyperwalletRequest::GetUserOperationReceipt(_) => Operation::GetUserOperationReceipt,
            HyperwalletRequest::BuildUserOperation(_) => Operation::BuildUserOperation,
            HyperwalletRequest::SignUserOperation(_) => Operation::SignUserOperation,
            HyperwalletRequest::BuildAndSignUserOperation(_) => {
                Operation::BuildAndSignUserOperation
            }
            HyperwalletRequest::EstimateUserOperationGas(_) => Operation::EstimateUserOperationGas,
            HyperwalletRequest::ConfigurePaymaster(_) => Operation::ConfigurePaymaster,

            // Hypermap Operations
            HyperwalletRequest::ResolveIdentity(_) => Operation::ResolveIdentity,
            HyperwalletRequest::CreateNote(_) => Operation::CreateNote,
            HyperwalletRequest::ReadNote(_) => Operation::ReadNote,
            HyperwalletRequest::SetupDelegation(_) => Operation::SetupDelegation,
            HyperwalletRequest::VerifyDelegation(_) => Operation::VerifyDelegation,
            HyperwalletRequest::MintEntry(_) => Operation::MintEntry,

            // Process Management (Legacy)
            HyperwalletRequest::UpdateSpendingLimits(_) => Operation::UpdateSpendingLimits,
        }
    }
}

/// Unified response type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperwalletResponse {
    pub success: bool,
    pub data: Option<HyperwalletResponseData>,
    pub error: Option<OperationError>,
    pub request_id: Option<String>,
}

impl HyperwalletResponse {
    pub fn success(data: HyperwalletResponseData) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            request_id: None,
        }
    }

    pub fn error(error: OperationError) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            request_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildAndSignUserOperationForPaymentRequest {
    pub eoa_wallet_id: String,
    pub tba_address: String,
    pub target: String,
    pub call_data: String,
    pub use_paymaster: bool,
    pub paymaster_config: Option<PaymasterConfig>,
    pub password: Option<String>,
}

/// Configuration for Circle paymaster (gasless transactions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymasterConfig {
    pub is_circle_paymaster: bool,
    pub paymaster_address: String,
    pub paymaster_verification_gas: String,
    pub paymaster_post_op_gas: String,
}

impl Default for PaymasterConfig {
    fn default() -> Self {
        Self {
            is_circle_paymaster: true,
            paymaster_address: "0x0578cFB241215b77442a541325d6A4E6dFE700Ec".to_string(), // Base Circle paymaster
            paymaster_verification_gas: "0x7a120".to_string(),                           // 500000
            paymaster_post_op_gas: "0x493e0".to_string(),                                // 300000
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWalletRequest {
    pub name: String,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockWalletRequest {
    pub session_id: SessionId,
    pub wallet_id: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportWalletRequest {
    pub name: String,
    pub private_key: String,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameWalletRequest {
    pub wallet_id: String,
    pub new_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportWalletRequest {
    pub wallet_id: String,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendEthRequest {
    pub wallet_id: String,
    pub to: String,
    pub amount: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendTokenRequest {
    pub wallet_id: String,
    pub token_address: String,
    pub to: String,
    pub amount: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveTokenRequest {
    pub token_address: String,
    pub spender: String,
    pub amount: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTokenBalanceRequest {
    pub wallet_id: String,
    pub token_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteViaTbaRequest {
    pub tba_address: String,
    pub target: String,
    pub call_data: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckTbaOwnershipRequest {
    pub tba_address: String,
    pub signer_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitUserOperationRequest {
    pub signed_user_operation: serde_json::Value,
    pub entry_point: String,
    pub bundler_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetUserOperationReceiptRequest {
    pub user_op_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveIdentityRequest {
    pub entry_name: String,
}

// === NEW PROPERLY TYPED REQUEST STRUCTS ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallContractRequest {
    pub to: String,
    pub data: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignTransactionRequest {
    pub to: String,
    pub value: String,
    pub data: Option<String>,
    pub gas_limit: Option<String>,
    pub gas_price: Option<String>,
    pub nonce: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignMessageRequest {
    pub message: String,
    pub message_type: MessageType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    PlainText,
    Eip191,
    Eip712 {
        domain: serde_json::Value,
        types: serde_json::Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTransactionHistoryRequest {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub from_block: Option<u64>,
    pub to_block: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstimateGasRequest {
    pub to: String,
    pub data: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTransactionReceiptRequest {
    pub tx_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupTbaDelegationRequest {
    pub tba_address: String,
    pub delegate_address: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildUserOperationRequest {
    pub target: String,
    pub call_data: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignUserOperationRequest {
    pub unsigned_user_operation: serde_json::Value,
    pub entry_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildAndSignUserOperationRequest {
    pub target: String,
    pub call_data: String,
    pub value: Option<String>,
    pub entry_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstimateUserOperationGasRequest {
    pub user_operation: serde_json::Value,
    pub entry_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurePaymasterRequest {
    pub paymaster_address: String,
    pub paymaster_data: Option<String>,
    pub verification_gas_limit: String,
    pub post_op_gas_limit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadNoteRequest {
    pub note_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupDelegationRequest {
    pub delegate_address: String,
    pub permissions: Vec<String>,
    pub expiry: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyDelegationRequest {
    pub delegate_address: String,
    pub signature: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintEntryRequest {
    pub entry_name: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSpendingLimitsRequest {
    pub new_limits: SpendingLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNoteRequest {
    pub note_data: serde_json::Value,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteWalletRequest {
    pub wallet_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetWalletInfoRequest {
    pub wallet_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBalanceRequest {
    pub wallet_id: String,
}

// === ESSENTIAL TYPES (NOT LEGACY) ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationError {
    pub code: ErrorCode,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl OperationError {
    pub fn internal_error(message: &str) -> Self {
        Self {
            code: ErrorCode::InternalError,
            message: message.to_string(),
            details: None,
        }
    }

    pub fn invalid_params(message: &str) -> Self {
        Self {
            code: ErrorCode::InvalidParams,
            message: message.to_string(),
            details: None,
        }
    }

    pub fn wallet_not_found(wallet_id: &str) -> Self {
        Self {
            code: ErrorCode::WalletNotFound,
            message: format!("Wallet '{}' not found or not accessible", wallet_id),
            details: None,
        }
    }

    pub fn chain_not_allowed(chain_id: u64) -> Self {
        Self {
            code: ErrorCode::ChainNotAllowed,
            message: format!("Chain ID {} is not allowed for this process", chain_id),
            details: None,
        }
    }

    pub fn blockchain_error(message: &str) -> Self {
        Self {
            code: ErrorCode::BlockchainError,
            message: format!("Blockchain error: {}", message),
            details: None,
        }
    }

    pub fn insufficient_funds(details: &str) -> Self {
        Self {
            code: ErrorCode::InsufficientFunds,
            message: format!("Insufficient funds: {}", details),
            details: None,
        }
    }

    pub fn spending_limit_exceeded(details: &str) -> Self {
        Self {
            code: ErrorCode::SpendingLimitExceeded,
            message: format!("Spending limit exceeded: {}", details),
            details: None,
        }
    }

    pub fn authentication_failed(reason: &str) -> Self {
        Self {
            code: ErrorCode::AuthenticationFailed,
            message: format!("Authentication failed: {}", reason),
            details: None,
        }
    }

    pub fn wallet_locked(wallet_id: &str) -> Self {
        Self {
            code: ErrorCode::WalletLocked,
            message: format!(
                "Wallet '{}' is locked. Unlock it first to perform operations",
                wallet_id
            ),
            details: None,
        }
    }

    pub fn operation_not_supported(operation: &str) -> Self {
        Self {
            code: ErrorCode::OperationNotSupported,
            message: format!("Operation '{}' is not supported or not enabled", operation),
            details: None,
        }
    }

    pub fn permission_denied(message: &str) -> Self {
        Self {
            code: ErrorCode::PermissionDenied,
            message: format!("Permission denied: {}", message),
            details: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorCode {
    PermissionDenied,
    WalletNotFound,
    InsufficientFunds,
    InvalidOperation,
    InvalidParams,
    SpendingLimitExceeded,
    ChainNotAllowed,
    BlockchainError,
    InternalError,
    AuthenticationFailed,
    WalletLocked,
    OperationNotSupported,
    VersionMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SpendingLimits {
    pub per_tx_eth: Option<String>,
    pub daily_eth: Option<String>,
    pub per_tx_usdc: Option<String>,
    pub daily_usdc: Option<String>,
    pub daily_reset_at: u64,
    pub spent_today_eth: String,
    pub spent_today_usdc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UpdatableSetting {
    SpendingLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessPermissions {
    pub address: ProcessAddress,
    pub allowed_operations: HashSet<Operation>,
    pub spending_limits: Option<SpendingLimits>,
    pub updatable_settings: Vec<UpdatableSetting>,
    pub registered_at: u64,
}

impl ProcessPermissions {
    /// Create new ProcessPermissions for a process during handshake registration
    pub fn new(address: crate::Address, required_operations: Vec<Operation>) -> Self {
        Self {
            address,
            allowed_operations: required_operations.into_iter().collect(),
            spending_limits: None,
            updatable_settings: vec![],
            registered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

// API Result Structs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockWalletResponse {
    pub success: bool,
    pub wallet_id: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWalletResponse {
    pub wallet_id: String,
    pub address: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportWalletResponse {
    pub wallet_id: String,
    pub address: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteWalletResponse {
    pub success: bool,
    pub wallet_id: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetWalletInfoResponse {
    pub wallet_id: String,
    pub address: String,
    pub name: String,
    pub chain_id: ChainId,
    pub is_locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBalanceResponse {
    pub balance: Balance,
    pub wallet_id: String,
    pub chain_id: ChainId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendEthResponse {
    pub tx_hash: String,
    pub from_address: String,
    pub to_address: String,
    pub amount: String,
    pub chain_id: ChainId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendTokenResponse {
    pub tx_hash: String,
    pub from_address: String,
    pub to_address: String,
    pub token_address: String,
    pub amount: String,
    pub chain_id: ChainId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNoteResponse {
    pub note_id: String,
    pub content_hash: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteViaTbaResponse {
    pub tx_hash: String,
    pub tba_address: String,
    pub target_address: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckTbaOwnershipResponse {
    pub tba_address: String,
    pub owner_address: String,
    pub is_owned: bool,
}

/// Unified response type that preserves type safety for all hyperwallet operations
/// This replaces serde_json::Value in the message dispatcher
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation_type")]
pub enum HyperwalletResponseData {
    // Session Management
    Handshake(HandshakeStep),
    UnlockWallet(UnlockWalletResponse),

    // Wallet Lifecycle
    CreateWallet(CreateWalletResponse),
    ImportWallet(ImportWalletResponse),
    DeleteWallet(DeleteWalletResponse),
    ExportWallet(ExportWalletResponse),

    // Wallet Queries
    ListWallets(ListWalletsResponse),
    GetWalletInfo(GetWalletInfoResponse),
    GetBalance(GetBalanceResponse),
    GetTokenBalance(GetTokenBalanceResponse),

    // Transactions
    SendEth(SendEthResponse),
    SendToken(SendTokenResponse),

    // ERC4337 Account Abstraction
    BuildAndSignUserOperationForPayment(BuildAndSignUserOperationResponse),
    SubmitUserOperation(SubmitUserOperationResponse),
    GetUserOperationReceipt(UserOperationReceiptResponse),

    // Hypermap
    CreateNote(CreateNoteResponse),

    // Token Bound Accounts
    ExecuteViaTba(ExecuteViaTbaResponse),
    CheckTbaOwnership(CheckTbaOwnershipResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub address: WalletAddress,
    pub name: Option<String>,
    pub chain_id: ChainId,
    pub encrypted: bool,
    pub created_at: Option<String>,
    pub last_used: Option<String>,
    pub spending_limits: Option<WalletSpendingLimits>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSpendingLimits {
    pub max_per_call: Option<String>,
    pub max_total: Option<String>,
    pub currency: String,
    pub total_spent: String,
    pub set_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxReceipt {
    pub hash: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    pub formatted: String,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildAndSignUserOperationResponse {
    pub signed_user_operation: serde_json::Value,
    pub entry_point: String,
    pub ready_to_submit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitUserOperationResponse {
    pub user_op_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportWalletResponse {
    pub address: String,
    pub private_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListWalletsResponse {
    pub process: String,
    pub wallets: Vec<Wallet>,
    pub total: usize,
}

// === NEW RESPONSE STRUCTS FOR TYPE SAFETY ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTokenBalanceResponse {
    pub balance: String,
    pub formatted: Option<String>,
    pub decimals: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOperationReceiptResponse {
    pub receipt: Option<serde_json::Value>,
    pub user_op_hash: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CallContractResponse {
    pub result: String,
    pub gas_used: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignTransactionResponse {
    pub signed_transaction: String,
    pub transaction_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessageResponse {
    pub signature: String,
    pub message_hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EstimateGasResponse {
    pub gas_estimate: String,
    pub gas_price: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetGasPriceResponse {
    pub gas_price: String,
    pub fast_gas_price: Option<String>,
    pub standard_gas_price: Option<String>,
    pub safe_gas_price: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionHistoryResponse {
    pub transactions: Vec<TransactionHistoryItem>,
    pub total: usize,
    pub page: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionHistoryItem {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub gas_used: Option<String>,
    pub timestamp: u64,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolveIdentityResponse {
    pub address: Option<String>,
    pub entry_name: String,
    pub found: bool,
}
