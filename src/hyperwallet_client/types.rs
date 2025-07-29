//! Shared types for the Hyperwallet protocol, used by both the client and the server.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub type ProcessAddress = String;
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

/// Categories for grouping operations.
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

/// A configuration object for the `initialize` handshake.
#[derive(Debug, Default)]
pub struct HandshakeConfig {
    pub(crate) required_operations: HashSet<Operation>,
    pub(crate) spending_limits: Option<SpendingLimits>,
    pub(crate) client_name: Option<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub server_version: String,
    pub session_id: SessionId,
    pub registered_permissions: ProcessPermissions,
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
pub struct ProcessAuth {
    pub process_address: String,
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperwalletRequest<T> {
    pub business_data: T,
    pub wallet_id: Option<String>,
    pub chain_id: Option<u64>,
    pub auth: ProcessAuth,
    pub request_id: Option<String>,
    pub timestamp: u64,
}

/// Typed message enum for type-safe communication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation")]
pub enum HyperwalletMessage {
    Handshake(HyperwalletRequest<HandshakeStep>),
    CreateWallet(HyperwalletRequest<CreateWalletRequest>),
    ImportWallet(HyperwalletRequest<ImportWalletRequest>),
    UnlockWallet(HyperwalletRequest<UnlockWalletRequest>),
    DeleteWallet(HyperwalletRequest<()>),
    RenameWallet(HyperwalletRequest<RenameWalletRequest>),
    ExportWallet(HyperwalletRequest<ExportWalletRequest>),
    GetWalletInfo(HyperwalletRequest<()>),
    ListWallets(HyperwalletRequest<()>),
    SetWalletLimits(HyperwalletRequest<SpendingLimits>),
    SendEth(HyperwalletRequest<SendEthRequest>),
    SendToken(HyperwalletRequest<SendTokenRequest>),
    ApproveToken(HyperwalletRequest<ApproveTokenRequest>),
    GetBalance(HyperwalletRequest<()>),
    GetTokenBalance(HyperwalletRequest<GetTokenBalanceRequest>),
    ExecuteViaTba(HyperwalletRequest<ExecuteViaTbaRequest>),
    CheckTbaOwnership(HyperwalletRequest<CheckTbaOwnershipRequest>),
    BuildAndSignUserOperationForPayment(
        HyperwalletRequest<BuildAndSignUserOperationForPaymentRequest>,
    ),
    SubmitUserOperation(HyperwalletRequest<SubmitUserOperationRequest>),
    GetUserOperationReceipt(HyperwalletRequest<GetUserOperationReceiptRequest>),
    ResolveIdentity(HyperwalletRequest<ResolveIdentityRequest>),
    CreateNote(HyperwalletRequest<serde_json::Value>), // Flexible for notes
}

/// Unified response type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperwalletResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<OperationError>,
    pub request_id: Option<String>,
    pub timestamp: u64,
}

/// Configuration for Circle paymaster (gasless transactions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymasterConfig {
    pub tba_address: Option<String>,
    pub is_circle_paymaster: bool,
    pub paymaster_address: String,
    pub paymaster_verification_gas: String,
    pub paymaster_post_op_gas: String,
}

impl Default for PaymasterConfig {
    fn default() -> Self {
        Self {
            tba_address: None,
            is_circle_paymaster: true,
            paymaster_address: "0x0578cFB241215b77442a541325d6A4E6dFE700Ec".to_string(), // Base Circle paymaster
            paymaster_verification_gas: "0x7a120".to_string(),                           // 500000
            paymaster_post_op_gas: "0x493e0".to_string(),                                // 300000
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildAndSignUserOperationForPaymentRequest {
    pub target: String,
    pub call_data: String,
    pub value: Option<String>,
    pub use_paymaster: bool,
    pub paymaster_config: Option<PaymasterConfig>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWalletRequest {
    pub name: String,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockWalletRequest {
    pub session_id: String,
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
    pub new_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportWalletRequest {
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendEthRequest {
    pub to: String,
    pub amount: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendTokenRequest {
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

// === LEGACY COMPATIBILITY ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRequest {
    pub operation: Operation,
    pub params: serde_json::Value,
    pub wallet_id: Option<String>,
    pub chain_id: Option<u64>,
    pub auth: ProcessAuth,
    pub request_id: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResponse {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<OperationError>,
    pub request_id: Option<String>,
    pub timestamp: u64,
}

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
    pub process_address: ProcessAddress,
    pub allowed_operations: HashSet<Operation>,
    pub spending_limits: Option<SpendingLimits>,
    pub updatable_settings: Vec<UpdatableSetting>,
    pub registered_at: u64,
}

// API Result Structs

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Balance {
    pub formatted: String,
    pub raw: String, // U256 as string
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BuildAndSignUserOperationResponse {
    pub signed_user_operation: serde_json::Value,
    pub entry_point: String,
    pub chain_id: u64,
    pub ready_to_submit: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitUserOperationResponse {
    pub user_op_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportWalletResponse {
    pub address: String,
    pub private_key: String,
    pub chain_id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListWalletsResponse {
    pub process: String,
    pub wallets: Vec<Wallet>,
    pub total: usize,
}
