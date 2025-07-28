//! Shared types for the Hyperwallet protocol, used by both the client and the server.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// Type Aliases
pub type ProcessAddress = String;
pub type WalletAddress = String;
pub type ChainId = u64;
pub type SessionId = String;
pub type UserOperationHash = String;
pub type Signature = Vec<u8>;

/// All possible wallet operations that can be performed through the hyperwallet service.
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

/// Information about an established session with Hyperwallet.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub server_version: String,
    pub session_id: SessionId,
    pub registered_permissions: ProcessPermissions,
}

/// The steps involved in the handshake protocol.
#[derive(Debug, Serialize, Deserialize)]
pub enum HandshakeStep {
    ClientHello {
        client_version: String,
        client_name: String,
    },
    Register {
        required_operations: Vec<Operation>,
        spending_limits: Option<SpendingLimits>,
    },
}

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
pub struct ProcessAuth {
    pub process_address: String,
    pub signature: Option<Vec<u8>>,
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
