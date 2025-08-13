//! Hyperwallet types exposed via WIT interface
//! This module re-exports the WIT-generated types and provides conversion utilities

use crate::hyperware::process::hyperwallet as wit;

// Re-export WIT types with original names for backwards compatibility
pub use wit::{
    Balance, ChainId, ClientHello, CompleteHandshake, CreateNoteResponse, CreateWalletRequest,
    CreateWalletResponse, DeleteWalletRequest, DeleteWalletResponse, ErrorCode,
    ExecuteViaTbaResponse, ExportWalletRequest, ExportWalletResponse, GetBalanceRequest,
    GetBalanceResponse, GetTokenBalanceRequest, GetTokenBalanceResponse, GetWalletInfoRequest,
    GetWalletInfoResponse, ImportWalletRequest, ImportWalletResponse, ListWalletsResponse,
    OperationError, PaymasterConfig, RegisterRequest, RenameWalletRequest, SendEthRequest,
    SendEthResponse, SendTokenRequest, SendTokenResponse, ServerWelcome, SessionId, Signature,
    SpendingLimits, UnlockWalletRequest, UnlockWalletResponse, UpdatableSetting, UserOperationHash,
    UserOperationReceiptResponse, Wallet, WalletAddress, WalletSpendingLimits,
};

// Re-export enum variants
pub use wit::{
    HandshakeStep, HyperwalletRequest, HyperwalletResponse, HyperwalletResponseData, MessageType,
    Operation, OperationCategory,
};

// Additional WIT types needed by clients
pub use wit::Eip712Data;

// Implement Default for PaymasterConfig
impl Default for wit::PaymasterConfig {
    fn default() -> Self {
        Self {
            is_circle_paymaster: true,
            paymaster_address: "0x0578cFB241215b77442a541325d6A4E6dFE700Ec".to_string(),
            paymaster_verification_gas: "0x7a120".to_string(),
            paymaster_post_op_gas: "0x493e0".to_string(),
        }
    }
}

// Re-export request types
pub use wit::{
    ApproveTokenRequest, BuildAndSignUserOperationForPaymentRequest,
    BuildAndSignUserOperationRequest, BuildUserOperationRequest, CallContractRequest,
    CheckTbaOwnershipRequest, ConfigurePaymasterRequest, CreateNoteRequest, EstimateGasRequest,
    EstimateUserOperationGasRequest, ExecuteViaTbaRequest, GetTransactionHistoryRequest,
    GetTransactionReceiptRequest, GetUserOperationReceiptRequest, MintEntryRequest,
    ReadNoteRequest, ResolveIdentityRequest, SetWalletLimitsRequest, SetupDelegationRequest,
    SetupTbaDelegationRequest, SignMessageRequest, SignTransactionRequest,
    SignUserOperationRequest, SubmitUserOperationRequest, UpdateSpendingLimitsRequest,
    VerifyDelegationRequest,
};

// SetWalletLimits request/response types (wallet-level limits)
// Not available in current WIT; requires WIT update to add request/response and variants.

// Re-export response types
pub use wit::{
    BuildAndSignUserOperationResponse, CheckTbaOwnershipResponse, SetWalletLimitsResponse,
    SubmitUserOperationResponse,
};

// Type aliases for compatibility
pub type ProcessAddress = crate::Address;

// Additional types that need conversion or special handling
pub use wit::HyperwalletMessage;
pub use wit::ProcessPermissions;

/// Session information combining handshake completion with metadata
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub server_version: String,
    pub session_id: SessionId,
    pub registered_permissions: ProcessPermissions,
    pub initial_chain_id: ChainId,
}

impl SessionInfo {
    /// Returns true when the server registered this operation for the session
    pub fn supports(&self, operation: &Operation) -> bool {
        self.registered_permissions
            .allowed_operations
            .iter()
            .any(|op| op == operation)
    }

    /// Returns the list of operations the server registered for the session
    pub fn allowed_operations(&self) -> &Vec<Operation> {
        &self.registered_permissions.allowed_operations
    }
}

/// Configuration for the handshake process
#[derive(Debug)]
pub struct HandshakeConfig {
    pub(crate) required_operations: Vec<Operation>,
    pub(crate) spending_limits: Option<SpendingLimits>,
    pub(crate) client_name: Option<String>,
    pub(crate) initial_chain_id: ChainId,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            required_operations: Vec::new(),
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
        for op in operations {
            if !self.required_operations.iter().any(|o| o == op) {
                self.required_operations.push(op.clone());
            }
        }
        self
    }

    pub fn require_category(mut self, category: OperationCategory) -> Self {
        // Convert operations matching the category
        let all_ops = all_operations();
        for op in all_ops {
            if operation_category(&op) == category
                && !self.required_operations.iter().any(|o| o == &op)
            {
                self.required_operations.push(op);
            }
        }
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

/// Get all available operations
pub fn all_operations() -> Vec<Operation> {
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

/// Get the category for an operation
pub fn operation_category(op: &Operation) -> OperationCategory {
    match op {
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

        Operation::ExecuteViaTba | Operation::CheckTbaOwnership | Operation::SetupTbaDelegation => {
            OperationCategory::TokenBoundAccount
        }

        Operation::BuildAndSignUserOperationForPayment
        | Operation::SubmitUserOperation
        | Operation::BuildUserOperation
        | Operation::SignUserOperation
        | Operation::BuildAndSignUserOperation
        | Operation::EstimateUserOperationGas
        | Operation::GetUserOperationReceipt
        | Operation::ConfigurePaymaster => OperationCategory::Erc4337,

        Operation::ResolveIdentity
        | Operation::CreateNote
        | Operation::ReadNote
        | Operation::SetupDelegation
        | Operation::VerifyDelegation
        | Operation::MintEntry => OperationCategory::Hypermap,

        Operation::BatchOperations | Operation::ScheduleOperation | Operation::CancelOperation => {
            OperationCategory::Advanced
        }
    }
}

/// Get the operation type for a HyperwalletRequest
pub fn operation_type(request: &HyperwalletRequest) -> Operation {
    match request {
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
        HyperwalletRequest::BuildAndSignUserOperation(_) => Operation::BuildAndSignUserOperation,
        HyperwalletRequest::EstimateUserOperationGas(_) => Operation::EstimateUserOperationGas,
        HyperwalletRequest::ConfigurePaymaster(_) => Operation::ConfigurePaymaster,
        HyperwalletRequest::SetWalletLimits(_) => Operation::SetWalletLimits,

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

// Helper functions for HyperwalletResponse
impl wit::HyperwalletResponse {
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

// Helper functions for OperationError
impl wit::OperationError {
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

// Add operation_type method to HyperwalletMessage
impl wit::HyperwalletMessage {
    pub fn operation_type(&self) -> Operation {
        operation_type(&self.request)
    }
}

// Conversion function for ProcessPermissions
impl wit::ProcessPermissions {
    pub fn new(address: crate::Address, required_operations: Vec<Operation>) -> Self {
        Self {
            address,
            allowed_operations: required_operations,
            spending_limits: None,
            updatable_settings: vec![],
            registered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

// Legacy type that doesn't exist in WIT - kept for compatibility
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TxReceipt {
    pub hash: String,
    pub details: serde_json::Value,
}
