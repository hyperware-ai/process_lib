//! High-level, ergonomic client for interacting with the `hyperwallet:hyperwallet:*` service.
//!
//! This module provides a type-safe and convenient way for Hyperware processes to manage
//! wallets and perform blockchain operations by communicating with the system's central
//! Hyperwallet service. The primary entry point is the `initialize` function, which
//! performs the handshake protocol to establish a session.
//! The main use of sessions is to tie it with wallets' "unlocked" state. Currently, I don't really
//! use it, but it might be an easier handle than the process string.
//!
//! It contains a public `types` submodule that defines the entire protocol, which is
//! also used by the Hyperwallet server process to ensure compatibility.

use crate::{Address, Request};
use serde::de::DeserializeOwned;
use thiserror::Error;

// Re-export the most important types for convenience for developers using this client.
pub use types::{
    HandshakeConfig, Operation, OperationCategory, OperationError, ProcessPermissions, SessionInfo,
    SpendingLimits,
};

/// The static address of the system's Hyperwallet service. (TODO: change when system package)
const HYPERWALLET_ADDRESS: &str = "hyperwallet:hyperwallet:sys";

/// Errors that can occur when interacting with the Hyperwallet client.
#[derive(Debug, Error)]
pub enum HyperwalletClientError {
    #[error("Handshake Error: Version incompatibility - client {client} vs server {server}")]
    VersionMismatch { client: String, server: String },
    #[error("Handshake Error: Required operation is not supported by the server: {operation:?}")]
    OperationNotSupported { operation: Operation },
    #[error("Communication error while sending request to Hyperwallet: {0}")]
    Communication(anyhow::Error),
    #[error("Hyperwallet service returned a failure response: {0:?}")]
    ServerError(OperationError),
    #[error("Failed to serialize request: {0}")]
    Serialization(serde_json::Error),
    #[error("Failed to deserialize response: {0}")]
    Deserialization(serde_json::Error),
}

/// Performs the full handshake and registration protocol with the Hyperwallet service.
/// This is the primary entry point for any process wanting to use Hyperwallet.
///
/// On success, it returns a `SessionInfo` containing the session ID required for
/// all subsequent calls.
pub fn initialize(config: HandshakeConfig) -> Result<SessionInfo, HyperwalletClientError> {
    let our_address = crate::our();
    let client_name = config
        .client_name
        .unwrap_or_else(|| our_address.process().to_string());

    // Step 1: Send ClientHello
    let hello_step = types::HandshakeStep::ClientHello {
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        client_name,
    };
    let welcome_response: types::OperationResponse = send_handshake_step(hello_step, &our_address)?;

    // Step 2: Parse ServerWelcome and check compatibility
    let welcome_data = welcome_response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "ServerWelcome response contained no data",
        ))
    })?;

    let supported_ops: Vec<Operation> =
        serde_json::from_value(welcome_data["supported_operations"].clone())
            .map_err(HyperwalletClientError::Deserialization)?;

    for op in &config.required_operations {
        if !supported_ops.contains(op) {
            return Err(HyperwalletClientError::OperationNotSupported {
                operation: op.clone(),
            });
        }
    }

    // Step 3: Send Register
    let register_step = types::HandshakeStep::Register {
        required_operations: config.required_operations.into_iter().collect(),
        spending_limits: config.spending_limits,
    };
    let complete_response = send_handshake_step(register_step, &our_address)?;

    // Step 4: Parse Complete and return SessionInfo
    let complete_data = complete_response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Complete response contained no data",
        ))
    })?;

    serde_json::from_value(complete_data).map_err(HyperwalletClientError::Deserialization)
}

/// Generic helper to create and send an `OperationRequest` to Hyperwallet.
/// yeah, not really necessary
fn send_request<T: DeserializeOwned>(
    _session_info: &SessionInfo,
    operation: Operation,
    params: serde_json::Value,
    wallet_id: Option<String>,
    chain_id: Option<u64>,
) -> Result<T, HyperwalletClientError> {
    let request = types::OperationRequest {
        operation,
        params,
        wallet_id,
        chain_id,
        // The session_id would be included here in the auth struct if needed
        auth: types::ProcessAuth {
            process_address: crate::our().to_string(),
            signature: None,
        },
        request_id: None,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let response: types::OperationResponse = execute_request(request)?;
    match response.data {
        Some(data) => serde_json::from_value(data).map_err(HyperwalletClientError::Deserialization),
        None => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Operation succeeded but returned no data"),
        )),
    }
}

// Internal helper for the handshake steps which don't have a session yet.
fn send_handshake_step(
    step: types::HandshakeStep,
    our_address: &Address,
) -> Result<types::OperationResponse, HyperwalletClientError> {
    let request = types::OperationRequest {
        operation: Operation::Handshake,
        params: serde_json::to_value(step).map_err(HyperwalletClientError::Serialization)?,
        auth: types::ProcessAuth {
            process_address: our_address.to_string(),
            signature: None,
        },
        wallet_id: None,
        chain_id: None,
        request_id: None,
        timestamp: 0,
    };
    execute_request(request)
}

// The lowest-level helper that handles sending the request and awaiting a response.
fn execute_request(
    request: types::OperationRequest,
) -> Result<types::OperationResponse, HyperwalletClientError> {
    let response = Request::new()
        .target(HYPERWALLET_ADDRESS.parse::<Address>().unwrap())
        .body(serde_json::to_vec(&request).map_err(HyperwalletClientError::Serialization)?)
        .send_and_await_response(5) // 5s timeout
        .map_err(|e| HyperwalletClientError::Communication(e.into()))?
        .map_err(|e| HyperwalletClientError::Communication(e.into()))?;

    let op_response: types::OperationResponse =
        serde_json::from_slice(response.body()).map_err(HyperwalletClientError::Deserialization)?;

    if !op_response.success {
        return Err(HyperwalletClientError::ServerError(
            op_response.error.unwrap_or_else(|| {
                types::OperationError::internal_error("Operation failed with no error details")
            }),
        ));
    }

    Ok(op_response)
}

/// Contains all the shared types for the Hyperwallet protocol.
pub mod types {
    use serde::{Deserialize, Serialize};
    use std::collections::HashSet;

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
            // In a real implementation, this would list all variants
            vec![]
        }
        pub fn category(&self) -> OperationCategory {
            match self {
                Operation::Handshake | Operation::UnlockWallet => OperationCategory::System,
                // ... other categories ...
                _ => OperationCategory::Query,
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
        pub session_id: String,
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

    // All other request/response and permission structs

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
        pub process_address: String,
        pub allowed_operations: HashSet<Operation>,
        pub spending_limits: Option<SpendingLimits>,
        pub updatable_settings: Vec<UpdatableSetting>,
        pub registered_at: u64,
    }
}
