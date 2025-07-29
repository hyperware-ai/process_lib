//! High-level, ergonomic client for interacting with the `hyperwallet:hyperwallet:*` service.
//!
//! This module provides a type-safe and convenient way for Hyperware processes to manage
//! wallets and perform blockchain operations. The primary entry point is the `initialize`
//! function, which performs the handshake protocol.
//!
//! It contains a public `types` submodule that defines the entire protocol, which is
//! also used by the Hyperwallet server process to ensure compatibility.

use crate::{Address, Request};
use thiserror::Error;

// Re-export the most important types for convenience.
pub use types::{
    ApproveTokenRequest,
    // Response types
    Balance,
    // Business logic types
    BuildAndSignUserOperationForPaymentRequest,
    CheckTbaOwnershipRequest,
    CreateWalletRequest,
    ExecuteViaTbaRequest,
    ExportWalletRequest,
    ExportWalletResponse,
    GetTokenBalanceRequest,
    GetUserOperationReceiptRequest,
    HandshakeConfig,
    HyperwalletMessage,
    HyperwalletRequest,
    HyperwalletResponse,
    ImportWalletRequest,
    ListWalletsResponse,
    Operation,
    OperationCategory,
    OperationError,
    // Convenience types
    PaymasterConfig,
    ProcessAuth,
    ProcessPermissions,
    RenameWalletRequest,
    ResolveIdentityRequest,
    SendEthRequest,
    SendTokenRequest,
    SessionInfo,
    SpendingLimits,
    SubmitUserOperationRequest,
    TxReceipt,
    UnlockWalletRequest,
    Wallet,
};

/// The process identifier for the system's Hyperwallet service.
const HYPERWALLET_PROCESS: &str = "hyperwallet:hyperwallet:hallman.hypr";

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
/// The calling process must provide its own address (`our`).
pub fn initialize(
    our: &Address,
    config: HandshakeConfig,
) -> Result<SessionInfo, HyperwalletClientError> {
    let client_name = config
        .client_name
        .unwrap_or_else(|| our.process().to_string());

    // Step 1: Send ClientHello
    let hello_step = types::HandshakeStep::ClientHello {
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        client_name,
    };
    let hello_message = types::HyperwalletMessage::Handshake(types::HyperwalletRequest {
        business_data: hello_step,
        wallet_id: None,
        chain_id: None,
        auth: types::ProcessAuth {
            process_address: our.to_string(),
            signature: None,
        },
        request_id: None,
        timestamp: current_timestamp(),
    });
    let welcome_response: types::HyperwalletResponse<serde_json::Value> =
        send_message(hello_message, our)?;

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
    let register_message = types::HyperwalletMessage::Handshake(types::HyperwalletRequest {
        business_data: register_step,
        wallet_id: None,
        chain_id: None,
        auth: types::ProcessAuth {
            process_address: our.to_string(),
            signature: None,
        },
        request_id: None,
        timestamp: current_timestamp(),
    });
    let complete_response: types::HyperwalletResponse<serde_json::Value> =
        send_message(register_message, our)?;

    // Step 4: Parse Complete and return SessionInfo
    let complete_data = complete_response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Complete response contained no data",
        ))
    })?;

    serde_json::from_value(complete_data).map_err(HyperwalletClientError::Deserialization)
}

// === INTERNAL HELPERS ===

/// Send a typed message to the hyperwallet service
pub(crate) fn send_message<T>(
    message: types::HyperwalletMessage,
    our: &Address,
) -> Result<types::HyperwalletResponse<T>, HyperwalletClientError>
where
    T: for<'de> serde::Deserialize<'de>,
{
    // Construct the full hyperwallet address using our node
    let process_id: crate::ProcessId = ("hyperwallet", "hyperwallet", "hallman.hypr").into();
    let hyperwallet_address = crate::Address::new(our.node(), process_id);

    let response = Request::new()
        .target(hyperwallet_address)
        .body(serde_json::to_vec(&message).map_err(HyperwalletClientError::Serialization)?)
        .send_and_await_response(5) // 5s timeout
        .map_err(|e| HyperwalletClientError::Communication(e.into()))?
        .map_err(|e| HyperwalletClientError::Communication(e.into()))?;

    let hyperwallet_response: types::HyperwalletResponse<T> =
        serde_json::from_slice(response.body()).map_err(HyperwalletClientError::Deserialization)?;

    if !hyperwallet_response.success {
        return Err(HyperwalletClientError::ServerError(
            hyperwallet_response.error.unwrap_or_else(|| {
                types::OperationError::internal_error("Operation failed with no error details")
            }),
        ));
    }

    Ok(hyperwallet_response)
}

/// Get current timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Contains all the shared types for the Hyperwallet protocol.
pub mod types;

/// High-level API functions
pub mod api;
