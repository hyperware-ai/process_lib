//! High-level, ergonomic client for interacting with the `hyperwallet:hyperwallet:*` service.
//!
//! This module provides a type-safe and convenient way for Hyperware processes to manage
//! wallets and perform blockchain operations. The primary entry point is the `initialize`
//! function, which performs the handshake protocol.
//!
//! It contains a public `types` submodule that defines the entire protocol, which is
//! also used by the Hyperwallet server process to ensure compatibility.

pub mod api;
pub mod types;

pub use api::{
    // Wallet Management
    create_wallet,
    import_wallet,
    unlock_wallet,
    delete_wallet,
    rename_wallet,
    set_wallet_limits,
    list_wallets,
    get_wallet_info,
    
    // Balance and Token Operations
    get_balance,
    get_token_balance,
    approve_token,
    send_eth,
    send_token,
    
    // TBA (Token Bound Account) Operations
    check_tba_ownership,
    execute_via_tba,
    create_tba_payment_calldata,
    create_usdc_payment_calldata,
    
    // User Operation Building and Submission
    build_and_sign_user_operation,
    build_and_sign_user_operation_for_payment,
    submit_user_operation,
    get_user_operation_receipt,
    
    // Gasless Payment Operations
    build_and_sign_gasless_payment,
    submit_gasless_payment,
    get_payment_receipt,
    execute_gasless_payment,
    execute_complete_gasless_payment,
    validate_gasless_payment_setup,
    extract_payment_tx_hash,
    
    // Miscellaneous
    create_note,
    resolve_identity,
};
pub use types::{
    // Request Types
    ApproveTokenRequest,
    CheckTbaOwnershipRequest,
    CreateWalletRequest,
    ExecuteViaTbaRequest,
    GetTokenBalanceRequest,
    GetUserOperationReceiptRequest,
    ImportWalletRequest,
    RenameWalletRequest,
    ResolveIdentityRequest,
    SendEthRequest,
    SendTokenRequest,
    SubmitUserOperationRequest,
    UnlockWalletRequest,
    
    // Response Types
    BuildAndSignUserOperationResponse,
    SubmitUserOperationResponse,
    TxReceipt,
    
    // Configuration and Data Types
    Balance,
    BuildAndSignUserOperationForPaymentRequest,
    HandshakeConfig,
    PaymasterConfig,
    ProcessPermissions,
    SessionInfo,
    SpendingLimits,
    UserOperationHash,
    Wallet,
    
    // Operation and Error Types
    Operation,
    OperationCategory,
    OperationError,
};

use crate::{Address, Request};
use thiserror::Error;

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
pub fn initialize(
    our: &Address,
    config: HandshakeConfig,
) -> Result<SessionInfo, HyperwalletClientError> {
    let client_name = config
        .client_name
        .unwrap_or_else(|| our.process().to_string());

    let hello_step = types::HandshakeStep::ClientHello {
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        client_name,
    };
    let welcome_response: types::OperationResponse = send_handshake_step(hello_step, our)?;

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

    let register_step = types::HandshakeStep::Register {
        required_operations: config.required_operations.into_iter().collect(),
        spending_limits: config.spending_limits,
    };
    let complete_response = send_handshake_step(register_step, our)?;

    let complete_data = complete_response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Complete response contained no data",
        ))
    })?;

    // Extract session info from the Complete response
    let session_id = complete_data["session_id"]
        .as_str()
        .ok_or_else(|| {
            HyperwalletClientError::ServerError(types::OperationError::internal_error(
                "Missing session_id in Complete response",
            ))
        })?
        .to_string();

    let registered_permissions: ProcessPermissions =
        serde_json::from_value(complete_data["registered_permissions"].clone())
            .map_err(HyperwalletClientError::Deserialization)?;

    // Get server version from the earlier welcome response
    let server_version = welcome_data["server_version"]
        .as_str()
        .ok_or_else(|| {
            HyperwalletClientError::ServerError(types::OperationError::internal_error(
                "Missing server_version in ServerWelcome response",
            ))
        })?
        .to_string();

    Ok(SessionInfo {
        server_version,
        session_id,
        registered_permissions,
    })
}

// Internal helper for the handshake steps.
fn send_handshake_step(
    step: types::HandshakeStep,
    our: &Address,
) -> Result<types::OperationResponse, HyperwalletClientError> {
    let request = types::OperationRequest {
        operation: Operation::Handshake,
        params: serde_json::to_value(step).map_err(HyperwalletClientError::Serialization)?,
        auth: types::ProcessAuth {
            process_address: our.to_string(),
            signature: None,
        },
        wallet_id: None,
        chain_id: None,
        request_id: None,
        timestamp: 0,
    };
    execute_request(request, our)
}

// The lowest-level helper that handles sending all requests.
pub(crate) fn execute_request(
    request: types::OperationRequest,
    our: &Address,
) -> Result<types::OperationResponse, HyperwalletClientError> {
    // Construct the full hyperwallet address using our node
    let process_id: crate::ProcessId = ("hyperwallet", "hyperwallet", "hallman.hypr").into();
    let hyperwallet_address = Address::new(our.node(), process_id);

    let response = Request::new()
        .target(hyperwallet_address)
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
