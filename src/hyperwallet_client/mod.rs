//! High-level, ergonomic client for interacting with the `hyperwallet:hyperwallet:*` service.
//!
//! This module provides a type-safe and convenient way for Hyperware processes to manage
//! wallets and perform blockchain operations. The primary entry point is the `initialize`
//! function, which performs the handshake protocol.
//!
//! ## Type-Safe Architecture
//!
//! The library uses `HyperwalletResponseData` enum instead of `serde_json::Value` for responses,
//! providing full type safety throughout the system:
//!
//! - **Individual Functions**: Return specific types like `HyperwalletResponse<CreateWalletResponse>`
//! - **Message Dispatcher**: Returns `HyperwalletResponse<HyperwalletResponseData>` with enum variants
//! - **Benefits**: Compile-time type checking, better IDE support, no information loss
//!
//! ## Example Usage
//!
//! ```rust
//! use hyperware_process_lib::hyperwallet_client::{self, HandshakeConfig, OperationCategory};
//!
//! // Initialize hyperwallet connection using category-based permissions
//! let config = HandshakeConfig::new()
//!     .require_category(OperationCategory::WalletManagement)
//!     .require_category(OperationCategory::ERC4337)
//!     .with_initial_chain(8453); // Set default chain to Base mainnet
//!
//! let session = hyperwallet_client::initialize(config)?;
//!
//! // Create a wallet (clean direct access)
//! let wallet = hyperwallet_client::create_wallet(
//!     &session.session_id,
//!     "MyWallet",
//!     Some("password123")
//! )?;
//!
//! // Send ETH (no more ::api:: indirection!)
//! let receipt = hyperwallet_client::send_eth(
//!     &session.session_id,
//!     &wallet.address,
//!     "0x0000000000000000000000000000000000000000",
//!     "1.5"
//! )?;
//!
//! // Execute gasless payments directly
//! let tx_hash = hyperwallet_client::execute_gasless_payment(
//!     &session.session_id,
//!     "signer_wallet",
//!     "0x742d35...", // TBA address
//!     "0x456789...", // recipient  
//!     1_000_000     // 1 USDC
//! )?;
//! ```

use crate::Request;
use thiserror::Error;

// Export the types module for advanced usage
pub mod types;

// Export the clean API functions
pub mod api;

// Re-export the most commonly used types for convenience
pub use types::{
    Balance, BuildAndSignUserOperationForPaymentRequest, BuildAndSignUserOperationResponse,
    ChainId, CheckTbaOwnershipResponse, CreateNoteResponse, CreateWalletRequest,
    CreateWalletResponse, DeleteWalletRequest, DeleteWalletResponse, ErrorCode,
    ExecuteViaTbaResponse, ExportWalletRequest, ExportWalletResponse, GetBalanceRequest,
    GetBalanceResponse, GetTokenBalanceRequest, GetTokenBalanceResponse, GetWalletInfoRequest,
    GetWalletInfoResponse, HandshakeConfig, HandshakeRequest, HandshakeResponseData, HandshakeStep,
    HyperwalletMessage, HyperwalletRequest, HyperwalletResponse, HyperwalletResponseData,
    ImportWalletRequest, ImportWalletResponse, ListWalletsResponse, Operation, OperationCategory,
    OperationError, PaymasterConfig, ProcessAddress, ProcessPermissions, SendEthRequest,
    SendEthResponse, SendTokenRequest, SendTokenResponse, SessionId, SessionInfo, SpendingLimits,
    SubmitUserOperationResponse, TxReceipt, UnlockWalletResponse, UpdatableSetting,
    UserOperationHash, UserOperationReceiptResponse, WalletAddress,
};

// Re-export all API functions for direct access
pub use api::{
    build_and_sign_user_operation_for_payment, create_tba_payment_calldata, create_wallet,
    delete_wallet, execute_gasless_payment, export_wallet, get_balance, get_token_balance,
    get_user_operation_receipt, get_wallet_info, import_wallet, list_wallets, send_eth, send_token,
    submit_user_operation, unlock_wallet,
};

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
pub fn initialize(config: HandshakeConfig) -> Result<SessionInfo, HyperwalletClientError> {
    let our = crate::our();
    let client_name = config
        .client_name
        .unwrap_or_else(|| our.process().to_string());

    // Step 1: Send ClientHello
    let hello_step = types::HandshakeStep::ClientHello {
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        client_name,
    };
    let hello_message = types::HyperwalletMessage::Handshake(types::HandshakeRequest {
        operation: hello_step,
    });

    // Step 2: Receive ServerWelcome with type safety
    let welcome_response: types::HyperwalletResponse<types::HandshakeStep> =
        send_message(hello_message)?;

    let welcome_step = welcome_response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing handshake step in ServerWelcome response",
        ))
    })?;

    let supported_operations = match welcome_step {
        types::HandshakeStep::ServerWelcome {
            supported_operations,
            ..
        } => supported_operations,
        _ => {
            return Err(HyperwalletClientError::ServerError(
                types::OperationError::internal_error(
                    "Expected ServerWelcome handshake step, got different step",
                ),
            ))
        }
    };

    // Step 3: Validate required operations
    for required_op in &config.required_operations {
        if !supported_operations.contains(required_op) {
            return Err(HyperwalletClientError::ServerError(types::OperationError {
                code: types::ErrorCode::PermissionDenied,
                message: format!(
                    "Required operation {:?} not supported by server",
                    required_op
                ),
                details: None,
            }));
        }
    }

    // Step 4: Send Register
    let register_step = types::HandshakeStep::Register {
        required_operations: config.required_operations.into_iter().collect(),
        spending_limits: config.spending_limits,
    };

    let register_message = types::HyperwalletMessage::Handshake(types::HandshakeRequest {
        operation: register_step,
    });

    // Step 5: Receive Complete with type safety
    let complete_response: types::HyperwalletResponse<types::HandshakeStep> =
        send_message(register_message)?;

    let complete_step = complete_response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Complete response contained no data",
        ))
    })?;

    // Extract SessionInfo using pattern matching
    match complete_step {
        types::HandshakeStep::Complete {
            registered_permissions,
            session_id,
        } => Ok(SessionInfo {
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            session_id,
            registered_permissions,
            initial_chain_id: config.initial_chain_id,
        }),
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error(
                "Expected Complete handshake step, received different step",
            ),
        )),
    }
}

// === INTERNAL HELPERS ===

/// Send a typed message to the hyperwallet service
pub(crate) fn send_message<T>(
    message: types::HyperwalletMessage,
) -> Result<types::HyperwalletResponse<T>, HyperwalletClientError>
where
    T: for<'de> serde::Deserialize<'de>,
{
    // Use local address pattern like HTTP client - hyperwallet is always local
    let response = Request::to(("our", "hyperwallet", "hyperwallet", "hallman.hypr"))
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

/// Get current timestamp for message construction.
pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
