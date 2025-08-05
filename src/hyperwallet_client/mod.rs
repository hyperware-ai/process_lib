use crate::Request;
use thiserror::Error;

pub mod api;
pub mod serde_impls;
mod serde_request_response_impls;
mod serde_variant_impls;
pub mod types;
pub use types::{
    Balance, BuildAndSignUserOperationForPaymentRequest, BuildAndSignUserOperationResponse,
    ChainId, CheckTbaOwnershipResponse, CreateNoteResponse, CreateWalletRequest,
    CreateWalletResponse, DeleteWalletRequest, DeleteWalletResponse, ErrorCode,
    ExecuteViaTbaResponse, ExportWalletRequest, ExportWalletResponse, GetBalanceRequest,
    GetBalanceResponse, GetTokenBalanceRequest, GetTokenBalanceResponse, GetWalletInfoRequest,
    GetWalletInfoResponse, HandshakeConfig, HandshakeStep, HyperwalletMessage, HyperwalletRequest,
    HyperwalletResponse, HyperwalletResponseData, ImportWalletRequest, ImportWalletResponse,
    ListWalletsResponse, Operation, OperationCategory, OperationError, PaymasterConfig,
    ProcessAddress, ProcessPermissions, RenameWalletRequest, SendEthRequest, SendEthResponse,
    SendTokenRequest, SendTokenResponse, SessionId, SessionInfo, SpendingLimits,
    SubmitUserOperationResponse, TxReceipt, UnlockWalletResponse, UpdatableSetting,
    UserOperationHash, UserOperationReceiptResponse, WalletAddress,
};

pub use api::{
    build_and_sign_user_operation_for_payment, create_tba_payment_calldata, create_wallet,
    delete_wallet, execute_gasless_payment, export_wallet, get_balance, get_token_balance,
    get_user_operation_receipt, get_wallet_info, import_wallet, list_wallets, rename_wallet,
    send_eth, send_token, submit_user_operation, unlock_wallet,
};

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
    let client_name = config.client_name.expect("Client name is required");

    let hello_step = types::HandshakeStep::ClientHello(types::ClientHello {
        client_version: "0.1.0".to_string(),
        client_name,
    });
    let hello_message = types::HyperwalletMessage {
        request: types::HyperwalletRequest::Handshake(hello_step),
        session_id: String::new(),
    };

    let welcome_response = send_message(hello_message)?;

    let welcome_step = match welcome_response.data {
        Some(types::HyperwalletResponseData::Handshake(step)) => step,
        _ => {
            return Err(HyperwalletClientError::ServerError(
                types::OperationError::internal_error(
                    "Missing or invalid handshake step in ServerWelcome response",
                ),
            ))
        }
    };

    let supported_operations = match welcome_step {
        types::HandshakeStep::ServerWelcome(server_welcome) => server_welcome.supported_operations,
        _ => {
            return Err(HyperwalletClientError::ServerError(
                types::OperationError::internal_error(
                    "Expected ServerWelcome handshake step, got different step",
                ),
            ))
        }
    };

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

    let register_step = types::HandshakeStep::Register(types::RegisterRequest {
        required_operations: config.required_operations.into_iter().collect(),
        spending_limits: config.spending_limits,
    });

    let register_message = types::HyperwalletMessage {
        request: types::HyperwalletRequest::Handshake(register_step),
        session_id: String::new(),
    };

    let complete_response = send_message(register_message)?;

    let complete_step = match complete_response.data {
        Some(types::HyperwalletResponseData::Handshake(step)) => step,
        _ => {
            return Err(HyperwalletClientError::ServerError(
                types::OperationError::internal_error(
                    "Complete response contained no data or invalid data type",
                ),
            ))
        }
    };

    // Extract SessionInfo using pattern matching
    match complete_step {
        types::HandshakeStep::Complete(complete_handshake) => {
            Ok(types::SessionInfo {
                server_version: "0.1.0".to_string(), //lol, server should send it's version
                session_id: complete_handshake.session_id,
                registered_permissions: complete_handshake.registered_permissions,
                initial_chain_id: config.initial_chain_id,
            })
        }
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error(
                "Expected Complete handshake step, received different step",
            ),
        )),
    }
}

// === INTERNAL HELPERS ===

pub(crate) fn send_message(
    message: types::HyperwalletMessage,
) -> Result<types::HyperwalletResponse, HyperwalletClientError> {
    // Use local address pattern like HTTP client - hyperwallet is always local
    let response = Request::to(("our", "hyperwallet", "hyperwallet", "hallman.hypr"))
        .body(serde_json::to_vec(&message).map_err(HyperwalletClientError::Serialization)?)
        .send_and_await_response(5) // 5s timeout
        .map_err(|e| HyperwalletClientError::Communication(e.into()))?
        .map_err(|e| HyperwalletClientError::Communication(e.into()))?;

    let hyperwallet_response: types::HyperwalletResponse =
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

pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
