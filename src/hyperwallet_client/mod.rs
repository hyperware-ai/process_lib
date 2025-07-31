use crate::Request;
use thiserror::Error;

pub mod api;
pub mod types;
pub use types::{
    Balance, BuildAndSignUserOperationForPaymentRequest, BuildAndSignUserOperationResponse,
    ChainId, CheckTbaOwnershipResponse, CreateNoteResponse, CreateWalletRequest,
    CreateWalletResponse, DeleteWalletRequest, DeleteWalletResponse, ErrorCode,
    ExecuteViaTbaResponse, ExportWalletRequest, ExportWalletResponse, GetBalanceRequest,
    GetBalanceResponse, GetTokenBalanceRequest, GetTokenBalanceResponse, GetWalletInfoRequest,
    GetWalletInfoResponse, HandshakeConfig, HandshakeRequest, HandshakeStep, HyperwalletMessage,
    HyperwalletRequest, HyperwalletResponse, HyperwalletResponseData, ImportWalletRequest,
    ImportWalletResponse, ListWalletsResponse, Operation, OperationCategory, OperationError,
    PaymasterConfig, ProcessAddress, ProcessPermissions, RenameWalletRequest, SendEthRequest,
    SendEthResponse, SendTokenRequest, SendTokenResponse, SessionId, SessionInfo, SpendingLimits,
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

    let hello_step = types::HandshakeStep::ClientHello {
        client_version: "0.1.0".to_string(),
        client_name,
    };
    let hello_message =
        types::HyperwalletMessage::Handshake(types::HandshakeRequest { step: hello_step });

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

    let register_step = types::HandshakeStep::Register {
        required_operations: config.required_operations.into_iter().collect(),
        spending_limits: config.spending_limits,
    };

    let register_message = types::HyperwalletMessage::Handshake(types::HandshakeRequest {
        step: register_step,
    });

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
        } => {
            Ok(SessionInfo {
                server_version: "0.1.0".to_string(), //lol, server should send it's version
                session_id,
                registered_permissions,
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

pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
