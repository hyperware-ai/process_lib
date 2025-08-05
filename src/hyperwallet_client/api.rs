use super::types::{
    self, Balance, BuildAndSignUserOperationForPaymentRequest, BuildAndSignUserOperationResponse,
    CreateWalletRequest, ExportWalletResponse, GetTokenBalanceResponse, HyperwalletMessage,
    HyperwalletRequest, ImportWalletRequest, ListWalletsResponse, PaymasterConfig,
    RenameWalletRequest, SendEthRequest, SendTokenRequest, SessionId, TxReceipt,
    UnlockWalletRequest, UserOperationReceiptResponse, Wallet,
};
use super::HyperwalletClientError;
use crate::wallet;
use alloy_primitives::{Address as EthAddress, U256};

pub fn create_wallet(
    session_id: &SessionId,
    name: Option<&str>,
    password: Option<&str>,
) -> Result<Wallet, HyperwalletClientError> {
    let message = build_message(
        session_id,
        HyperwalletRequest::CreateWallet(CreateWalletRequest {
            name: name.map(|s| s.to_string()).unwrap_or_default(),
            password: password.map(|s| s.to_string()),
        }),
    );

    let response = super::send_message(message)?;
    match response.data {
        Some(types::HyperwalletResponseData::CreateWallet(wallet_response)) => {
            Ok(types::Wallet {
                address: wallet_response.address,
                name: Some(wallet_response.name),
                chain_id: 8453, // Base mainnet - TODO: get from response
                encrypted: password.is_some(),
                created_at: None,
                last_used: None,
                spending_limits: None,
            })
        }
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Missing or invalid wallet data in response"),
        )),
    }
}

pub fn import_wallet(
    session_id: &SessionId,
    name: &str,
    private_key: &str,
    password: Option<&str>,
) -> Result<Wallet, HyperwalletClientError> {
    let message = build_message(
        session_id,
        HyperwalletRequest::ImportWallet(ImportWalletRequest {
            name: name.to_string(),
            private_key: private_key.to_string(),
            password: password.map(|s| s.to_string()),
        }),
    );

    let response = super::send_message(message)?;
    match response.data {
        Some(types::HyperwalletResponseData::ImportWallet(wallet_response)) => {
            Ok(types::Wallet {
                address: wallet_response.address,
                name: Some(wallet_response.name),
                chain_id: 8453, // Base mainnet - TODO: get from response
                encrypted: password.is_some(),
                created_at: None,
                last_used: None,
                spending_limits: None,
            })
        }
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Missing or invalid wallet data in response"),
        )),
    }
}

pub fn unlock_wallet(
    session_id: &SessionId,
    target_session_id: &str,
    wallet_id: &str,
    password: &str,
) -> Result<(), HyperwalletClientError> {
    let message = build_message(
        session_id,
        HyperwalletRequest::UnlockWallet(UnlockWalletRequest {
            session_id: target_session_id.to_string(),
            wallet_id: wallet_id.to_string(),
            password: password.to_string(),
        }),
    );

    let response = super::send_message(message)?;
    match response.data {
        Some(types::HyperwalletResponseData::UnlockWallet(_)) => Ok(()),
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Failed to unlock wallet"),
        )),
    }
}

pub fn list_wallets(session_id: &SessionId) -> Result<ListWalletsResponse, HyperwalletClientError> {
    let message = build_message(session_id, HyperwalletRequest::ListWallets);

    let response = super::send_message(message)?;
    match response.data {
        Some(types::HyperwalletResponseData::ListWallets(list_response)) => Ok(list_response),
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Missing or invalid wallet list in response"),
        )),
    }
}

pub fn get_wallet_info(
    session_id: &SessionId,
    wallet_id: &str,
) -> Result<Wallet, HyperwalletClientError> {
    let message = build_message(
        session_id,
        HyperwalletRequest::GetWalletInfo(types::GetWalletInfoRequest {
            wallet_id: wallet_id.to_string(),
        }),
    );

    let response = super::send_message(message)?;
    match response.data {
        Some(types::HyperwalletResponseData::GetWalletInfo(info_response)) => Ok(types::Wallet {
            address: info_response.address,
            name: Some(info_response.name),
            chain_id: info_response.chain_id,
            encrypted: info_response.is_locked,
            created_at: None,
            last_used: None,
            spending_limits: None,
        }),
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Missing or invalid wallet data in response"),
        )),
    }
}

pub fn delete_wallet(
    session_id: &SessionId,
    wallet_id: &str,
) -> Result<(), HyperwalletClientError> {
    let message = build_message(
        session_id,
        HyperwalletRequest::DeleteWallet(types::DeleteWalletRequest {
            wallet_id: wallet_id.to_string(),
        }),
    );

    let response = super::send_message(message)?;
    match response.data {
        Some(types::HyperwalletResponseData::DeleteWallet(_)) => Ok(()),
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Failed to delete wallet"),
        )),
    }
}

pub fn export_wallet(
    session_id: &SessionId,
    wallet_id: &str,
    password: Option<&str>,
) -> Result<ExportWalletResponse, HyperwalletClientError> {
    let message = build_message(
        session_id,
        HyperwalletRequest::ExportWallet(types::ExportWalletRequest {
            wallet_id: wallet_id.to_string(),
            password: password.map(|s| s.to_string()),
        }),
    );

    let response = super::send_message(message)?;
    match response.data {
        Some(types::HyperwalletResponseData::ExportWallet(export_response)) => Ok(export_response),
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Missing export data in response"),
        )),
    }
}

pub fn rename_wallet(
    session_id: &SessionId,
    wallet_id: &str,
    new_name: &str,
) -> Result<(), HyperwalletClientError> {
    let message = build_message(
        session_id,
        HyperwalletRequest::RenameWallet(RenameWalletRequest {
            wallet_id: wallet_id.to_string(),
            new_name: new_name.to_string(),
        }),
    );
    let response = super::send_message(message)?;
    // RenameWallet doesn't have a response variant in the enum, so we just check for success
    if response.error.is_none() {
        Ok(())
    } else {
        Err(HyperwalletClientError::ServerError(
            response.error.unwrap_or_else(|| {
                types::OperationError::internal_error("Failed to rename wallet")
            }),
        ))
    }
}

// === TRANSACTIONS ===

pub fn send_eth(
    session_id: &SessionId,
    wallet_id: &str,
    to_address: &str,
    amount_eth: &str,
) -> Result<TxReceipt, HyperwalletClientError> {
    let message = build_message(
        session_id,
        HyperwalletRequest::SendEth(SendEthRequest {
            wallet_id: wallet_id.to_string(),
            to: to_address.to_string(),
            amount: amount_eth.to_string(),
        }),
    );

    let response = super::send_message(message)?;
    match response.data {
        Some(types::HyperwalletResponseData::SendEth(send_response)) => Ok(TxReceipt {
            hash: send_response.tx_hash,
            details: serde_json::json!({
                "from": send_response.from_address,
                "to": send_response.to_address,
                "amount": send_response.amount,
                "chain_id": send_response.chain_id,
            }),
        }),
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Missing transaction receipt in response"),
        )),
    }
}

pub fn send_token(
    session_id: &SessionId,
    wallet_id: &str,
    token_address: &str,
    to_address: &str,
    amount: &str,
) -> Result<TxReceipt, HyperwalletClientError> {
    let message = build_message(
        session_id,
        HyperwalletRequest::SendToken(SendTokenRequest {
            wallet_id: wallet_id.to_string(),
            token_address: token_address.to_string(),
            to: to_address.to_string(),
            amount: amount.to_string(),
        }),
    );

    let response = super::send_message(message)?;
    match response.data {
        Some(types::HyperwalletResponseData::SendToken(send_response)) => Ok(TxReceipt {
            hash: send_response.tx_hash,
            details: serde_json::json!({
                "from": send_response.from_address,
                "to": send_response.to_address,
                "token_address": send_response.token_address,
                "amount": send_response.amount,
                "chain_id": send_response.chain_id,
            }),
        }),
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Missing transaction receipt in response"),
        )),
    }
}

// === QUERIES ===

pub fn get_balance(
    session_id: &SessionId,
    wallet_id: &str,
) -> Result<Balance, HyperwalletClientError> {
    let message = build_message(
        session_id,
        HyperwalletRequest::GetBalance(types::GetBalanceRequest {
            wallet_id: wallet_id.to_string(),
        }),
    );

    let response = super::send_message(message)?;
    match response.data {
        Some(types::HyperwalletResponseData::GetBalance(balance_response)) => {
            Ok(balance_response.balance)
        }
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Missing balance data in response"),
        )),
    }
}

pub fn get_token_balance(
    session_id: &SessionId,
    wallet_id: &str,
    token_address: &str,
) -> Result<GetTokenBalanceResponse, HyperwalletClientError> {
    let message = build_message(
        session_id,
        HyperwalletRequest::GetTokenBalance(types::GetTokenBalanceRequest {
            wallet_id: wallet_id.to_string(),
            token_address: token_address.to_string(),
        }),
    );

    let response = super::send_message(message)?;
    match response.data {
        Some(types::HyperwalletResponseData::GetTokenBalance(balance_response)) => {
            Ok(balance_response)
        }
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Missing token balance data in response"),
        )),
    }
}

// === ACCOUNT ABSTRACTION ===

pub fn build_and_sign_user_operation_for_payment(
    session_id: &SessionId,
    eoa_wallet_id: &str,
    tba_address: &str,
    target: &str,
    call_data: &str,
    use_paymaster: bool,
    paymaster_config: Option<PaymasterConfig>,
    password: Option<&str>,
) -> Result<BuildAndSignUserOperationResponse, HyperwalletClientError> {
    let message = build_message(
        session_id,
        HyperwalletRequest::BuildAndSignUserOperationForPayment(
            BuildAndSignUserOperationForPaymentRequest {
                eoa_wallet_id: eoa_wallet_id.to_string(),
                tba_address: tba_address.to_string(),
                target: target.to_string(),
                call_data: call_data.to_string(),
                use_paymaster,
                paymaster_config,
                password: password.map(|s| s.to_string()),
            },
        ),
    );

    let response = super::send_message(message)?;
    match response.data {
        Some(types::HyperwalletResponseData::BuildAndSignUserOperationForPayment(
            build_response,
        )) => Ok(build_response),
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Missing UserOperation build response data"),
        )),
    }
}

pub fn submit_user_operation(
    session_id: &SessionId,
    signed_user_operation: serde_json::Value,
    entry_point: &str,
    bundler_url: Option<&str>,
) -> Result<String, HyperwalletClientError> {
    let message = build_message(
        session_id,
        HyperwalletRequest::SubmitUserOperation(types::SubmitUserOperationRequest {
            signed_user_operation: serde_json::to_string(&signed_user_operation)
                .map_err(HyperwalletClientError::Serialization)?,
            entry_point: entry_point.to_string(),
            bundler_url: bundler_url.map(|s| s.to_string()),
        }),
    );

    let response = super::send_message(message)?;
    match response.data {
        Some(types::HyperwalletResponseData::SubmitUserOperation(submit_response)) => {
            Ok(submit_response.user_op_hash)
        }
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Missing UserOperation response data"),
        )),
    }
}

pub fn get_user_operation_receipt(
    session_id: &SessionId,
    user_op_hash: &str,
) -> Result<UserOperationReceiptResponse, HyperwalletClientError> {
    let message = build_message(
        session_id,
        HyperwalletRequest::GetUserOperationReceipt(types::GetUserOperationReceiptRequest {
            user_op_hash: user_op_hash.to_string(),
        }),
    );

    let response = super::send_message(message)?;
    match response.data {
        Some(types::HyperwalletResponseData::GetUserOperationReceipt(receipt_response)) => {
            Ok(receipt_response)
        }
        _ => Err(HyperwalletClientError::ServerError(
            types::OperationError::internal_error("Missing UserOperation receipt data in response"),
        )),
    }
}

// === CONVENIENCE FUNCTIONS ===

pub fn execute_gasless_payment(
    session_id: &SessionId,
    signer_wallet_id: &str,
    tba_address: &str,
    recipient_address: &str,
    amount_usdc: u128,
) -> Result<String, HyperwalletClientError> {
    let usdc_contract = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"; // Base USDC

    let tba_calldata = create_tba_payment_calldata(usdc_contract, recipient_address, amount_usdc)?;

    let build_response = build_and_sign_user_operation_for_payment(
        session_id,
        signer_wallet_id,
        tba_address,
        tba_address,
        &tba_calldata,
        true,
        Default::default(),
        None, // password
    )?;

    let user_op_hash = submit_user_operation(
        session_id,
        serde_json::from_str(&build_response.signed_user_operation)
            .map_err(HyperwalletClientError::Deserialization)?,
        &build_response.entry_point,
        None, // bundler_url
    )?;

    let receipt_response =
        get_user_operation_receipt(session_id, &user_op_hash).unwrap_or_else(|_| {
            UserOperationReceiptResponse {
                receipt: None,
                user_op_hash: user_op_hash.clone(),
                status: "pending".to_string(),
            }
        });

    let tx_hash = receipt_response
        .receipt
        .as_ref()
        .and_then(|r| serde_json::from_str::<serde_json::Value>(r).ok())
        .and_then(|v| v.get("transactionHash").cloned())
        .and_then(|h| h.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| user_op_hash.clone());

    Ok(tx_hash)
}

// === HELPER FUNCTIONS ===

pub fn create_tba_payment_calldata(
    usdc_contract: &str,
    recipient_address: &str,
    amount_usdc: u128,
) -> Result<String, HyperwalletClientError> {
    // Parse addresses
    let usdc_addr = usdc_contract.parse::<EthAddress>().map_err(|_| {
        HyperwalletClientError::ServerError(types::OperationError::invalid_params(
            "Invalid USDC contract address",
        ))
    })?;

    let recipient_addr = recipient_address.parse::<EthAddress>().map_err(|_| {
        HyperwalletClientError::ServerError(types::OperationError::invalid_params(
            "Invalid recipient address",
        ))
    })?;

    let erc20_calldata =
        wallet::create_erc20_transfer_calldata(recipient_addr, U256::from(amount_usdc));

    // Create TBA execute calldata using wallet.rs
    let tba_calldata = wallet::create_tba_userop_calldata(usdc_addr, U256::ZERO, erc20_calldata, 0);

    Ok(format!("0x{}", hex::encode(tba_calldata)))
}

// === INTERNAL HELPERS ===

fn build_message(session_id: &SessionId, request: HyperwalletRequest) -> HyperwalletMessage {
    HyperwalletMessage {
        request,
        session_id: session_id.clone(),
    }
}
