use super::types::{
    self, Balance, BuildAndSignUserOperationForPaymentRequest, BuildAndSignUserOperationResponse,
    CreateWalletRequest, ExportWalletResponse, GetTokenBalanceResponse, HyperwalletMessage,
    HyperwalletRequest, HyperwalletResponse, ImportWalletRequest, ListWalletsResponse,
    PaymasterConfig, RenameWalletRequest, SendEthRequest, SendTokenRequest, SessionId,
    SubmitUserOperationResponse, TxReceipt, UnlockWalletRequest, UserOperationReceiptResponse,
    Wallet,
};
use super::HyperwalletClientError;
use crate::wallet;
use alloy_primitives::{Address as EthAddress, U256};

pub fn create_wallet(
    session_id: &SessionId,
    name: Option<&str>,
    password: Option<&str>,
) -> Result<Wallet, HyperwalletClientError> {
    let request = build_request(
        session_id,
        CreateWalletRequest {
            name: name.map(|s| s.to_string()).unwrap_or_default(),
            password: password.map(|s| s.to_string()),
        },
    );

    let message = HyperwalletMessage::CreateWallet(request);
    let response: HyperwalletResponse<Wallet> = super::send_message(message)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing wallet data in response",
        ))
    })
}

pub fn import_wallet(
    session_id: &SessionId,
    name: &str,
    private_key: &str,
    password: Option<&str>,
) -> Result<Wallet, HyperwalletClientError> {
    let request = build_request(
        session_id,
        ImportWalletRequest {
            name: name.to_string(),
            private_key: private_key.to_string(),
            password: password.map(|s| s.to_string()),
        },
    );

    let message = HyperwalletMessage::ImportWallet(request);
    let response: HyperwalletResponse<Wallet> = super::send_message(message)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing wallet data in response",
        ))
    })
}

pub fn unlock_wallet(
    session_id: &SessionId,
    target_session_id: &str,
    wallet_id: &str,
    password: &str,
) -> Result<(), HyperwalletClientError> {
    let request = build_request(
        session_id,
        UnlockWalletRequest {
            session_id: target_session_id.to_string(),
            wallet_id: wallet_id.to_string(),
            password: password.to_string(),
        },
    );

    let message = HyperwalletMessage::UnlockWallet(request);
    let _response: HyperwalletResponse<()> = super::send_message(message)?;
    Ok(())
}

pub fn list_wallets(session_id: &SessionId) -> Result<ListWalletsResponse, HyperwalletClientError> {
    let request = build_request(session_id, ());

    let message = HyperwalletMessage::ListWallets(request);
    let response: HyperwalletResponse<ListWalletsResponse> = super::send_message(message)?;
    let list_response = response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing wallet list in response",
        ))
    })?;

    Ok(list_response)
}

pub fn get_wallet_info(
    session_id: &SessionId,
    wallet_id: &str,
) -> Result<Wallet, HyperwalletClientError> {
    let request = build_request(
        session_id,
        types::GetWalletInfoRequest {
            wallet_id: wallet_id.to_string(),
        },
    );

    let message = HyperwalletMessage::GetWalletInfo(request);
    let response: HyperwalletResponse<Wallet> = super::send_message(message)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing wallet data in response",
        ))
    })
}

pub fn delete_wallet(
    session_id: &SessionId,
    wallet_id: &str,
) -> Result<(), HyperwalletClientError> {
    let request = build_request(
        session_id,
        types::DeleteWalletRequest {
            wallet_id: wallet_id.to_string(),
        },
    );

    let message = HyperwalletMessage::DeleteWallet(request);
    let _response: HyperwalletResponse<()> = super::send_message(message)?;
    Ok(())
}

pub fn export_wallet(
    session_id: &SessionId,
    wallet_id: &str,
    password: Option<&str>,
) -> Result<ExportWalletResponse, HyperwalletClientError> {
    let request = build_request(
        session_id,
        types::ExportWalletRequest {
            wallet_id: wallet_id.to_string(),
            password: password.map(|s| s.to_string()),
        },
    );

    let message = HyperwalletMessage::ExportWallet(request);
    let response: HyperwalletResponse<ExportWalletResponse> = super::send_message(message)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing export data in response",
        ))
    })
}

pub fn rename_wallet(
    session_id: &SessionId,
    wallet_id: &str,
    new_name: &str,
) -> Result<(), HyperwalletClientError> {
    let request = build_request(
        session_id,
        RenameWalletRequest {
            wallet_id: wallet_id.to_string(),
            new_name: new_name.to_string(),
        },
    );
    let message = HyperwalletMessage::RenameWallet(request);
    let _response: HyperwalletResponse<()> = super::send_message(message)?;
    Ok(())
}

// === TRANSACTIONS ===

pub fn send_eth(
    session_id: &SessionId,
    wallet_id: &str,
    to_address: &str,
    amount_eth: &str,
) -> Result<TxReceipt, HyperwalletClientError> {
    let request = build_request(
        session_id,
        SendEthRequest {
            wallet_id: wallet_id.to_string(),
            to: to_address.to_string(),
            amount: amount_eth.to_string(),
        },
    );

    let message = HyperwalletMessage::SendEth(request);
    let response: HyperwalletResponse<TxReceipt> = super::send_message(message)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing transaction receipt in response",
        ))
    })
}

pub fn send_token(
    session_id: &SessionId,
    wallet_id: &str,
    token_address: &str,
    to_address: &str,
    amount: &str,
) -> Result<TxReceipt, HyperwalletClientError> {
    let request = build_request(
        session_id,
        SendTokenRequest {
            wallet_id: wallet_id.to_string(),
            token_address: token_address.to_string(),
            to: to_address.to_string(),
            amount: amount.to_string(),
        },
    );

    let message = HyperwalletMessage::SendToken(request);
    let response: HyperwalletResponse<TxReceipt> = super::send_message(message)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing transaction receipt in response",
        ))
    })
}

// === QUERIES ===

pub fn get_balance(
    session_id: &SessionId,
    wallet_id: &str,
) -> Result<Balance, HyperwalletClientError> {
    let request = build_request(
        session_id,
        types::GetBalanceRequest {
            wallet_id: wallet_id.to_string(),
        },
    );

    let message = HyperwalletMessage::GetBalance(request);
    let response: HyperwalletResponse<Balance> = super::send_message(message)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing balance data in response",
        ))
    })
}

pub fn get_token_balance(
    session_id: &SessionId,
    wallet_id: &str,
    token_address: &str,
) -> Result<GetTokenBalanceResponse, HyperwalletClientError> {
    let request = build_request(
        session_id,
        types::GetTokenBalanceRequest {
            wallet_id: wallet_id.to_string(),
            token_address: token_address.to_string(),
        },
    );

    let message = HyperwalletMessage::GetTokenBalance(request);
    let response: HyperwalletResponse<GetTokenBalanceResponse> = super::send_message(message)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing token balance data in response",
        ))
    })
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
    let request = build_request(
        session_id,
        BuildAndSignUserOperationForPaymentRequest {
            eoa_wallet_id: eoa_wallet_id.to_string(),
            tba_address: tba_address.to_string(),
            target: target.to_string(),
            call_data: call_data.to_string(),
            use_paymaster,
            paymaster_config,
            password: password.map(|s| s.to_string()),
        },
    );

    let message = HyperwalletMessage::BuildAndSignUserOperationForPayment(request);
    let response: HyperwalletResponse<BuildAndSignUserOperationResponse> =
        super::send_message(message)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing UserOperation build response data",
        ))
    })
}

pub fn submit_user_operation(
    session_id: &SessionId,
    signed_user_operation: serde_json::Value,
    entry_point: &str,
    bundler_url: Option<&str>,
) -> Result<String, HyperwalletClientError> {
    let request = build_request(
        session_id,
        types::SubmitUserOperationRequest {
            signed_user_operation,
            entry_point: entry_point.to_string(),
            bundler_url: bundler_url.map(|s| s.to_string()),
        },
    );

    let message = HyperwalletMessage::SubmitUserOperation(request);
    let response: HyperwalletResponse<SubmitUserOperationResponse> = super::send_message(message)?;
    let data = response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing UserOperation response data",
        ))
    })?;

    // Direct field access - no manual JSON parsing needed!
    Ok(data.user_op_hash)
}

pub fn get_user_operation_receipt(
    session_id: &SessionId,
    user_op_hash: &str,
) -> Result<UserOperationReceiptResponse, HyperwalletClientError> {
    let request = build_request(
        session_id,
        types::GetUserOperationReceiptRequest {
            user_op_hash: user_op_hash.to_string(),
        },
    );

    let message = HyperwalletMessage::GetUserOperationReceipt(request);
    let response: HyperwalletResponse<UserOperationReceiptResponse> = super::send_message(message)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing UserOperation receipt data in response",
        ))
    })
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
        build_response.signed_user_operation,
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
        .and_then(|r| r.get("transactionHash"))
        .and_then(|h| h.as_str())
        .unwrap_or(&user_op_hash) // Fallback to user op hash
        .to_string();

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

fn build_request<T>(session_id: &SessionId, operation_data: T) -> HyperwalletRequest<T> {
    HyperwalletRequest {
        data: operation_data,
        session_id: session_id.clone(),
    }
}
