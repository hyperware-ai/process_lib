//! Public API wrappers for Hyperwallet operations using clean typed messaging.
//!
//! All functions take specific HyperwalletRequest<BusinessType> objects for perfect type safety.
//! Users construct the exact request type needed and get compile-time verification.

use super::types::{
    self, ApproveTokenRequest, Balance, BuildAndSignUserOperationForPaymentRequest,
    CheckTbaOwnershipRequest, CreateWalletRequest, ExecuteViaTbaRequest, ExportWalletRequest,
    ExportWalletResponse, GetTokenBalanceRequest, GetUserOperationReceiptRequest,
    HyperwalletMessage, HyperwalletRequest, HyperwalletResponse, ImportWalletRequest,
    ListWalletsResponse, PaymasterConfig, RenameWalletRequest, ResolveIdentityRequest,
    SendEthRequest, SendTokenRequest, SpendingLimits, SubmitUserOperationRequest, TxReceipt,
    UnlockWalletRequest, Wallet,
};
use super::HyperwalletClientError;
use crate::{wallet, Address};
use alloy_primitives::{Address as EthAddress, U256};

/// Creates a new wallet for the process.
pub fn create_wallet(
    our: &Address,
    request: HyperwalletRequest<CreateWalletRequest>,
) -> Result<Wallet, HyperwalletClientError> {
    let message = HyperwalletMessage::CreateWallet(request);
    let response: HyperwalletResponse<Wallet> = super::send_message(message, our)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing wallet data in response",
        ))
    })
}

/// Sends ETH from a managed wallet.
pub fn send_eth(
    our: &Address,
    request: HyperwalletRequest<SendEthRequest>,
) -> Result<TxReceipt, HyperwalletClientError> {
    let message = HyperwalletMessage::SendEth(request);
    let response: HyperwalletResponse<TxReceipt> = super::send_message(message, our)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing transaction receipt in response",
        ))
    })
}

/// Retrieves the native balance of a managed wallet.
pub fn get_balance(
    our: &Address,
    request: HyperwalletRequest<()>,
) -> Result<Balance, HyperwalletClientError> {
    let message = HyperwalletMessage::GetBalance(request);
    let response: HyperwalletResponse<Balance> = super::send_message(message, our)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing balance data in response",
        ))
    })
}

/// Creates a note in the hypermap.
pub fn create_note(
    our: &Address,
    request: HyperwalletRequest<serde_json::Value>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let message = HyperwalletMessage::CreateNote(request);
    let response: HyperwalletResponse<serde_json::Value> = super::send_message(message, our)?;
    Ok(response.data.unwrap_or_default())
}

/// Executes a transaction via Token Bound Account (TBA).
pub fn execute_via_tba(
    our: &Address,
    request: HyperwalletRequest<ExecuteViaTbaRequest>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let message = HyperwalletMessage::ExecuteViaTba(request);
    let response: HyperwalletResponse<serde_json::Value> = super::send_message(message, our)?;
    Ok(response.data.unwrap_or_default())
}

/// Checks TBA ownership.
pub fn check_tba_ownership(
    our: &Address,
    request: HyperwalletRequest<CheckTbaOwnershipRequest>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let message = HyperwalletMessage::CheckTbaOwnership(request);
    let response: HyperwalletResponse<serde_json::Value> = super::send_message(message, our)?;
    Ok(response.data.unwrap_or_default())
}

/// Unlocks a wallet with the provided password.
pub fn unlock_wallet(
    our: &Address,
    request: HyperwalletRequest<UnlockWalletRequest>,
) -> Result<(), HyperwalletClientError> {
    let message = HyperwalletMessage::UnlockWallet(request);
    let _response: HyperwalletResponse<()> = super::send_message(message, our)?;
    Ok(())
}

/// Imports a wallet from a private key.
pub fn import_wallet(
    our: &Address,
    request: HyperwalletRequest<ImportWalletRequest>,
) -> Result<Wallet, HyperwalletClientError> {
    let message = HyperwalletMessage::ImportWallet(request);
    let response: HyperwalletResponse<Wallet> = super::send_message(message, our)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing wallet data in response",
        ))
    })
}

/// Lists all wallets accessible to the process.
pub fn list_wallets(
    our: &Address,
    request: HyperwalletRequest<()>,
) -> Result<Vec<Wallet>, HyperwalletClientError> {
    let message = HyperwalletMessage::ListWallets(request);
    let response: HyperwalletResponse<ListWalletsResponse> = super::send_message(message, our)?;
    let list_response = response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing wallet list in response",
        ))
    })?;

    Ok(list_response.wallets)
}

/// Gets detailed information about a specific wallet.
pub fn get_wallet_info(
    our: &Address,
    request: HyperwalletRequest<()>,
) -> Result<Wallet, HyperwalletClientError> {
    let message = HyperwalletMessage::GetWalletInfo(request);
    let response: HyperwalletResponse<Wallet> = super::send_message(message, our)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing wallet data in response",
        ))
    })
}

/// Deletes a wallet permanently.
pub fn delete_wallet(
    our: &Address,
    request: HyperwalletRequest<()>,
) -> Result<(), HyperwalletClientError> {
    let message = HyperwalletMessage::DeleteWallet(request);
    let _response: HyperwalletResponse<()> = super::send_message(message, our)?;
    Ok(())
}

/// Renames a wallet.
pub fn rename_wallet(
    our: &Address,
    request: HyperwalletRequest<RenameWalletRequest>,
) -> Result<(), HyperwalletClientError> {
    let message = HyperwalletMessage::RenameWallet(request);
    let _response: HyperwalletResponse<()> = super::send_message(message, our)?;
    Ok(())
}

/// Sets spending limits for a wallet.
pub fn set_wallet_limits(
    our: &Address,
    request: HyperwalletRequest<SpendingLimits>,
) -> Result<(), HyperwalletClientError> {
    let message = HyperwalletMessage::SetWalletLimits(request);
    let _response: HyperwalletResponse<()> = super::send_message(message, our)?;
    Ok(())
}

/// Sends tokens from a managed wallet.
pub fn send_token(
    our: &Address,
    request: HyperwalletRequest<SendTokenRequest>,
) -> Result<TxReceipt, HyperwalletClientError> {
    let message = HyperwalletMessage::SendToken(request);
    let response: HyperwalletResponse<TxReceipt> = super::send_message(message, our)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing transaction receipt in response",
        ))
    })
}

/// Approves a spender to transfer tokens from a managed wallet.
pub fn approve_token(
    our: &Address,
    request: HyperwalletRequest<ApproveTokenRequest>,
) -> Result<TxReceipt, HyperwalletClientError> {
    let message = HyperwalletMessage::ApproveToken(request);
    let response: HyperwalletResponse<TxReceipt> = super::send_message(message, our)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing transaction receipt in response",
        ))
    })
}

/// Gets the token balance for a wallet.
pub fn get_token_balance(
    our: &Address,
    request: HyperwalletRequest<GetTokenBalanceRequest>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let message = HyperwalletMessage::GetTokenBalance(request);
    let response: HyperwalletResponse<serde_json::Value> = super::send_message(message, our)?;
    Ok(response.data.unwrap_or_default())
}

/// High-level convenience function for building and signing UserOperations with TBA support.
pub fn build_and_sign_user_operation(
    our: &Address,
    request: HyperwalletRequest<BuildAndSignUserOperationForPaymentRequest>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let message = HyperwalletMessage::BuildAndSignUserOperationForPayment(request);
    let response: HyperwalletResponse<serde_json::Value> = super::send_message(message, our)?;
    Ok(response.data.unwrap_or_default())
}

/// Submits a UserOperation to the network.
pub fn submit_user_operation(
    our: &Address,
    request: HyperwalletRequest<SubmitUserOperationRequest>,
) -> Result<String, HyperwalletClientError> {
    let message = HyperwalletMessage::SubmitUserOperation(request);
    let response: HyperwalletResponse<serde_json::Value> = super::send_message(message, our)?;
    let data = response.data.unwrap_or_default();
    data.get("user_op_hash")
        .and_then(|h| h.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            HyperwalletClientError::ServerError(types::OperationError::internal_error(
                "Missing UserOperation hash in response",
            ))
        })
}

/// Gets the receipt for a UserOperation.
pub fn get_user_operation_receipt(
    our: &Address,
    request: HyperwalletRequest<GetUserOperationReceiptRequest>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let message = HyperwalletMessage::GetUserOperationReceipt(request);
    let response: HyperwalletResponse<serde_json::Value> = super::send_message(message, our)?;
    Ok(response.data.unwrap_or_default())
}

/// Exports a wallet's private key.
pub fn export_wallet(
    our: &Address,
    request: HyperwalletRequest<ExportWalletRequest>,
) -> Result<ExportWalletResponse, HyperwalletClientError> {
    let message = HyperwalletMessage::ExportWallet(request);
    let response: HyperwalletResponse<ExportWalletResponse> = super::send_message(message, our)?;
    response.data.ok_or_else(|| {
        HyperwalletClientError::ServerError(types::OperationError::internal_error(
            "Missing export data in response",
        ))
    })
}

/// Resolves an identity name to an address via Hypermap.
pub fn resolve_identity(
    our: &Address,
    request: HyperwalletRequest<ResolveIdentityRequest>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let message = HyperwalletMessage::ResolveIdentity(request);
    let response: HyperwalletResponse<serde_json::Value> = super::send_message(message, our)?;
    Ok(response.data.unwrap_or_default())
}

// === HELPER FUNCTIONS ===

/// Creates TBA execute calldata for an ERC20 transfer payment.
/// This wraps the existing wallet.rs functions to make payments simpler.
pub fn create_tba_payment_calldata(
    usdc_contract: &str,
    recipient_address: &str,
    amount_usdc: u128,
) -> Result<String, HyperwalletClientError> {
    // Parse addresses
    let usdc_addr = usdc_contract.parse::<EthAddress>().map_err(|_| {
        HyperwalletClientError::ServerError(super::types::OperationError::invalid_params(
            "Invalid USDC contract address",
        ))
    })?;

    let recipient_addr = recipient_address.parse::<EthAddress>().map_err(|_| {
        HyperwalletClientError::ServerError(super::types::OperationError::invalid_params(
            "Invalid recipient address",
        ))
    })?;

    // Convert USDC amount to units (6 decimals)
    let amount_units = amount_usdc * 1_000_000;

    // Create ERC20 transfer calldata using wallet.rs
    let erc20_calldata =
        wallet::create_erc20_transfer_calldata(recipient_addr, U256::from(amount_units));

    // Create TBA execute calldata using wallet.rs
    let tba_calldata = wallet::create_tba_userop_calldata(
        usdc_addr,      // target: USDC contract
        U256::ZERO,     // value: 0 (no ETH transfer)
        erc20_calldata, // data: ERC20 transfer calldata
        0,              // operation: 0 = CALL
    );

    Ok(format!("0x{}", hex::encode(tba_calldata)))
}

/// Simplified gasless payment function - abstracts away all complexity.
pub fn build_and_sign_gasless_payment(
    our: &Address,
    session_info: &super::types::SessionInfo,
    signer_wallet_id: &str,
    tba_address: &str,
    call_data: &str,
    chain_id: Option<u64>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let request = super::types::BuildAndSignUserOperationForPaymentRequest {
        target: tba_address.to_string(),
        call_data: call_data.to_string(),
        value: Some("0".to_string()),
        use_paymaster: true,
        paymaster_config: Some(create_paymaster_config_with_tba(Some(tba_address))),
        password: None,
    };

    let hyperwallet_request = super::types::HyperwalletRequest {
        business_data: request,
        wallet_id: Some(signer_wallet_id.to_string()),
        chain_id,
        auth: super::types::ProcessAuth {
            process_address: our.to_string(),
            signature: None,
        },
        request_id: None,
        timestamp: current_timestamp(),
    };

    build_and_sign_user_operation(our, hyperwallet_request)
}

/// Simplified submit that extracts entry point automatically from build response.
pub fn submit_gasless_payment(
    our: &Address,
    session_info: &super::types::SessionInfo,
    signed_user_op_response: serde_json::Value,
    chain_id: Option<u64>,
) -> Result<String, HyperwalletClientError> {
    // Extract signed UserOperation and entry point from the build response
    let signed_user_op = signed_user_op_response
        .get("signed_user_operation")
        .ok_or_else(|| {
            HyperwalletClientError::ServerError(super::types::OperationError::internal_error(
                "Missing signed_user_operation in response",
            ))
        })?
        .clone();

    let entry_point = signed_user_op_response
        .get("entry_point")
        .and_then(|e| e.as_str())
        .ok_or_else(|| {
            HyperwalletClientError::ServerError(super::types::OperationError::internal_error(
                "Missing entry_point in response",
            ))
        })?;

    let request = super::types::SubmitUserOperationRequest {
        signed_user_operation: signed_user_op,
        entry_point: entry_point.to_string(),
        bundler_url: None,
    };

    let hyperwallet_request = super::types::HyperwalletRequest {
        business_data: request,
        wallet_id: None,
        chain_id,
        auth: super::types::ProcessAuth {
            process_address: our.to_string(),
            signature: None,
        },
        request_id: None,
        timestamp: current_timestamp(),
    };

    submit_user_operation(our, hyperwallet_request)
}

/// Get receipt with proper transaction hash extraction.
pub fn get_payment_receipt(
    our: &Address,
    session_info: &super::types::SessionInfo,
    user_op_hash: &str,
    chain_id: Option<u64>,
) -> Result<(String, serde_json::Value), HyperwalletClientError> {
    let request = super::types::GetUserOperationReceiptRequest {
        user_op_hash: user_op_hash.to_string(),
    };
    let hyperwallet_request = super::types::HyperwalletRequest {
        business_data: request,
        wallet_id: None,
        chain_id,
        auth: super::types::ProcessAuth {
            process_address: our.to_string(),
            signature: None,
        },
        request_id: None,
        timestamp: current_timestamp(),
    };
    let receipt = get_user_operation_receipt(our, hyperwallet_request)?;

    // Extract transaction hash if available
    let tx_hash = receipt
        .get("receipt")
        .and_then(|r| r.get("transactionHash"))
        .and_then(|h| h.as_str())
        .unwrap_or(user_op_hash) // Fallback to user op hash
        .to_string();

    Ok((tx_hash, receipt))
}

/// Complete payment function that handles everything internally.
pub fn execute_complete_gasless_payment(
    our: &Address,
    session_info: &super::types::SessionInfo,
    signer_wallet_id: &str,
    tba_address: &str,
    recipient_address: &str,
    amount_usdc: u128,
    chain_id: u64,
) -> Result<String, HyperwalletClientError> {
    // Step 1: Get USDC contract for the chain
    let usdc_contract = match chain_id {
        8453 => "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // Base USDC
        _ => {
            return Err(HyperwalletClientError::ServerError(
                super::types::OperationError::invalid_params(&format!(
                    "Unsupported chain ID: {}",
                    chain_id
                )),
            ))
        }
    };

    // Step 2: Create payment calldata using wallet.rs functions
    let tba_calldata = create_tba_payment_calldata(usdc_contract, recipient_address, amount_usdc)?;

    // Step 3: Build and sign gasless payment
    let signed_data = build_and_sign_gasless_payment(
        our,
        session_info,
        signer_wallet_id,
        tba_address,
        &tba_calldata,
        Some(chain_id),
    )?;

    // Step 4: Submit payment
    let user_op_hash = submit_gasless_payment(our, session_info, signed_data, Some(chain_id))?;

    // Step 5: Get receipt and extract transaction hash
    let (tx_hash, _receipt) = get_payment_receipt(our, session_info, &user_op_hash, Some(chain_id))
        .unwrap_or_else(|_| {
            // Fallback to user op hash if receipt fails
            (user_op_hash.clone(), serde_json::Value::Null)
        });

    Ok(tx_hash)
}

/// Validates payment setup and returns the required addresses and amounts.
pub fn validate_gasless_payment_setup(
    tba_address: Option<&String>,
    recipient_address: &str,
    amount_usdc_str: &str,
    chain_id: u64,
) -> Result<(String, String, String, f64), HyperwalletClientError> {
    // Get USDC contract address for the chain
    let usdc_contract = match chain_id {
        8453 => "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // Base USDC
        _ => {
            return Err(HyperwalletClientError::ServerError(
                super::types::OperationError::invalid_params(&format!(
                    "Unsupported chain ID: {}",
                    chain_id
                )),
            ))
        }
    };

    // Check if TBA is configured
    let tba = match tba_address {
        Some(addr) => addr.clone(),
        None => {
            return Err(HyperwalletClientError::ServerError(
                super::types::OperationError::invalid_params("TBA not configured"),
            ))
        }
    };

    // Validate recipient address format
    recipient_address.parse::<EthAddress>().map_err(|_| {
        HyperwalletClientError::ServerError(super::types::OperationError::invalid_params(
            "Invalid recipient address",
        ))
    })?;

    // Parse and validate USDC amount
    let amount_usdc = amount_usdc_str.parse::<f64>().map_err(|_| {
        HyperwalletClientError::ServerError(super::types::OperationError::invalid_params(
            "Invalid USDC amount",
        ))
    })?;

    if amount_usdc <= 0.0 {
        return Err(HyperwalletClientError::ServerError(
            super::types::OperationError::invalid_params("USDC amount must be positive"),
        ));
    }

    Ok((
        usdc_contract.to_string(),
        tba,
        recipient_address.to_string(),
        amount_usdc,
    ))
}

/// Extracts transaction hash from a payment receipt, with fallback logic.
pub fn extract_payment_tx_hash(
    receipt_result: Result<(String, serde_json::Value), HyperwalletClientError>,
    user_op_hash_fallback: &str,
) -> String {
    match receipt_result {
        Ok((tx_hash, _receipt)) => tx_hash,
        Err(_) => {
            // Fallback to user op hash if receipt fails
            user_op_hash_fallback.to_string()
        }
    }
}

/// Helper function to create a PaymasterConfig with TBA address for gasless transactions.
pub fn create_paymaster_config_with_tba(tba_address: Option<&str>) -> PaymasterConfig {
    let mut config = PaymasterConfig::default();
    config.tba_address = tba_address.map(|s| s.to_string());
    config
}

// === INTERNAL HELPERS ===

// Uses the shared send_message function from the parent module

/// Get current timestamp for message construction.
pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
