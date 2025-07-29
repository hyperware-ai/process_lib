//! Public API wrappers for Hyperwallet operations.

use super::types::{self, Balance, Operation, SessionInfo, SpendingLimits, TxReceipt, Wallet};
use super::{execute_request, HyperwalletClientError};
use crate::Address;

/// Creates a new wallet for the process.
pub fn create_wallet(
    our: &Address,
    session_info: &SessionInfo,
    name: &str,
    password: Option<&str>,
) -> Result<Wallet, HyperwalletClientError> {
    let params = serde_json::json!({ "name": name, "password": password });
    let request = build_request(
        our,
        session_info,
        Operation::CreateWallet,
        params,
        None,
        None,
    );
    let response = execute_request(request, our)?;
    serde_json::from_value(response.data.unwrap_or_default())
        .map_err(HyperwalletClientError::Deserialization)
}

/// Sends ETH from a managed wallet.
pub fn send_eth(
    our: &Address,
    session_info: &SessionInfo,
    wallet_id: &str,
    to: &str,
    amount: &str, // e.g., "0.1 ETH"
    chain_id: Option<u64>,
) -> Result<TxReceipt, HyperwalletClientError> {
    let params = serde_json::json!({ "to": to, "amount": amount });
    let request = build_request(
        our,
        session_info,
        Operation::SendEth,
        params,
        Some(wallet_id.to_string()),
        chain_id,
    );
    let response = execute_request(request, our)?;
    serde_json::from_value(response.data.unwrap_or_default())
        .map_err(HyperwalletClientError::Deserialization)
}

/// Retrieves the native balance of a managed wallet.
pub fn get_balance(
    our: &Address,
    session_info: &SessionInfo,
    wallet_id: &str,
    chain_id: Option<u64>,
) -> Result<Balance, HyperwalletClientError> {
    let request = build_request(
        our,
        session_info,
        Operation::GetBalance,
        serde_json::Value::Null,
        Some(wallet_id.to_string()),
        chain_id,
    );
    let response = execute_request(request, our)?;
    serde_json::from_value(response.data.unwrap_or_default())
        .map_err(HyperwalletClientError::Deserialization)
}

/// Creates a note in the hypermap.
pub fn create_note(
    our: &Address,
    session_info: &SessionInfo,
    note_data: serde_json::Value,
    chain_id: Option<u64>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let request = build_request(
        our,
        session_info,
        Operation::CreateNote,
        note_data,
        None,
        chain_id,
    );
    let response = execute_request(request, our)?;
    Ok(response.data.unwrap_or_default())
}

/// Executes a transaction via Token Bound Account (TBA).
pub fn execute_via_tba(
    our: &Address,
    session_info: &SessionInfo,
    tba_address: &str,
    target: &str,
    call_data: &[u8],
    value: Option<&str>,
    chain_id: Option<u64>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let params = serde_json::json!({
        "tba_address": tba_address,
        "target": target,
        "call_data": format!("0x{}", hex::encode(call_data)),
        "value": value,
    });
    let request = build_request(
        our,
        session_info,
        Operation::ExecuteViaTba,
        params,
        None,
        chain_id,
    );
    let response = execute_request(request, our)?;
    Ok(response.data.unwrap_or_default())
}

/// Checks TBA ownership.
pub fn check_tba_ownership(
    our: &Address,
    session_info: &SessionInfo,
    tba_address: &str,
    signer_address: &str,
    chain_id: Option<u64>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let params = serde_json::json!({
        "tba_address": tba_address,
        "signer_address": signer_address,
    });
    let request = build_request(
        our,
        session_info,
        Operation::CheckTbaOwnership,
        params,
        None,
        chain_id,
    );
    let response = execute_request(request, our)?;
    Ok(response.data.unwrap_or_default())
}

/// Unlocks a wallet with the provided password.
pub fn unlock_wallet(
    our: &Address,
    session_info: &SessionInfo,
    wallet_id: &str,
    password: &str,
) -> Result<(), HyperwalletClientError> {
    let params = serde_json::json!({
        "session_id": session_info.session_id,
        "wallet_id": wallet_id,
        "password": password
    });
    let request = build_request(
        our,
        session_info,
        Operation::UnlockWallet,
        params,
        None, // Don't duplicate wallet_id in request.wallet_id
        None,
    );
    execute_request(request, our)?;
    Ok(())
}

/// Imports a wallet from a private key.
pub fn import_wallet(
    our: &Address,
    session_info: &SessionInfo,
    name: &str,
    private_key: &str,
    password: Option<&str>,
) -> Result<Wallet, HyperwalletClientError> {
    let params = serde_json::json!({
        "name": name,
        "private_key": private_key,
        "password": password,
    });
    let request = build_request(
        our,
        session_info,
        Operation::ImportWallet,
        params,
        None,
        None,
    );
    let response = execute_request(request, our)?;
    serde_json::from_value(response.data.unwrap_or_default())
        .map_err(HyperwalletClientError::Deserialization)
}

/// Lists all wallets accessible to the process.
pub fn list_wallets(
    our: &Address,
    session_info: &SessionInfo,
) -> Result<Vec<Wallet>, HyperwalletClientError> {
    let request = build_request(
        our,
        session_info,
        Operation::ListWallets,
        serde_json::Value::Null,
        None,
        None,
    );
    let response = execute_request(request, our)?;
    serde_json::from_value(response.data.unwrap_or_default())
        .map_err(HyperwalletClientError::Deserialization)
}

/// Gets detailed information about a specific wallet.
pub fn get_wallet_info(
    our: &Address,
    session_info: &SessionInfo,
    wallet_id: &str,
) -> Result<Wallet, HyperwalletClientError> {
    let request = build_request(
        our,
        session_info,
        Operation::GetWalletInfo,
        serde_json::Value::Null,
        Some(wallet_id.to_string()),
        None,
    );
    let response = execute_request(request, our)?;
    serde_json::from_value(response.data.unwrap_or_default())
        .map_err(HyperwalletClientError::Deserialization)
}

/// Deletes a wallet permanently.
pub fn delete_wallet(
    our: &Address,
    session_info: &SessionInfo,
    wallet_id: &str,
) -> Result<(), HyperwalletClientError> {
    let request = build_request(
        our,
        session_info,
        Operation::DeleteWallet,
        serde_json::Value::Null,
        Some(wallet_id.to_string()),
        None,
    );
    execute_request(request, our)?;
    Ok(())
}

/// Renames a wallet.
pub fn rename_wallet(
    our: &Address,
    session_info: &SessionInfo,
    wallet_id: &str,
    new_name: &str,
) -> Result<(), HyperwalletClientError> {
    let params = serde_json::json!({ "new_name": new_name });
    let request = build_request(
        our,
        session_info,
        Operation::RenameWallet,
        params,
        Some(wallet_id.to_string()),
        None,
    );
    execute_request(request, our)?;
    Ok(())
}

/// Sets spending limits for a wallet.
pub fn set_wallet_limits(
    our: &Address,
    session_info: &SessionInfo,
    wallet_id: &str,
    limits: SpendingLimits,
) -> Result<(), HyperwalletClientError> {
    let params = serde_json::to_value(limits).map_err(HyperwalletClientError::Serialization)?;
    let request = build_request(
        our,
        session_info,
        Operation::SetWalletLimits,
        params,
        Some(wallet_id.to_string()),
        None,
    );
    execute_request(request, our)?;
    Ok(())
}

/// Sends tokens from a managed wallet.
pub fn send_token(
    our: &Address,
    session_info: &SessionInfo,
    wallet_id: &str,
    token_address: &str,
    to: &str,
    amount: &str,
    chain_id: Option<u64>,
) -> Result<TxReceipt, HyperwalletClientError> {
    let params = serde_json::json!({
        "token_address": token_address,
        "to": to,
        "amount": amount,
    });
    let request = build_request(
        our,
        session_info,
        Operation::SendToken,
        params,
        Some(wallet_id.to_string()),
        chain_id,
    );
    let response = execute_request(request, our)?;
    serde_json::from_value(response.data.unwrap_or_default())
        .map_err(HyperwalletClientError::Deserialization)
}

/// Approves a spender to transfer tokens from a managed wallet.
pub fn approve_token(
    our: &Address,
    session_info: &SessionInfo,
    wallet_id: &str,
    token_address: &str,
    spender: &str,
    amount: &str,
    chain_id: Option<u64>,
) -> Result<TxReceipt, HyperwalletClientError> {
    let params = serde_json::json!({
        "token_address": token_address,
        "spender": spender,
        "amount": amount,
    });
    let request = build_request(
        our,
        session_info,
        Operation::ApproveToken,
        params,
        Some(wallet_id.to_string()),
        chain_id,
    );
    let response = execute_request(request, our)?;
    serde_json::from_value(response.data.unwrap_or_default())
        .map_err(HyperwalletClientError::Deserialization)
}

/// Gets the token balance for a wallet.
pub fn get_token_balance(
    our: &Address,
    session_info: &SessionInfo,
    wallet_id: &str,
    token_address: &str,
    chain_id: Option<u64>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let params = serde_json::json!({ "token_address": token_address });
    let request = build_request(
        our,
        session_info,
        Operation::GetTokenBalance,
        params,
        Some(wallet_id.to_string()),
        chain_id,
    );
    let response = execute_request(request, our)?;
    Ok(response.data.unwrap_or_default())
}

/// Builds and signs a UserOperation for payment via ERC-4337.
pub fn build_and_sign_user_operation_for_payment(
    our: &Address,
    session_info: &SessionInfo,
    wallet_id: &str,
    target: &str,
    call_data: &str,
    value: Option<&str>,
    use_paymaster: bool,
    metadata: Option<serde_json::Map<String, serde_json::Value>>,
    password: Option<&str>,
    chain_id: Option<u64>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let mut params = serde_json::json!({
        "target": target,
        "call_data": call_data,
        "use_paymaster": use_paymaster,
    });
    
    if let Some(v) = value {
        params["value"] = serde_json::Value::String(v.to_string());
    }
    
    if let Some(pwd) = password {
        params["password"] = serde_json::Value::String(pwd.to_string());
    }
    
    // Pass metadata through to hyperwallet
    if let Some(meta) = metadata {
        params["metadata"] = serde_json::Value::Object(meta);
    }
    
    let request = build_request(
        our,
        session_info,
        Operation::BuildAndSignUserOperationForPayment,
        params,
        Some(wallet_id.to_string()),
        chain_id,
    );
    let response = execute_request(request, our)?;
    Ok(response.data.unwrap_or_default())
}

/// High-level convenience function for building and signing UserOperations with TBA support.
/// This mirrors your current build_and_sign_user_operation function.
pub fn build_and_sign_user_operation(
    our: &Address,
    session_info: &SessionInfo,
    wallet_id: &str,
    target: &str,
    call_data: &str,
    value: Option<&str>,
    use_paymaster: bool,
    tba_address: Option<&str>,
    password: Option<&str>,
    chain_id: Option<u64>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let mut params = serde_json::json!({
        "target": target,
        "call_data": call_data,
        "use_paymaster": use_paymaster,
    });
    
    if let Some(v) = value {
        params["value"] = serde_json::Value::String(v.to_string());
    }
    
    if let Some(pwd) = password {
        params["password"] = serde_json::Value::String(pwd.to_string());
    }
    
    // Create metadata with Circle paymaster configuration if using paymaster
    if use_paymaster {
        let mut metadata = serde_json::Map::new();
        
        // Always add Circle paymaster metadata for gasless transactions
        // These constants should be defined somewhere accessible
        metadata.insert("paymaster_address".to_string(), 
            serde_json::json!("0x2Ac3c1d3e24b45c6C310534Bc2Dd84B5ed576335")); // Base Circle paymaster
        metadata.insert("is_circle_paymaster".to_string(), serde_json::json!(true));
        metadata.insert("paymaster_verification_gas".to_string(), 
            serde_json::json!("0x30000")); // 196608
        metadata.insert("paymaster_post_op_gas".to_string(), 
            serde_json::json!("0x20000")); // 131072
        
        // Add TBA address if provided - tells hyperwallet to use TBA as sender
        if let Some(tba) = tba_address {
            metadata.insert("tba_address".to_string(), serde_json::json!(tba));
        }
        
        params["metadata"] = serde_json::Value::Object(metadata);
    }
    
    let request = build_request(
        our,
        session_info,
        Operation::BuildAndSignUserOperationForPayment,
        params,
        Some(wallet_id.to_string()),
        chain_id,
    );
    let response = execute_request(request, our)?;
    Ok(response.data.unwrap_or_default())
}

/// Submits a UserOperation to the network.
pub fn submit_user_operation(
    our: &Address,
    session_info: &SessionInfo,
    signed_user_operation: serde_json::Value,
    entry_point: &str,
    bundler_url: Option<&str>,
    chain_id: Option<u64>,
) -> Result<String, HyperwalletClientError> {
    let params = serde_json::json!({
        "signed_user_operation": signed_user_operation,
        "entry_point": entry_point,
        "bundler_url": bundler_url,
    });
    let request = build_request(
        our,
        session_info,
        Operation::SubmitUserOperation,
        params,
        None,
        chain_id,
    );
    let response = execute_request(request, our)?;

    // Extract user_op_hash from response data
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
    session_info: &SessionInfo,
    user_op_hash: &str,
    chain_id: Option<u64>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let params = serde_json::json!({ "user_op_hash": user_op_hash });
    let request = build_request(
        our,
        session_info,
        Operation::GetUserOperationReceipt,
        params,
        None,
        chain_id,
    );
    let response = execute_request(request, our)?;
    Ok(response.data.unwrap_or_default())
}

/// High-level convenience function that executes a complete payment flow.
/// This function handles: session management, building UserOp, submitting, and waiting for receipt.
pub fn execute_gasless_payment(
    our: &Address,
    wallet_id: &str,
    target: &str,
    call_data: &str,
    value: Option<&str>,
    tba_address: Option<&str>,
    password: Option<&str>,
    chain_id: Option<u64>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    // Step 1: Initialize session if needed (you might want to cache this)
    let session = super::initialize(our, super::HandshakeConfig::new())?;
    
    // Step 2: Build and sign UserOperation
    let signed_data = build_and_sign_user_operation(
        our,
        &session,
        wallet_id,
        target,
        call_data,
        value,
        true, // Always use paymaster for gasless
        tba_address,
        password,
        chain_id,
    )?;
    
    // Step 3: Extract signed UserOperation and entry point
    let signed_user_op = signed_data.get("signed_user_operation")
        .ok_or_else(|| HyperwalletClientError::ServerError(
            super::types::OperationError::internal_error("Missing signed_user_operation in response")
        ))?
        .clone();
    
    let entry_point = signed_data.get("entry_point")
        .and_then(|e| e.as_str())
        .ok_or_else(|| HyperwalletClientError::ServerError(
            super::types::OperationError::internal_error("Missing entry_point in response")
        ))?;
    
    // Step 4: Submit UserOperation
    let user_op_hash = submit_user_operation(
        our,
        &session,
        signed_user_op,
        entry_point,
        None, // Use default bundler
        chain_id,
    )?;
    
    // Step 5: Get receipt (you might want to add polling with timeout)
    let receipt = get_user_operation_receipt(our, &session, &user_op_hash, chain_id)?;
    
    Ok(receipt)
}

/// Simplified gasless payment function - abstracts away all complexity.
/// This is what the operator should actually use.
pub fn build_and_sign_gasless_payment(
    our: &Address,
    session_info: &SessionInfo,
    signer_wallet_id: &str,
    tba_address: &str,
    call_data: &str,
    chain_id: Option<u64>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let params = serde_json::json!({
        "target": tba_address,
        "call_data": call_data,
        "use_paymaster": true,  // Always gasless
        "metadata": {
            "tba_address": tba_address,
            "is_circle_paymaster": true,
            "paymaster_address": "0x0578cFB241215b77442a541325d6A4E6dFE700Ec",
            "paymaster_verification_gas": "0x7a120",
            "paymaster_post_op_gas": "0x493e0"
        }
    });
    
    let request = build_request(
        our,
        session_info,
        Operation::BuildAndSignUserOperationForPayment,
        params,
        Some(signer_wallet_id.to_string()),
        chain_id,
    );
    let response = execute_request(request, our)?;
    Ok(response.data.unwrap_or_default())
}

/// Simplified submit that extracts entry point automatically from build response.
pub fn submit_gasless_payment(
    our: &Address,
    session_info: &SessionInfo,
    signed_user_op_response: serde_json::Value,
    chain_id: Option<u64>,
) -> Result<String, HyperwalletClientError> {
    // Extract signed UserOperation and entry point from the build response
    let signed_user_op = signed_user_op_response.get("signed_user_operation")
        .ok_or_else(|| HyperwalletClientError::ServerError(
            super::types::OperationError::internal_error("Missing signed_user_operation in response")
        ))?
        .clone();
    
    let entry_point = signed_user_op_response.get("entry_point")
        .and_then(|e| e.as_str())
        .ok_or_else(|| HyperwalletClientError::ServerError(
            super::types::OperationError::internal_error("Missing entry_point in response")
        ))?;
    
    // Submit using the extracted data
    submit_user_operation(our, session_info, signed_user_op, entry_point, None, chain_id)
}

/// Get receipt with proper transaction hash extraction.
pub fn get_payment_receipt(
    our: &Address,
    session_info: &SessionInfo,
    user_op_hash: &str,
    chain_id: Option<u64>,
) -> Result<(String, serde_json::Value), HyperwalletClientError> {
    let receipt = get_user_operation_receipt(our, session_info, user_op_hash, chain_id)?;
    
    // Extract transaction hash if available
    let tx_hash = receipt.get("receipt")
        .and_then(|r| r.get("transactionHash"))
        .and_then(|h| h.as_str())
        .unwrap_or(user_op_hash) // Fallback to user op hash
        .to_string();
    
    Ok((tx_hash, receipt))
}

/// Resolves an identity name to an address via Hypermap.
pub fn resolve_identity(
    our: &Address,
    session_info: &SessionInfo,
    entry_name: &str,
    chain_id: Option<u64>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let params = serde_json::json!({ "entry_name": entry_name });
    let request = build_request(
        our,
        session_info,
        Operation::ResolveIdentity,
        params,
        None,
        chain_id,
    );
    let response = execute_request(request, our)?;
    Ok(response.data.unwrap_or_default())
}

// Internal helper to reduce boilerplate in the API functions.
fn build_request(
    our: &Address,
    _session_info: &SessionInfo,
    operation: Operation,
    params: serde_json::Value,
    wallet_id: Option<String>,
    chain_id: Option<u64>,
) -> types::OperationRequest {
    types::OperationRequest {
        operation,
        params,
        wallet_id,
        chain_id,
        auth: types::ProcessAuth {
            process_address: our.to_string(),
            signature: None, // Session ID could be sent here
        },
        request_id: None,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}
