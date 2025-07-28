//! Public API wrappers for Hyperwallet operations.

use super::types::{
    self, Balance, Operation, SessionInfo, SpendingLimits, TxReceipt, UserOperationHash, Wallet,
};
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
    amount: &str,
    chain_id: Option<u64>,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let params = serde_json::json!({
        "target": target,
        "amount": amount,
    });
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
    user_operation: serde_json::Value,
    entry_point: &str,
) -> Result<UserOperationHash, HyperwalletClientError> {
    let params = serde_json::json!({
        "user_operation": user_operation,
        "entry_point": entry_point,
    });
    let request = build_request(
        our,
        session_info,
        Operation::SubmitUserOperation,
        params,
        None,
        None,
    );
    let response = execute_request(request, our)?;
    serde_json::from_value(response.data.unwrap_or_default())
        .map_err(HyperwalletClientError::Deserialization)
}

/// Gets the receipt for a UserOperation.
pub fn get_user_operation_receipt(
    our: &Address,
    session_info: &SessionInfo,
    user_op_hash: &UserOperationHash,
) -> Result<serde_json::Value, HyperwalletClientError> {
    let params = serde_json::json!({ "user_operation_hash": user_op_hash });
    let request = build_request(
        our,
        session_info,
        Operation::GetUserOperationReceipt,
        params,
        None,
        None,
    );
    let response = execute_request(request, our)?;
    Ok(response.data.unwrap_or_default())
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
