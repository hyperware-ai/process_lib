////! Higher-level Ethereum utilities for common operations in Hyperware.
////!
////! This module provides utility functions for common Ethereum operations in the Hyperware
////! ecosystem, particularly focusing on integrating with Hypermap for name resolution.
////!
////! The main goals of this module are:
////! 1. Provide simple, developer-friendly functions for common operations
////! 2. Abstract away the complexity of blockchain interactions
////! 3. Integrate with Hypermap for human-readable addressing
////!
////! ## Usage Examples
////!
////! ```rust
////! use hyperware_process_lib::eth_utils;
////!
////! // Send ETH to a Hypermap name
////! let tx_hash = eth_utils::send_eth("alice.hypr", 1.3)?;
////!
////! // Check if a wallet owns an NFT
////! let has_token = eth_utils::has_nft(contract_address, token_id, wallet_address)?;
////!
////! // Get a token balance
////! let balance = eth_utils::get_token_balance(token_address, wallet_address)?;
////!
////! // Send tokens to a Hypermap name
////! let tx_hash = eth_utils::send_token_to_name(token_address, "bob.hypr", amount)?;
////! ```
//
//use crate::eth::{
//    Address,
//    EthError,
//    TxHash,
//    U256
//};
//use crate::hypermap::{Hypermap, HYPERMAP_ADDRESS};
//use crate::wallet::{Wallet, WalletError};
//use std::str::FromStr;
//use thiserror::Error;
//use sha3::Digest;
//
///// Default chain ID to use for operations if not specified.
///// Currently set to Base (Coinbase L2).
//pub const DEFAULT_CHAIN_ID: u64 = crate::hypermap::HYPERMAP_CHAIN_ID;
//
///// Default timeout (in milliseconds) for Ethereum RPC operations.
//pub const DEFAULT_TIMEOUT_MS: u64 = 60_000; // 60 seconds
//
///// Errors that can occur in Ethereum utility operations
//#[derive(Debug, Error)]
//pub enum EthUtilsError {
//    #[error("Ethereum RPC error: {0}")]
//    Eth(#[from] EthError),
//
//    #[error("Wallet error: {0}")]
//    Wallet(#[from] WalletError),
//
//    #[error("Name resolution error: {0}")]
//    NameResolution(String),
//
//    #[error("Transaction error: {0}")]
//    Transaction(String),
//}
//
///// Send Ether to an address
/////
///// This function creates, signs, and sends a transaction to send ETH to an address.
/////
///// # Parameters
///// - `provider`: The Ethereum provider to use
///// - `wallet`: The wallet to send from
///// - `to`: The recipient address
///// - `amount_wei`: The amount to send in wei
///// - `gas_limit`: Optional gas limit (defaults to 21000)
///// - `gas_price`: Optional gas price (defaults to auto-estimation)
/////
///// # Returns
///// A `Result<TxHash, EthUtilsError>` representing the transaction hash if successful
/////
///// # Example
///// ```rust
///// use hyperware_process_lib::{eth_utils, wallet, eth};
///// use alloy_primitives::{Address, U256};
///// use std::str::FromStr;
/////
///// // Create wallet and provider
///// let wallet = wallet::Wallet::from_private_key(
/////     "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
/////     8453 // Base chain ID
///// )?;
///// let provider = eth::Provider::new(8453, 60000);
///// let to = Address::from_str("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")?;
///// let amount = U256::from(1000000000000000000u64); // 1 ETH
/////
///// // Send ETH
///// let tx_hash = eth_utils::send_eth(&provider, &wallet, to, amount, None, None)?;
///// println!("Transaction hash: {}", tx_hash);
///// ```
//pub fn send_eth(
//    provider: &crate::eth::Provider,
//    wallet: &Wallet,
//    to: Address,
//    amount_wei: U256,
//    gas_limit: Option<u64>,
//    gas_price: Option<u128>
//) -> Result<TxHash, EthUtilsError> {
//    // Create RLP-encoded transaction
//    let nonce = provider.get_transaction_count(wallet.address(), None)?;
//    let nonce_u64 = u64::try_from(nonce).unwrap_or(0);
//
//    // Get gas price if not provided
//    let gas_price_value = if let Some(price) = gas_price {
//        price
//    } else {
//        let current_gas_price = provider.get_gas_price()?;
//        u128::try_from(current_gas_price).unwrap_or(20000000000)
//    };
//
//    // Get gas limit
//    let gas_limit_value = gas_limit.unwrap_or(21000);
//
//    // Create and sign a transaction manually
//    // First, construct the RLP-encoded transaction
//    let mut rlp_data = Vec::new();
//    rlp_data.extend_from_slice(to.as_slice());
//    rlp_data.extend_from_slice(&amount_wei.to_be_bytes::<32>());
//    rlp_data.extend_from_slice(&nonce_u64.to_be_bytes());
//    rlp_data.extend_from_slice(&gas_limit_value.to_be_bytes());
//    rlp_data.extend_from_slice(&gas_price_value.to_be_bytes());
//
//    // Hash the transaction data with keccak256
//    let mut hasher = sha3::Keccak256::new();
//    hasher.update(&rlp_data);
//    let tx_hash = hasher.finalize();
//
//    // Sign the transaction hash
//    let signed_tx = wallet.sign_transaction_hash(&tx_hash)?;
//
//    // Send raw transaction
//    let tx_hash = provider.send_raw_transaction(signed_tx)?;
//
//    Ok(tx_hash)
//}
//
///// Sends Ether to the owner of the specified Hypermap name.
/////
///// This function first resolves the name to its owner address using Hypermap,
///// then sends the specified amount of Ether to that address.
/////
///// # Parameters
///// - `provider`: The Ethereum provider to use
///// - `wallet`: The wallet to send from
///// - `name`: The Hypermap name (e.g., "alice.hypr")
///// - `amount_eth`: The amount of Ether to send (as a f64)
/////
///// # Returns
///// A `Result<TxHash, EthUtilsError>` representing the transaction hash if successful
/////
///// # Example
///// ```rust
///// use hyperware_process_lib::{eth_utils, wallet, eth};
/////
///// // Create wallet and provider
///// let wallet = wallet::Wallet::from_private_key(
/////     "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
/////     8453 // Base chain ID
///// )?;
///// let provider = eth::Provider::new(8453, 60000);
/////
///// // Send 1.3 ETH to alice.hypr
///// let tx_hash = eth_utils::send_eth_to_name(&provider, &wallet, "alice.hypr", 1.3)?;
///// println!("Transaction hash: {}", tx_hash);
///// ```
//pub fn send_eth_to_name(
//    provider: &crate::eth::Provider,
//    wallet: &Wallet,
//    name: &str,
//    amount_eth: f64
//) -> Result<TxHash, EthUtilsError> {
//    // Get Hypermap instance using our provider
//    let hypermap = Hypermap::new(provider.clone(),
//        Address::from_str(HYPERMAP_ADDRESS).unwrap());
//
//    // Format the name if needed (add .hypr if missing)
//    let formatted_name = format_hypermap_name(name);
//
//    // Resolve name to owner address
//    let (_, owner, _) = hypermap.get(&formatted_name)
//        .map_err(|e| EthUtilsError::NameResolution(format!("Failed to resolve name '{}': {}", formatted_name, e)))?;
//
//    // Convert amount to wei (1 ETH = 10^18 wei)
//    let amount_wei = (amount_eth * 1e18) as u128;
//    let amount_in_wei = U256::from(amount_wei);
//
//    // Send ETH to the resolved address
//    send_eth(provider, wallet, owner, amount_in_wei, None, None)
//}
//
///// Format a name for Hypermap resolution
/////
///// If the name already contains a dot (.), it's returned as is.
///// Otherwise, ".hypr" is appended to the name.
/////
///// # Parameters
///// - `name`: The name to format
/////
///// # Returns
///// A formatted name suitable for Hypermap resolution
//fn format_hypermap_name(name: &str) -> String {
//    // If name already has a domain extension, return as is
//    if name.contains('.') {
//        return name.to_string();
//    }
//
//    // Otherwise, add the default .hypr extension
//    format!("{}.hypr", name)
//}
//
///// Resolve a Hypermap name to its owner's Ethereum address
/////
///// # Parameters
///// - `name`: The Hypermap name to resolve
///// - `chain_id`: Optional chain ID to use (defaults to Base chain)
///// - `timeout_ms`: Optional timeout in milliseconds (defaults to 60 seconds)
/////
///// # Returns
///// A `Result<Address, EthError>` representing the owner's Ethereum address
/////
///// # Example
///// ```rust
///// use hyperware_process_lib::eth_utils;
/////
///// let owner = eth_utils::resolve_name("alice.hypr", None, None)?;
///// println!("Owner address: {}", owner);
///// ```
//pub fn resolve_name(
//    name: &str,
//    chain_id: Option<u64>,
//    timeout_ms: Option<u64>
//) -> Result<Address, EthError> {
//    // Use provided chain ID or default
//    let chain_id = chain_id.unwrap_or(DEFAULT_CHAIN_ID);
//    let timeout = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
//
//    // Create provider
//    let provider = crate::eth::Provider::new(chain_id, timeout);
//
//    // Get Hypermap instance using our provider
//    let hypermap = Hypermap::new(provider,
//        Address::from_str(HYPERMAP_ADDRESS).unwrap());
//
//    // Format the name if needed (add .hypr if missing)
//    let formatted_name = format_hypermap_name(name);
//
//    // Resolve name to owner address
//    let (_, owner, _) = hypermap.get(&formatted_name)?;
//
//    Ok(owner)
//}
//
//#[cfg(test)]
//mod tests {
//    use super::*;
//    use alloy_primitives::{Address, U256};
//    use std::str::FromStr;
//
//    #[test]
//    fn test_format_hypermap_name() {
//        // Test with name that already has dot
//        let name_with_dot = "test.hypr";
//        assert_eq!(format_hypermap_name(name_with_dot), name_with_dot);
//
//        // Test with name that doesn't have dot
//        let name_without_dot = "test";
//        assert_eq!(format_hypermap_name(name_without_dot), "test.hypr");
//    }
//
//    // Note: These tests would need real providers and wallets to run
//    // We'll implement placeholders that describe what should be tested
//
//    #[test]
//    #[ignore] // Ignore this test since it requires network connectivity
//    fn test_resolve_name() {
//        // This would test name resolution with real provider and chain
//        // let name = "test.hypr";
//        // let result = resolve_name(name, Some(DEFAULT_CHAIN_ID), Some(DEFAULT_TIMEOUT_MS));
//        // assert!(result.is_ok());
//    }
//
//    #[test]
//    #[ignore] // Ignore this test since it requires network connectivity
//    fn test_send_eth_to_name() {
//        // This would test ETH sending with real provider and wallet
//        // let wallet = Wallet::new_random(DEFAULT_CHAIN_ID).unwrap();
//        // let provider = crate::eth::Provider::new(DEFAULT_CHAIN_ID, DEFAULT_TIMEOUT_MS);
//        // let result = send_eth_to_name(&provider, &wallet, "test.hypr", 0.001);
//        // assert!(result.is_ok());
//    }
//}
