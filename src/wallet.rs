//! Ethereum wallet functionality for Hyperware.
//!
//! This module provides higher-level wallet functionality, building on top of
//! the cryptographic operations in the signer module. It handles transaction 
//! construction, name resolution, and account management.
//!
//! wallet module:
//! 1. Provides convenient transaction creation and submission
//! 2. Handles Hypermap name resolution
//! 3. Manages account state and balances
//! 4. Offers a simpler interface for common ETH operations (more to do here)

use crate::eth::{
    Provider, 
    EthError,
    BlockNumberOrTag
};
use crate::signer::{
    Signer, 
    LocalSigner, 
    TransactionData, 
    SignerError, 
    EncryptedSignerData
};
use crate::{hypermap, kiprintln};

use thiserror::Error;
use alloy_primitives::{Address as EthAddress, TxHash, U256};
use alloy::rpc::types::TransactionReceipt;
use std::str::FromStr;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("signing error: {0}")]
    SignerError(#[from] SignerError),
    
    #[error("ethereum error: {0}")]
    EthError(#[from] EthError),
    
    #[error("name resolution error: {0}")]
    NameResolutionError(String),
    
    #[error("invalid amount: {0}")]
    InvalidAmount(String),
    
    #[error("transaction error: {0}")]
    TransactionError(String),

    #[error("gas estimation error: {0}")]
    GasEstimationError(String),
    
    #[error("insufficient funds: {0}")]
    InsufficientFunds(String),
    
    #[error("network congestion: {0}")]
    NetworkCongestion(String),
    
    #[error("transaction underpriced")]
    TransactionUnderpriced,
    
    #[error("transaction nonce too low")]
    TransactionNonceTooLow,
}

/// Represents the storage state of a wallet's private key
#[derive(Debug, Clone)]
pub enum KeyStorage {
    /// An unencrypted wallet with a signer
    Decrypted(LocalSigner),
    
    /// An encrypted wallet - contains all the necessary data
    Encrypted(EncryptedSignerData),
}

impl KeyStorage {
    /// Get the encrypted data if this is an encrypted key storage
    pub fn get_encrypted_data(&self) -> Option<Vec<u8>> {
        match self {
            KeyStorage::Encrypted(data) => Some(data.encrypted_data.clone()),
            KeyStorage::Decrypted(_) => None,
        }
    }
    
    /// Get the address associated with this wallet
    pub fn get_address(&self) -> String {
        match self {
            KeyStorage::Decrypted(signer) => signer.address().to_string(),
            KeyStorage::Encrypted(data) => data.address.clone(),
        }
    }
    
    /// Get the chain ID associated with this wallet
    pub fn get_chain_id(&self) -> u64 {
        match self {
            KeyStorage::Decrypted(signer) => signer.chain_id(),
            KeyStorage::Encrypted(data) => data.chain_id,
        }
    }
}

/// Represents an amount of ETH with proper formatting
#[derive(Debug, Clone)]
pub struct EthAmount {
    /// Value in wei
    wei_value: U256,
}

impl EthAmount {
    /// Create a new amount from ETH value
    pub fn from_eth(eth_value: f64) -> Self {
        // Convert ETH to wei (1 ETH = 10^18 wei)
        let wei = (eth_value * 1_000_000_000_000_000_000.0) as u128;
        Self {
            wei_value: U256::from(wei),
        }
    }
    
    /// Create from a string like "0.1 ETH" or "10 wei"
    pub fn from_string(amount_str: &str) -> Result<Self, WalletError> {
        let parts: Vec<&str> = amount_str.trim().split_whitespace().collect();
        
        if parts.is_empty() {
            return Err(WalletError::InvalidAmount(
                "Empty amount string".to_string()
            ));
        }
        
        let value_str = parts[0];
        let unit = parts.get(1).map(|s| s.to_lowercase()).unwrap_or_else(|| "eth".to_string());
        
        let value = value_str.parse::<f64>()
            .map_err(|_| WalletError::InvalidAmount(format!("Invalid numeric value: {}", value_str)))?;
            
        match unit.as_str() {
            "eth" => Ok(Self::from_eth(value)),
            "wei" => Ok(Self {
                wei_value: U256::from(value as u128),
            }),
            _ => Err(WalletError::InvalidAmount(format!("Unknown unit: {}", unit))),
        }
    }
    
    /// Get the value in wei
    pub fn as_wei(&self) -> U256 {
        self.wei_value
    }
    
    /// Get a human-readable string representation
    pub fn to_string(&self) -> String {
        // For values over 0.0001 ETH, show in ETH, otherwise in wei
        if self.wei_value >= U256::from(100_000_000_000_000u128) {
            // Convert to u128 first (safe since ETH total supply fits in u128) then to f64
            let wei_u128 = self.wei_value.to::<u128>();
            let eth_value = wei_u128 as f64 / 1_000_000_000_000_000_000.0;
            format!("{:.6} ETH", eth_value)
        } else {
            format!("{} wei", self.wei_value)
        }
    }
}

/// Transaction receipt returned after sending
#[derive(Debug, Clone)]
pub struct TxReceipt {
    /// Transaction hash
    pub hash: TxHash,
    /// Transaction details
    pub details: String,
}

// The checks here aren't solid, but it works for now. Will also expand with full hypermap support
/// Resolve a .hypr name to an Ethereum address using Hypermap. 
pub fn resolve_name(name: &str, _chain_id: u64) -> Result<EthAddress, WalletError> {
    // If it's already an address, just parse it
    if name.starts_with("0x") && name.len() == 42 {
        return EthAddress::from_str(name)
            .map_err(|_| WalletError::NameResolutionError(format!("Invalid address format: {}", name)));
    }
    
    // Format the name properly if it doesn't contain dots
    let formatted_name = if !name.contains('.') {
        format!("{}.hypr", name)
    } else {
        name.to_string()
    };
    
    // Use hypermap resolution
    let hypermap = hypermap::Hypermap::default(60);
    match hypermap.get(&formatted_name) {
        Ok((_tba, owner, _)) => {
            Ok(owner)
        },
        Err(e) => {
            Err(WalletError::NameResolutionError(
                format!("Failed to resolve name '{}': {}", name, e)
            ))
        }
    }
}

/// Send ETH to an address or name
pub fn send_eth<S: Signer>(
    to: &str,
    amount: EthAmount,
    provider: Provider,
    signer: &S,
) -> Result<TxReceipt, WalletError> {

    kiprintln!("PROCESS_LIB::send_eth provider: {:#?}", provider);

    // Current chain-specific handling
    let chain_id = signer.chain_id();
    kiprintln!("PROCESS_LIB::send_eth chain_id: {}", chain_id);
    
    // This part needs improvement - detect network type more robustly
    let is_test_network = chain_id == 31337 || chain_id == 1337;
    
    // Use network-specific gas strategies
    let (gas_price, priority_fee) = match chain_id {

        // just rough calculations for now
        1 => calculate_eth_mainnet_gas(&provider)?, // mainnet
        8453 => calculate_base_gas(&provider)?, // Base
        10 => calculate_optimism_gas(&provider)?, // Optimism

        // Test networks - keep your current approach
        _ if is_test_network => (2_000_000_000, 100_000_000),
        
        // 30% 
        _ => {
            kiprintln!("PROCESS_LIB::send_eth getting gas price");
            let base_fee = provider.get_gas_price()?.to::<u128>();
            kiprintln!("PROCESS_LIB::send_eth base_fee: {}", base_fee);
            let adjusted_fee = (base_fee * 130) / 100;
            kiprintln!("PROCESS_LIB::send_eth adjusted_fee: {}", adjusted_fee);
            (adjusted_fee, adjusted_fee / 10)
        }
    };

    kiprintln!("PROCESS_LIB::send_eth gas_price: {}", gas_price);

    // Resolve the name to an address
    let to_address = resolve_name(to, chain_id)?;

    kiprintln!("PROCESS_LIB::send_eth to_address: {}", to_address);

    // Get the current nonce for the signer's address
    let from_address = signer.address();
    let nonce = provider.get_transaction_count(from_address, None)?
        .to::<u64>();

    kiprintln!("PROCESS_LIB::send_eth nonce: {}", nonce);

    // Standard gas limit for ETH transfer
    let gas_limit = 21000;
    
    // Prepare transaction data
    let tx_data = TransactionData {
        to: to_address,
        value: amount.as_wei(),
        data: None, // No data for simple ETH transfer
        nonce,
        gas_limit,
        gas_price,
        max_priority_fee: Some(priority_fee),
        chain_id,
    };

    kiprintln!("PROCESS_LIB::send_eth tx_data: {:#?}", tx_data);
    
    // Sign the transaction
    let signed_tx = signer.sign_transaction(&tx_data)?;

    kiprintln!("PROCESS_LIB::send_eth signed_tx: {:?}", signed_tx);
    
    // Send the transaction
    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;

    kiprintln!("lol PROCESS_LIB::send_eth tx_hash: {}", tx_hash);
    
    // Return the receipt with transaction details
    Ok(TxReceipt {
        hash: tx_hash,
        details: format!("Sent {} to {}", amount.to_string(), to),
    })
}

// Helper function to calculate EIP-1559 gas parameters with network-specific values
fn calculate_eip1559_gas(
    provider: &Provider, 
    buffer_fraction: u128, 
    priority_fee: u128
) -> Result<(u128, u128), WalletError> {
    kiprintln!("PROCESS_LIB::calculate_eip1559_gas provider\n", );
    // Get latest block
    let latest_block = provider.get_block_by_number(BlockNumberOrTag::Latest, false)?
        .ok_or_else(|| WalletError::TransactionError("Failed to get latest block".into()))?;

    kiprintln!("PROCESS_LIB::calculate_eip1559_gas latest_block: {:#?}", latest_block);
    
    // Get base fee
    let base_fee = latest_block.header.inner.base_fee_per_gas
        .ok_or_else(|| WalletError::TransactionError("No base fee in block".into()))?
        as u128;

    kiprintln!("PROCESS_LIB::calculate_eip1559_gas base_fee: {}", base_fee);
    
    // Calculate max fee with the provided buffer fraction
    let max_fee = base_fee + (base_fee / buffer_fraction);

    kiprintln!("PROCESS_LIB::calculate_eip1559_gas max_fee: {}", max_fee);
    
    Ok((max_fee, priority_fee))
}

// Network-specific gas calculation for Ethereum mainnet
fn calculate_eth_mainnet_gas(provider: &Provider) -> Result<(u128, u128), WalletError> {
    // For mainnet: 50% buffer and 1.5 gwei priority fee
    calculate_eip1559_gas(provider, 2, 1_500_000_000u128)
}

fn calculate_base_gas(provider: &Provider) -> Result<(u128, u128), WalletError> {
    // Get the latest block to determine current gas conditions
    let latest_block = provider.get_block_by_number(BlockNumberOrTag::Latest, false)?
        .ok_or_else(|| WalletError::TransactionError("Failed to get latest block".into()))?;
    
    // Get base fee from the block
    let base_fee = latest_block.header.inner.base_fee_per_gas
        .ok_or_else(|| WalletError::TransactionError("No base fee in block".into()))?
        as u128;
    
    // Calculate max fee with a 33% buffer
    let max_fee = base_fee + (base_fee / 3);
    
    // Dynamic priority fee - 10% of base fee, but with a minimum and a maximum
    // Low minimum for Base which has very low gas prices
    let min_priority_fee = 100_000u128; // 0.0001 gwei minimum
    let max_priority_fee = max_fee / 2; // Never more than half the max fee
    
    let priority_fee = std::cmp::max(
        min_priority_fee,
        std::cmp::min(base_fee / 10, max_priority_fee)
    );
    
    Ok((max_fee, priority_fee))
}

//// Gas calculation for Base network
//fn calculate_base_gas(provider: &Provider) -> Result<(u128, u128), WalletError> {
//    // For Base: 33% buffer and 0.5 gwei priority fee
//    calculate_eip1559_gas(provider, 3, 500_000_000u128)
//}

// Gas calculation for Optimism network
fn calculate_optimism_gas(provider: &Provider) -> Result<(u128, u128), WalletError> {
    // For Optimism: 25% buffer and 0.3 gwei priority fee
    calculate_eip1559_gas(provider, 4, 300_000_000u128)
}

/// Get the ETH balance for an address or name
pub fn get_balance(
    address_or_name: &str,
    chain_id: u64,
    provider: Provider,
) -> Result<EthAmount, WalletError> {
    // Resolve name to address
    let address = resolve_name(address_or_name, chain_id)?;
    
    // Query balance
    let balance = provider.get_balance(address, None)?;
    
    // Return formatted amount
    Ok(EthAmount {
        wei_value: balance,
    })
}

pub fn wait_for_transaction(
    tx_hash: TxHash, 
    provider: Provider,
    confirmations: u64,
    timeout_secs: u64
) -> Result<TransactionReceipt, WalletError> {
    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);
    
    loop {
        // Check if we've exceeded the timeout
        if start_time.elapsed() > timeout {
            return Err(WalletError::TransactionError(
                format!("Transaction confirmation timeout after {} seconds", timeout_secs)
            ));
        }
        
        // Try to get the receipt
        if let Ok(Some(receipt)) = provider.get_transaction_receipt(tx_hash) {
            // Check if we have enough confirmations
            let latest_block = provider.get_block_number()?;
            let receipt_block = receipt.block_number.unwrap_or(0) as u64;
            
            if latest_block >= receipt_block + confirmations {
                return Ok(receipt);
            }
        }
        
        // Wait a bit before checking again
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

// Extract error information from RPC errors
fn extract_rpc_error(error: &EthError) -> WalletError {
    match error {
        EthError::RpcError(value) => {
            // Try to parse the error message
            if let Some(message) = value.get("message").and_then(|m| m.as_str()) {
                if message.contains("insufficient funds") {
                    return WalletError::InsufficientFunds(message.to_string());
                } else if message.contains("underpriced") {
                    return WalletError::TransactionUnderpriced;
                } else if message.contains("nonce too low") {
                    return WalletError::TransactionNonceTooLow;
                }
                // Add more error patterns as needed
            }
            WalletError::TransactionError(format!("RPC error: {:?}", value))
        },
        _ => WalletError::TransactionError(format!("Ethereum error: {:?}", error))
    }
}