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

use crate::eth::{EthError, Provider};
use crate::hypermap;
use crate::signer::{EncryptedSignerData, LocalSigner, Signer, SignerError, TransactionData};

use alloy_primitives::{Address as EthAddress, TxHash, U256};
use std::str::FromStr;
use thiserror::Error;

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
                "Empty amount string".to_string(),
            ));
        }

        let value_str = parts[0];
        let unit = parts
            .get(1)
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "eth".to_string());

        let value = value_str.parse::<f64>().map_err(|_| {
            WalletError::InvalidAmount(format!("Invalid numeric value: {}", value_str))
        })?;

        match unit.as_str() {
            "eth" => Ok(Self::from_eth(value)),
            "wei" => Ok(Self {
                wei_value: U256::from(value as u128),
            }),
            _ => Err(WalletError::InvalidAmount(format!(
                "Unknown unit: {}",
                unit
            ))),
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
        return EthAddress::from_str(name).map_err(|_| {
            WalletError::NameResolutionError(format!("Invalid address format: {}", name))
        });
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
        Ok((_tba, owner, _)) => Ok(owner),
        Err(e) => Err(WalletError::NameResolutionError(format!(
            "Failed to resolve name '{}': {}",
            name, e
        ))),
    }
}

/// Send ETH to an address or name
pub fn send_eth<S: Signer>(
    to: &str,
    amount: EthAmount,
    provider: Provider,
    signer: &S,
) -> Result<TxReceipt, WalletError> {
    // Special handling for Anvil (31337) or other test networks
    let chain_id = signer.chain_id();
    // temp
    let is_test_network = chain_id == 31337 || chain_id == 1337;

    // Resolve the name to an address
    let to_address = resolve_name(to, chain_id)?;

    // Get the current nonce for the signer's address
    let from_address = signer.address();
    let nonce = provider
        .get_transaction_count(from_address, None)?
        .to::<u64>();

    // Get gas pricing based on network
    let (gas_price, priority_fee) = if is_test_network {
        // For test networks like Anvil, use a fixed gas price that's known to work
        // These specific values work reliably with Anvil
        (2_000_000_000, 100_000_000) // 2 gwei, 0.1 gwei priority fee
    } else {
        // For real networks, get current gas price
        let base_fee = provider.get_gas_price()?.to::<u128>();

        // Increase by 20% to ensure transaction goes through
        let adjusted_fee = (base_fee * 120) / 100;

        // Priority fee at 10% of gas price
        (adjusted_fee, adjusted_fee / 10)
    };

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

    // Sign the transaction
    let signed_tx = signer.sign_transaction(&tx_data)?;

    // Send the transaction
    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;

    // Return the receipt with transaction details
    Ok(TxReceipt {
        hash: tx_hash,
        details: format!("Sent {} to {}", amount.to_string(), to),
    })
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
    Ok(EthAmount { wei_value: balance })
}
