//! ## (unfinished, unpolished and not fully tested)  Ethereum wallet functionality for Hyperware.
//!
//! This module provides high-level wallet functionality for Ethereum,
//! including transaction signing, contract interaction, and account management.
//! It provides a simple interface for sending ETH and interacting with ERC20,
//! ERC721, and ERC1155 tokens.
//!
//! ERC6551 + the hypermap is not supported yet.
//! 

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
use crate::hypermap::{
    namehash, 
    valid_note, 
    valid_fact, 
    valid_name,
};
use crate::hypermap;
use crate::kiprintln;

use thiserror::Error;
use alloy_primitives::{
    Address as EthAddress, 
    TxHash, 
    U256,
    Bytes
};
use alloy::rpc::types::{
    Block, BlockId, Filter, FilterBlockOption, FilterSet, Log, Transaction,
    TransactionReceipt, request::TransactionRequest,
};
use alloy_primitives::TxKind;
use std::str::FromStr;
use alloy_sol_types::{sol, SolCall};
use serde::{Serialize, Deserialize};
sol! {
    interface IERC20 {
        function balanceOf(address who) external view returns (uint256);
        function transfer(address to, uint256 value) external returns (bool);
        function approve(address spender, uint256 value) external returns (bool);
        function transferFrom(address from, address to, uint256 value) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function totalSupply() external view returns (uint256);
        function decimals() external view returns (uint8);
        function symbol() external view returns (string);
        function name() external view returns (string);
    }

    interface IERC721 {
        function balanceOf(address owner) external view returns (uint256);
        function ownerOf(uint256 tokenId) external view returns (address);
        function safeTransferFrom(address from, address to, uint256 tokenId) external;
        function transferFrom(address from, address to, uint256 tokenId) external;
        function approve(address to, uint256 tokenId) external;
        function setApprovalForAll(address operator, bool approved) external;
        function getApproved(uint256 tokenId) external view returns (address);
        function isApprovedForAll(address owner, address operator) external view returns (bool);
    }

    interface IERC1155 {
        function balanceOf(address account, uint256 id) external view returns (uint256);
        function balanceOfBatch(address[] accounts, uint256[] ids) external view returns (uint256[]);
        function setApprovalForAll(address operator, bool approved) external;
        function isApprovedForAll(address account, address operator) external view returns (bool);
        function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes data) external;
        function safeBatchTransferFrom(address from, address to, uint256[] ids, uint256[] amounts, bytes data) external;
    }

    interface IERC6551Account {
        function execute(address to, uint256 value, bytes calldata data, uint8 operation) external returns (bytes);
    }
}

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
    
    #[error("permission denied: {0}")]
    PermissionDenied(String),
}

/// Represents the storage state of a wallet's private key
#[derive(Debug, Clone)]
pub enum KeyStorage {
    /// An unencrypted wallet with a signer
    Decrypted(LocalSigner),
    Encrypted(EncryptedSignerData),
}

// Manual implementation of Serialize for KeyStorage
impl Serialize for KeyStorage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        
        match self {
            KeyStorage::Decrypted(signer) => {
                let mut state = serializer.serialize_struct("KeyStorage", 2)?;
                state.serialize_field("type", "Decrypted")?;
                state.serialize_field("signer", signer)?;
                state.end()
            },
            KeyStorage::Encrypted(data) => {
                let mut state = serializer.serialize_struct("KeyStorage", 2)?;
                state.serialize_field("type", "Encrypted")?;
                state.serialize_field("data", data)?;
                state.end()
            }
        }
    }
}

// Manual implementation of Deserialize for KeyStorage
impl<'de> Deserialize<'de> for KeyStorage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "type")]
        enum KeyStorageData {
            #[serde(rename = "Decrypted")]
            Decrypted { signer: LocalSigner },
            
            #[serde(rename = "Encrypted")]
            Encrypted { data: EncryptedSignerData },
        }
        
        let data = KeyStorageData::deserialize(deserializer)?;
        
        match data {
            KeyStorageData::Decrypted { signer } => Ok(KeyStorage::Decrypted(signer)),
            KeyStorageData::Encrypted { data } => Ok(KeyStorage::Encrypted(data)),
        }
    }
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
        // Just return the numerical value without denomination
        if self.wei_value >= U256::from(100_000_000_000_000u128) {
            // Convert to u128 first (safe since ETH total supply fits in u128) then to f64
            let wei_u128 = self.wei_value.to::<u128>();
            let eth_value = wei_u128 as f64 / 1_000_000_000_000_000_000.0;
            format!("{:.6}", eth_value)
        } else {
            format!("{}", self.wei_value)
        }
    }

    /// Get a formatted string with denomination (for display purposes)
    pub fn to_display_string(&self) -> String {
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

/// Result type for Hypermap transactions
#[derive(Debug, Clone)]
pub struct HypermapTxReceipt {
    /// Transaction hash
    pub hash: TxHash,
    /// Description of the operation
    pub description: String,
}

//
// HELPER FUNCTIONS
//

/// Helper for making contract view function calls
fn call_view_function<T: SolCall>(
    contract: EthAddress,
    call: T,
    provider: &Provider
) -> Result<T::Return, WalletError> {
    let call_data = call.abi_encode();
    let tx = TransactionRequest {
        to: Some(TxKind::Call(contract)),
        input: call_data.into(),
        ..Default::default()
    };
    
    let result = provider.call(tx, None)?;
    
    if result.is_empty() {
        return Err(WalletError::TransactionError("Empty result from call".into()));
    }
    
    match T::abi_decode_returns(&result, true) {
        Ok(decoded) => Ok(decoded),
        Err(e) => Err(WalletError::TransactionError(
            format!("Failed to decode result: {}", e)
        ))
    }
}

/// Calculate gas parameters based on network type
fn calculate_gas_params(provider: &Provider, chain_id: u64) -> Result<(u128, u128), WalletError> {

    match chain_id {
        1 => { // Mainnet: 50% buffer and 1.5 gwei priority fee
            let latest_block = provider.get_block_by_number(BlockNumberOrTag::Latest, false)?
                .ok_or_else(|| WalletError::TransactionError("Failed to get latest block".into()))?;
            
            let base_fee = latest_block.header.inner.base_fee_per_gas
                .ok_or_else(|| WalletError::TransactionError("No base fee in block".into()))?
                as u128;
            
            Ok((base_fee + (base_fee / 2), 1_500_000_000u128))
        },
        8453 => { // Base
            let latest_block = provider.get_block_by_number(BlockNumberOrTag::Latest, false)?
                .ok_or_else(|| WalletError::TransactionError("Failed to get latest block".into()))?;
            
            let base_fee = latest_block.header.inner.base_fee_per_gas
                .ok_or_else(|| WalletError::TransactionError("No base fee in block".into()))?
                as u128;
            
            
            let max_fee = base_fee + (base_fee / 3);
            
            let min_priority_fee = 100_000u128;
            
            let max_priority_fee = max_fee / 2;
            
            let priority_fee = std::cmp::max(min_priority_fee, std::cmp::min(base_fee / 10, max_priority_fee));

            Ok((max_fee, priority_fee))
        },
        10 => { // Optimism: 25% buffer and 0.3 gwei priority fee
            let latest_block = provider.get_block_by_number(BlockNumberOrTag::Latest, false)?
                .ok_or_else(|| WalletError::TransactionError("Failed to get latest block".into()))?;
            
            let base_fee = latest_block.header.inner.base_fee_per_gas
                .ok_or_else(|| WalletError::TransactionError("No base fee in block".into()))?
                as u128;
            
            Ok((base_fee + (base_fee / 4), 300_000_000u128))
        },
        31337 | 1337 => { // Test networks
            Ok((2_000_000_000, 100_000_000))
        },
        _ => { // Default: 30% buffer
            let base_fee = provider.get_gas_price()?.to::<u128>();
            let adjusted_fee = (base_fee * 130) / 100;
            Ok((adjusted_fee, adjusted_fee / 10))
        }
    }
}

/// Prepare and send a transaction with common parameters
fn prepare_and_send_tx<S: Signer, F>(
    to: EthAddress,
    call_data: Vec<u8>,
    value: U256,
    provider: &Provider,
    signer: &S,
    gas_limit: Option<u64>,
    format_receipt: F
) -> Result<TxReceipt, WalletError>
where F: FnOnce(TxHash) -> String {

    // Get the current nonce for the signer's address
    let signer_address = signer.address();
    let nonce = provider.get_transaction_count(signer_address, None)?
        .to::<u64>();
    
    
    // Calculate gas parameters based on chain ID
    let (gas_price, priority_fee) = calculate_gas_params(provider, signer.chain_id())?;
    
    
    // Use provided gas limit or estimate it with 20% buffer
    let gas_limit = match gas_limit {
        Some(limit) => limit,
        None => {
            let tx_req = TransactionRequest {
                from: Some(signer_address),
                to: Some(TxKind::Call(to)),
                input: call_data.clone().into(),
                ..Default::default()
            };
            
            match provider.estimate_gas(tx_req, None) {
                Ok(gas) => {
                    let limit = (gas.to::<u64>() * 120) / 100; // Add 20% buffer
                    limit
                },
                Err(_) => {
                    100_000 // Default value if estimation fails
                }
            }
        }
    };
    
    // Prepare transaction data
    let tx_data = TransactionData {
        to,
        value,
        data: Some(call_data),
        nonce,
        gas_limit,
        gas_price,
        max_priority_fee: Some(priority_fee),
        chain_id: signer.chain_id(),
    };
    
    
    // Sign and send transaction
    let signed_tx = signer.sign_transaction(&tx_data)?;
    
    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;
    
    kiprintln!("PL:: Transaction sent with hash: {}", tx_hash);
    
    // Return the receipt with formatted details
    Ok(TxReceipt {
        hash: tx_hash,
        details: format_receipt(tx_hash),
    })
}

/// Helper for creating Hypermap transaction operations
fn create_hypermap_tx<S: Signer, F>(
    parent_entry: &str,
    hypermap_call_data: Bytes,
    description_fn: F,
    provider: Provider,
    signer: &S
) -> Result<HypermapTxReceipt, WalletError>
where F: FnOnce() -> String {
    // Get the parent TBA address and verify ownership
    let hypermap = provider.hypermap();
    let parent_hash_str = namehash(parent_entry);
    let (tba, owner, _) = hypermap.get_hash(&parent_hash_str)?;
    
    // Check that the signer is the owner of the parent entry
    let signer_address = signer.address();
    if signer_address != owner {
        return Err(WalletError::PermissionDenied(
            format!("Signer address {} does not own the entry {}", signer_address, parent_entry)
        ));
    }
    
    // Create the ERC-6551 execute call
    let execute_call = IERC6551Account::executeCall {
        to: *hypermap.address(),
        value: U256::ZERO,
        data: hypermap_call_data,
        operation: 0, // CALL operation
    };
    
    // Format receipt message
    let description = description_fn();
    let format_receipt = move |_| description.clone();
    
    // For ERC-6551 operations we need a higher gas limit
    let gas_limit = Some(600_000);
    
    // Send the transaction
    let receipt = prepare_and_send_tx(
        tba,
        execute_call.abi_encode(),
        U256::ZERO,
        &provider,
        signer,
        gas_limit,
        format_receipt
    )?;
    
    // Convert to Hypermap receipt
    Ok(HypermapTxReceipt {
        hash: receipt.hash,
        description: receipt.details,
    })
}

//
// NAME RESOLUTION
//

// Resolve a .hypr/.os/future tlzs names to an Ethereum address using Hypermap
pub fn resolve_name(name: &str, chain_id: u64) -> Result<EthAddress, WalletError> {
    // If it's already an address, just parse it
    if name.starts_with("0x") && name.len() == 42 {
        return EthAddress::from_str(name).map_err(|_| {
            WalletError::NameResolutionError(format!("Invalid address format: {}", name))
        });
    }
    
    // hardcoded to .hypr for now
    let formatted_name = if !name.contains('.') {
        format!("{}.hypr", name)
    } else {
        name.to_string()
    };

    // Use hypermap resolution
    let hypermap = hypermap::Hypermap::default(chain_id);
    match hypermap.get(&formatted_name) {
        Ok((_tba, owner, _)) => Ok(owner),
        Err(e) => Err(WalletError::NameResolutionError(format!(
            "Failed to resolve name '{}': {}",
            name, e
        ))),
    }
}

/// Resolve a token symbol to its contract address on the specified chain
pub fn resolve_token_symbol(token: &str, chain_id: u64) -> Result<EthAddress, WalletError> {
    // If it's already an address, just parse it
    if token.starts_with("0x") && token.len() == 42 {
        return EthAddress::from_str(token)
            .map_err(|_| WalletError::NameResolutionError(format!("Invalid address format: {}", token)));
    }
    
    // Convert to uppercase for case-insensitive comparison
    let token_upper = token.to_uppercase();
    
    // Map of known token addresses by chain ID and symbol
    match chain_id {
        1 => { // Ethereum Mainnet
            match token_upper.as_str() {
                "USDC" => EthAddress::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                    .map_err(|_| WalletError::NameResolutionError("Invalid USDC address format".to_string())),
                "USDT" => EthAddress::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7")
                    .map_err(|_| WalletError::NameResolutionError("Invalid USDT address format".to_string())),
                "DAI" => EthAddress::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                    .map_err(|_| WalletError::NameResolutionError("Invalid DAI address format".to_string())),
                "WETH" => EthAddress::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                    .map_err(|_| WalletError::NameResolutionError("Invalid WETH address format".to_string())),
                "WBTC" => EthAddress::from_str("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599")
                    .map_err(|_| WalletError::NameResolutionError("Invalid WBTC address format".to_string())),
                _ => Err(WalletError::NameResolutionError(
                    format!("Token '{}' not recognized on chain ID {}", token, chain_id)
                )),
            }
        },
        8453 => { // Base
            match token_upper.as_str() {
                "USDC" => EthAddress::from_str("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
                    .map_err(|_| WalletError::NameResolutionError("Invalid USDC address format".to_string())),
                "DAI" => EthAddress::from_str("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb")
                    .map_err(|_| WalletError::NameResolutionError("Invalid DAI address format".to_string())),
                "WETH" => EthAddress::from_str("0x4200000000000000000000000000000000000006")
                    .map_err(|_| WalletError::NameResolutionError("Invalid WETH address format".to_string())),
                _ => Err(WalletError::NameResolutionError(
                    format!("Token '{}' not recognized on chain ID {}", token, chain_id)
                )),
            }
        },
        10 => { // Optimism
            match token_upper.as_str() {
                "USDC" => EthAddress::from_str("0x7F5c764cBc14f9669B88837ca1490cCa17c31607")
                    .map_err(|_| WalletError::NameResolutionError("Invalid USDC address format".to_string())),
                "DAI" => EthAddress::from_str("0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1")
                    .map_err(|_| WalletError::NameResolutionError("Invalid DAI address format".to_string())),
                "WETH" => EthAddress::from_str("0x4200000000000000000000000000000000000006")
                    .map_err(|_| WalletError::NameResolutionError("Invalid WETH address format".to_string())),
                _ => Err(WalletError::NameResolutionError(
                    format!("Token '{}' not recognized on chain ID {}", token, chain_id)
                )),
            }
        },
        137 => { // Polygon
            match token_upper.as_str() {
                "USDC" => EthAddress::from_str("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174")
                    .map_err(|_| WalletError::NameResolutionError("Invalid USDC address format".to_string())),
                "USDT" => EthAddress::from_str("0xc2132D05D31c914a87C6611C10748AEb04B58e8F")
                    .map_err(|_| WalletError::NameResolutionError("Invalid USDT address format".to_string())),
                "DAI" => EthAddress::from_str("0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063")
                    .map_err(|_| WalletError::NameResolutionError("Invalid DAI address format".to_string())),
                "WETH" => EthAddress::from_str("0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619")
                    .map_err(|_| WalletError::NameResolutionError("Invalid WETH address format".to_string())),
                "WMATIC" => EthAddress::from_str("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270")
                    .map_err(|_| WalletError::NameResolutionError("Invalid WMATIC address format".to_string())),
                _ => Err(WalletError::NameResolutionError(
                    format!("Token '{}' not recognized on chain ID {}", token, chain_id)
                )),
            }
        },
        42161 => { // Arbitrum
            match token_upper.as_str() {
                "USDC" => EthAddress::from_str("0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8")
                    .map_err(|_| WalletError::NameResolutionError("Invalid USDC address format".to_string())),
                "USDT" => EthAddress::from_str("0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9")
                    .map_err(|_| WalletError::NameResolutionError("Invalid USDT address format".to_string())),
                "DAI" => EthAddress::from_str("0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1")
                    .map_err(|_| WalletError::NameResolutionError("Invalid DAI address format".to_string())),
                "WETH" => EthAddress::from_str("0x82aF49447D8a07e3bd95BD0d56f35241523fBab1")
                    .map_err(|_| WalletError::NameResolutionError("Invalid WETH address format".to_string())),
                _ => Err(WalletError::NameResolutionError(
                    format!("Token '{}' not recognized on chain ID {}", token, chain_id)
                )),
            }
        },
        11155111 => { // Sepolia Testnet
            match token_upper.as_str() {
                // Common tokens on Sepolia testnet
                "USDC" => EthAddress::from_str("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238")
                    .map_err(|_| WalletError::NameResolutionError("Invalid USDC address format".to_string())),
                "USDT" => EthAddress::from_str("0x8267cF9254734C6Eb452a7bb9AAF97B392258b21")
                    .map_err(|_| WalletError::NameResolutionError("Invalid USDT address format".to_string())),
                "DAI" => EthAddress::from_str("0x3e622317f8C93f7328350cF0B56d9eD4C620C5d6")
                    .map_err(|_| WalletError::NameResolutionError("Invalid DAI address format".to_string())),
                "WETH" => EthAddress::from_str("0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9")
                    .map_err(|_| WalletError::NameResolutionError("Invalid WETH address format".to_string())),
                _ => Err(WalletError::NameResolutionError(
                    format!("Token '{}' not recognized on Sepolia testnet. Please use a contract address.", token)
                )),
            }
        },
        // Test networks
        31337 | 1337 => {
            return Err(WalletError::NameResolutionError(
                format!("Token symbol resolution not supported on test networks. Please use the full contract address.")
            ));
        },
        _ => {
            return Err(WalletError::NameResolutionError(
                format!("Token symbol resolution not supported for chain ID {}", chain_id)
            ));
        }
    }
    .map_err(|e| match e {
        WalletError::NameResolutionError(msg) => WalletError::NameResolutionError(msg),
        _ => WalletError::NameResolutionError(
            format!("Invalid address format for token '{}' on chain ID {}", token, chain_id)
        ),
    })
}


//
// ETHEREUM FUNCTIONS
//

/// Send ETH to an address or name
pub fn send_eth<S: Signer>(
    to: &str,
    amount: EthAmount,
    provider: Provider,
    signer: &S,
) -> Result<TxReceipt, WalletError> {
    // Resolve the name to an address
    let to_address = resolve_name(to, signer.chain_id())?;
    
    // Standard gas limit for ETH transfer is always 21000
    let gas_limit = Some(21000);
    
    // Format receipt message
    let amount_str = amount.to_string();
    let format_receipt = move |_tx_hash| {
        format!("Sent {} to {}", amount_str, to)
    };
    
    // For ETH transfers, we have no call data
    let empty_call_data = vec![];
    
    // Use the helper function to prepare and send the transaction
    prepare_and_send_tx(
        to_address,
        empty_call_data,
        amount.as_wei(),
        &provider,
        signer,
        gas_limit,
        format_receipt
    )
}

/// Get the ETH balance for an address or name
pub fn get_eth_balance(
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

/// Wait for a transaction to be confirmed
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

//
// ERC-20 TOKEN FUNCTIONS
//

/// Get the ERC20 token balance of an address or name
/// Returns the balance in token units (adjusted for decimals)
pub fn erc20_balance_of(
    token_address: &str,
    owner_address: &str,
    provider: &Provider
) -> Result<f64, WalletError> {
    // First try to resolve the token as a symbol
    let token = match resolve_token_symbol(token_address, provider.chain_id) {
        Ok(addr) => addr,
        Err(_) => resolve_name(token_address, provider.chain_id)?, // Fall back to regular name resolution
    };
    
    let owner = resolve_name(owner_address, provider.chain_id)?;
    
    let call = IERC20::balanceOfCall { who: owner };
    let balance = call_view_function(token, call, provider)?;
    
    let decimals = erc20_decimals(token_address, provider)?;
    let balance_float = balance._0.to::<u128>() as f64 / 10f64.powi(decimals as i32);
    
    Ok(balance_float)
}

/// Get the number of decimals for an ERC20 token
pub fn erc20_decimals(token_address: &str, provider: &Provider) -> Result<u8, WalletError> {
    let token = match resolve_token_symbol(token_address, provider.chain_id) {
        Ok(addr) => addr,
        Err(_) => resolve_name(token_address, provider.chain_id)?,
    };
    
    let call = IERC20::decimalsCall {};
    let decimals = call_view_function(token, call, provider)?;
    Ok(decimals._0)
}

/// Get the token symbol for an ERC20 token
pub fn erc20_symbol(token_address: &str, provider: &Provider) -> Result<String, WalletError> {
    let token = match resolve_token_symbol(token_address, provider.chain_id) {
        Ok(addr) => addr,
        Err(_) => resolve_name(token_address, provider.chain_id)?,
    };
    
    let call = IERC20::symbolCall {};
    let symbol = call_view_function(token, call, provider)?;
    Ok(symbol._0)
}

/// Get the token name for an ERC20 token
pub fn erc20_name(token_address: &str, provider: &Provider) -> Result<String, WalletError> {
    let token = match resolve_token_symbol(token_address, provider.chain_id) {
        Ok(addr) => addr,
        Err(_) => resolve_name(token_address, provider.chain_id)?,
    };
    
    let call = IERC20::nameCall {};
    let name = call_view_function(token, call, provider)?;
    Ok(name._0)
}

/// Get the total supply of an ERC20 token
pub fn erc20_total_supply(token_address: &str, provider: &Provider) -> Result<U256, WalletError> {
    let token = match resolve_token_symbol(token_address, provider.chain_id) {
        Ok(addr) => addr,
        Err(_) => resolve_name(token_address, provider.chain_id)?,
    };
    
    let call = IERC20::totalSupplyCall {};
    let total_supply = call_view_function(token, call, provider)?;
    Ok(total_supply._0)
}

/// Get the allowance for an ERC20 token
pub fn erc20_allowance(
    token_address: &str,
    owner_address: &str,
    spender_address: &str,
    provider: &Provider
) -> Result<U256, WalletError> {
    let token = match resolve_token_symbol(token_address, provider.chain_id) {
        Ok(addr) => addr,
        Err(_) => resolve_name(token_address, provider.chain_id)?,
    };
    
    let owner = resolve_name(owner_address, provider.chain_id)?;
    let spender = resolve_name(spender_address, provider.chain_id)?;
    
    let call = IERC20::allowanceCall { owner, spender };
    let allowance = call_view_function(token, call, provider)?;
    Ok(allowance._0)
}

/// Transfer ERC20 tokens to an address or name
pub fn erc20_transfer<S: Signer>(
    token_address: &str,
    to_address: &str,
    amount: U256,
    provider: &Provider,
    signer: &S
) -> Result<TxReceipt, WalletError> {
    kiprintln!("PL:: Transferring {} tokens to {} on {}", amount, to_address, provider.chain_id);

    // Resolve token address (could be a symbol like "USDC")
    let token = match resolve_token_symbol(token_address, provider.chain_id) {
        Ok(addr) => addr,
        Err(_) => resolve_name(token_address, provider.chain_id)?,
    };
    
    kiprintln!("PL:: Resolved token address: {}", token);
    
    // Resolve recipient address
    let to = resolve_name(to_address, provider.chain_id)?;
    kiprintln!("PL:: Resolved recipient address: {}", to);
    
    // Create the call
    let call = IERC20::transferCall { to, value: amount };
    let call_data = call.abi_encode();
    
    // Get token details for receipt formatting
    let token_symbol = erc20_symbol(token_address, provider).unwrap_or_else(|_| "tokens".to_string());
    let token_decimals = erc20_decimals(token_address, provider).unwrap_or(18);
    
    
    // Format receipt message
    let format_receipt = move |_| {
        let amount_float = amount.to::<u128>() as f64 / 10f64.powi(token_decimals as i32);
        format!("Transferred {:.6} {} to {}", amount_float, token_symbol, to_address)
    };
    
    
    // Prepare and send transaction
    prepare_and_send_tx(
        token, 
        call_data, 
        U256::ZERO, 
        provider,
        signer,
        Some(100_000), // Default gas limit for ERC20 transfers
        format_receipt
    )
}

/// Approve an address to spend ERC20 tokens
pub fn erc20_approve<S: Signer>(
    token_address: &str,
    spender_address: &str,
    amount: U256,
    provider: &Provider,
    signer: &S
) -> Result<TxReceipt, WalletError> {
    // Resolve addresses
    let token = resolve_name(token_address, provider.chain_id)?;
    let spender = resolve_name(spender_address, provider.chain_id)?;
    
    // Create the call
    let call = IERC20::approveCall { spender, value: amount };
    let call_data = call.abi_encode();
    
    // Get token details for receipt formatting
    let token_symbol = erc20_symbol(token_address, provider).unwrap_or_else(|_| "tokens".to_string());
    let token_decimals = erc20_decimals(token_address, provider).unwrap_or(18);
    
    // Format receipt message
    let format_receipt = move |_| {
        let amount_float = amount.to::<u128>() as f64 / 10f64.powi(token_decimals as i32);
        format!("Approved {:.6} {} to be spent by {}", amount_float, token_symbol, spender_address)
    };
    
    // Prepare and send transaction
    prepare_and_send_tx(
        token,
        call_data,
        U256::ZERO,
        provider,
        signer,
        Some(60_000), // Default gas limit for approvals
        format_receipt
    )
}

/// Transfer ERC20 tokens from one address to another (requires approval)
pub fn erc20_transfer_from<S: Signer>(
    token_address: &str,
    from_address: &str,
    to_address: &str,
    amount: U256,
    provider: &Provider,
    signer: &S
) -> Result<TxReceipt, WalletError> {
    // Resolve addresses
    let token = resolve_name(token_address, provider.chain_id)?;
    let from = resolve_name(from_address, provider.chain_id)?;
    let to = resolve_name(to_address, provider.chain_id)?;
    
    // Create the call
    let call = IERC20::transferFromCall { from, to, value: amount };
    let call_data = call.abi_encode();
    
    // Get token details for receipt formatting
    let token_symbol = erc20_symbol(token_address, provider).unwrap_or_else(|_| "tokens".to_string());
    let token_decimals = erc20_decimals(token_address, provider).unwrap_or(18);
    
    // Format receipt message
    let format_receipt = move |_| {
        let amount_float = amount.to::<u128>() as f64 / 10f64.powi(token_decimals as i32);
        format!("Transferred {:.6} {} from {} to {}", 
            amount_float, token_symbol, from_address, to_address)
    };
    
    // Prepare and send transaction
    prepare_and_send_tx(
        token,
        call_data,
        U256::ZERO,
        provider,
        signer,
        Some(100_000), // Default gas limit
        format_receipt
    )
}

//
// ERC-721 NFT FUNCTIONS
//

/// Get the NFT balance of an address
pub fn erc721_balance_of(
    token_address: &str,
    owner_address: &str,
    provider: &Provider
) -> Result<U256, WalletError> {
    let token = resolve_name(token_address, provider.chain_id)?;
    let owner = resolve_name(owner_address, provider.chain_id)?;
    
    let call = IERC721::balanceOfCall { owner };
    let balance = call_view_function(token, call, provider)?;
    Ok(balance._0)
}

/// Get the owner of an NFT token
pub fn erc721_owner_of(
    token_address: &str,
    token_id: U256,
    provider: &Provider
) -> Result<EthAddress, WalletError> {
    let token = resolve_name(token_address, provider.chain_id)?;
    let call = IERC721::ownerOfCall { tokenId: token_id };
    let owner = call_view_function(token, call, provider)?;
    Ok(owner._0)
}

/// Check if an operator is approved for all NFTs of an owner
pub fn erc721_is_approved_for_all(
    token_address: &str,
    owner_address: &str,
    operator_address: &str,
    provider: &Provider
) -> Result<bool, WalletError> {
    let token = resolve_name(token_address, provider.chain_id)?;
    let owner = resolve_name(owner_address, provider.chain_id)?;
    let operator = resolve_name(operator_address, provider.chain_id)?;
    
    let call = IERC721::isApprovedForAllCall { owner, operator };
    let is_approved = call_view_function(token, call, provider)?;
    Ok(is_approved._0)
}

/// Safely transfer an NFT
pub fn erc721_safe_transfer_from<S: Signer>(
    token_address: &str,
    from_address: &str,
    to_address: &str,
    token_id: U256,
    provider: &Provider,
    signer: &S
) -> Result<TxReceipt, WalletError> {
    // Resolve addresses
    let token = resolve_name(token_address, provider.chain_id)?;
    let from = resolve_name(from_address, provider.chain_id)?;
    let to = resolve_name(to_address, provider.chain_id)?;
    
    // Create the call
    let call = IERC721::safeTransferFromCall { from, to, tokenId: token_id };
    let call_data = call.abi_encode();
    
    // Format receipt message
    let format_receipt = move |_| {
        format!("Safely transferred NFT ID {} from {} to {}", token_id, from_address, to_address)
    };
    
    // Prepare and send transaction
    prepare_and_send_tx(
        token,
        call_data,
        U256::ZERO,
        provider,
        signer,
        Some(200_000), // Higher gas limit for NFT transfers
        format_receipt
    )
}

/// Set approval for all tokens to an operator
pub fn erc721_set_approval_for_all<S: Signer>(
    token_address: &str,
    operator_address: &str,
    approved: bool,
    provider: &Provider,
    signer: &S
) -> Result<TxReceipt, WalletError> {
    // Resolve addresses
    let token = resolve_name(token_address, provider.chain_id)?;
    let operator = resolve_name(operator_address, provider.chain_id)?;
    
    // Create the call
    let call = IERC721::setApprovalForAllCall { operator, approved };
    let call_data = call.abi_encode();
    
    // Format receipt message
    let format_receipt = move |_| {
        format!(
            "{} operator {} to manage all of your NFTs in contract {}", 
            if approved { "Approved" } else { "Revoked approval for" },
            operator_address,
            token_address
        )
    };
    
    // Prepare and send transaction
    prepare_and_send_tx(
        token,
        call_data,
        U256::ZERO,
        provider,
        signer,
        Some(60_000), // Default gas limit for approvals
        format_receipt
    )
}

//
// ERC-1155 MULTI-TOKEN FUNCTIONS
//

/// Get the balance of a specific token ID for an account
pub fn erc1155_balance_of(
    token_address: &str,
    account_address: &str,
    token_id: U256,
    provider: &Provider
) -> Result<U256, WalletError> {
    let token = resolve_name(token_address, provider.chain_id)?;
    let account = resolve_name(account_address, provider.chain_id)?;
    
    let call = IERC1155::balanceOfCall { account, id: token_id };
    let balance = call_view_function(token, call, provider)?;
    Ok(balance._0)
}

/// Get balances for multiple accounts and token IDs
pub fn erc1155_balance_of_batch(
    token_address: &str,
    account_addresses: Vec<&str>,
    token_ids: Vec<U256>,
    provider: &Provider
) -> Result<Vec<U256>, WalletError> {
    // Check that arrays are same length
    if account_addresses.len() != token_ids.len() {
        return Err(WalletError::TransactionError(
            "Arrays of accounts and token IDs must have the same length".into()
        ));
    }
    
    // Resolve token address
    let token = resolve_name(token_address, provider.chain_id)?;
    
    // Resolve all account addresses
    let mut accounts = Vec::with_capacity(account_addresses.len());
    for addr in account_addresses {
        accounts.push(resolve_name(addr, provider.chain_id)?);
    }
    
    let call = IERC1155::balanceOfBatchCall { accounts, ids: token_ids };
    let balances = call_view_function(token, call, provider)?;
    Ok(balances._0)
}

/// Check if an operator is approved for all tokens of an account
pub fn erc1155_is_approved_for_all(
    token_address: &str,
    account_address: &str,
    operator_address: &str,
    provider: &Provider
) -> Result<bool, WalletError> {
    let token = resolve_name(token_address, provider.chain_id)?;
    let account = resolve_name(account_address, provider.chain_id)?;
    let operator = resolve_name(operator_address, provider.chain_id)?;
    
    let call = IERC1155::isApprovedForAllCall { account, operator };
    let is_approved = call_view_function(token, call, provider)?;
    Ok(is_approved._0)
}

/// Set approval for all tokens to an operator
pub fn erc1155_set_approval_for_all<S: Signer>(
    token_address: &str,
    operator_address: &str,
    approved: bool,
    provider: &Provider,
    signer: &S
) -> Result<TxReceipt, WalletError> {
    // Resolve addresses
    let token = resolve_name(token_address, provider.chain_id)?;
    let operator = resolve_name(operator_address, provider.chain_id)?;
    
    // Create the call
    let call = IERC1155::setApprovalForAllCall { operator, approved };
    let call_data = call.abi_encode();
    
    // Format receipt message
    let format_receipt = move |_| {
        format!(
            "{} operator {} to manage all of your ERC1155 tokens in contract {}", 
            if approved { "Approved" } else { "Revoked approval for" },
            operator_address,
            token_address
        )
    };
    
    // Prepare and send transaction
    prepare_and_send_tx(
        token,
        call_data,
        U256::ZERO,
        provider,
        signer,
        Some(60_000), // Default gas limit for approvals
        format_receipt
    )
}

/// Transfer a single ERC1155 token
pub fn erc1155_safe_transfer_from<S: Signer>(
    token_address: &str,
    from_address: &str,
    to_address: &str,
    token_id: U256,
    amount: U256,
    data: Vec<u8>,
    provider: &Provider,
    signer: &S
) -> Result<TxReceipt, WalletError> {
    // Resolve addresses
    let token = resolve_name(token_address, provider.chain_id)?;
    let from = resolve_name(from_address, provider.chain_id)?;
    let to = resolve_name(to_address, provider.chain_id)?;
    
    // Create the call
    let call = IERC1155::safeTransferFromCall { 
        from, 
        to, 
        id: token_id,
        amount,
        data: Bytes::from(data)
    };
    let call_data = call.abi_encode();
    
    // Format receipt message
    let format_receipt = move |_| {
        format!(
            "Transferred {} of token ID {} from {} to {}", 
            amount, token_id, from_address, to_address
        )
    };
    
    // Prepare and send transaction
    prepare_and_send_tx(
        token,
        call_data,
        U256::ZERO,
        provider,
        signer,
        Some(150_000), // Default gas limit for ERC1155 transfers
        format_receipt
    )
}

/// Batch transfer multiple ERC1155 tokens
pub fn erc1155_safe_batch_transfer_from<S: Signer>(
    token_address: &str,
    from_address: &str,
    to_address: &str,
    token_ids: Vec<U256>,
    amounts: Vec<U256>,
    data: Vec<u8>,
    provider: &Provider,
    signer: &S
) -> Result<TxReceipt, WalletError> {
    // Check that arrays are same length
    if token_ids.len() != amounts.len() {
        return Err(WalletError::TransactionError(
            "Arrays of token IDs and amounts must have the same length".into()
        ));
    }
    
    // Resolve addresses
    let token = resolve_name(token_address, provider.chain_id)?;
    let from = resolve_name(from_address, provider.chain_id)?;
    let to = resolve_name(to_address, provider.chain_id)?;
    
    // Create the call
    let call = IERC1155::safeBatchTransferFromCall { 
        from, 
        to, 
        ids: token_ids.clone(),
        amounts: amounts.clone(),
        data: Bytes::from(data)
    };
    let call_data = call.abi_encode();
    
    // For batch transfers, gas estimation is tricky - use a formula that scales with token count
    let token_count = token_ids.len();
    // Base gas (200,000) + extra per token (50,000 each)
    let default_gas = Some(200_000 + (token_count as u64 * 50_000));
    
    // Format receipt message
    let format_receipt = move |_| {
        format!(
            "Batch transferred {} token types from {} to {}", 
            token_count, from_address, to_address
        )
    };
    
    // Prepare and send transaction
    prepare_and_send_tx(
        token,
        call_data,
        U256::ZERO,
        provider,
        signer,
        default_gas,
        format_receipt
    )
}

//
// HYPERMAP FUNCTIONS
//

/// Create a note (mutable data) on a Hypermap namespace entry
pub fn create_note<S: Signer>(
    parent_entry: &str,
    note_key: &str,
    data: Vec<u8>,
    provider: Provider,
    signer: &S,
) -> Result<HypermapTxReceipt, WalletError> {
    // Verify the note key is valid
    if !valid_note(note_key) {
        return Err(WalletError::NameResolutionError(
            format!("Invalid note key '{}'. Must start with '~' and contain only lowercase letters, numbers, and hyphens", note_key)
        ));
    }

    // Create the note function call data
    let note_function = hypermap::contract::noteCall {
        note: Bytes::from(note_key.as_bytes().to_vec()),
        data: Bytes::from(data),
    };
    
    // Create the hypermap transaction
    create_hypermap_tx(
        parent_entry,
        Bytes::from(note_function.abi_encode()),
        || format!("Created note '{}' on '{}'", note_key, parent_entry),
        provider,
        signer
    )
}

/// Create a fact (immutable data) on a Hypermap namespace entry
pub fn create_fact<S: Signer>(
    parent_entry: &str,
    fact_key: &str,
    data: Vec<u8>,
    provider: Provider,
    signer: &S,
) -> Result<HypermapTxReceipt, WalletError> {
    // Verify the fact key is valid
    if !valid_fact(fact_key) {
        return Err(WalletError::NameResolutionError(
            format!("Invalid fact key '{}'. Must start with '!' and contain only lowercase letters, numbers, and hyphens", fact_key)
        ));
    }

    // Create the fact function call data
    let fact_function = hypermap::contract::factCall {
        fact: Bytes::from(fact_key.as_bytes().to_vec()),
        data: Bytes::from(data),
    };
    
    // Create the hypermap transaction
    create_hypermap_tx(
        parent_entry,
        Bytes::from(fact_function.abi_encode()),
        || format!("Created fact '{}' on '{}'", fact_key, parent_entry),
        provider,
        signer
    )
}

/// Mint a new namespace entry under a parent entry
pub fn mint_entry<S: Signer>(
    parent_entry: &str,
    label: &str,
    recipient: &str,
    implementation: &str,
    provider: Provider,
    signer: &S,
) -> Result<HypermapTxReceipt, WalletError> {
    // Verify the label is valid
    if !valid_name(label) {
        return Err(WalletError::NameResolutionError(
            format!("Invalid label '{}'. Must contain only lowercase letters, numbers, and hyphens", label)
        ));
    }

    // Resolve addresses
    let recipient_address = resolve_name(recipient, provider.chain_id)?;
    let implementation_address = resolve_name(implementation, provider.chain_id)?;

    // Create the mint function call data
    let mint_function = hypermap::contract::mintCall {
        who: recipient_address,
        label: Bytes::from(label.as_bytes().to_vec()),
        initialization: Bytes::default(), // No initialization data
        erc721Data: Bytes::default(),    // No ERC721 data
        implementation: implementation_address,
    };
    
    // Create the hypermap transaction
    create_hypermap_tx(
        parent_entry,
        Bytes::from(mint_function.abi_encode()),
        || format!("Minted new entry '{}' under '{}'", label, parent_entry),
        provider,
        signer
    )
}

/// Set the gene for a namespace entry
pub fn set_gene<S: Signer>(
    entry: &str,
    gene_implementation: &str,
    provider: Provider,
    signer: &S,
) -> Result<HypermapTxReceipt, WalletError> {
    // Resolve gene implementation address
    let gene_address = resolve_name(gene_implementation, provider.chain_id)?;

    // Create the gene function call data
    let gene_function = hypermap::contract::geneCall {
        _gene: gene_address,
    };
    
    // Create the hypermap transaction
    create_hypermap_tx(
        entry,
        Bytes::from(gene_function.abi_encode()),
        || format!("Set gene for '{}' to '{}'", entry, gene_implementation),
        provider,
        signer
    )
}



// TODO: TEST
//
//
//
//
//
//

/// Transaction details in a more user-friendly format
#[derive(Debug, Clone)]
pub struct TransactionDetails {
    pub hash: TxHash,
    pub from: EthAddress,
    pub to: Option<EthAddress>,
    pub value: EthAmount,
    pub block_number: Option<u64>,
    pub timestamp: Option<u64>,
    pub gas_used: Option<u64>,
    pub gas_price: Option<U256>,
    pub success: Option<bool>,
    pub direction: TransactionDirection,
}

/// Direction of the transaction relative to the address
#[derive(Debug, Clone, PartialEq)]
pub enum TransactionDirection {
    Incoming,
    Outgoing,
    SelfTransfer,
}

/// Get transactions for an address - simplified version that works with Alloy
pub fn get_address_transactions(
    address_or_name: &str,
    provider: &Provider,
    max_blocks_back: Option<u64>
) -> Result<Vec<TransactionDetails>, WalletError> {
    let target_address = resolve_name(address_or_name, provider.chain_id)?;
    
    // Get block range
    let latest_block = provider.get_block_number()?;
    let blocks_back = max_blocks_back.unwrap_or(1000);
    let start_block = if latest_block > blocks_back {
        latest_block - blocks_back
    } else {
        0
    };
    
    // Create filter to find logs involving our address
    let filter = Filter {
        block_option: FilterBlockOption::Range {
            from_block: Some(start_block.into()),
            to_block: Some(latest_block.into()),
        },
        address: FilterSet::from(vec![target_address]),
        topics: Default::default(),
    };
    
    // Get logs matching our filter
    let logs = provider.get_logs(&filter)?;
    kiprintln!("Found {} logs involving address {}", logs.len(), target_address);
    
    // Extract unique transaction hashes
    let mut tx_hashes = Vec::new();
    for log in logs {
        if let Some(hash) = log.transaction_hash {
            if !tx_hashes.contains(&hash) {
                tx_hashes.push(hash);
            }
        }
    }
    
    // Create transaction details objects for each tx hash
    let mut transactions = Vec::new();
    
    for tx_hash in tx_hashes {
        // For each transaction, create a basic TransactionDetails object
        // with just the transaction hash and basic direction
        let mut tx_detail = TransactionDetails {
            hash: tx_hash,
            from: EthAddress::default(), // We'll update this if we can get the transaction
            to: None,
            value: EthAmount { wei_value: U256::ZERO },
            block_number: None,
            timestamp: None,
            gas_used: None,
            gas_price: None,
            success: None,
            direction: TransactionDirection::Incoming, // Default, will update if needed
        };
        
        // Try to get transaction receipt for more details
        if let Ok(Some(receipt)) = provider.get_transaction_receipt(tx_hash) {
            // Update from receipt fields that we know exist
            tx_detail.block_number = receipt.block_number;
            
            // Get transaction success status if available
            let status = receipt.status();
            if status {
                tx_detail.success = Some(true);
            } else {
                tx_detail.success = Some(false);
            }
            
            // Try to get original transaction for more details
            if let Ok(Some(tx)) = provider.get_transaction_by_hash(tx_hash) {
                // Update from transaction fields
                tx_detail.from = tx.from;
                
                // Set direction based on compared addresses
                if tx.from == target_address {
                    tx_detail.direction = TransactionDirection::Outgoing;
                } else {
                    tx_detail.direction = TransactionDirection::Incoming;
                }
                
                // Try to get block timestamp if we have block number
                if let Some(block_num) = tx_detail.block_number {
                    if let Ok(Some(block)) = provider.get_block_by_number(BlockNumberOrTag::Number(block_num), false) {
                        // Block header timestamp is a u64, not an Option
                        tx_detail.timestamp = Some(block.header.timestamp);
                    }
                }
            }
        }
        
        transactions.push(tx_detail);
    }
    
    // Sort by block number (descending)
    transactions.sort_by(|a, b| {
        match (b.block_number, a.block_number) {
            (Some(b_num), Some(a_num)) => b_num.cmp(&a_num),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });
    
    Ok(transactions)
}

/// Format transaction details for display
pub fn format_transaction_details(tx: &TransactionDetails) -> String {
    // Symbol to represent transaction direction
    let direction_symbol = match tx.direction {
        TransactionDirection::Incoming => "←",
        TransactionDirection::Outgoing => "→",
        TransactionDirection::SelfTransfer => "↻",
    };
    
    // Transaction status
    let status = match tx.success {
        Some(true) => "Succeeded",
        Some(false) => "Failed",
        None => "Unknown",
    };
    
    // Format value
    let value = tx.value.to_string();
    
    // Format timestamp without external dependencies
    let timestamp = match tx.timestamp {
        Some(ts) => format_timestamp(ts),
        None => "Pending".to_string(),
    };
    
    // Format to and from addresses
    let from_addr = format!("{:.8}...{}", 
        tx.from.to_string()[0..10].to_string(),
        tx.from.to_string()[34..].to_string());
    
    let to_addr = tx.to.map_or("Contract Creation".to_string(), |addr| 
        format!("{:.8}...{}", 
            addr.to_string()[0..10].to_string(),
            addr.to_string()[34..].to_string())
    );
    
    // Format final output
    format!(
        "TX: {} [{}]\n   {} {} {}\n   Block: {}, Status: {}, Value: {}, Time: {}",
        tx.hash,
        status,
        from_addr,
        direction_symbol,
        to_addr,
        tx.block_number.map_or("Pending".to_string(), |b| b.to_string()),
        status,
        value,
        timestamp
    )
}
/// Format a Unix timestamp without external dependencies
fn format_timestamp(timestamp: u64) -> String {
    // Simple timestamp formatting
    // We'll use a very basic approach that doesn't rely on date/time libraries
    
    // Convert to seconds, minutes, hours, days since epoch
    let secs = timestamp % 60;
    let mins = (timestamp / 60) % 60;
    let hours = (timestamp / 3600) % 24;
    let days_since_epoch = timestamp / 86400;
    
    // Very rough estimation - doesn't account for leap years properly
    let years_since_epoch = days_since_epoch / 365;
    let days_this_year = days_since_epoch % 365;
    
    // Rough month calculation
    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0;
    let mut day = days_this_year as u32;
    
    // Adjust for leap years in a very rough way
    let is_leap_year = (1970 + years_since_epoch as u32) % 4 == 0;
    let month_days = if is_leap_year {
        let mut md = month_days.to_vec();
        md[1] = 29; // February has 29 days in leap years
        md
    } else {
        month_days.to_vec()
    };
    
    // Find month and day
    for (i, &days_in_month) in month_days.iter().enumerate() {
        if day < days_in_month {
            month = i;
            break;
        }
        day -= days_in_month;
    }
    
    // Adjust to 1-based
    day += 1;
    month += 1;
    
    // Format the date
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        1970 + years_since_epoch,
        month,
        day,
        hours,
        mins,
        secs
    )
}

// New structured type to hold all ERC20 token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenDetails {
    pub address: String,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub total_supply: String,
    pub balance: String,
    pub formatted_balance: String,
}

/// Get all relevant details for an ERC20 token in one call
/// This consolidates multiple calls into a single function for frontend use
pub fn get_token_details(
    token_address: &str,
    wallet_address: &str,
    provider: &Provider
) -> Result<TokenDetails, WalletError> {
    // First resolve the token address (could be a symbol or address)
    let token = match resolve_token_symbol(token_address, provider.chain_id) {
        Ok(addr) => addr,
        Err(_) => resolve_name(token_address, provider.chain_id)?,
    };
    
    // Get basic token information
    let token_str = token.to_string();
    let symbol = erc20_symbol(token_address, provider)?;
    let name = erc20_name(token_address, provider)?;
    let decimals = erc20_decimals(token_address, provider)?;
    
    // Get total supply
    let total_supply = erc20_total_supply(token_address, provider)?;
    let total_supply_float = total_supply.to::<u128>() as f64 / 10f64.powi(decimals as i32);
    let formatted_total_supply = format!("{:.2}", total_supply_float);
    
    // Get balance if wallet address is provided
    let (balance, formatted_balance) = if !wallet_address.is_empty() {
        let balance = erc20_balance_of(token_address, wallet_address, provider)?;
        (balance.to_string(), format!("{:.6}", balance))
    } else {
        ("0".to_string(), "0.000000".to_string())
    };
    
    Ok(TokenDetails {
        address: token_str,
        symbol,
        name,
        decimals,
        total_supply: formatted_total_supply,
        balance,
        formatted_balance,
    })
}
