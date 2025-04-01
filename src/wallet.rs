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
use crate::{
    kiprintln
};

use thiserror::Error;
use alloy_primitives::{
    Address as EthAddress, 
    TxHash, 
    U256,
    Bytes
};
use alloy::rpc::types::{
    TransactionReceipt, 
    TransactionRequest
};
use alloy_primitives::TxKind;
use std::str::FromStr;
use alloy_sol_types::{sol, SolCall};

// Define token standards using sol! macro
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
    kiprintln!("PL:: Calculating gas parameters for chain ID: {}", chain_id);

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
            kiprintln!("PL:: Calculating gas parameters for Base");
            let latest_block = provider.get_block_by_number(BlockNumberOrTag::Latest, false)?
                .ok_or_else(|| WalletError::TransactionError("Failed to get latest block".into()))?;
            
            kiprintln!("PL:: Got latest block");
            let base_fee = latest_block.header.inner.base_fee_per_gas
                .ok_or_else(|| WalletError::TransactionError("No base fee in block".into()))?
                as u128;
            
            kiprintln!("PL:: Got base fee: {}", base_fee);
            
            let max_fee = base_fee + (base_fee / 3);
            kiprintln!("PL:: max fee: {}", max_fee);
            
            let min_priority_fee = 100_000u128;
            kiprintln!("PL:: min priority fee: {}", min_priority_fee);
            
            let max_priority_fee = max_fee / 2;
            kiprintln!("PL:: max priority fee: {}", max_priority_fee);
            
            let priority_fee = std::cmp::max(min_priority_fee, std::cmp::min(base_fee / 10, max_priority_fee));
            kiprintln!("PL:: priority fee: {}", priority_fee);

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
    kiprintln!("PL:: Preparing transaction...");

    // Get the current nonce for the signer's address
    let signer_address = signer.address();
    let nonce = provider.get_transaction_count(signer_address, None)?
        .to::<u64>();
    
    kiprintln!("PL:: Got nonce: {}", nonce);
    
    // Calculate gas parameters based on chain ID
    let (gas_price, priority_fee) = calculate_gas_params(provider, signer.chain_id())?;
    
    kiprintln!("PL:: Calculated gas params - price: {}, priority fee: {}", gas_price, priority_fee);
    
    // Use provided gas limit or estimate it with 20% buffer
    let gas_limit = match gas_limit {
        Some(limit) => {
            kiprintln!("PL:: Using provided gas limit: {}", limit);
            limit
        },
        None => {
            kiprintln!("PL:: Estimating gas limit...");
            let tx_req = TransactionRequest {
                from: Some(signer_address),
                to: Some(TxKind::Call(to)),
                input: call_data.clone().into(),
                ..Default::default()
            };
            
            match provider.estimate_gas(tx_req, None) {
                Ok(gas) => {
                    let limit = (gas.to::<u64>() * 120) / 100; // Add 20% buffer
                    kiprintln!("PL:: Estimated gas limit with buffer: {}", limit);
                    limit
                },
                Err(_) => {
                    kiprintln!("PL:: Gas estimation failed, using default: 100,000");
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
    
    kiprintln!("PL:: Signing transaction...");
    
    // Sign and send transaction
    let signed_tx = signer.sign_transaction(&tx_data)?;
    
    kiprintln!("PL:: Sending transaction...");
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

// Resolve a .hypr name to an Ethereum address using Hypermap
pub fn resolve_name(name: &str, chain_id: u64) -> Result<EthAddress, WalletError> {
    // If it's already an address, just parse it
    if name.starts_with("0x") && name.len() == 42 {
        return EthAddress::from_str(name)
            .map_err(|_| WalletError::NameResolutionError(format!("Invalid address format: {}", name)));
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
    let token = resolve_name(token_address, provider.chain_id)?;
    let owner = resolve_name(owner_address, provider.chain_id)?;
    
    let call = IERC20::balanceOfCall { who: owner };
    let balance = call_view_function(token, call, provider)?;
    
    let decimals = erc20_decimals(token_address, provider)?;
    let balance_float = balance._0.to::<u128>() as f64 / 10f64.powi(decimals as i32);
    
    Ok(balance_float)
}

/// Get the number of decimals for an ERC20 token
pub fn erc20_decimals(token_address: &str, provider: &Provider) -> Result<u8, WalletError> {
    let token = resolve_name(token_address, provider.chain_id)?;
    let call = IERC20::decimalsCall {};
    let decimals = call_view_function(token, call, provider)?;
    Ok(decimals._0)
}

/// Get the token symbol for an ERC20 token
pub fn erc20_symbol(token_address: &str, provider: &Provider) -> Result<String, WalletError> {
    let token = resolve_name(token_address, provider.chain_id)?;
    let call = IERC20::symbolCall {};
    let symbol = call_view_function(token, call, provider)?;
    Ok(symbol._0)
}

/// Get the token name for an ERC20 token
pub fn erc20_name(token_address: &str, provider: &Provider) -> Result<String, WalletError> {
    let token = resolve_name(token_address, provider.chain_id)?;
    let call = IERC20::nameCall {};
    let name = call_view_function(token, call, provider)?;
    Ok(name._0)
}

/// Get the total supply of an ERC20 token
pub fn erc20_total_supply(token_address: &str, provider: &Provider) -> Result<U256, WalletError> {
    let token = resolve_name(token_address, provider.chain_id)?;
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
    let token = resolve_name(token_address, provider.chain_id)?;
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

    // Resolve addresses
    let token = resolve_name(token_address, provider.chain_id)?;
    let to = resolve_name(to_address, provider.chain_id)?;
    
    kiprintln!("PL:: Resolved token address: {}", token);
    kiprintln!("PL:: Resolved recipient address: {}", to);
    
    // Create the call
    let call = IERC20::transferCall { to, value: amount };
    let call_data = call.abi_encode();
    
    // Get token details for receipt formatting
    let token_symbol = erc20_symbol(token_address, provider).unwrap_or_else(|_| "tokens".to_string());
    let token_decimals = erc20_decimals(token_address, provider).unwrap_or(18);
    
    kiprintln!("PL:: Token symbol: {}", token_symbol);
    kiprintln!("PL:: Token decimals: {}", token_decimals);
    
    // Format receipt message
    let format_receipt = move |_| {
        let amount_float = amount.to::<u128>() as f64 / 10f64.powi(token_decimals as i32);
        format!("Transferred {:.6} {} to {}", amount_float, token_symbol, to_address)
    };
    
    kiprintln!("PL:: Sending ERC20 transfer transaction...");
    
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





//use crate::eth::{
//    Provider, 
//    EthError,
//    BlockNumberOrTag
//};
//use crate::signer::{
//    Signer, 
//    LocalSigner, 
//    TransactionData, 
//    SignerError, 
//    EncryptedSignerData
//};
//use crate::hypermap::{
//    namehash, 
//    valid_note, 
//    valid_fact, 
//    valid_name,
//};
//use crate::{
//    hypermap, 
//    kiprintln
//};
//
//use thiserror::Error;
//use alloy_primitives::{
//    Address as EthAddress, 
//    TxHash, 
//    U256,
//    Bytes
//};
//use alloy::rpc::types::{
//    TransactionReceipt, 
//    TransactionRequest
//};
//use alloy_primitives::TxKind;
//use std::str::FromStr;
//use alloy_sol_types::{sol, SolCall};
//
//sol! {
//    interface IERC20 {
//        function balanceOf(address who) external view returns (uint256);
//        function transfer(address to, uint256 value) external returns (bool);
//        function approve(address spender, uint256 value) external returns (bool);
//        function transferFrom(address from, address to, uint256 value) external returns (bool);
//        function allowance(address owner, address spender) external view returns (uint256);
//        function totalSupply() external view returns (uint256);
//        function decimals() external view returns (uint8);
//        function symbol() external view returns (string);
//        function name() external view returns (string);
//    }
//
//    interface IERC721 {
//        function balanceOf(address owner) external view returns (uint256);
//        function ownerOf(uint256 tokenId) external view returns (address);
//        function safeTransferFrom(address from, address to, uint256 tokenId) external;
//        function transferFrom(address from, address to, uint256 tokenId) external;
//        function approve(address to, uint256 tokenId) external;
//        function setApprovalForAll(address operator, bool approved) external;
//        function getApproved(uint256 tokenId) external view returns (address);
//        function isApprovedForAll(address owner, address operator) external view returns (bool);
//    }
//
//    interface IERC1155 {
//        function balanceOf(address account, uint256 id) external view returns (uint256);
//        function balanceOfBatch(address[] accounts, uint256[] ids) external view returns (uint256[]);
//        function setApprovalForAll(address operator, bool approved) external;
//        function isApprovedForAll(address account, address operator) external view returns (bool);
//        function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes data) external;
//        function safeBatchTransferFrom(address from, address to, uint256[] ids, uint256[] amounts, bytes data) external;
//    }
//
//    interface IERC6551Account {
//        function execute(address to, uint256 value, bytes calldata data, uint8 operation) external returns (bytes);
//    }
//}
//
//#[derive(Debug, Error)]
//pub enum WalletError {
//    #[error("signing error: {0}")]
//    SignerError(#[from] SignerError),
//    
//    #[error("ethereum error: {0}")]
//    EthError(#[from] EthError),
//    
//    #[error("name resolution error: {0}")]
//    NameResolutionError(String),
//    
//    #[error("invalid amount: {0}")]
//    InvalidAmount(String),
//    
//    #[error("transaction error: {0}")]
//    TransactionError(String),
//
//    #[error("gas estimation error: {0}")]
//    GasEstimationError(String),
//    
//    #[error("insufficient funds: {0}")]
//    InsufficientFunds(String),
//    
//    #[error("network congestion: {0}")]
//    NetworkCongestion(String),
//    
//    #[error("transaction underpriced")]
//    TransactionUnderpriced,
//    
//    #[error("transaction nonce too low")]
//    TransactionNonceTooLow,
//    
//    #[error("permission denied: {0}")]
//    PermissionDenied(String),
//}
//
///// Represents the storage state of a wallet's private key
//#[derive(Debug, Clone)]
//pub enum KeyStorage {
//    /// An unencrypted wallet with a signer
//    Decrypted(LocalSigner),
//    
//    /// An encrypted wallet - contains all the necessary data
//    Encrypted(EncryptedSignerData),
//}
//
//impl KeyStorage {
//    /// Get the encrypted data if this is an encrypted key storage
//    pub fn get_encrypted_data(&self) -> Option<Vec<u8>> {
//        match self {
//            KeyStorage::Encrypted(data) => Some(data.encrypted_data.clone()),
//            KeyStorage::Decrypted(_) => None,
//        }
//    }
//    
//    /// Get the address associated with this wallet
//    pub fn get_address(&self) -> String {
//        match self {
//            KeyStorage::Decrypted(signer) => signer.address().to_string(),
//            KeyStorage::Encrypted(data) => data.address.clone(),
//        }
//    }
//    
//    /// Get the chain ID associated with this wallet
//    pub fn get_chain_id(&self) -> u64 {
//        match self {
//            KeyStorage::Decrypted(signer) => signer.chain_id(),
//            KeyStorage::Encrypted(data) => data.chain_id,
//        }
//    }
//}
//
///// Represents an amount of ETH with proper formatting
//#[derive(Debug, Clone)]
//pub struct EthAmount {
//    /// Value in wei
//    wei_value: U256,
//}
//
//impl EthAmount {
//    /// Create a new amount from ETH value
//    pub fn from_eth(eth_value: f64) -> Self {
//        // Convert ETH to wei (1 ETH = 10^18 wei)
//        let wei = (eth_value * 1_000_000_000_000_000_000.0) as u128;
//        Self {
//            wei_value: U256::from(wei),
//        }
//    }
//    
//    /// Create from a string like "0.1 ETH" or "10 wei"
//    pub fn from_string(amount_str: &str) -> Result<Self, WalletError> {
//        let parts: Vec<&str> = amount_str.trim().split_whitespace().collect();
//        
//        if parts.is_empty() {
//            return Err(WalletError::InvalidAmount(
//                "Empty amount string".to_string()
//            ));
//        }
//        
//        let value_str = parts[0];
//        let unit = parts.get(1).map(|s| s.to_lowercase()).unwrap_or_else(|| "eth".to_string());
//        
//        let value = value_str.parse::<f64>()
//            .map_err(|_| WalletError::InvalidAmount(format!("Invalid numeric value: {}", value_str)))?;
//            
//        match unit.as_str() {
//            "eth" => Ok(Self::from_eth(value)),
//            "wei" => Ok(Self {
//                wei_value: U256::from(value as u128),
//            }),
//            _ => Err(WalletError::InvalidAmount(format!("Unknown unit: {}", unit))),
//        }
//    }
//    
//    /// Get the value in wei
//    pub fn as_wei(&self) -> U256 {
//        self.wei_value
//    }
//    
//    /// Get a human-readable string representation
//    pub fn to_string(&self) -> String {
//        // For values over 0.0001 ETH, show in ETH, otherwise in wei
//        if self.wei_value >= U256::from(100_000_000_000_000u128) {
//            // Convert to u128 first (safe since ETH total supply fits in u128) then to f64
//            let wei_u128 = self.wei_value.to::<u128>();
//            let eth_value = wei_u128 as f64 / 1_000_000_000_000_000_000.0;
//            format!("{:.6} ETH", eth_value)
//        } else {
//            format!("{} wei", self.wei_value)
//        }
//    }
//}
//
///// Transaction receipt returned after sending
//#[derive(Debug, Clone)]
//pub struct TxReceipt {
//    /// Transaction hash
//    pub hash: TxHash,
//    /// Transaction details
//    pub details: String,
//}
//
//// Resolve a .hypr name to an Ethereum address using Hypermap
//pub fn resolve_name(name: &str, chain_id: u64) -> Result<EthAddress, WalletError> {
//    // If it's already an address, just parse it
//    if name.starts_with("0x") && name.len() == 42 {
//        return EthAddress::from_str(name)
//            .map_err(|_| WalletError::NameResolutionError(format!("Invalid address format: {}", name)));
//    }
//    
//    // hardcoded to .hypr for now
//    let formatted_name = if !name.contains('.') {
//        format!("{}.hypr", name)
//    } else {
//        kiprintln!("PROCESS_LIB::resolve_name name: {}", name);
//        name.to_string()
//    };
//    
//    // Use hypermap resolution
//    let hypermap = hypermap::Hypermap::default(chain_id);
//    match hypermap.get(&formatted_name) {
//        Ok((_tba, owner, _)) => {
//            Ok(owner)
//        },
//        Err(e) => {
//            Err(WalletError::NameResolutionError(
//                format!("Failed to resolve name '{}': {}", name, e)
//            ))
//        }
//    }
//}
//
///// Send ETH to an address or name
//pub fn send_eth<S: Signer>(
//    to: &str,
//    amount: EthAmount,
//    provider: Provider,
//    signer: &S,
//) -> Result<TxReceipt, WalletError> {
//    kiprintln!("PROCESS_LIB::send_eth starting transaction");
//
//    // Current chain-specific handling
//    let chain_id = signer.chain_id();
//    kiprintln!("PROCESS_LIB::send_eth chain_id: {}", chain_id);
//    
//    // This part needs improvement - detect network type more robustly
//    let is_test_network = chain_id == 31337 || chain_id == 1337;
//    
//    // Use network-specific gas strategies
//    let (gas_price, priority_fee) = match chain_id {
//        // just rough calculations for now
//        1 => calculate_eth_mainnet_gas(&provider)?, // mainnet
//        8453 => calculate_base_gas(&provider)?, // Base
//        10 => calculate_optimism_gas(&provider)?, // Optimism
//
//        // Test networks - keep your current approach
//        _ if is_test_network => (2_000_000_000, 100_000_000),
//        
//        // 30% buffer on other networks
//        _ => {
//            kiprintln!("PROCESS_LIB::send_eth getting gas price");
//            let base_fee = provider.get_gas_price()?.to::<u128>();
//            kiprintln!("PROCESS_LIB::send_eth base_fee: {}", base_fee);
//            let adjusted_fee = (base_fee * 130) / 100;
//            kiprintln!("PROCESS_LIB::send_eth adjusted_fee: {}", adjusted_fee);
//            (adjusted_fee, adjusted_fee / 10)
//        }
//    };
//
//    kiprintln!("PROCESS_LIB::send_eth gas_price: {}", gas_price);
//
//    // Resolve the name to an address
//    let to_address = resolve_name(to, chain_id)?;
//    kiprintln!("PROCESS_LIB::send_eth to_address: {}", to_address);
//
//    // Get the current nonce for the signer's address
//    let from_address = signer.address();
//    let nonce = provider.get_transaction_count(from_address, None)?
//        .to::<u64>();
//    kiprintln!("PROCESS_LIB::send_eth nonce: {}", nonce);
//
//    // Standard gas limit for ETH transfer
//    let gas_limit = 21000;
//    
//    // Prepare transaction data
//    let tx_data = TransactionData {
//        to: to_address,
//        value: amount.as_wei(),
//        data: None, // No data for simple ETH transfer
//        nonce,
//        gas_limit,
//        gas_price,
//        max_priority_fee: Some(priority_fee),
//        chain_id,
//    };
//
//    kiprintln!("PROCESS_LIB::send_eth tx_data prepared");
//    
//    // Sign the transaction
//    let signed_tx = signer.sign_transaction(&tx_data)?;
//    kiprintln!("PROCESS_LIB::send_eth transaction signed");
//    
//    // Send the transaction
//    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;
//    kiprintln!("PROCESS_LIB::send_eth tx_hash: {}", tx_hash);
//    
//    // Return the receipt with transaction details
//    Ok(TxReceipt {
//        hash: tx_hash,
//        details: format!("Sent {} to {}", amount.to_string(), to),
//    })
//}
//
//// Helper function to calculate EIP-1559 gas parameters with network-specific values
//fn calculate_eip1559_gas(
//    provider: &Provider, 
//    buffer_fraction: u128, 
//    priority_fee: u128
//) -> Result<(u128, u128), WalletError> {
//    kiprintln!("PROCESS_LIB::calculate_eip1559_gas starting");
//    // Get latest block
//    let latest_block = provider.get_block_by_number(BlockNumberOrTag::Latest, false)?
//        .ok_or_else(|| WalletError::TransactionError("Failed to get latest block".into()))?;
//
//    kiprintln!("PROCESS_LIB::calculate_eip1559_gas latest_block received");
//    
//    // Get base fee
//    let base_fee = latest_block.header.inner.base_fee_per_gas
//        .ok_or_else(|| WalletError::TransactionError("No base fee in block".into()))?
//        as u128;
//
//    kiprintln!("PROCESS_LIB::calculate_eip1559_gas base_fee: {}", base_fee);
//    
//    // Calculate max fee with the provided buffer fraction
//    let max_fee = base_fee + (base_fee / buffer_fraction);
//    kiprintln!("PROCESS_LIB::calculate_eip1559_gas max_fee: {}", max_fee);
//    
//    Ok((max_fee, priority_fee))
//}
//
//// Network-specific gas calculation for Ethereum mainnet
//fn calculate_eth_mainnet_gas(provider: &Provider) -> Result<(u128, u128), WalletError> {
//    // For mainnet: 50% buffer and 1.5 gwei priority fee
//    calculate_eip1559_gas(provider, 2, 1_500_000_000u128)
//}
//
//// Gas calculation for Base
//fn calculate_base_gas(provider: &Provider) -> Result<(u128, u128), WalletError> {
//    // Get the latest block to determine current gas conditions
//    let latest_block = provider.get_block_by_number(BlockNumberOrTag::Latest, false)?
//        .ok_or_else(|| WalletError::TransactionError("Failed to get latest block".into()))?;
//    
//    // Get base fee from the block
//    let base_fee = latest_block.header.inner.base_fee_per_gas
//        .ok_or_else(|| WalletError::TransactionError("No base fee in block".into()))?
//        as u128;
//    
//    // Calculate max fee with a 33% buffer
//    let max_fee = base_fee + (base_fee / 3);
//    
//    // Dynamic priority fee - 10% of base fee, but with a minimum and a maximum
//    // Low minimum for Base which has very low gas prices
//    let min_priority_fee = 100_000u128; // 0.0001 gwei minimum
//    let max_priority_fee = max_fee / 2; // Never more than half the max fee
//    
//    let priority_fee = std::cmp::max(
//        min_priority_fee,
//        std::cmp::min(base_fee / 10, max_priority_fee)
//    );
//    
//    Ok((max_fee, priority_fee))
//}
//
//// Gas calculation for Optimism network
//fn calculate_optimism_gas(provider: &Provider) -> Result<(u128, u128), WalletError> {
//    // For Optimism: 25% buffer and 0.3 gwei priority fee
//    calculate_eip1559_gas(provider, 4, 300_000_000u128)
//}
//
///// Get the ETH balance for an address or name
//pub fn get_eth_balance(
//    address_or_name: &str,
//    chain_id: u64,
//    provider: Provider,
//) -> Result<EthAmount, WalletError> {
//    // Resolve name to address
//    let address = resolve_name(address_or_name, chain_id)?;
//    
//    // Query balance
//    let balance = provider.get_balance(address, None)?;
//    
//    // Return formatted amount
//    Ok(EthAmount {
//        wei_value: balance,
//    })
//}
//
///// Wait for a transaction to be confirmed
//pub fn wait_for_transaction(
//    tx_hash: TxHash, 
//    provider: Provider,
//    confirmations: u64,
//    timeout_secs: u64
//) -> Result<TransactionReceipt, WalletError> {
//    let start_time = std::time::Instant::now();
//    let timeout = std::time::Duration::from_secs(timeout_secs);
//    
//    loop {
//        // Check if we've exceeded the timeout
//        if start_time.elapsed() > timeout {
//            return Err(WalletError::TransactionError(
//                format!("Transaction confirmation timeout after {} seconds", timeout_secs)
//            ));
//        }
//        
//        // Try to get the receipt
//        if let Ok(Some(receipt)) = provider.get_transaction_receipt(tx_hash) {
//            // Check if we have enough confirmations
//            let latest_block = provider.get_block_number()?;
//            let receipt_block = receipt.block_number.unwrap_or(0) as u64;
//            
//            if latest_block >= receipt_block + confirmations {
//                return Ok(receipt);
//            }
//        }
//        
//        // Wait a bit before checking again
//        std::thread::sleep(std::time::Duration::from_secs(2));
//    }
//}
//
////
//// ERC-20 TOKEN FUNCTIONS
////
//
///// Get the ERC20 token balance of an address or name
///// Returns the balance in token units (adjusted for decimals)
//pub fn erc20_balance_of(
//    token_address: &str,
//    owner_address: &str,
//    provider: &Provider
//) -> Result<f64, WalletError> {
//    kiprintln!("PROCESS_LIB::erc20_balance_of starting");
//    
//    // Resolve addresses
//    let token = resolve_name(token_address, provider.chain_id)?;
//    kiprintln!("PROCESS_LIB::erc20_balance_of token: {}", token);
//    let owner = resolve_name(owner_address, provider.chain_id)?;
//    kiprintln!("PROCESS_LIB::erc20_balance_of owner: {}", owner);
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC20::balanceOfCall { who: owner };
//    let call_data = call.abi_encode();
//    
//    // Create the transaction request for eth_call
//    let tx = TransactionRequest {
//        to: Some(TxKind::Call(token)),
//        input: call_data.into(),
//        ..Default::default()
//    };
//    
//    // Call the contract
//    let result = provider.call(tx, None)?;
//    
//    // Verify we got a valid result
//    if result.is_empty() {
//        return Err(WalletError::TransactionError("Empty result from balanceOf call".into()));
//    }
//    
//    // Decode the result
//    let balance = match IERC20::balanceOfCall::abi_decode_returns(&result, true) {
//        Ok(decoded) => decoded._0, // Returns (U256,)
//        Err(e) => return Err(WalletError::TransactionError(
//            format!("Failed to decode balanceOf result: {}", e)
//        )),
//    };
//    
//    // Get the token's decimals
//    let decimals = erc20_decimals(token_address, provider)?;
//    
//    // Calculate the token amount
//    let balance_u128 = balance.to::<u128>();
//    let balance_float = balance_u128 as f64 / 10f64.powi(decimals as i32);
//    
//    Ok(balance_float)
//}
//
///// Get the number of decimals for an ERC20 token
//pub fn erc20_decimals(token_address: &str, provider: &Provider) -> Result<u8, WalletError> {
//    kiprintln!("PROCESS_LIB::erc20_decimals starting");
//    
//    // Resolve token address
//    let token = resolve_name(token_address, provider.chain_id)?;
//    kiprintln!("PROCESS_LIB::erc20_decimals token: {}", token);
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC20::decimalsCall {};
//    let call_data = call.abi_encode();
//    
//    // Create the transaction request
//    let tx = TransactionRequest {
//        to: Some(TxKind::Call(token)),
//        input: call_data.into(),
//        ..Default::default()
//    };
//    
//    // Call the contract
//    let result = provider.call(tx, None)?;
//    kiprintln!("PROCESS_LIB::erc20_decimals result received");
//    
//    // Verify we got a valid result
//    if result.is_empty() {
//        return Err(WalletError::TransactionError("Empty result from decimals call".into()));
//    }
//    
//    // Decode the result
//    let decimals = match IERC20::decimalsCall::abi_decode_returns(&result, true) {
//        Ok(decoded) => decoded._0, // Returns (u8,)
//        Err(e) => return Err(WalletError::TransactionError(
//            format!("Failed to decode decimals result: {}", e)
//        )),
//    };
//    
//    Ok(decimals)
//}
//
///// Get the token symbol for an ERC20 token
//pub fn erc20_symbol(token_address: &str, provider: &Provider) -> Result<String, WalletError> {
//    kiprintln!("PROCESS_LIB::erc20_symbol starting");
//    
//    // Resolve token address
//    let token = resolve_name(token_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC20::symbolCall {};
//    let call_data = call.abi_encode();
//    
//    // Create the transaction request
//    let tx = TransactionRequest {
//        to: Some(TxKind::Call(token)),
//        input: call_data.into(),
//        ..Default::default()
//    };
//    
//    // Call the contract
//    let result = provider.call(tx, None)?;
//    
//    // Verify we got a valid result
//    if result.is_empty() {
//        return Err(WalletError::TransactionError("Empty result from symbol call".into()));
//    }
//    
//    // Decode the result
//    let symbol = match IERC20::symbolCall::abi_decode_returns(&result, true) {
//        Ok(decoded) => decoded._0, // Returns (String,)
//        Err(e) => return Err(WalletError::TransactionError(
//            format!("Failed to decode symbol result: {}", e)
//        )),
//    };
//    
//    Ok(symbol)
//}
//
///// Get the token name for an ERC20 token
//pub fn erc20_name(token_address: &str, provider: &Provider) -> Result<String, WalletError> {
//    kiprintln!("PROCESS_LIB::erc20_name starting");
//    
//    // Resolve token address
//    let token = resolve_name(token_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC20::nameCall {};
//    let call_data = call.abi_encode();
//    
//    // Create the transaction request
//    let tx = TransactionRequest {
//        to: Some(TxKind::Call(token)),
//        input: call_data.into(),
//        ..Default::default()
//    };
//    
//    // Call the contract
//    let result = provider.call(tx, None)?;
//    
//    // Verify we got a valid result
//    if result.is_empty() {
//        return Err(WalletError::TransactionError("Empty result from name call".into()));
//    }
//    
//    // Decode the result
//    let name = match IERC20::nameCall::abi_decode_returns(&result, true) {
//        Ok(decoded) => decoded._0, // Returns (String,)
//        Err(e) => return Err(WalletError::TransactionError(
//            format!("Failed to decode name result: {}", e)
//        )),
//    };
//    
//    Ok(name)
//}
//
///// Get the total supply of an ERC20 token
//pub fn erc20_total_supply(token_address: &str, provider: &Provider) -> Result<U256, WalletError> {
//    kiprintln!("PROCESS_LIB::erc20_total_supply starting");
//    
//    // Resolve token address
//    let token = resolve_name(token_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC20::totalSupplyCall {};
//    let call_data = call.abi_encode();
//    
//    // Create the transaction request
//    let tx = TransactionRequest {
//        to: Some(TxKind::Call(token)),
//        input: call_data.into(),
//        ..Default::default()
//    };
//    
//    // Call the contract
//    let result = provider.call(tx, None)?;
//    
//    // Verify we got a valid result
//    if result.is_empty() {
//        return Err(WalletError::TransactionError("Empty result from totalSupply call".into()));
//    }
//    
//    // Decode the result
//    let total_supply = match IERC20::totalSupplyCall::abi_decode_returns(&result, true) {
//        Ok(decoded) => decoded._0, // Returns (U256,)
//        Err(e) => return Err(WalletError::TransactionError(
//            format!("Failed to decode totalSupply result: {}", e)
//        )),
//    };
//    
//    Ok(total_supply)
//}
//
///// Get the allowance for an ERC20 token
//pub fn erc20_allowance(
//    token_address: &str,
//    owner_address: &str,
//    spender_address: &str,
//    provider: &Provider
//) -> Result<U256, WalletError> {
//    kiprintln!("PROCESS_LIB::erc20_allowance starting");
//    
//    // Resolve addresses
//    let token = resolve_name(token_address, provider.chain_id)?;
//    let owner = resolve_name(owner_address, provider.chain_id)?;
//    let spender = resolve_name(spender_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC20::allowanceCall { owner, spender };
//    let call_data = call.abi_encode();
//    
//    // Create the transaction request
//    let tx = TransactionRequest {
//        to: Some(TxKind::Call(token)),
//        input: call_data.into(),
//        ..Default::default()
//    };
//    
//    // Call the contract
//    let result = provider.call(tx, None)?;
//    
//    // Verify we got a valid result
//    if result.is_empty() {
//        return Err(WalletError::TransactionError("Empty result from allowance call".into()));
//    }
//    
//    // Decode the result
//    let allowance = match IERC20::allowanceCall::abi_decode_returns(&result, true) {
//        Ok(decoded) => decoded._0, // Returns (U256,)
//        Err(e) => return Err(WalletError::TransactionError(
//            format!("Failed to decode allowance result: {}", e)
//        )),
//    };
//    
//    Ok(allowance)
//}
//
///// Transfer ERC20 tokens to an address or name
//pub fn erc20_transfer<S: Signer>(
//    token_address: &str,
//    to_address: &str,
//    amount: U256,
//    provider: &Provider,
//    signer: &S
//) -> Result<TxReceipt, WalletError> {
//    kiprintln!("PROCESS_LIB::erc20_transfer starting");
//    
//    // Resolve addresses
//    let token = resolve_name(token_address, provider.chain_id)?;
//    let to = resolve_name(to_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC20::transferCall { to, value: amount };
//    let call_data = call.abi_encode();
//    
//    // Get the current nonce for the signer's address
//    let from_address = signer.address();
//    let nonce = provider.get_transaction_count(from_address, None)?
//        .to::<u64>();
//    
//    // Estimate gas for the token transfer
//    let tx_req = TransactionRequest {
//        from: Some(from_address),
//        to: Some(TxKind::Call(token)),
//        input: call_data.clone().into(),
//        ..Default::default()
//    };
//    
//    // Try to estimate gas, fall back to 100,000 if estimation fails
//    let gas_limit = match provider.estimate_gas(tx_req, None) {
//        Ok(gas) => (gas.to::<u64>() * 120) / 100, // Add 20% buffer
//        Err(_) => 100_000, // Default gas limit for ERC20 transfers
//    };
//    
//    // Calculate gas price based on the chain
//    let (gas_price, priority_fee) = match signer.chain_id() {
//        1 => calculate_eth_mainnet_gas(provider)?,
//        8453 => calculate_base_gas(provider)?,
//        10 => calculate_optimism_gas(provider)?,
//        _ => {
//            let base_fee = provider.get_gas_price()?.to::<u128>();
//            let adjusted_fee = (base_fee * 130) / 100;
//            (adjusted_fee, adjusted_fee / 10)
//        }
//    };
//    
//    // Prepare transaction data
//    let tx_data = TransactionData {
//        to: token,
//        value: U256::ZERO, // No ETH sent with token transfers
//        data: Some(call_data),
//        nonce,
//        gas_limit,
//        gas_price,
//        max_priority_fee: Some(priority_fee),
//        chain_id: signer.chain_id(),
//    };
//    
//    // Sign and send transaction
//    let signed_tx = signer.sign_transaction(&tx_data)?;
//    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;
//    
//    // Get token details to improve the receipt message
//    let token_symbol = match erc20_symbol(token_address, provider) {
//        Ok(symbol) => symbol,
//        Err(_) => "tokens".to_string(),
//    };
//    
//    let token_decimals = match erc20_decimals(token_address, provider) {
//        Ok(decimals) => decimals,
//        Err(_) => 18, // Assume 18 decimals if unavailable
//    };
//    
//    // Format amount in token units
//    let amount_float = amount.to::<u128>() as f64 / 10f64.powi(token_decimals as i32);
//    
//    Ok(TxReceipt {
//        hash: tx_hash,
//        details: format!("Transferred {:.6} {} to {}", amount_float, token_symbol, to_address),
//    })
//}
//
///// Approve an address to spend ERC20 tokens
//pub fn erc20_approve<S: Signer>(
//    token_address: &str,
//    spender_address: &str,
//    amount: U256,
//    provider: &Provider,
//    signer: &S
//) -> Result<TxReceipt, WalletError> {
//    kiprintln!("PROCESS_LIB::erc20_approve starting");
//    
//    // Resolve addresses
//    let token = resolve_name(token_address, provider.chain_id)?;
//    let spender = resolve_name(spender_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC20::approveCall { spender, value: amount };
//    let call_data = call.abi_encode();
//    
//    // Get the current nonce for the signer's address
//    let from_address = signer.address();
//    let nonce = provider.get_transaction_count(from_address, None)?
//        .to::<u64>();
//    
//    // Estimate gas
//    let tx_req = TransactionRequest {
//        from: Some(from_address),
//        to: Some(TxKind::Call(token)),
//        input: call_data.clone().into(),
//        ..Default::default()
//    };
//    
//    // Try to estimate gas, fall back to 60,000 if estimation fails
//    let gas_limit = match provider.estimate_gas(tx_req, None) {
//        Ok(gas) => (gas.to::<u64>() * 120) / 100, // Add 20% buffer
//        Err(_) => 60_000, // Default gas limit for ERC20 approvals
//    };
//    
//    // Calculate gas price based on the chain
//    let (gas_price, priority_fee) = match signer.chain_id() {
//        1 => calculate_eth_mainnet_gas(provider)?,
//        8453 => calculate_base_gas(provider)?,
//        10 => calculate_optimism_gas(provider)?,
//        _ => {
//            let base_fee = provider.get_gas_price()?.to::<u128>();
//            let adjusted_fee = (base_fee * 130) / 100;
//            (adjusted_fee, adjusted_fee / 10)
//        }
//    };
//    
//    // Prepare transaction data
//    let tx_data = TransactionData {
//        to: token,
//        value: U256::ZERO, // No ETH sent with token approvals
//        data: Some(call_data),
//        nonce,
//        gas_limit,
//        gas_price,
//        max_priority_fee: Some(priority_fee),
//        chain_id: signer.chain_id(),
//    };
//    
//    // Sign and send transaction
//    let signed_tx = signer.sign_transaction(&tx_data)?;
//    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;
//    
//    // Get token details to improve the receipt message
//    let token_symbol = match erc20_symbol(token_address, provider) {
//        Ok(symbol) => symbol,
//        Err(_) => "tokens".to_string(),
//    };
//    
//    let token_decimals = match erc20_decimals(token_address, provider) {
//        Ok(decimals) => decimals,
//        Err(_) => 18, // Assume 18 decimals if unavailable
//    };
//    
//    // Format amount in token units
//    let amount_float = amount.to::<u128>() as f64 / 10f64.powi(token_decimals as i32);
//    
//    Ok(TxReceipt {
//        hash: tx_hash,
//        details: format!("Approved {:.6} {} to be spent by {}", amount_float, token_symbol, spender_address),
//    })
//}
//
///// Transfer ERC20 tokens from one address to another (requires approval)
//pub fn erc20_transfer_from<S: Signer>(
//    token_address: &str,
//    from_address: &str,
//    to_address: &str,
//    amount: U256,
//    provider: &Provider,
//    signer: &S
//) -> Result<TxReceipt, WalletError> {
//    kiprintln!("PROCESS_LIB::erc20_transfer_from starting");
//    
//    // Resolve addresses
//    let token = resolve_name(token_address, provider.chain_id)?;
//    let from = resolve_name(from_address, provider.chain_id)?;
//    let to = resolve_name(to_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC20::transferFromCall { from, to, value: amount };
//    let call_data = call.abi_encode();
//    
//    // Get the current nonce for the signer's address
//    let signer_address = signer.address();
//    let nonce = provider.get_transaction_count(signer_address, None)?
//        .to::<u64>();
//    
//    // Estimate gas
//    let tx_req = TransactionRequest {
//        from: Some(signer_address),
//        to: Some(TxKind::Call(token)),
//        input: call_data.clone().into(),
//        ..Default::default()
//    };
//    
//    // Try to estimate gas, fall back to 100,000 if estimation fails
//    let gas_limit = match provider.estimate_gas(tx_req, None) {
//        Ok(gas) => (gas.to::<u64>() * 120) / 100, // Add 20% buffer
//        Err(_) => 100_000, // Default gas limit
//    };
//    
//    // Calculate gas price based on the chain
//    let (gas_price, priority_fee) = match signer.chain_id() {
//        1 => calculate_eth_mainnet_gas(provider)?,
//        8453 => calculate_base_gas(provider)?,
//        10 => calculate_optimism_gas(provider)?,
//        _ => {
//            let base_fee = provider.get_gas_price()?.to::<u128>();
//            let adjusted_fee = (base_fee * 130) / 100;
//            (adjusted_fee, adjusted_fee / 10)
//        }
//    };
//    
//    // Prepare transaction data
//    let tx_data = TransactionData {
//        to: token,
//        value: U256::ZERO, // No ETH sent with token transfers
//        data: Some(call_data),
//        nonce,
//        gas_limit,
//        gas_price,
//        max_priority_fee: Some(priority_fee),
//        chain_id: signer.chain_id(),
//    };
//    
//    // Sign and send transaction
//    let signed_tx = signer.sign_transaction(&tx_data)?;
//    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;
//    
//    // Get token details to improve the receipt message
//    let token_symbol = match erc20_symbol(token_address, provider) {
//        Ok(symbol) => symbol,
//        Err(_) => "tokens".to_string(),
//    };
//    
//    let token_decimals = match erc20_decimals(token_address, provider) {
//        Ok(decimals) => decimals,
//        Err(_) => 18, // Assume 18 decimals if unavailable
//    };
//    
//    // Format amount in token units
//    let amount_float = amount.to::<u128>() as f64 / 10f64.powi(token_decimals as i32);
//    
//    Ok(TxReceipt {
//        hash: tx_hash,
//        details: format!("Transferred {:.6} {} from {} to {}", 
//            amount_float, token_symbol, from_address, to_address),
//    })
//}
//
////
//// HYPERMAP AND ERC-6551 FUNCTIONS
////
//
///// Result type for Hypermap transactions
//#[derive(Debug, Clone)]
//pub struct HypermapTxReceipt {
//    /// Transaction hash
//    pub hash: TxHash,
//    /// Description of the operation
//    pub description: String,
//}
//
///// Create a note (mutable data) on a Hypermap namespace entry
//pub fn create_note<S: Signer>(
//    parent_entry: &str,
//    note_key: &str,
//    data: Vec<u8>,
//    provider: Provider,
//    signer: &S,
//) -> Result<HypermapTxReceipt, WalletError> {
//    // Verify the note key is valid
//    if !valid_note(note_key) {
//        return Err(WalletError::NameResolutionError(
//            format!("Invalid note key '{}'. Must start with '~' and contain only lowercase letters, numbers, and hyphens", note_key)
//        ));
//    }
//
//    // Get the parent TBA address
//    let hypermap = provider.hypermap();
//    let parent_hash_str = namehash(parent_entry);
//    
//    println!("Parent entry: {}", parent_entry);
//    println!("Parent hash: {}", parent_hash_str);
//    
//    let (tba, owner, _) = hypermap.get_hash(&parent_hash_str)?;
//    
//    println!("TBA address (parent): {}", tba);
//    println!("Owner address: {}", owner);
//    
//    // Check that the signer is the owner of the parent entry
//    let signer_address = signer.address();
//    println!("Signer address: {}", signer_address);
//    
//    if signer_address != owner {
//        return Err(WalletError::PermissionDenied(
//            format!("Signer address {} does not own the parent entry {}", signer_address, parent_entry)
//        ));
//    }
//    
//    // Get the hypermap contract address
//    let hypermap_address = *hypermap.address();
//    println!("Hypermap contract address: {}", hypermap_address);
//
//    // Create the note function call data
//    let note_function = hypermap::contract::noteCall {
//        note: Bytes::from(note_key.as_bytes().to_vec()),
//        data: Bytes::from(data),
//    };
//    let note_call_data = note_function.abi_encode();
//    
//    // Now create an ERC-6551 execute call to send from the wallet to the TBA
//    let execute_call = IERC6551Account::executeCall {
//        to: hypermap_address,
//        value: U256::ZERO,
//        data: Bytes::from(note_call_data),
//        operation: 0 // CALL operation
//    };
//    let execute_call_data = execute_call.abi_encode();
//    
//    // Send the transaction from the wallet to the TBA
//    let (tx_hash, _) = send_transaction(
//        tba,
//        execute_call_data.into(),
//        U256::ZERO,
//        provider,
//        signer
//    )?;
//    
//    // Return the receipt with transaction details
//    Ok(HypermapTxReceipt {
//        hash: tx_hash,
//        description: format!("Created note '{}' on '{}'", note_key, parent_entry),
//    })
//}
//
///// Create a fact (immutable data) on a Hypermap namespace entry
//pub fn create_fact<S: Signer>(
//    parent_entry: &str,
//    fact_key: &str,
//    data: Vec<u8>,
//    provider: Provider,
//    signer: &S,
//) -> Result<HypermapTxReceipt, WalletError> {
//    // Verify the fact key is valid
//    if !valid_fact(fact_key) {
//        return Err(WalletError::NameResolutionError(
//            format!("Invalid fact key '{}'. Must start with '!' and contain only lowercase letters, numbers, and hyphens", fact_key)
//        ));
//    }
//
//    // Get the parent TBA address
//    let hypermap = provider.hypermap();
//    let parent_hash_str = namehash(parent_entry);
//    let (tba, owner, _) = hypermap.get_hash(&parent_hash_str)?;
//    
//    // Check that the signer is the owner of the parent entry
//    let signer_address = signer.address();
//    if signer_address != owner {
//        return Err(WalletError::PermissionDenied(
//            format!("Signer address {} does not own the parent entry {}", signer_address, parent_entry)
//        ));
//    }
//
//    // Get the hypermap contract address
//    let hypermap_address = *hypermap.address();
//
//    // Create the fact function call data
//    let fact_function = hypermap::contract::factCall {
//        fact: Bytes::from(fact_key.as_bytes().to_vec()),
//        data: Bytes::from(data),
//    };
//    let fact_call_data = fact_function.abi_encode();
//
//    // Create an ERC-6551 execute call
//    let execute_call = IERC6551Account::executeCall {
//        to: hypermap_address,
//        value: U256::ZERO,
//        data: Bytes::from(fact_call_data),
//        operation: 0 // CALL operation
//    };
//    let execute_call_data = execute_call.abi_encode();
//
//    // Send the transaction
//    let (tx_hash, _) = send_transaction(
//        tba,
//        execute_call_data.into(),
//        U256::ZERO,
//        provider,
//        signer
//    )?;
//    
//    // Return the receipt with transaction details
//    Ok(HypermapTxReceipt {
//        hash: tx_hash,
//        description: format!("Created fact '{}' on '{}'", fact_key, parent_entry),
//    })
//}
//
///// Mint a new namespace entry under a parent entry
//pub fn mint_entry<S: Signer>(
//    parent_entry: &str,
//    label: &str,
//    recipient: &str,
//    implementation: &str,
//    provider: Provider,
//    signer: &S,
//) -> Result<HypermapTxReceipt, WalletError> {
//    // Verify the label is valid
//    if !valid_name(label) {
//        return Err(WalletError::NameResolutionError(
//            format!("Invalid label '{}'. Must contain only lowercase letters, numbers, and hyphens", label)
//        ));
//    }
//
//    // Get the parent TBA address
//    let hypermap = provider.hypermap();
//    let parent_hash_str = namehash(parent_entry);
//    kiprintln!("PROCESS_LIB::mint_entry parent_hash_str: {}", parent_hash_str);
//    let (tba, owner, _) = hypermap.get_hash(&parent_hash_str)?;
//    
//    // Check that the signer is the owner of the parent entry
//    let signer_address = signer.address();
//    if signer_address != owner {
//        return Err(WalletError::PermissionDenied(
//            format!("Signer address {} does not own the parent entry {}", signer_address, parent_entry)
//        ));
//    }
//
//    // Resolve recipient address
//    let recipient_address = resolve_name(recipient, provider.chain_id)?;
//    
//    // Resolve implementation address
//    let implementation_address = resolve_name(implementation, provider.chain_id)?;
//
//    // Get the hypermap contract address
//    let hypermap_address = *hypermap.address();
//
//    // Create the mint function call data
//    let mint_function = hypermap::contract::mintCall {
//        who: recipient_address,
//        label: Bytes::from(label.as_bytes().to_vec()),
//        initialization: Bytes::default(), // No initialization data
//        erc721Data: Bytes::default(),    // No ERC721 data
//        implementation: implementation_address,
//    };
//    let mint_call_data = mint_function.abi_encode();
//
//    // Create an ERC-6551 execute call
//    let execute_call = IERC6551Account::executeCall {
//        to: hypermap_address,
//        value: U256::ZERO,
//        data: Bytes::from(mint_call_data),
//        operation: 0 // CALL operation
//    };
//    let execute_call_data = execute_call.abi_encode();
//
//    kiprintln!("Parent entry: {}", parent_entry);
//    kiprintln!("Parent hash: {}", parent_hash_str);
//    kiprintln!("TBA address: {}", tba);
//    kiprintln!("Owner address: {}", owner);
//    kiprintln!("Signer address: {}", signer_address);
//
//    // Send the transaction
//    let (tx_hash, _) = send_transaction(
//        tba,
//        execute_call_data.into(),
//        U256::ZERO,
//        provider,
//        signer
//    )?;
//    
//    // Return the receipt with transaction details
//    Ok(HypermapTxReceipt {
//        hash: tx_hash,
//        description: format!("Minted new entry '{}' under '{}'", label, parent_entry),
//    })
//}
//
///// Set the gene for a namespace entry
//pub fn set_gene<S: Signer>(
//    entry: &str,
//    gene_implementation: &str,
//    provider: Provider,
//    signer: &S,
//) -> Result<HypermapTxReceipt, WalletError> {
//    // Get the entry's TBA address
//    let hypermap = provider.hypermap();
//    let entry_hash_str = namehash(entry);
//    let (tba, owner, _) = hypermap.get_hash(&entry_hash_str)?;
//    
//    // Check that the signer is the owner of the entry
//    let signer_address = signer.address();
//    if signer_address != owner {
//        return Err(WalletError::PermissionDenied(
//            format!("Signer address {} does not own the entry {}", signer_address, entry)
//        ));
//    }
//
//    // Resolve gene implementation address
//    let gene_address = resolve_name(gene_implementation, provider.chain_id)?;
//
//    // Get the hypermap contract address
//    let hypermap_address = *hypermap.address();
//
//    // Create the gene function call data
//    let gene_function = hypermap::contract::geneCall {
//        _gene: gene_address,
//    };
//    let gene_call_data = gene_function.abi_encode();
//
//    // Create an ERC-6551 execute call
//    let execute_call = IERC6551Account::executeCall {
//        to: hypermap_address,
//        value: U256::ZERO,
//        data: Bytes::from(gene_call_data),
//        operation: 0 // CALL operation
//    };
//    let execute_call_data = execute_call.abi_encode();
//
//    // Send the transaction
//    let (tx_hash, _) = send_transaction(
//        tba,
//        execute_call_data.into(),
//        U256::ZERO,
//        provider,
//        signer
//    )?;
//    
//    // Return the receipt with transaction details
//    Ok(HypermapTxReceipt {
//        hash: tx_hash,
//        description: format!("Set gene for '{}' to '{}'", entry, gene_implementation),
//    })
//}
//
///// Send a transaction to an address with custom data and value
//fn send_transaction<S: Signer>(
//    to: EthAddress,
//    data: Bytes,
//    value: U256,
//    provider: Provider,
//    signer: &S,
//) -> Result<(TxHash, Vec<u8>), WalletError> {
//    let chain_id = signer.chain_id();
//    
//    kiprintln!("PROCESS_LIB::send_transaction starting");
//    kiprintln!("PROCESS_LIB::send_transaction chain_id: {}", chain_id);
//    
//    // Get gas estimates - use 50% buffer for Base to ensure acceptance
//    let base_fee = provider.get_gas_price()?.to::<u128>();
//    let gas_price = (base_fee * 150) / 100; // 50% buffer
//    let priority_fee = gas_price / 5;      // 20% of gas price
//    
//    kiprintln!("PROCESS_LIB::send_transaction base_fee: {}, priority_fee: {}", base_fee, priority_fee);
//    kiprintln!("PROCESS_LIB::send_transaction gas_price: {}", gas_price);
//    
//    // Get the current nonce for the signer's address
//    let from_address = signer.address();
//    let nonce = provider.get_transaction_count(from_address, None)?
//        .to::<u64>();
//    
//    kiprintln!("PROCESS_LIB::send_transaction nonce: {}", nonce);
//
//    // For ERC-6551 account operations, use a higher gas limit
//    // The ERC-6551 execute function is complex and gas-intensive
//    let estimated_gas = 500_000; // Start high for ERC-6551
//    
//    // Add 50% buffer to estimated gas since this is a complex operation
//    let gas_limit = (estimated_gas * 150) / 100;
//    
//    kiprintln!("PROCESS_LIB::send_transaction estimated_gas: {}", estimated_gas);
//    kiprintln!("PROCESS_LIB::send_transaction gas_limit: {}", gas_limit);
//    
//    // Prepare transaction data
//    let tx_data = TransactionData {
//        to,
//        value,
//        data: Some(data.to_vec()),
//        nonce,
//        gas_limit,
//        gas_price,
//        max_priority_fee: Some(priority_fee),
//        chain_id,
//    };
//    
//    // Sign the transaction
//    let signed_tx = signer.sign_transaction(&tx_data)?;
//    kiprintln!("PROCESS_LIB::send_transaction signed");
//    
//    // Send the transaction
//    let tx_hash = provider.send_raw_transaction(signed_tx.clone().into())?;
//    kiprintln!("PROCESS_LIB::send_transaction tx_hash: {}", tx_hash);
//    
//    // Return both the hash and the raw transaction data
//    Ok((tx_hash, signed_tx))
//}
//
////
//// ERC-721 NFT FUNCTIONS
////
//
///// Get the NFT balance of an address
//pub fn erc721_balance_of(
//    token_address: &str,
//    owner_address: &str,
//    provider: &Provider
//) -> Result<U256, WalletError> {
//    kiprintln!("PROCESS_LIB::erc721_balance_of starting");
//    
//    // Resolve addresses
//    let token = resolve_name(token_address, provider.chain_id)?;
//    let owner = resolve_name(owner_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC721::balanceOfCall { owner };
//    let call_data = call.abi_encode();
//    
//    // Create the transaction request
//    let tx = TransactionRequest {
//        to: Some(TxKind::Call(token)),
//        input: call_data.into(),
//        ..Default::default()
//    };
//    
//    // Call the contract
//    let result = provider.call(tx, None)?;
//    
//    // Verify we got a valid result
//    if result.is_empty() {
//        return Err(WalletError::TransactionError("Empty result from balanceOf call".into()));
//    }
//    
//    // Decode the result
//    let balance = match IERC721::balanceOfCall::abi_decode_returns(&result, true) {
//        Ok(decoded) => decoded._0, // Returns (U256,)
//        Err(e) => return Err(WalletError::TransactionError(
//            format!("Failed to decode balanceOf result: {}", e)
//        )),
//    };
//    
//    Ok(balance)
//}
//
///// Get the owner of an NFT token
//pub fn erc721_owner_of(
//    token_address: &str,
//    token_id: U256,
//    provider: &Provider
//) -> Result<EthAddress, WalletError> {
//    kiprintln!("PROCESS_LIB::erc721_owner_of starting");
//    
//    // Resolve token address
//    let token = resolve_name(token_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC721::ownerOfCall { tokenId: token_id };
//    let call_data = call.abi_encode();
//    
//    // Create the transaction request
//    let tx = TransactionRequest {
//        to: Some(TxKind::Call(token)),
//        input: call_data.into(),
//        ..Default::default()
//    };
//    
//    // Call the contract
//    let result = provider.call(tx, None)?;
//    
//    // Verify we got a valid result
//    if result.is_empty() {
//        return Err(WalletError::TransactionError("Empty result from ownerOf call".into()));
//    }
//    
//    // Decode the result
//    let owner = match IERC721::ownerOfCall::abi_decode_returns(&result, true) {
//        Ok(decoded) => decoded._0, // Returns (address,)
//        Err(e) => return Err(WalletError::TransactionError(
//            format!("Failed to decode ownerOf result: {}", e)
//        )),
//    };
//    
//    Ok(owner)
//}
//
///// Check if an operator is approved for all NFTs of an owner
//pub fn erc721_is_approved_for_all(
//    token_address: &str,
//    owner_address: &str,
//    operator_address: &str,
//    provider: &Provider
//) -> Result<bool, WalletError> {
//    kiprintln!("PROCESS_LIB::erc721_is_approved_for_all starting");
//    
//    // Resolve addresses
//    let token = resolve_name(token_address, provider.chain_id)?;
//    let owner = resolve_name(owner_address, provider.chain_id)?;
//    let operator = resolve_name(operator_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC721::isApprovedForAllCall { owner, operator };
//    let call_data = call.abi_encode();
//    
//    // Create the transaction request
//    let tx = TransactionRequest {
//        to: Some(TxKind::Call(token)),
//        input: call_data.into(),
//        ..Default::default()
//    };
//    
//    // Call the contract
//    let result = provider.call(tx, None)?;
//    
//    // Verify we got a valid result
//    if result.is_empty() {
//        return Err(WalletError::TransactionError("Empty result from isApprovedForAll call".into()));
//    }
//    
//    // Decode the result
//    let is_approved = match IERC721::isApprovedForAllCall::abi_decode_returns(&result, true) {
//        Ok(decoded) => decoded._0, // Returns (bool,)
//        Err(e) => return Err(WalletError::TransactionError(
//            format!("Failed to decode isApprovedForAll result: {}", e)
//        )),
//    };
//    
//    Ok(is_approved)
//}
//
///// Safely transfer an NFT
//pub fn erc721_safe_transfer_from<S: Signer>(
//    token_address: &str,
//    from_address: &str,
//    to_address: &str,
//    token_id: U256,
//    provider: &Provider,
//    signer: &S
//) -> Result<TxReceipt, WalletError> {
//    kiprintln!("PROCESS_LIB::erc721_safe_transfer_from starting");
//    
//    // Resolve addresses
//    let token = resolve_name(token_address, provider.chain_id)?;
//    let from = resolve_name(from_address, provider.chain_id)?;
//    let to = resolve_name(to_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC721::safeTransferFromCall { from, to, tokenId: token_id };
//    let call_data = call.abi_encode();
//    
//    // Get the current nonce for the signer's address
//    let signer_address = signer.address();
//    let nonce = provider.get_transaction_count(signer_address, None)?
//        .to::<u64>();
//    
//    // Estimate gas
//    let tx_req = TransactionRequest {
//        from: Some(signer_address),
//        to: Some(TxKind::Call(token)),
//        input: call_data.clone().into(),
//        ..Default::default()
//    };
//    
//    // Try to estimate gas, fall back to 200,000 if estimation fails
//    let gas_limit = match provider.estimate_gas(tx_req, None) {
//        Ok(gas) => (gas.to::<u64>() * 120) / 100, // Add 20% buffer
//        Err(_) => 200_000, // Default gas limit for NFT transfers (higher than ERC20)
//    };
//    
//    // Calculate gas price based on the chain
//    let (gas_price, priority_fee) = match signer.chain_id() {
//        1 => calculate_eth_mainnet_gas(provider)?,
//        8453 => calculate_base_gas(provider)?,
//        10 => calculate_optimism_gas(provider)?,
//        _ => {
//            let base_fee = provider.get_gas_price()?.to::<u128>();
//            let adjusted_fee = (base_fee * 130) / 100;
//            (adjusted_fee, adjusted_fee / 10)
//        }
//    };
//    
//    // Prepare transaction data
//    let tx_data = TransactionData {
//        to: token,
//        value: U256::ZERO, // No ETH sent with NFT transfers
//        data: Some(call_data),
//        nonce,
//        gas_limit,
//        gas_price,
//        max_priority_fee: Some(priority_fee),
//        chain_id: signer.chain_id(),
//    };
//    
//    // Sign and send transaction
//    let signed_tx = signer.sign_transaction(&tx_data)?;
//    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;
//    
//    Ok(TxReceipt {
//        hash: tx_hash,
//        details: format!("Safely transferred NFT ID {} from {} to {}", token_id, from_address, to_address),
//    })
//}
//
///// Set approval for all tokens to an operator
//pub fn erc721_set_approval_for_all<S: Signer>(
//    token_address: &str,
//    operator_address: &str,
//    approved: bool,
//    provider: &Provider,
//    signer: &S
//) -> Result<TxReceipt, WalletError> {
//    kiprintln!("PROCESS_LIB::erc721_set_approval_for_all starting");
//    
//    // Resolve addresses
//    let token = resolve_name(token_address, provider.chain_id)?;
//    let operator = resolve_name(operator_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC721::setApprovalForAllCall { operator, approved };
//    let call_data = call.abi_encode();
//    
//    // Get the current nonce for the signer's address
//    let signer_address = signer.address();
//    let nonce = provider.get_transaction_count(signer_address, None)?
//        .to::<u64>();
//    
//    // Estimate gas
//    let tx_req = TransactionRequest {
//        from: Some(signer_address),
//        to: Some(TxKind::Call(token)),
//        input: call_data.clone().into(),
//        ..Default::default()
//    };
//    
//    // Try to estimate gas, fall back to 60,000 if estimation fails
//    let gas_limit = match provider.estimate_gas(tx_req, None) {
//        Ok(gas) => (gas.to::<u64>() * 120) / 100, // Add 20% buffer
//        Err(_) => 60_000, // Default gas limit
//    };
//    
//    // Calculate gas price based on the chain
//    let (gas_price, priority_fee) = match signer.chain_id() {
//        1 => calculate_eth_mainnet_gas(provider)?,
//        8453 => calculate_base_gas(provider)?,
//        10 => calculate_optimism_gas(provider)?,
//        _ => {
//            let base_fee = provider.get_gas_price()?.to::<u128>();
//            let adjusted_fee = (base_fee * 130) / 100;
//            (adjusted_fee, adjusted_fee / 10)
//        }
//    };
//    
//    // Prepare transaction data
//    let tx_data = TransactionData {
//        to: token,
//        value: U256::ZERO,
//        data: Some(call_data),
//        nonce,
//        gas_limit,
//        gas_price,
//        max_priority_fee: Some(priority_fee),
//        chain_id: signer.chain_id(),
//    };
//    
//    // Sign and send transaction
//    let signed_tx = signer.sign_transaction(&tx_data)?;
//    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;
//    
//    Ok(TxReceipt {
//        hash: tx_hash,
//        details: format!(
//            "{} operator {} to manage all of your NFTs in contract {}", 
//            if approved { "Approved" } else { "Revoked approval for" },
//            operator_address,
//            token_address
//        ),
//    })
//}
//
////
//// ERC-1155 MULTI-TOKEN FUNCTIONS
////
//
///// Get the balance of a specific token ID for an account
//pub fn erc1155_balance_of(
//    token_address: &str,
//    account_address: &str,
//    token_id: U256,
//    provider: &Provider
//) -> Result<U256, WalletError> {
//    kiprintln!("PROCESS_LIB::erc1155_balance_of starting");
//    
//    // Resolve addresses
//    let token = resolve_name(token_address, provider.chain_id)?;
//    let account = resolve_name(account_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC1155::balanceOfCall { account, id: token_id };
//    let call_data = call.abi_encode();
//    
//    // Create the transaction request
//    let tx = TransactionRequest {
//        to: Some(TxKind::Call(token)),
//        input: call_data.into(),
//        ..Default::default()
//    };
//    
//    // Call the contract
//    let result = provider.call(tx, None)?;
//    
//    // Verify we got a valid result
//    if result.is_empty() {
//        return Err(WalletError::TransactionError("Empty result from balanceOf call".into()));
//    }
//    
//    // Decode the result
//    let balance = match IERC1155::balanceOfCall::abi_decode_returns(&result, true) {
//        Ok(decoded) => decoded._0, // Returns (U256,)
//        Err(e) => return Err(WalletError::TransactionError(
//            format!("Failed to decode balanceOf result: {}", e)
//        )),
//    };
//    
//    Ok(balance)
//}
//
///// Get balances for multiple accounts and token IDs
//pub fn erc1155_balance_of_batch(
//    token_address: &str,
//    account_addresses: Vec<&str>,
//    token_ids: Vec<U256>,
//    provider: &Provider
//) -> Result<Vec<U256>, WalletError> {
//    kiprintln!("PROCESS_LIB::erc1155_balance_of_batch starting");
//    
//    // Check that arrays are same length
//    if account_addresses.len() != token_ids.len() {
//        return Err(WalletError::TransactionError(
//            "Arrays of accounts and token IDs must have the same length".into()
//        ));
//    }
//    
//    // Resolve token address
//    let token = resolve_name(token_address, provider.chain_id)?;
//    
//    // Resolve all account addresses
//    let mut accounts = Vec::with_capacity(account_addresses.len());
//    for addr in account_addresses {
//        accounts.push(resolve_name(addr, provider.chain_id)?);
//    }
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC1155::balanceOfBatchCall { accounts, ids: token_ids };
//    let call_data = call.abi_encode();
//    
//    // Create the transaction request
//    let tx = TransactionRequest {
//        to: Some(TxKind::Call(token)),
//        input: call_data.into(),
//        ..Default::default()
//    };
//    
//    // Call the contract
//    let result = provider.call(tx, None)?;
//    
//    // Verify we got a valid result
//    if result.is_empty() {
//        return Err(WalletError::TransactionError("Empty result from balanceOfBatch call".into()));
//    }
//    
//    // Decode the result
//    let balances = match IERC1155::balanceOfBatchCall::abi_decode_returns(&result, true) {
//        Ok(decoded) => decoded._0, // Returns (Vec<U256>,)
//        Err(e) => return Err(WalletError::TransactionError(
//            format!("Failed to decode balanceOfBatch result: {}", e)
//        )),
//    };
//    
//    Ok(balances)
//}
//
///// Check if an operator is approved for all tokens of an account
//pub fn erc1155_is_approved_for_all(
//    token_address: &str,
//    account_address: &str,
//    operator_address: &str,
//    provider: &Provider
//) -> Result<bool, WalletError> {
//    kiprintln!("PROCESS_LIB::erc1155_is_approved_for_all starting");
//    
//    // Resolve addresses
//    let token = resolve_name(token_address, provider.chain_id)?;
//    let account = resolve_name(account_address, provider.chain_id)?;
//    let operator = resolve_name(operator_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC1155::isApprovedForAllCall { account, operator };
//    let call_data = call.abi_encode();
//    
//    // Create the transaction request
//    let tx = TransactionRequest {
//        to: Some(TxKind::Call(token)),
//        input: call_data.into(),
//        ..Default::default()
//    };
//    
//    // Call the contract
//    let result = provider.call(tx, None)?;
//    
//    // Verify we got a valid result
//    if result.is_empty() {
//        return Err(WalletError::TransactionError("Empty result from isApprovedForAll call".into()));
//    }
//    
//    // Decode the result
//    let is_approved = match IERC1155::isApprovedForAllCall::abi_decode_returns(&result, true) {
//        Ok(decoded) => decoded._0, // Returns (bool,)
//        Err(e) => return Err(WalletError::TransactionError(
//            format!("Failed to decode isApprovedForAll result: {}", e)
//        )),
//    };
//    
//    Ok(is_approved)
//}
//
///// Set approval for all tokens to an operator
//pub fn erc1155_set_approval_for_all<S: Signer>(
//    token_address: &str,
//    operator_address: &str,
//    approved: bool,
//    provider: &Provider,
//    signer: &S
//) -> Result<TxReceipt, WalletError> {
//    kiprintln!("PROCESS_LIB::erc1155_set_approval_for_all starting");
//    
//    // Resolve addresses
//    let token = resolve_name(token_address, provider.chain_id)?;
//    let operator = resolve_name(operator_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC1155::setApprovalForAllCall { operator, approved };
//    let call_data = call.abi_encode();
//    
//    // Get the current nonce for the signer's address
//    let signer_address = signer.address();
//    let nonce = provider.get_transaction_count(signer_address, None)?
//        .to::<u64>();
//    
//    // Estimate gas
//    let tx_req = TransactionRequest {
//        from: Some(signer_address),
//        to: Some(TxKind::Call(token)),
//        input: call_data.clone().into(),
//        ..Default::default()
//    };
//    
//    // Try to estimate gas, fall back to 60,000 if estimation fails
//    let gas_limit = match provider.estimate_gas(tx_req, None) {
//        Ok(gas) => (gas.to::<u64>() * 120) / 100, // Add 20% buffer
//        Err(_) => 60_000, // Default gas limit
//    };
//    
//    // Calculate gas price based on the chain
//    let (gas_price, priority_fee) = match signer.chain_id() {
//        1 => calculate_eth_mainnet_gas(provider)?,
//        8453 => calculate_base_gas(provider)?,
//        10 => calculate_optimism_gas(provider)?,
//        _ => {
//            let base_fee = provider.get_gas_price()?.to::<u128>();
//            let adjusted_fee = (base_fee * 130) / 100;
//            (adjusted_fee, adjusted_fee / 10)
//        }
//    };
//    
//    // Prepare transaction data
//    let tx_data = TransactionData {
//        to: token,
//        value: U256::ZERO,
//        data: Some(call_data),
//        nonce,
//        gas_limit,
//        gas_price,
//        max_priority_fee: Some(priority_fee),
//        chain_id: signer.chain_id(),
//    };
//    
//    // Sign and send transaction
//    let signed_tx = signer.sign_transaction(&tx_data)?;
//    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;
//    
//    Ok(TxReceipt {
//        hash: tx_hash,
//        details: format!(
//            "{} operator {} to manage all of your ERC1155 tokens in contract {}", 
//            if approved { "Approved" } else { "Revoked approval for" },
//            operator_address,
//            token_address
//        ),
//    })
//}
//
///// Transfer a single ERC1155 token
//pub fn erc1155_safe_transfer_from<S: Signer>(
//    token_address: &str,
//    from_address: &str,
//    to_address: &str,
//    token_id: U256,
//    amount: U256,
//    data: Vec<u8>,
//    provider: &Provider,
//    signer: &S
//) -> Result<TxReceipt, WalletError> {
//    kiprintln!("PROCESS_LIB::erc1155_safe_transfer_from starting");
//    
//    // Resolve addresses
//    let token = resolve_name(token_address, provider.chain_id)?;
//    let from = resolve_name(from_address, provider.chain_id)?;
//    let to = resolve_name(to_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC1155::safeTransferFromCall { 
//        from, 
//        to, 
//        id: token_id,
//        amount,
//        data: Bytes::from(data)
//    };
//    let call_data = call.abi_encode();
//    
//    // Get the current nonce for the signer's address
//    let signer_address = signer.address();
//    let nonce = provider.get_transaction_count(signer_address, None)?
//        .to::<u64>();
//    
//    // Estimate gas
//    let tx_req = TransactionRequest {
//        from: Some(signer_address),
//        to: Some(TxKind::Call(token)),
//        input: call_data.clone().into(),
//        ..Default::default()
//    };
//    
//    // Try to estimate gas, fall back to 150,000 if estimation fails
//    let gas_limit = match provider.estimate_gas(tx_req, None) {
//        Ok(gas) => (gas.to::<u64>() * 120) / 100, // Add 20% buffer
//        Err(_) => 150_000, // Default gas limit
//    };
//    
//    // Calculate gas price based on the chain
//    let (gas_price, priority_fee) = match signer.chain_id() {
//        1 => calculate_eth_mainnet_gas(provider)?,
//        8453 => calculate_base_gas(provider)?,
//        10 => calculate_optimism_gas(provider)?,
//        _ => {
//            let base_fee = provider.get_gas_price()?.to::<u128>();
//            let adjusted_fee = (base_fee * 130) / 100;
//            (adjusted_fee, adjusted_fee / 10)
//        }
//    };
//    
//    // Prepare transaction data
//    let tx_data = TransactionData {
//        to: token,
//        value: U256::ZERO,
//        data: Some(call_data),
//        nonce,
//        gas_limit,
//        gas_price,
//        max_priority_fee: Some(priority_fee),
//        chain_id: signer.chain_id(),
//    };
//    
//    // Sign and send transaction
//    let signed_tx = signer.sign_transaction(&tx_data)?;
//    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;
//    
//    Ok(TxReceipt {
//        hash: tx_hash,
//        details: format!(
//            "Transferred {} of token ID {} from {} to {}", 
//            amount, token_id, from_address, to_address
//        ),
//    })
//}
//
///// Batch transfer multiple ERC1155 tokens
//pub fn erc1155_safe_batch_transfer_from<S: Signer>(
//    token_address: &str,
//    from_address: &str,
//    to_address: &str,
//    token_ids: Vec<U256>,
//    amounts: Vec<U256>,
//    data: Vec<u8>,
//    provider: &Provider,
//    signer: &S
//) -> Result<TxReceipt, WalletError> {
//    kiprintln!("PROCESS_LIB::erc1155_safe_batch_transfer_from starting");
//    
//    // Check that arrays are same length
//    if token_ids.len() != amounts.len() {
//        return Err(WalletError::TransactionError(
//            "Arrays of token IDs and amounts must have the same length".into()
//        ));
//    }
//    
//    // Resolve addresses
//    let token = resolve_name(token_address, provider.chain_id)?;
//    let from = resolve_name(from_address, provider.chain_id)?;
//    let to = resolve_name(to_address, provider.chain_id)?;
//    
//    // Create the call using sol! macro generated struct
//    let call = IERC1155::safeBatchTransferFromCall { 
//        from, 
//        to, 
//        ids: token_ids.clone(),
//        amounts: amounts.clone(),
//        data: Bytes::from(data)
//    };
//    let call_data = call.abi_encode();
//    
//    // Get the current nonce for the signer's address
//    let signer_address = signer.address();
//    let nonce = provider.get_transaction_count(signer_address, None)?
//        .to::<u64>();
//    
//    // Estimate gas - this can be expensive, especially with many tokens
//    let tx_req = TransactionRequest {
//        from: Some(signer_address),
//        to: Some(TxKind::Call(token)),
//        input: call_data.clone().into(),
//        ..Default::default()
//    };
//    
//    // Try to estimate gas, fall back to 200,000 + 50,000 per token if estimation fails
//    let fallback_gas = 200_000 + (token_ids.len() as u64 * 50_000);
//    let gas_limit = match provider.estimate_gas(tx_req, None) {
//        Ok(gas) => (gas.to::<u64>() * 120) / 100, // Add 20% buffer
//        Err(_) => fallback_gas, // Default gas limit that scales with number of tokens
//    };
//    
//    // Calculate gas price based on the chain
//    let (gas_price, priority_fee) = match signer.chain_id() {
//        1 => calculate_eth_mainnet_gas(provider)?,
//        8453 => calculate_base_gas(provider)?,
//        10 => calculate_optimism_gas(provider)?,
//        _ => {
//            let base_fee = provider.get_gas_price()?.to::<u128>();
//            let adjusted_fee = (base_fee * 130) / 100;
//            (adjusted_fee, adjusted_fee / 10)
//        }
//    };
//    
//    // Prepare transaction data
//    let tx_data = TransactionData {
//        to: token,
//        value: U256::ZERO,
//        data: Some(call_data),
//        nonce,
//        gas_limit,
//        gas_price,
//        max_priority_fee: Some(priority_fee),
//        chain_id: signer.chain_id(),
//    };
//    
//    // Sign and send transaction
//    let signed_tx = signer.sign_transaction(&tx_data)?;
//    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;
//    
//    Ok(TxReceipt {
//        hash: tx_hash,
//        details: format!(
//            "Batch transferred {} token types from {} to {}", 
//            token_ids.len(), from_address, to_address
//        ),
//    })
//}



////! Ethereum wallet functionality for Hyperware.
////!
////! This module provides higher-level wallet functionality, building on top of
////! the cryptographic operations in the signer module. It handles transaction 
////! construction, name resolution, and account management.
////!
////! wallet module:
////! 1. Provides convenient transaction creation and submission
////! 2. Handles Hypermap name resolution
////! 3. Manages account state and balances
////! 4. Offers a simpler interface for common ETH operations (more to do here)
//
//use crate::eth::{
//    Provider, 
//    EthError,
//    BlockNumberOrTag
//};
//use crate::signer::{
//    Signer, 
//    LocalSigner, 
//    TransactionData, 
//    SignerError, 
//    EncryptedSignerData
//};
//use crate::hypermap::{
//    namehash, 
//    valid_note, 
//    valid_fact, 
//    valid_name,
//};
//use crate::{hypermap, kiprintln};
//
//use thiserror::Error;
//use alloy_primitives::{
//    Address as EthAddress, 
//    TxHash, 
//    U256,
//    Bytes
//};
//use alloy::rpc::types::{
//    TransactionReceipt, 
//    TransactionRequest
//};
//use alloy_primitives::TxKind;
//use std::str::FromStr;
//use alloy_sol_types::SolCall;
//
//#[derive(Debug, Error)]
//pub enum WalletError {
//    #[error("signing error: {0}")]
//    SignerError(#[from] SignerError),
//    
//    #[error("ethereum error: {0}")]
//    EthError(#[from] EthError),
//    
//    #[error("name resolution error: {0}")]
//    NameResolutionError(String),
//    
//    #[error("invalid amount: {0}")]
//    InvalidAmount(String),
//    
//    #[error("transaction error: {0}")]
//    TransactionError(String),
//
//    #[error("gas estimation error: {0}")]
//    GasEstimationError(String),
//    
//    #[error("insufficient funds: {0}")]
//    InsufficientFunds(String),
//    
//    #[error("network congestion: {0}")]
//    NetworkCongestion(String),
//    
//    #[error("transaction underpriced")]
//    TransactionUnderpriced,
//    
//    #[error("transaction nonce too low")]
//    TransactionNonceTooLow,
//    
//    #[error("permission denied: {0}")]
//    PermissionDenied(String),
//}
//
///// Represents the storage state of a wallet's private key
//#[derive(Debug, Clone)]
//pub enum KeyStorage {
//    /// An unencrypted wallet with a signer
//    Decrypted(LocalSigner),
//    
//    /// An encrypted wallet - contains all the necessary data
//    Encrypted(EncryptedSignerData),
//}
//
//impl KeyStorage {
//    /// Get the encrypted data if this is an encrypted key storage
//    pub fn get_encrypted_data(&self) -> Option<Vec<u8>> {
//        match self {
//            KeyStorage::Encrypted(data) => Some(data.encrypted_data.clone()),
//            KeyStorage::Decrypted(_) => None,
//        }
//    }
//    
//    /// Get the address associated with this wallet
//    pub fn get_address(&self) -> String {
//        match self {
//            KeyStorage::Decrypted(signer) => signer.address().to_string(),
//            KeyStorage::Encrypted(data) => data.address.clone(),
//        }
//    }
//    
//    /// Get the chain ID associated with this wallet
//    pub fn get_chain_id(&self) -> u64 {
//        match self {
//            KeyStorage::Decrypted(signer) => signer.chain_id(),
//            KeyStorage::Encrypted(data) => data.chain_id,
//        }
//    }
//}
//
///// Represents an amount of ETH with proper formatting
//#[derive(Debug, Clone)]
//pub struct EthAmount {
//    /// Value in wei
//    wei_value: U256,
//}
//
//impl EthAmount {
//    /// Create a new amount from ETH value
//    pub fn from_eth(eth_value: f64) -> Self {
//        // Convert ETH to wei (1 ETH = 10^18 wei)
//        let wei = (eth_value * 1_000_000_000_000_000_000.0) as u128;
//        Self {
//            wei_value: U256::from(wei),
//        }
//    }
//    
//    /// Create from a string like "0.1 ETH" or "10 wei"
//    pub fn from_string(amount_str: &str) -> Result<Self, WalletError> {
//        let parts: Vec<&str> = amount_str.trim().split_whitespace().collect();
//        
//        if parts.is_empty() {
//            return Err(WalletError::InvalidAmount(
//                "Empty amount string".to_string()
//            ));
//        }
//        
//        let value_str = parts[0];
//        let unit = parts.get(1).map(|s| s.to_lowercase()).unwrap_or_else(|| "eth".to_string());
//        
//        let value = value_str.parse::<f64>()
//            .map_err(|_| WalletError::InvalidAmount(format!("Invalid numeric value: {}", value_str)))?;
//            
//        match unit.as_str() {
//            "eth" => Ok(Self::from_eth(value)),
//            "wei" => Ok(Self {
//                wei_value: U256::from(value as u128),
//            }),
//            _ => Err(WalletError::InvalidAmount(format!("Unknown unit: {}", unit))),
//        }
//    }
//    
//    /// Get the value in wei
//    pub fn as_wei(&self) -> U256 {
//        self.wei_value
//    }
//    
//    /// Get a human-readable string representation
//    pub fn to_string(&self) -> String {
//        // For values over 0.0001 ETH, show in ETH, otherwise in wei
//        if self.wei_value >= U256::from(100_000_000_000_000u128) {
//            // Convert to u128 first (safe since ETH total supply fits in u128) then to f64
//            let wei_u128 = self.wei_value.to::<u128>();
//            let eth_value = wei_u128 as f64 / 1_000_000_000_000_000_000.0;
//            format!("{:.6} ETH", eth_value)
//        } else {
//            format!("{} wei", self.wei_value)
//        }
//    }
//}
//
///// Transaction receipt returned after sending
//#[derive(Debug, Clone)]
//pub struct TxReceipt {
//    /// Transaction hash
//    pub hash: TxHash,
//    /// Transaction details
//    pub details: String,
//}
//
//// The checks here aren't solid, but it works for now. Will also expand with full hypermap support
///// Resolve a .hypr name to an Ethereum address using Hypermap. 
//pub fn resolve_name(name: &str, _chain_id: u64) -> Result<EthAddress, WalletError> {
//    // If it's already an address, just parse it
//    if name.starts_with("0x") && name.len() == 42 {
//        return EthAddress::from_str(name)
//            .map_err(|_| WalletError::NameResolutionError(format!("Invalid address format: {}", name)));
//    }
//    
//    // hardcoded to .hypr for now
//    let formatted_name = if !name.contains('.') {
//        format!("{}.hypr", name)
//    } else {
//        kiprintln!("PROCESS_LIB::resolve_name name: {}", name);
//        name.to_string()
//    };
//    
//    // Use hypermap resolution
//    let hypermap = hypermap::Hypermap::default(60);
//    match hypermap.get(&formatted_name) {
//        Ok((_tba, owner, _)) => {
//            Ok(owner)
//        },
//        Err(e) => {
//            Err(WalletError::NameResolutionError(
//                format!("Failed to resolve name '{}': {}", name, e)
//            ))
//        }
//    }
//}
//
///// Send ETH to an address or name
//pub fn send_eth<S: Signer>(
//    to: &str,
//    amount: EthAmount,
//    provider: Provider,
//    signer: &S,
//) -> Result<TxReceipt, WalletError> {
//
//    kiprintln!("PROCESS_LIB::send_eth provider: {:#?}", provider);
//
//    // Current chain-specific handling
//    let chain_id = signer.chain_id();
//    kiprintln!("PROCESS_LIB::send_eth chain_id: {}", chain_id);
//    
//    // This part needs improvement - detect network type more robustly
//    let is_test_network = chain_id == 31337 || chain_id == 1337;
//    
//    // Use network-specific gas strategies
//    let (gas_price, priority_fee) = match chain_id {
//
//        // just rough calculations for now
//        1 => calculate_eth_mainnet_gas(&provider)?, // mainnet
//        8453 => calculate_base_gas(&provider)?, // Base
//        10 => calculate_optimism_gas(&provider)?, // Optimism
//
//        // Test networks - keep your current approach
//        _ if is_test_network => (2_000_000_000, 100_000_000),
//        
//        // 30% 
//        _ => {
//            kiprintln!("PROCESS_LIB::send_eth getting gas price");
//            let base_fee = provider.get_gas_price()?.to::<u128>();
//            kiprintln!("PROCESS_LIB::send_eth base_fee: {}", base_fee);
//            let adjusted_fee = (base_fee * 130) / 100;
//            kiprintln!("PROCESS_LIB::send_eth adjusted_fee: {}", adjusted_fee);
//            (adjusted_fee, adjusted_fee / 10)
//        }
//    };
//
//    kiprintln!("PROCESS_LIB::send_eth gas_price: {}", gas_price);
//
//    // Resolve the name to an address
//    let to_address = resolve_name(to, chain_id)?;
//
//    kiprintln!("PROCESS_LIB::send_eth to_address: {}", to_address);
//
//    // Get the current nonce for the signer's address
//    let from_address = signer.address();
//    let nonce = provider.get_transaction_count(from_address, None)?
//        .to::<u64>();
//
//    kiprintln!("PROCESS_LIB::send_eth nonce: {}", nonce);
//
//    // Standard gas limit for ETH transfer
//    let gas_limit = 21000;
//    
//    // Prepare transaction data
//    let tx_data = TransactionData {
//        to: to_address,
//        value: amount.as_wei(),
//        data: None, // No data for simple ETH transfer
//        nonce,
//        gas_limit,
//        gas_price,
//        max_priority_fee: Some(priority_fee),
//        chain_id,
//    };
//
//    kiprintln!("PROCESS_LIB::send_eth tx_data: {:#?}", tx_data);
//    
//    // Sign the transaction
//    let signed_tx = signer.sign_transaction(&tx_data)?;
//
//    kiprintln!("PROCESS_LIB::send_eth signed_tx: {:?}", signed_tx);
//    
//    // Send the transaction
//    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;
//
//    kiprintln!("lol PROCESS_LIB::send_eth tx_hash: {}", tx_hash);
//    
//    // Return the receipt with transaction details
//    Ok(TxReceipt {
//        hash: tx_hash,
//        details: format!("Sent {} to {}", amount.to_string(), to),
//    })
//}
//
//// Helper function to calculate EIP-1559 gas parameters with network-specific values
//fn calculate_eip1559_gas(
//    provider: &Provider, 
//    buffer_fraction: u128, 
//    priority_fee: u128
//) -> Result<(u128, u128), WalletError> {
//    kiprintln!("PROCESS_LIB::calculate_eip1559_gas provider\n", );
//    // Get latest block
//    let latest_block = provider.get_block_by_number(BlockNumberOrTag::Latest, false)?
//        .ok_or_else(|| WalletError::TransactionError("Failed to get latest block".into()))?;
//
//    kiprintln!("PROCESS_LIB::calculate_eip1559_gas latest_block: {:#?}", latest_block);
//    
//    // Get base fee
//    let base_fee = latest_block.header.inner.base_fee_per_gas
//        .ok_or_else(|| WalletError::TransactionError("No base fee in block".into()))?
//        as u128;
//
//    kiprintln!("PROCESS_LIB::calculate_eip1559_gas base_fee: {}", base_fee);
//    
//    // Calculate max fee with the provided buffer fraction
//    let max_fee = base_fee + (base_fee / buffer_fraction);
//
//    kiprintln!("PROCESS_LIB::calculate_eip1559_gas max_fee: {}", max_fee);
//    
//    Ok((max_fee, priority_fee))
//}
//
//// Network-specific gas calculation for Ethereum mainnet
//fn calculate_eth_mainnet_gas(provider: &Provider) -> Result<(u128, u128), WalletError> {
//    // For mainnet: 50% buffer and 1.5 gwei priority fee
//    calculate_eip1559_gas(provider, 2, 1_500_000_000u128)
//}
//
//fn calculate_base_gas(provider: &Provider) -> Result<(u128, u128), WalletError> {
//    // Get the latest block to determine current gas conditions
//    let latest_block = provider.get_block_by_number(BlockNumberOrTag::Latest, false)?
//        .ok_or_else(|| WalletError::TransactionError("Failed to get latest block".into()))?;
//    
//    // Get base fee from the block
//    let base_fee = latest_block.header.inner.base_fee_per_gas
//        .ok_or_else(|| WalletError::TransactionError("No base fee in block".into()))?
//        as u128;
//    
//    // Calculate max fee with a 33% buffer
//    let max_fee = base_fee + (base_fee / 3);
//    
//    // Dynamic priority fee - 10% of base fee, but with a minimum and a maximum
//    // Low minimum for Base which has very low gas prices
//    let min_priority_fee = 100_000u128; // 0.0001 gwei minimum
//    let max_priority_fee = max_fee / 2; // Never more than half the max fee
//    
//    let priority_fee = std::cmp::max(
//        min_priority_fee,
//        std::cmp::min(base_fee / 10, max_priority_fee)
//    );
//    
//    Ok((max_fee, priority_fee))
//}
//
//// Gas calculation for Optimism network
//fn calculate_optimism_gas(provider: &Provider) -> Result<(u128, u128), WalletError> {
//    // For Optimism: 25% buffer and 0.3 gwei priority fee
//    calculate_eip1559_gas(provider, 4, 300_000_000u128)
//}
//
///// Get the ETH balance for an address or name
//pub fn get_balance(
//    address_or_name: &str,
//    chain_id: u64,
//    provider: Provider,
//) -> Result<EthAmount, WalletError> {
//    // Resolve name to address
//    let address = resolve_name(address_or_name, chain_id)?;
//    
//    // Query balance
//    let balance = provider.get_balance(address, None)?;
//    
//    // Return formatted amount
//    Ok(EthAmount {
//        wei_value: balance,
//    })
//}
//
//pub fn wait_for_transaction(
//    tx_hash: TxHash, 
//    provider: Provider,
//    confirmations: u64,
//    timeout_secs: u64
//) -> Result<TransactionReceipt, WalletError> {
//    let start_time = std::time::Instant::now();
//    let timeout = std::time::Duration::from_secs(timeout_secs);
//    
//    loop {
//        // Check if we've exceeded the timeout
//        if start_time.elapsed() > timeout {
//            return Err(WalletError::TransactionError(
//                format!("Transaction confirmation timeout after {} seconds", timeout_secs)
//            ));
//        }
//        
//        // Try to get the receipt
//        if let Ok(Some(receipt)) = provider.get_transaction_receipt(tx_hash) {
//            // Check if we have enough confirmations
//            let latest_block = provider.get_block_number()?;
//            let receipt_block = receipt.block_number.unwrap_or(0) as u64;
//            
//            if latest_block >= receipt_block + confirmations {
//                return Ok(receipt);
//            }
//        }
//        
//        // Wait a bit before checking again
//        std::thread::sleep(std::time::Duration::from_secs(2));
//    }
//}
//
////// Extract error information from RPC errors
////fn extract_rpc_error(error: &EthError) -> WalletError {
////    match error {
////        EthError::RpcError(value) => {
////            // Try to parse the error message
////            if let Some(message) = value.get("message").and_then(|m| m.as_str()) {
////                if message.contains("insufficient funds") {
////                    return WalletError::InsufficientFunds(message.to_string());
////                } else if message.contains("underpriced") {
////                    return WalletError::TransactionUnderpriced;
////                } else if message.contains("nonce too low") {
////                    return WalletError::TransactionNonceTooLow;
////                }
////                // Add more error patterns as needed
////            }
////            WalletError::TransactionError(format!("RPC error: {:?}", value))
////        },
////        _ => WalletError::TransactionError(format!("Ethereum error: {:?}", error))
////    }
////}
//
//// ERC-20 Read Function Selectors (_ = NOT CHECKED)
//const ERC20_BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31]; // balanceOf(address)
//const ERC20_DECIMALS: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];   // decimals()
//const _ERC20_ALLOWANCE: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];  // allowance(address,address)
//const _ERC20_TOTAL_SUPPLY: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd]; // totalSupply()
//const _ERC20_SYMBOL: [u8; 4] = [0x95, 0xd8, 0x9b, 0x41];     // symbol()
//const _ERC20_NAME: [u8; 4] = [0x06, 0xfd, 0xde, 0x03];       // name()
//
//// ERC-20 Write Function Selectors  
//const _ERC20_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];   // transfer(address,uint256)
//const _ERC20_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd]; // transferFrom(address,address,uint256)
//const _ERC20_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];    // approve(address,uint256)
//
///// Get the balance of ERC20 tokens for an address
//pub fn erc20_balance_of(
//    token_address: &str,
//    owner_address: &str,
//    provider: Provider
//) -> Result<f64, WalletError> {
//    kiprintln!("PROCESS_LIB::erc20_balance_of token_address: {}", token_address);
//    // Resolve addresses
//    let token: EthAddress = resolve_name(&token_address, provider.chain_id)?;
//    kiprintln!("PROCESS_LIB::erc20_balance_of token: {}", token);
//    let owner = resolve_name(&owner_address, provider.chain_id)?;
//    kiprintln!("PROCESS_LIB::erc20_balance_of owner: {}", owner);
//    
//    // The ERC20 balanceOf function selector: keccak256("balanceOf(address)")[0:4]
//    //let selector = [0xa9, 0x05, 0x9c, 0xbb];
//    let selector = ERC20_BALANCE_OF;
//    kiprintln!("PROCESS_LIB::erc20_balance_of selector: {:?}", selector);
//    
//    // Encode the owner address parameter (padded to 32 bytes)
//    let mut call_data = Vec::with_capacity(4 + 32);
//    call_data.extend_from_slice(&selector);
//    call_data.extend_from_slice(&[0u8; 12]); // 12 bytes of padding
//    call_data.extend_from_slice(owner.as_slice());
//    kiprintln!("PROCESS_LIB::erc20_balance_of call_data: {:?}", call_data);
//    
//    // Create the transaction request for eth_call
//    let tx = TransactionRequest {
//        to: Some(TxKind::Call(token)),
//        input: call_data.into(),
//        ..Default::default()
//    };
//
//    kiprintln!("PROCESS_LIB::erc20_balance_of tx: {:#?}", tx);
//    
//    // Call the contract
//    let result = provider.call(tx, None)?;
//
//    kiprintln!("PROCESS_LIB::erc20_balance_of result: {:?}", result);
//    
//    // Parse the result (a uint256 value)
//    if result.len() < 32 {
//        kiprintln!("PROCESS_LIB::erc20_balance_of Invalid result length");
//        return Err(WalletError::TransactionError("Invalid result length".into()));
//    }
//    
//    // Convert the bytes to a U256
//    let balance = U256::from_be_bytes::<32>(result[0..32].try_into().unwrap());
//    
//    // TODO: This should be based on the contract's decimals, fix later with a LUT
//    //Ok(EthAmount { wei_value: balance })
//
//    let decimals = erc20_decimals(token, &provider)?;
//    let balance_u128 = balance.to::<u128>();
//    let balance_float = balance_u128 as f64 / 10f64.powi(decimals as i32);
//    Ok(balance_float) // Returns balance in full tokens (e.g., 390.159112 USDC)
//
//}
//
//pub fn erc20_decimals(token_address: EthAddress, provider: &Provider) -> Result<u8, WalletError> {
//    kiprintln!("PROCESS_LIB::erc20_decimals token_address: {}", token_address);
//    let token = token_address;
//    kiprintln!("PROCESS_LIB::erc20_decimals token: {}", token);
//    let selector = ERC20_DECIMALS;
//    let call_data = selector.to_vec();  // ✅ Ensure it's exactly 4 bytes
//
//    kiprintln!("PROCESS_LIB::erc20_decimals selector: {:?}", selector);
//
//    let tx = TransactionRequest {
//        to: Some(TxKind::Call(token)),
//        input: call_data.into(),
//        ..Default::default()
//    };
//
//    let result = provider.call(tx, None)?;
//    kiprintln!("PROCESS_LIB::erc20_decimals result: {:?}", result);
//
//    if result.len() < 32 {
//        return Err(WalletError::TransactionError("Invalid decimals response".into()));
//    }
//    kiprintln!("PROCESS_LIB::erc20_decimals done", );
//
//    Ok(result[31]) // Decimals are stored in the last byte of the 32-byte response
//}
//
//
/////// Transfer ERC20 tokens to another address
////pub fn erc20_transfer<S: Signer>(
////    token_address: &str,
////    to_address: &str,
////    amount: EthAmount,
////    provider: Provider,
////    signer: &S
////) -> Result<TxReceipt, WalletError> {
////    // Resolve addresses
////    let token = resolve_name(token_address, provider.chain_id())?;
////    let to = resolve_name(to_address, provider.chain_id())?;
////    
////    // The ERC20 transfer function selector: keccak256("transfer(address,uint256)")[0:4]
////    let selector = [0xa9, 0x05, 0x9c, 0xbb];
////    
////    // Encode the parameters: address recipient, uint256 amount
////    let mut call_data = Vec::with_capacity(4 + 32 + 32);
////    call_data.extend_from_slice(&selector);
////    
////    // Recipient address (padded to 32 bytes)
////    call_data.extend_from_slice(&[0u8; 12]); // 12 bytes of padding
////    call_data.extend_from_slice(to.as_slice());
////    
////    // Amount (padded to 32 bytes)
////    let amount_bytes = amount.as_wei().to_be_bytes::<32>();
////    call_data.extend_from_slice(&amount_bytes);
////    
////    // Get the current nonce
////    let from_address = signer.address();
////    let nonce = provider.get_transaction_count(from_address, None)?.to::<u64>();
////    
////    // Estimate gas for the token transfer (usually around 60k for ERC20 transfers)
////    let tx_req = TransactionRequest {
////        from: Some(from_address),
////        to: Some(token),
////        data: Some(call_data.clone().into()),
////        ..Default::default()
////    };
////    
////    let gas_limit = provider.estimate_gas(tx_req, None)?
////        .to::<u64>()
////        .saturating_mul(12).saturating_div(10); // Add 20% buffer
////    
////    // Calculate gas price based on the chain
////    let (gas_price, priority_fee) = match signer.chain_id() {
////        // Use your existing gas calculation functions
////        1 => calculate_eth_mainnet_gas(&provider)?,
////        8453 => calculate_base_gas(&provider)?,
////        _ => {
////            let base_fee = provider.get_gas_price()?.to::<u128>();
////            let adjusted_fee = (base_fee * 130) / 100;
////            (adjusted_fee, adjusted_fee / 10)
////        }
////    };
////    
////    // Create transaction data
////    let tx_data = TransactionData {
////        to: token,
////        value: U256::ZERO, // No ETH sent with token transfers
////        data: Some(call_data),
////        nonce,
////        gas_limit,
////        gas_price,
////        max_priority_fee: Some(priority_fee),
////        chain_id: signer.chain_id(),
////    };
////    
////    // Sign and send transaction
////    let signed_tx = signer.sign_transaction(&tx_data)?;
////    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;
////    
////    Ok(TxReceipt {
////        hash: tx_hash,
////        details: format!("Sent {} tokens to {}", amount.to_string(), to_address),
////    })
////}
//
//// THE HYPERMAP stuff
//
///// Result type for Hypermap transactions
//#[derive(Debug, Clone)]
//pub struct HypermapTxReceipt {
//    /// Transaction hash
//    pub hash: TxHash,
//    /// Description of the operation
//    pub description: String,
//}
//
///// Create a note (mutable data) on a Hypermap namespace entry
///// 
///// # Parameters
///// - `parent_entry`: The namespace entry (e.g. "mynode.hypr") where the note will be created
///// - `note_key`: The note key to create (must start with '~')
///// - `data`: The data to store in the note
///// - `provider`: The Ethereum provider to use
///// - `signer`: The signer to use for signing the transaction
///// 
///// # Returns
///// A result containing a HypermapTxReceipt or a WalletError
//pub fn create_note<S: Signer>(
//    parent_entry: &str,
//    note_key: &str,
//    data: Vec<u8>,
//    provider: Provider,
//    signer: &S,
//) -> Result<HypermapTxReceipt, WalletError> {
//    // Verify the note key is valid
//    if !valid_note(note_key) {
//        return Err(WalletError::NameResolutionError(
//            format!("Invalid note key '{}'. Must start with '~' and contain only lowercase letters, numbers, and hyphens", note_key)
//        ));
//    }
//
//    // Get the parent TBA address
//    let hypermap = provider.hypermap();
//    let parent_hash_str = namehash(parent_entry);
//    
//    println!("Parent entry: {}", parent_entry);
//    println!("Parent hash: {}", parent_hash_str);
//    
//    let (tba, owner, _) = hypermap.get_hash(&parent_hash_str)?;
//    
//    println!("TBA address (parent): {}", tba);
//    println!("Owner address: {}", owner);
//    
//    // Check that the signer is the owner of the parent entry
//    let signer_address = signer.address();
//    println!("Signer address: {}", signer_address);
//    
//    if signer_address != owner {
//        return Err(WalletError::PermissionDenied(
//            format!("Signer address {} does not own the parent entry {}", signer_address, parent_entry)
//        ));
//    }
//    
//    // Get the hypermap contract address
//    let hypermap_address = *hypermap.address();
//    println!("Hypermap contract address: {}", hypermap_address);
//
//    // Create the note function call data
//    let note_function = hypermap::contract::noteCall {
//        note: Bytes::from(note_key.as_bytes().to_vec()),
//        data: Bytes::from(data),
//    };
//    let note_call_data = note_function.abi_encode();
//    
//    // ?? Bytes::from(note_call_data) or note_call_data?
//    // Now create an ERC-6551 execute call to send from the wallet to the TBA
//    let execute_call_data = create_execute_calldata(
//        hypermap_address,
//        U256::ZERO,
//        Bytes::from(note_call_data),
//        0 // CALL operation
//    );
//    
//    // Send the transaction from the wallet to the TBA
//    let (tx_hash, tx_data) = send_transaction(
//        tba,
//        execute_call_data,
//        U256::ZERO,
//        provider,
//        signer
//    )?;
//    
//    // Return the receipt with transaction details
//    Ok(HypermapTxReceipt {
//        hash: tx_hash,
//        description: format!("Created note '{}' on '{}'", note_key, parent_entry),
//    })
//}
//
///// Helper function to create calldata for the TBA's execute function
///// 
///// The ERC-6551 execute function has this signature:
///// function execute(address to, uint256 value, bytes calldata data, uint8 operation)
///// 
///// Parameters:
///// - to: The target contract to call (the Hypermap contract)
///// - value: Amount of ETH to send (usually 0)
///// - data: The calldata for the target function
///// - operation: The type of operation (0 = CALL, 1 = DELEGATECALL, etc.)
//fn create_execute_calldata(
//    to: EthAddress,
//    value: U256,
//    data: Bytes,
//    operation: u8
//) -> Bytes {
//    // Function selector for execute(address,uint256,bytes,uint8)
//    // keccak256("execute(address,uint256,bytes,uint8)")[0:4]
//    let selector = [0x44, 0xc0, 0x28, 0xfe];
//    
//    // Encode to address (padded to 32 bytes)
//    let mut to_bytes = vec![0u8; 32];
//    to_bytes[12..32].copy_from_slice(to.as_slice());
//    
//    // Encode value (uint256)
//    let value_bytes = value.to_be_bytes::<32>();
//    
//    // Calculate offset for the dynamic bytes data
//    // This is the offset in 32-byte words to where the bytes data starts
//    // 3 fixed params (address, uint256, uint256 offset) + 1 more fixed param after = 4 * 32 = 128 bytes
//    let offset = U256::from(128);
//    let offset_bytes = offset.to_be_bytes::<32>();
//    
//    // Encode operation (padded to 32 bytes)
//    let mut operation_bytes = vec![0u8; 32];
//    operation_bytes[31] = operation;
//    
//    // Encode bytes length
//    let data_len = U256::from(data.len());
//    let data_len_bytes = data_len.to_be_bytes::<32>();
//    
//    // Encode bytes data (with padding to 32-byte boundary)
//    let mut padded_data = data.to_vec();
//    if padded_data.len() % 32 != 0 {
//        let padding = vec![0u8; 32 - (padded_data.len() % 32)];
//        padded_data.extend_from_slice(&padding);
//    }
//    
//    // Combine everything into final calldata
//    let mut result = Vec::new();
//    result.extend_from_slice(&selector);          // Function selector (4 bytes)
//    result.extend_from_slice(&to_bytes);          // To address (32 bytes)
//    result.extend_from_slice(&value_bytes);       // Value (32 bytes)
//    result.extend_from_slice(&offset_bytes);      // Data offset (32 bytes)
//    result.extend_from_slice(&operation_bytes);   // Operation (32 bytes)
//    result.extend_from_slice(&data_len_bytes);    // Data length (32 bytes)
//    result.extend_from_slice(&padded_data);       // Data (padded)
//    
//    Bytes::from(result)
//}
//
///// Send a transaction to the token-bound account
//fn send_transaction<S: Signer>(
//    to: EthAddress,
//    data: Bytes,
//    value: U256,
//    provider: Provider,
//    signer: &S,
//) -> Result<(TxHash, Vec<u8>), WalletError> {
//    let chain_id = signer.chain_id();
//    
//    kiprintln!("PROCESS_LIB::send_transaction starting");
//    kiprintln!("PROCESS_LIB::send_transaction chain_id: {}", chain_id);
//    
//    // Get gas estimates - use 50% buffer for Base to ensure acceptance
//    let base_fee = provider.get_gas_price()?.to::<u128>();
//    let gas_price = (base_fee * 150) / 100; // 50% buffer
//    let priority_fee = gas_price / 5;      // 20% of gas price
//    
//    kiprintln!("PROCESS_LIB::send_transaction base_fee: {}, priority_fee: {}", base_fee, priority_fee);
//    kiprintln!("PROCESS_LIB::send_transaction gas_price: {}", gas_price);
//    
//    // Get the current nonce for the signer's address
//    let from_address = signer.address();
//    let nonce = provider.get_transaction_count(from_address, None)?
//        .to::<u64>();
//    
//    kiprintln!("PROCESS_LIB::send_transaction nonce: {}", nonce);
//
//    // For ERC-6551 account operations, use a higher gas limit
//    // The ERC-6551 execute function is complex and gas-intensive
//    let estimated_gas = 500_000; // Start high for ERC-6551
//    
//    // Add 50% buffer to estimated gas since this is a complex operation
//    let gas_limit = (estimated_gas * 150) / 100;
//    
//    kiprintln!("PROCESS_LIB::send_transaction estimated_gas: {}", estimated_gas);
//    kiprintln!("PROCESS_LIB::send_transaction gas_limit: {}", gas_limit);
//    
//    // Prepare transaction data
//    let tx_data = TransactionData {
//        to,
//        value,
//        data: Some(data.to_vec()),
//        nonce,
//        gas_limit,
//        gas_price,
//        max_priority_fee: Some(priority_fee),
//        chain_id,
//    };
//    
//    // Sign the transaction
//    let signed_tx = signer.sign_transaction(&tx_data)?;
//    kiprintln!("PROCESS_LIB::send_transaction signed");
//    
//    // Send the transaction
//    let tx_hash = provider.send_raw_transaction(signed_tx.clone().into())?;
//    kiprintln!("PROCESS_LIB::send_transaction tx_hash: {}", tx_hash);
//    
//    // Return both the hash and the raw transaction data
//    Ok((tx_hash, signed_tx))
//}
//
/////// A simple test function to create a note
////pub fn test_create_note<S: Signer>(
////    parent_entry: &str,  // e.g., "lazybonesitis.os"
////    provider: Provider,
////    signer: &S,
////) -> Result<(), WalletError> {
////    println!("=== TESTING NOTE CREATION ===");
////    println!("Parent entry: {}", parent_entry);
////    
////    // Simple test note
////    let note_key = "~test-note";
////    let data = "This is a test note created at ".to_string() + &chrono::Utc::now().to_rfc3339();
////    
////    println!("Creating note: {}", note_key);
////    println!("Data: {}", data);
////    
////    match create_note(
////        parent_entry,
////        note_key,
////        data.as_bytes().to_vec(),
////        provider,
////        signer
////    ) {
////        Ok(receipt) => {
////            println!("Success! Transaction hash: {}", receipt.hash);
////            println!("Description: {}", receipt.description);
////            Ok(())
////        },
////        Err(e) => {
////            println!("Error creating note: {:?}", e);
////            Err(e)
////        }
////    }
////}
//
/////// Create a note (mutable data) on a Hypermap namespace entry
/////// 
/////// # Parameters
/////// - `parent_entry`: The namespace entry (e.g. "mynode.hypr") where the note will be created
/////// - `note_key`: The note key to create (must start with '~')
/////// - `data`: The data to store in the note
/////// - `provider`: The Ethereum provider to use
/////// - `signer`: The signer to use for signing the transaction
/////// 
/////// # Returns
/////// A result containing a HypermapTxReceipt or a WalletError
////pub fn create_note<S: Signer>(
////    parent_entry: &str,
////    note_key: &str,
////    data: Vec<u8>,
////    provider: Provider,
////    signer: &S,
////) -> Result<HypermapTxReceipt, WalletError> {
////    // Verify the note key is valid
////    if !valid_note(note_key) {
////        return Err(WalletError::NameResolutionError(
////            format!("Invalid note key '{}'. Must start with '~' and contain only lowercase letters, numbers, and hyphens", note_key)
////        ));
////    }
////
////    // Get the parent TBA address
////    let hypermap = provider.hypermap();
////    let parent_hash_str = namehash(parent_entry);
////    let (tba, owner, _) = hypermap.get_hash(&parent_hash_str)?;
////    
////    // Check that the signer is the owner of the parent entry
////    let signer_address = signer.address();
////    if signer_address != owner {
////        return Err(WalletError::PermissionDenied(
////            format!("Signer address {} does not own the parent entry {}", signer_address, parent_entry)
////        ));
////    }
////
////    // Create the note call data
////    let note_function = hypermap::contract::noteCall {
////        note: Bytes::from(note_key.as_bytes().to_vec()),
////        data: Bytes::from(data),
////    };
////    let call_data = note_function.abi_encode();
////
////    // Prepare and send the transaction
////    send_tba_transaction(
////        tba,
////        call_data.into(),
////        U256::ZERO, // No ETH value to send
////        provider,
////        signer,
////        format!("Created note '{}' on '{}'", note_key, parent_entry),
////    )
////}
//
///// Create a fact (immutable data) on a Hypermap namespace entry
///// 
///// # Parameters
///// - `parent_entry`: The namespace entry (e.g. "mynode.hypr") where the fact will be created
///// - `fact_key`: The fact key to create (must start with '!')
///// - `data`: The data to store in the fact
///// - `provider`: The Ethereum provider to use
///// - `signer`: The signer to use for signing the transaction
///// 
///// # Returns
///// A result containing a HypermapTxReceipt or a WalletError
//pub fn create_fact<S: Signer>(
//    parent_entry: &str,
//    fact_key: &str,
//    data: Vec<u8>,
//    provider: Provider,
//    signer: &S,
//) -> Result<HypermapTxReceipt, WalletError> {
//    // Verify the fact key is valid
//    if !valid_fact(fact_key) {
//        return Err(WalletError::NameResolutionError(
//            format!("Invalid fact key '{}'. Must start with '!' and contain only lowercase letters, numbers, and hyphens", fact_key)
//        ));
//    }
//
//    // Get the parent TBA address
//    let hypermap = provider.hypermap();
//    let parent_hash_str = namehash(parent_entry);
//    let (tba, owner, _) = hypermap.get_hash(&parent_hash_str)?;
//    
//    // Check that the signer is the owner of the parent entry
//    let signer_address = signer.address();
//    if signer_address != owner {
//        return Err(WalletError::PermissionDenied(
//            format!("Signer address {} does not own the parent entry {}", signer_address, parent_entry)
//        ));
//    }
//
//    // Create the fact call data
//    let fact_function = hypermap::contract::factCall {
//        fact: Bytes::from(fact_key.as_bytes().to_vec()),
//        data: Bytes::from(data),
//    };
//    let call_data = fact_function.abi_encode();
//
//    // Prepare and send the transaction
//    send_tba_transaction(
//        tba,
//        call_data.into(),
//        U256::ZERO, // No ETH value to send
//        provider,
//        signer,
//        format!("Created fact '{}' on '{}'", fact_key, parent_entry),
//    )
//}
//
///// Mint a new namespace entry under a parent entry
///// 
///// # Parameters
///// - `parent_entry`: The parent namespace entry (e.g. "mynode.hypr")
///// - `label`: The new label to mint (without prefix or parent)
///// - `recipient`: The address that will own the new entry
///// - `implementation`: The address of the token-bound account implementation
///// - `provider`: The Ethereum provider to use
///// - `signer`: The signer to use for signing the transaction
///// 
///// # Returns
///// A result containing a HypermapTxReceipt or a WalletError
//pub fn mint_entry<S: Signer>(
//    parent_entry: &str,
//    label: &str,
//    recipient: &str,
//    implementation: &str,
//    provider: Provider,
//    signer: &S,
//) -> Result<HypermapTxReceipt, WalletError> {
//    // Verify the label is valid
//    if !valid_name(label) {
//        return Err(WalletError::NameResolutionError(
//            format!("Invalid label '{}'. Must contain only lowercase letters, numbers, and hyphens", label)
//        ));
//    }
//
//    // Get the parent TBA address
//    let hypermap = provider.hypermap();
//    let parent_hash_str = namehash(parent_entry);
//    kiprintln!("PROCESS_LIB::mint_entry parent_hash_str: {}", parent_hash_str);
//    let (tba, owner, _) = hypermap.get_hash(&parent_hash_str)?;
//    
//    // Check that the signer is the owner of the parent entry
//    let signer_address = signer.address();
//    if signer_address != owner {
//        return Err(WalletError::PermissionDenied(
//            format!("Signer address {} does not own the parent entry {}", signer_address, parent_entry)
//        ));
//    }
//
//    // Resolve recipient address
//    let recipient_address = resolve_name(recipient, provider.chain_id)?;
//    
//    // Resolve implementation address
//    let implementation_address = resolve_name(implementation, provider.chain_id)?;
//
//    // Create the mint call data
//    let mint_function = hypermap::contract::mintCall {
//        who: recipient_address,
//        label: Bytes::from(label.as_bytes().to_vec()),
//        initialization: Bytes::default(), // No initialization data
//        erc721Data: Bytes::default(),    // No ERC721 data
//        implementation: implementation_address,
//    };
//    let call_data = mint_function.abi_encode();
//
//    kiprintln!("Parent entry: {}", parent_entry);
//    kiprintln!("Parent hash: {}", parent_hash_str);
//    kiprintln!("TBA address: {}", tba);
//    kiprintln!("Owner address: {}", owner);
//    kiprintln!("Signer address: {}", signer_address);
//
//    // Prepare and send the transaction
//    send_tba_transaction(
//        tba,
//        call_data.into(),
//        U256::ZERO, // No ETH value to send
//        provider,
//        signer,
//        format!("Minted new entry '{}' under '{}'", label, parent_entry),
//    )
//}
//
///// Set the gene for a namespace entry
///// 
///// # Parameters
///// - `entry`: The namespace entry (e.g. "mynode.hypr") to set the gene for
///// - `gene_implementation`: The address of the token-bound account implementation to use as the gene
///// - `provider`: The Ethereum provider to use
///// - `signer`: The signer to use for signing the transaction
///// 
///// # Returns
///// A result containing a HypermapTxReceipt or a WalletError
//pub fn set_gene<S: Signer>(
//    entry: &str,
//    gene_implementation: &str,
//    provider: Provider,
//    signer: &S,
//) -> Result<HypermapTxReceipt, WalletError> {
//    // Get the entry's TBA address
//    let hypermap = provider.hypermap();
//    let entry_hash_str = namehash(entry);
//    let (tba, owner, _) = hypermap.get_hash(&entry_hash_str)?;
//    
//    // Check that the signer is the owner of the entry
//    let signer_address = signer.address();
//    if signer_address != owner {
//        return Err(WalletError::PermissionDenied(
//            format!("Signer address {} does not own the entry {}", signer_address, entry)
//        ));
//    }
//
//    // Resolve gene implementation address
//    let gene_address = resolve_name(gene_implementation, provider.chain_id)?;
//
//    // Create the gene call data
//    let gene_function = hypermap::contract::geneCall {
//        _gene: gene_address,
//    };
//    let call_data = gene_function.abi_encode();
//
//    // Prepare and send the transaction
//    send_tba_transaction(
//        tba,
//        call_data.into(),
//        U256::ZERO, // No ETH value to send
//        provider,
//        signer,
//        format!("Set gene for '{}' to '{}'", entry, gene_implementation),
//    )
//}
//
///// Helper function to send a transaction to a token-bound account
//fn send_tba_transaction<S: Signer>(
//    tba: EthAddress,
//    data: Bytes,
//    value: U256,
//    provider: Provider,
//    signer: &S,
//    description: String,
//) -> Result<HypermapTxReceipt, WalletError> {
//    kiprintln!("PROCESS_LIB::send_tba_transaction starting");
//
//    let chain_id = signer.chain_id();
//    kiprintln!("PROCESS_LIB::send_tba_transaction chain_id: {}", chain_id);
//
//    // TODO: change from hardcoded base to dynamic
//    let (base_fee, priority_fee) = calculate_base_gas(&provider)?;
//    kiprintln!("PROCESS_LIB::send_tba_transaction base_fee: {}, priority_fee: {}", base_fee, priority_fee);
//    
//    let gas_price = (base_fee * 180) / 100; 
//    kiprintln!("PROCESS_LIB::send_tba_transaction gas_price: {}", gas_price);
//    
//    // Get the current nonce for the signer's address
//    let from_address = signer.address();
//    let nonce = provider.get_transaction_count(from_address, None)?
//        .to::<u64>();
//    kiprintln!("PROCESS_LIB::send_tba_transaction nonce: {}", nonce);
//
//    // Estimate gas limit for the transaction
//    let tx_req = TransactionRequest::default()
//        .from(from_address)
//        .to(tba)
//        .input(data.clone().into())
//        .value(value);
//    
//    let estimated_gas = match provider.estimate_gas(tx_req, None) {
//        Ok(gas) => gas.to::<u64>(),
//        Err(_) => {
//            // If estimation fails, use a conservative gas limit
//            // This might happen for new contracts or complex interactions
//            300_000
//        }
//    };
//    kiprintln!("PROCESS_LIB::send_tba_transaction estimated_gas: {}", estimated_gas);
//    
//    // Add 120% buffer to estimated gas
//    let gas_limit = (estimated_gas * 220) / 100;
//    kiprintln!("PROCESS_LIB::send_tba_transaction gas_limit: {}", gas_limit);
//    
//    // Prepare transaction data
//    let tx_data = TransactionData {
//        to: tba,
//        value,
//        data: Some(data.to_vec()),
//        nonce,
//        gas_limit,
//        gas_price,
//        max_priority_fee: Some(priority_fee),
//        chain_id,
//    };
//    //kiprintln!("PROCESS_LIB::send_tba_transaction tx_data: {:#?}", tx_data);
//    
//    // Sign the transaction
//    let signed_tx = signer.sign_transaction(&tx_data)?;
//    kiprintln!("PROCESS_LIB::send_tba_transaction signed");
//    
//    // Send the transaction
//    let tx_hash = provider.send_raw_transaction(signed_tx.into())?;
//    kiprintln!("PROCESS_LIB::send_tba_transaction tx_hash: {}", tx_hash);
//    
//    // Return the receipt with transaction details
//    Ok(HypermapTxReceipt {
//        hash: tx_hash,
//        description,
//    })
//}
//
//
//
//
//


