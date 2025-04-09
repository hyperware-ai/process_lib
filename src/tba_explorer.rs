/// not ready for thought


use crate::{
    eth::{
        self, 
        Bytes, 
        Provider,
        Address as EthAddress
    },
    hypermap::{
        self, 
        Hypermap
    },
    println as kiprintln,
};
use alloy_primitives::{
    B256, 
    FixedBytes
};
use alloy::rpc_types::request::{
    TransactionInput, 
    TransactionRequest
};
use alloy_sol_types::SolValue;
use std::str::FromStr;
use hex;
use serde::{
    Serialize, 
    Deserialize
};

/// ERC-6551 Account Interface for interacting with Token-Bound Accounts
pub struct Erc6551Account {
    address: EthAddress,
    provider: Provider,
}

impl Erc6551Account {
    pub fn new(address: EthAddress, provider: Provider) -> Self {
        Self { address, provider }
    }
    
    /// Get token information from the TBA
    pub fn token(&self) -> Result<(u64, EthAddress, u64)> {
        // Function selector for token()
        let selector = [0x45, 0xc3, 0x11, 0x87]; // token()
        
        let tx_req = TransactionRequest::default()
            .input(TransactionInput::new(Bytes::from(selector.to_vec())))
            .to(self.address);
        
        let res_bytes = self.provider.call(tx_req, None)?;
        
        // Parse the response (chainId, tokenContract, tokenId)
        if res_bytes.len() < 96 {
            return Err(anyhow!("Invalid response length for token() call"));
        }
        
        // Extract chainId (first 32 bytes)
        let chain_id = u64::from_be_bytes([
            res_bytes[24], res_bytes[25], res_bytes[26], res_bytes[27],
            res_bytes[28], res_bytes[29], res_bytes[30], res_bytes[31],
        ]);
        
        // Extract tokenContract (next 32 bytes, but we only need 20 bytes)
        let token_contract = EthAddress::from_slice(&res_bytes[44..64]);
        
        // Extract tokenId (last 32 bytes)
        let token_id = u64::from_be_bytes([
            res_bytes[88], res_bytes[89], res_bytes[90], res_bytes[91],
            res_bytes[92], res_bytes[93], res_bytes[94], res_bytes[95],
        ]);
        
        Ok((chain_id, token_contract, token_id))
    }
    
    /// Check if a signer is valid for this account
    pub fn is_valid_signer(&self, signer: &EthAddress) -> Result<bool> {
        // Function selector for isValidSigner(address,bytes)
        let selector = [0x52, 0x65, 0x78, 0x4c, 0x3c];
        
        // Encode the signer address (padded to 32 bytes)
        let mut call_data = Vec::with_capacity(68);
        call_data.extend_from_slice(&selector);
        
        // Add the address parameter (padded to 32 bytes)
        call_data.extend_from_slice(&[0; 12]); // 12 bytes padding
        call_data.extend_from_slice(signer.as_slice());
        
        // Add offset to empty bytes array (32) and length (0)
        call_data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32]);
        call_data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        
        let tx_req = TransactionRequest::default()
            .input(TransactionInput::new(Bytes::from(call_data)))
            .to(self.address);
        
        match self.provider.call(tx_req, None) {
            Ok(res) => {
                // Expect a boolean response (32 bytes with last byte being 0 or 1)
                if res.len() >= 32 && (res[31] == 1) {
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            Err(e) => {
                kiprintln!("isValidSigner call failed: {:?}", e);
                Ok(false)
            }
        }
    }
    
    /// Get the implementation address of this TBA
    pub fn get_implementation(&self) -> Result<EthAddress> {
        // EIP-1967 implementation slot
        let impl_slot = B256::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")?;
        
        match self.provider.get_storage_at(self.address, impl_slot, None) {
            Ok(value) => {
                // Extract address from storage value (last 20 bytes)
                let bytes = value.as_ref();
                if bytes.len() >= 20 {
                    let impl_addr = EthAddress::from_slice(&bytes[bytes.len()-20..]);
                    Ok(impl_addr)
                } else {
                    Err(anyhow!("Invalid implementation address format"))
                }
            },
            Err(e) => Err(anyhow!("Failed to get implementation: {:?}", e)),
        }
    }
    
    /// Check if an auth-key is set on the TBA
    pub fn has_auth_key(&self) -> Result<bool> {
        // Storage slot for auth keys (depends on implementation)
        // This would need to match the exact implementation's storage layout
        let auth_key_slot = B256::from_str("0x0000000000000000000000000000000000000000000000000000000000000001")?;
        
        match self.provider.get_storage_at(self.address, auth_key_slot, None) {
            Ok(value) => {
                // Check if the slot has a non-zero value
                let bytes = value.as_ref();
                Ok(!bytes.iter().all(|&b| b == 0))
            },
            Err(e) => {
                kiprintln!("Failed to check auth key: {:?}", e);
                Ok(false)
            }
        }
    }
}

/// Complete TBA information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TbaInfo {
    pub node_name: String,
    pub tba_address: EthAddress,
    pub owner_address: EthAddress,
    pub implementation: EthAddress,
    pub chain_id: u64,
    pub token_contract: EthAddress,
    pub token_id: u64,
    pub auth_signers: Vec<EthAddress>,
}

/// Extended Hypermap functionality specifically for TBA exploration
pub struct TbaExplorer {
    hypermap: Hypermap,
}

impl TbaExplorer {
    pub fn new(timeout: u64) -> Self {
        Self {
            hypermap: Hypermap::default(timeout),
        }
    }
    
    /// Format a node name to ensure it has proper extension
    pub fn format_node_name(&self, node_name: &str) -> String {
        if !node_name.contains('.') {
            format!("{}.hypr", node_name)
        } else {
            node_name.to_string()
        }
    }
    
    /// Get information about a TBA by node name
    pub fn get_tba_info(&self, node_name: &str) -> Result<TbaInfo> {
        // Format node name properly
        let name = self.format_node_name(node_name);
        
        // Get TBA and owner from Hypermap
        let (tba_address, owner_address, _) = self.hypermap.get(&name)?;
        
        // Create ERC-6551 account wrapper
        let account = Erc6551Account::new(tba_address, self.hypermap.provider.clone());
        
        // Get token info
        let (chain_id, token_contract, token_id) = match account.token() {
            Ok(info) => info,
            Err(e) => {
                kiprintln!("Failed to get token info: {:?}", e);
                // Provide defaults
                (0, EthAddress::default(), 0)
            }
        };
        
        // Get implementation
        let implementation = match account.get_implementation() {
            Ok(impl_addr) => impl_addr,
            Err(e) => {
                kiprintln!("Failed to get implementation: {:?}", e);
                EthAddress::default()
            }
        };
        
        // Get custom auth signers from ~auth-signers note if it exists
        let auth_signers = self.get_auth_signers(&name)?;
        
        Ok(TbaInfo {
            node_name: name,
            tba_address,
            owner_address,
            implementation,
            chain_id,
            token_contract, 
            token_id,
            auth_signers,
        })
    }
    
    /// Get authorized signers from a node's notes
    fn get_auth_signers(&self, node_name: &str) -> Result<Vec<EthAddress>> {
        let mut auth_signers = Vec::new();
        
        // Get the namehash
        let namehash = hypermap::namehash(node_name);
        
        // Create filter for ~auth-signers note
        let note_filter = self.hypermap.notes_filter(&["~auth-signers"])
            .topic1(vec![FixedBytes::<32>::from_str(&namehash)?]);
        
        // Get logs
        let logs = self.hypermap.provider.get_logs(&note_filter)?;
        
        if logs.is_empty() {
            return Ok(Vec::new());
        }
        
        // Process the latest version of the note
        if let Some(latest_log) = logs.last() {
            if let Ok(note) = hypermap::decode_note_log(latest_log) {
                // Try to parse as JSON list of addresses
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&note.data) {
                    if let Some(addresses) = json.as_array() {
                        for addr in addresses {
                            if let Some(addr_str) = addr.as_str() {
                                if let Ok(address) = EthAddress::from_str(addr_str) {
                                    auth_signers.push(address);
                                }
                            }
                        }
                    }
                } else {
                    // If not JSON, try to parse as comma-separated list
                    let data_str = String::from_utf8_lossy(&note.data);
                    for addr_str in data_str.split(',') {
                        let trimmed = addr_str.trim();
                        if let Ok(address) = EthAddress::from_str(trimmed) {
                            auth_signers.push(address);
                        }
                    }
                }
            }
        }
        
        Ok(auth_signers)
    }
    
    /// Check if an address is authorized to sign for a node's TBA
    pub fn is_authorized_signer(&self, node_name: &str, signer: &EthAddress) -> Result<bool> {
        // Get TBA info
        let tba_info = self.get_tba_info(node_name)?;
        
        // Check if signer is owner (always authorized)
        if &tba_info.owner_address == signer {
            return Ok(true);
        }
        
        // Check if signer is in auth_signers list from note
        if tba_info.auth_signers.contains(signer) {
            return Ok(true);
        }
        
        // Check using isValidSigner directly
        let account = Erc6551Account::new(tba_info.tba_address, self.hypermap.provider.clone());
        account.is_valid_signer(signer)
    }
    
    /// Get all ~net-key and any custom signing keys from a node
    pub fn get_signing_keys(&self, node_name: &str) -> Result<Vec<Vec<u8>>> {
        let mut keys = Vec::new();
        
        // Format node name
        let name = self.format_node_name(node_name);
        
        // Get the namehash
        let namehash = hypermap::namehash(&name);
        
        // Create filter for ~net-key and ~signing-key notes
        let keys_filter = self.hypermap.notes_filter(&["~net-key", "~signing-key"])
            .topic1(vec![FixedBytes::<32>::from_str(&namehash)?]);
        
        // Get logs
        let logs = self.hypermap.provider.get_logs(&keys_filter)?;
        
        for log in logs {
            if let Ok(note) = hypermap::decode_note_log(&log) {
                // Add the key data
                keys.push(note.data.to_vec());
            }
        }
        
        Ok(keys)
    }
    
    /// Check if a TBA supports the custom auth signer mechanism
    pub fn supports_auth_signers(&self, node_name: &str) -> Result<bool> {
        // Get TBA info
        let tba_info = self.get_tba_info(node_name)?;
        
        // Check if the implementation is the customized TBA
        // This would require knowing the specific implementation address
        // For now, we'll just check if the implementation isn't the default
        if tba_info.implementation == EthAddress::default() {
            return Ok(false);
        }
        
        // We could also check if there's already an auth_signers note
        if !tba_info.auth_signers.is_empty() {
            return Ok(true);
        }
        
        // Try calling isValidSigner with a test address to see if it works
        let account = Erc6551Account::new(tba_info.tba_address, self.hypermap.provider.clone());
        
        // Check if auth key slot is used
        account.has_auth_key()
    }
    
    /// Format key data for storage in Hypermap
    pub fn format_auth_signers(&self, signers: &[EthAddress]) -> Result<Bytes> {
        // Format as JSON array of address strings
        let signer_strings: Vec<String> = signers.iter()
            .map(|addr| addr.to_string())
            .collect();
        
        let json = serde_json::to_string(&signer_strings)?;
        
        Ok(Bytes::copy_from_slice(json.as_bytes()))
    }
}

/// Helper function to convert a hex string to an Address
pub fn hex_to_address(hex_str: &str) -> Result<EthAddress> {
    let cleaned = hex_str.trim_start_matches("0x");
    if cleaned.len() != 40 {
        return Err(anyhow!("Invalid address length"));
    }
    
    let bytes = hex::decode(cleaned)?;
    Ok(EthAddress::from_slice(&bytes))
}

/// Helper function to convert bytes to a human-readable format
pub fn format_bytes(bytes: &[u8]) -> String {
    if bytes.len() <= 64 {
        // For small data, show full hex
        format!("0x{}", hex::encode(bytes))
    } else {
        // For larger data, truncate
        format!("0x{}...{} ({} bytes)",
            hex::encode(&bytes[..8]),
            hex::encode(&bytes[bytes.len() - 8..]),
            bytes.len())
    }
}