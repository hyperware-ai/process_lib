//! Ethereum signer functionality for Hyperware.
//!
//! This module provides low-level cryptographic signing operations for Ethereum,
//! including private key management, message signing, and transaction signing.
//! It separates the cryptographic concerns from the higher-level wallet functionality.

use crate::eth::EthError;
use hex;
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    network::eip2718::Encodable2718,
    network::TxSignerSync,
    primitives::TxKind,
    signers::{local::PrivateKeySigner, SignerSync},
};
use alloy_primitives::{Address as EthAddress, B256, U256};
use std::str::FromStr;

// For encryption/decryption
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;
const TAG_SIZE: usize = 16;

/// Transaction data structure used for signing transactions
#[derive(Debug, Clone)]
pub struct TransactionData {
    /// The recipient address
    pub to: EthAddress,
    /// The amount to send in wei
    pub value: U256,
    /// Optional transaction data (for contract interactions)
    pub data: Option<Vec<u8>>,
    /// The transaction nonce
    pub nonce: u64,
    /// The maximum gas for the transaction
    pub gas_limit: u64,
    /// The gas price in wei
    pub gas_price: u128,
    /// Optional max priority fee (for EIP-1559 transactions)
    pub max_priority_fee: Option<u128>,
    /// The chain ID for the transaction
    pub chain_id: u64,
}

/// Errors that can occur during signing operations
#[derive(Debug, Error)]
pub enum SignerError {
    #[error("failed to generate random bytes: {0}")]
    RandomGenerationError(String),

    #[error("invalid private key format: {0}")]
    InvalidPrivateKey(String),

    #[error("chain ID mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch { expected: u64, actual: u64 },

    #[error("failed to sign transaction or message: {0}")]
    SigningError(String),

    #[error("ethereum error: {0}")]
    EthError(#[from] EthError),

    #[error("encryption error: {0}")]
    EncryptionError(String),

    #[error("decryption error: {0}")]
    DecryptionError(String),
}

/// The storage format for encrypted signers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSignerData {
    /// The encrypted private key data
    pub encrypted_data: Vec<u8>,
    /// The Ethereum address (for quick reference without decryption)
    pub address: String,
    /// The chain ID this signer is for
    pub chain_id: u64,
}

/// The Signer trait defines the interface for all signing implementations
pub trait Signer {
    /// Get the Ethereum address associated with this signer
    fn address(&self) -> EthAddress;

    /// Get the chain ID this signer is configured for
    fn chain_id(&self) -> u64;

    /// Sign a transaction with the private key
    fn sign_transaction(&self, tx_data: &TransactionData) -> Result<Vec<u8>, SignerError>;

    /// Sign a message following Ethereum's personal_sign format
    fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;
}

/// Local signer implementation using a private key stored in memory
#[derive(Debug, Clone)]
pub struct LocalSigner {
    /// The underlying private key signer from alloy
    pub inner: PrivateKeySigner,

    /// The Ethereum address derived from the private key
    pub address: EthAddress,

    /// The chain ID this signer is configured for
    pub chain_id: u64,

    /// The private key as a hex string
    pub private_key_hex: String,
}

// Manual implementation of Serialize for LocalSigner
impl Serialize for LocalSigner {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        // Serialize only the fields we need
        let mut state = serializer.serialize_struct("LocalSigner", 3)?;
        state.serialize_field("address", &self.address)?;
        state.serialize_field("chain_id", &self.chain_id)?;
        state.serialize_field("private_key_hex", &self.private_key_hex)?;
        state.end()
    }
}

// Manual implementation of Deserialize for LocalSigner
impl<'de> Deserialize<'de> for LocalSigner {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct LocalSignerData {
            address: EthAddress,
            chain_id: u64,
            private_key_hex: String,
        }

        let data = LocalSignerData::deserialize(deserializer)?;

        // Reconstruct the LocalSigner from the private key
        match LocalSigner::from_private_key(&data.private_key_hex, data.chain_id) {
            Ok(signer) => Ok(signer),
            Err(e) => Err(serde::de::Error::custom(format!(
                "Failed to reconstruct signer: {}",
                e
            ))),
        }
    }
}

impl LocalSigner {
    /// Create a new signer with a randomly generated private key
    pub fn new_random(chain_id: u64) -> Result<Self, SignerError> {
        // Generate a secure random private key directly
        let mut rng = thread_rng();
        let mut private_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut private_key_bytes);

        // Make sure the private key is valid (less than curve order)
        // TODO: This is a simplification
        let max_scalar =
            hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
                .map_err(|_| {
                    SignerError::RandomGenerationError("Failed to decode max scalar".to_string())
                })?;

        // Simple check: if our random bytes are >= max_scalar, regenerate
        // This is a simplified approach - production code would use more sophisticated comparison
        if private_key_bytes.as_slice().cmp(max_scalar.as_slice()) != std::cmp::Ordering::Less {
            // Try again with a new random value
            rng.fill_bytes(&mut private_key_bytes);
        }

        // Convert to B256 for the PrivateKeySigner
        let key = B256::from_slice(&private_key_bytes);

        // Store the private key hex string for later use
        let private_key_hex = format!("0x{}", hex::encode(private_key_bytes));

        // Create the PrivateKeySigner
        let inner = match PrivateKeySigner::from_bytes(&key) {
            Ok(signer) => signer,
            Err(e) => return Err(SignerError::InvalidPrivateKey(e.to_string())),
        };

        let address = inner.address();

        Ok(Self {
            inner,
            address,
            chain_id,
            private_key_hex,
        })
    }

    /// Create a signer from a private key in hexadecimal string format
    pub fn from_private_key(private_key: &str, chain_id: u64) -> Result<Self, SignerError> {
        // Remove 0x prefix if present
        let clean_key = private_key.trim_start_matches("0x");

        // Parse hex string into bytes
        if clean_key.len() != 64 {
            return Err(SignerError::InvalidPrivateKey(
                "Private key must be 32 bytes (64 hex characters)".to_string(),
            ));
        }

        let key_bytes =
            hex::decode(clean_key).map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;

        Self::from_bytes(&key_bytes, chain_id, format!("0x{}", clean_key))
    }

    /// Create a signer from raw private key bytes
    fn from_bytes(
        bytes: &[u8],
        chain_id: u64,
        private_key_hex: String,
    ) -> Result<Self, SignerError> {
        if bytes.len() != 32 {
            return Err(SignerError::InvalidPrivateKey(
                "Private key must be exactly 32 bytes".to_string(),
            ));
        }

        // Convert to B256 (fixed bytes)
        let key = B256::from_slice(bytes);

        // Create the PrivateKeySigner
        let inner = match PrivateKeySigner::from_bytes(&key) {
            Ok(wallet) => wallet,
            Err(e) => return Err(SignerError::InvalidPrivateKey(e.to_string())),
        };

        let address = inner.address();

        Ok(Self {
            inner,
            address,
            chain_id,
            private_key_hex,
        })
    }

    /// Encrypt this signer using a password
    pub fn encrypt(&self, password: &str) -> Result<EncryptedSignerData, SignerError> {
        // Extract the private key hex (without 0x prefix)
        let clean_key = self.private_key_hex.trim_start_matches("0x");

        // Convert to bytes
        let key_bytes =
            hex::decode(clean_key).map_err(|e| SignerError::EncryptionError(e.to_string()))?;

        // Encrypt the private key
        let encrypted_data =
            encrypt_data(&key_bytes, password).map_err(|e| SignerError::EncryptionError(e))?;

        // Create encrypted data structure
        Ok(EncryptedSignerData {
            encrypted_data,
            address: self.address.to_string(),
            chain_id: self.chain_id,
        })
    }

    /// Decrypt an encrypted signer
    pub fn decrypt(encrypted: &EncryptedSignerData, password: &str) -> Result<Self, SignerError> {
        let decrypted_bytes = decrypt_data(&encrypted.encrypted_data, password)
            .map_err(|e| SignerError::DecryptionError(e))?;

        // Convert bytes back to hex string
        let private_key_hex = format!("0x{}", hex::encode(&decrypted_bytes));

        // Create a new signer with the specified chain ID
        Self::from_bytes(&decrypted_bytes, encrypted.chain_id, private_key_hex)
    }

    /// Export the private key as a hexadecimal string
    pub fn export_private_key(&self) -> String {
        self.private_key_hex.clone()
    }
}

impl Signer for LocalSigner {
    fn address(&self) -> EthAddress {
        self.address
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn sign_transaction(&self, tx_data: &TransactionData) -> Result<Vec<u8>, SignerError> {
        // Verify chain ID matches the signer's chain ID
        if tx_data.chain_id != self.chain_id {
            return Err(SignerError::ChainIdMismatch {
                expected: self.chain_id,
                actual: tx_data.chain_id,
            });
        }

        // Convert hyperware types to alloy types
        let to_str = tx_data.to.to_string();
        let to = alloy_primitives::Address::from_str(&to_str)
            .map_err(|e| SignerError::SigningError(format!("Invalid contract address: {}", e)))?;

        // Create transaction based on chain type
        // Both Ethereum mainnet and Base use EIP-1559 transactions
        let mut tx = TxEip1559 {
            chain_id: tx_data.chain_id,
            nonce: tx_data.nonce,
            to: TxKind::Call(to),
            gas_limit: tx_data.gas_limit,
            max_fee_per_gas: tx_data.gas_price,
            // Use provided priority fee or calculate a reasonable default based on the chain
            max_priority_fee_per_gas: tx_data.max_priority_fee.unwrap_or_else(|| {
                match tx_data.chain_id {
                    // Ethereum mainnet (1)
                    1 => tx_data.gas_price / 10,
                    // Base (8453) - typically accepts lower priority fees
                    8453 => tx_data.gas_price / 5,
                    // Default fallback for other networks
                    _ => tx_data.gas_price / 10,
                }
            }),
            input: tx_data.data.clone().unwrap_or_default().into(),
            value: tx_data.value,
            ..Default::default()
        };

        // Sign the transaction with the wallet
        let sig = match self.inner.sign_transaction_sync(&mut tx) {
            Ok(sig) => sig,
            Err(e) => return Err(SignerError::SigningError(e.to_string())),
        };

        // Create signed transaction envelope
        let signed = TxEnvelope::from(tx.into_signed(sig));

        // Encode the transaction
        let mut buf = vec![];
        signed.encode_2718(&mut buf);

        Ok(buf)
    }

    fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        // Create the Ethereum signed message prefixed hash
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let prefixed_message = [prefix.as_bytes(), message].concat();

        // Hash the message
        let hash = sha3::Keccak256::digest(&prefixed_message);
        let hash_bytes = B256::from_slice(hash.as_slice());

        // Sign the hash
        match self.inner.sign_hash_sync(&hash_bytes) {
            Ok(signature) => Ok(signature.as_bytes().to_vec()),
            Err(e) => Err(SignerError::SigningError(e.to_string())),
        }
    }
}

/// Encrypt a private key using a password
pub fn encrypt_data(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let mut rng = thread_rng();

    // Generate salt
    let mut salt = [0u8; SALT_SIZE];
    rng.fill_bytes(&mut salt);

    // Generate nonce
    let mut nonce = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce);

    // Derive key using SHA3
    let key = derive_key(password.as_bytes(), &salt);

    // Encrypt data using XOR
    let encrypted_data = encrypt_with_key(data, &key, &nonce);

    // Generate authentication tag
    let tag = compute_tag(&salt, &nonce, &encrypted_data, &key);

    // Combine all components
    Ok([
        salt.as_ref(),
        nonce.as_ref(),
        encrypted_data.as_ref(),
        tag.as_ref(),
    ]
    .concat())
}

/// Decrypt an encrypted private key
pub fn decrypt_data(encrypted_data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    // Check if data is long enough to contain all components
    if encrypted_data.len() < SALT_SIZE + NONCE_SIZE + TAG_SIZE {
        return Err("Encrypted data is too short".into());
    }

    // Extract components
    let salt = &encrypted_data[..SALT_SIZE];
    let nonce = &encrypted_data[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
    let tag = &encrypted_data[encrypted_data.len() - TAG_SIZE..];
    let ciphertext = &encrypted_data[SALT_SIZE + NONCE_SIZE..encrypted_data.len() - TAG_SIZE];

    // Derive key
    let key = derive_key(password.as_bytes(), salt);

    // Verify the authentication tag
    let expected_tag = compute_tag(salt, nonce, ciphertext, &key);
    if tag != expected_tag {
        return Err("Decryption failed: Authentication tag mismatch".into());
    }

    // Decrypt data
    let plaintext = decrypt_with_key(ciphertext, &key, nonce);

    Ok(plaintext)
}

/// Derive a key from a password and salt using SHA3
fn derive_key(password: &[u8], salt: &[u8]) -> [u8; KEY_SIZE] {
    // Initial hash
    let mut hasher = Sha3_256::new();
    hasher.update(salt);
    hasher.update(password);
    let mut key = hasher.finalize().into();

    // Multiple iterations for stronger key derivation
    for _ in 0..10000 {
        let mut hasher = Sha3_256::new();
        hasher.update(key);
        hasher.update(salt);
        key = hasher.finalize().into();
    }

    key
}

/// Encrypt data with a key and nonce using XOR
fn encrypt_with_key(data: &[u8], key: &[u8; KEY_SIZE], nonce: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());

    for (i, &byte) in data.iter().enumerate() {
        // Create a unique keystream byte for each position
        let key_byte = key[i % key.len()];
        let nonce_byte = nonce[i % nonce.len()];
        let keystream = key_byte ^ nonce_byte ^ (i as u8);

        // XOR with data
        result.push(byte ^ keystream);
    }

    result
}

/// Decrypt data (same as encrypt since XOR is symmetric)
fn decrypt_with_key(data: &[u8], key: &[u8; KEY_SIZE], nonce: &[u8]) -> Vec<u8> {
    encrypt_with_key(data, key, nonce)
}

/// Compute an authentication tag using SHA3
fn compute_tag(salt: &[u8], nonce: &[u8], data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(salt);
    hasher.update(nonce);
    hasher.update(data);
    hasher.update(key);

    let hash = hasher.finalize();
    hash[..TAG_SIZE].to_vec()
}
