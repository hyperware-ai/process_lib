use crate::eth::{
    BlockNumberOrTag, EthError, Filter as EthFilter, FilterBlockOption, Log as EthLog, Provider,
};
use crate::hypermap::contract::getCall;
use crate::hyperware::process::hypermap_cacher::{
    CacherRequest, CacherResponse, CacherStatus, GetLogsByRangeRequest, LogsMetadata, Manifest,
    ManifestItem,
};
use crate::{net, sign};
use crate::{print_to_terminal, Address as HyperAddress, Request};
use alloy::hex;
use alloy::rpc::types::request::{TransactionInput, TransactionRequest};
use alloy_primitives::{keccak256, Address, Bytes, FixedBytes, B256};
use alloy_sol_types::{SolCall, SolEvent, SolValue};
use contract::tokenCall;
use serde::{
    self,
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::str::FromStr;

/// hypermap deployment address on base
pub const HYPERMAP_ADDRESS: &'static str = "0x000000000044C6B8Cb4d8f0F889a3E47664EAeda";
/// base chain id
#[cfg(not(feature = "simulation-mode"))]
pub const HYPERMAP_CHAIN_ID: u64 = 8453; // base
#[cfg(feature = "simulation-mode")]
pub const HYPERMAP_CHAIN_ID: u64 = 31337; // fakenet
/// first block (minus one) of hypermap deployment on base
#[cfg(not(feature = "simulation-mode"))]
pub const HYPERMAP_FIRST_BLOCK: u64 = 27_270_411;
#[cfg(feature = "simulation-mode")]
pub const HYPERMAP_FIRST_BLOCK: u64 = 0;
/// the root hash of hypermap, empty bytes32
pub const HYPERMAP_ROOT_HASH: &'static str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogCache {
    pub metadata: LogsMetadata,
    pub logs: Vec<EthLog>,
}

const DEFAULT_CACHER_NODES: [&str; 0] = [];
const CACHER_REQUEST_TIMEOUT_S: u64 = 15;

/// Sol structures for Hypermap requests
pub mod contract {
    use alloy_sol_macro::sol;

    sol! {
        /// Emitted when a new namespace entry is minted.
        /// - parenthash: The hash of the parent namespace entry.
        /// - childhash: The hash of the minted namespace entry's full path.
        /// - labelhash: The hash of only the label (the final entry in the path).
        /// - label: The label (the final entry in the path) of the new entry.
        event Mint(
            bytes32 indexed parenthash,
            bytes32 indexed childhash,
            bytes indexed labelhash,
            bytes label
        );

        /// Emitted when a fact is created on an existing namespace entry.
        /// Facts are immutable and may only be written once. A fact label is
        /// prepended with an exclamation mark (!) to indicate that it is a fact.
        /// - parenthash The hash of the parent namespace entry.
        /// - facthash The hash of the newly created fact's full path.
        /// - labelhash The hash of only the label (the final entry in the path).
        /// - label The label of the fact.
        /// - data The data stored at the fact.
        event Fact(
            bytes32 indexed parenthash,
            bytes32 indexed facthash,
            bytes indexed labelhash,
            bytes label,
            bytes data
        );

        /// Emitted when a new note is created on an existing namespace entry.
        /// Notes are mutable. A note label is prepended with a tilde (~) to indicate
        /// that it is a note.
        /// - parenthash: The hash of the parent namespace entry.
        /// - notehash: The hash of the newly created note's full path.
        /// - labelhash: The hash of only the label (the final entry in the path).
        /// - label: The label of the note.
        /// - data: The data stored at the note.
        event Note(
            bytes32 indexed parenthash,
            bytes32 indexed notehash,
            bytes indexed labelhash,
            bytes label,
            bytes data
        );

        /// Emitted when a gene is set for an existing namespace entry.
        /// A gene is a specific TBA implementation which will be applied to all
        /// sub-entries of the namespace entry.
        /// - entry: The namespace entry's namehash.
        /// - gene: The address of the TBA implementation.
        event Gene(bytes32 indexed entry, address indexed gene);

        /// Emitted when the zeroth namespace entry is minted.
        /// Occurs exactly once at initialization.
        /// - zeroTba: The address of the zeroth TBA
        event Zero(address indexed zeroTba);

        /// Emitted when a namespace entry is transferred from one address
        /// to another.
        /// - from: The address of the sender.
        /// - to: The address of the recipient.
        /// - id: The namehash of the namespace entry (converted to uint256).
        event Transfer(
            address indexed from,
            address indexed to,
            uint256 indexed id
        );

        /// Emitted when a namespace entry is approved for transfer.
        /// - owner: The address of the owner.
        /// - spender: The address of the spender.
        /// - id: The namehash of the namespace entry (converted to uint256).
        event Approval(
            address indexed owner,
            address indexed spender,
            uint256 indexed id
        );

        /// Emitted when an operator is approved for all of an owner's
        /// namespace entries.
        /// - owner: The address of the owner.
        /// - operator: The address of the operator.
        /// - approved: Whether the operator is approved.
        event ApprovalForAll(
            address indexed owner,
            address indexed operator,
            bool approved
        );

        /// Retrieves information about a specific namespace entry.
        /// - namehash The namehash of the namespace entry to query.
        ///
        /// Returns:
        /// - tba: The address of the token-bound account associated
        /// with the entry.
        /// - owner: The address of the entry owner.
        /// - data: The note or fact bytes associated with the entry
        /// (empty if not a note or fact).
        function get(
            bytes32 namehash
        ) external view returns (address tba, address owner, bytes memory data);

        /// Mints a new namespace entry and creates a token-bound account for
        /// it. Must be called by a parent namespace entry token-bound account.
        /// - who: The address to own the new namespace entry.
        /// - label: The label to mint beneath the calling parent entry.
        /// - initialization: Initialization calldata applied to the new
        /// minted entry's token-bound account.
        /// - erc721Data: ERC-721 data -- passed to comply with
        /// `ERC721TokenReceiver.onERC721Received()`.
        /// - implementation: The address of the implementation contract for
        /// the token-bound account: this will be overriden by the gene if the
        /// parent entry has one set.
        ///
        /// Returns:
        /// - tba: The address of the new entry's token-bound account.
        function mint(
            address who,
            bytes calldata label,
            bytes calldata initialization,
            bytes calldata erc721Data,
            address implementation
        ) external returns (address tba);

        /// Sets the gene for the calling namespace entry.
        /// - _gene: The address of the TBA implementation to set for all
        /// children of the calling namespace entry.
        function gene(address _gene) external;

        /// Creates a new fact beneath the calling namespace entry.
        /// - fact: The fact label to create. Must be prepended with an
        /// exclamation mark (!).
        /// - data: The data to be stored at the fact.
        ///
        /// Returns:
        /// - facthash: The namehash of the newly created fact.
        function fact(
            bytes calldata fact,
            bytes calldata data
        ) external returns (bytes32 facthash);

        /// Creates a new note beneath the calling namespace entry.
        /// - note: The note label to create. Must be prepended with a tilde (~).
        /// - data: The data to be stored at the note.
        ///
        /// Returns:
        /// - notehash: The namehash of the newly created note.
        function note(
            bytes calldata note,
            bytes calldata data
        ) external returns (bytes32 notehash);

        /// Retrieves the token-bound account address of a namespace entry.
        /// - entry: The entry namehash (as uint256) for which to get the
        /// token-bound account.
        ///
        /// Returns:
        /// - tba: The token-bound account address of the namespace entry.
        function tbaOf(uint256 entry) external view returns (address tba);

        function balanceOf(address owner) external view returns (uint256);

        function getApproved(uint256 entry) external view returns (address);

        function isApprovedForAll(
            address owner,
            address operator
        ) external view returns (bool);

        function ownerOf(uint256 entry) external view returns (address);

        function setApprovalForAll(address operator, bool approved) external;

        function approve(address spender, uint256 entry) external;

        function safeTransferFrom(address from, address to, uint256 id) external;

        function safeTransferFrom(
            address from,
            address to,
            uint256 id,
            bytes calldata data
        ) external;

        function transferFrom(address from, address to, uint256 id) external;

        function supportsInterface(bytes4 interfaceId) external view returns (bool);

        /// Gets the token identifier that owns this token-bound account (TBA).
        /// This is a core function of the ERC-6551 standard that returns the
        /// identifying information about the NFT that owns this account.
        /// The return values are constant and cannot change over time.
        ///
        /// Returns:
        /// - chainId: The EIP-155 chain ID where the owning NFT exists
        /// - tokenContract: The contract address of the owning NFT
        /// - tokenId: The token ID of the owning NFT
        function token()
            external
            view
            returns (uint256 chainId, address tokenContract, uint256 tokenId);
    }
}

/// A mint log from the hypermap, converted to a 'resolved' format using
/// namespace data saved in the hns-indexer.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Mint {
    pub name: String,
    pub parent_path: String,
}

/// A note log from the hypermap, converted to a 'resolved' format using
/// namespace data saved in the hns-indexer
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Note {
    pub note: String,
    pub parent_path: String,
    pub data: Bytes,
}

/// A fact log from the hypermap, converted to a 'resolved' format using
/// namespace data saved in the hns-indexer
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fact {
    pub fact: String,
    pub parent_path: String,
    pub data: Bytes,
}

/// Errors that can occur when decoding a log from the hypermap using
/// [`decode_mint_log()`] or [`decode_note_log()`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DecodeLogError {
    /// The log's topic is not a mint or note event.
    UnexpectedTopic(B256),
    /// The name is not valid (according to [`valid_name`]).
    InvalidName(String),
    /// An error occurred while decoding the log.
    DecodeError(String),
    /// The parent name could not be resolved with `hns-indexer`.
    UnresolvedParent(String),
}

impl fmt::Display for DecodeLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeLogError::UnexpectedTopic(topic) => write!(f, "Unexpected topic: {:?}", topic),
            DecodeLogError::InvalidName(name) => write!(f, "Invalid name: {}", name),
            DecodeLogError::DecodeError(err) => write!(f, "Decode error: {}", err),
            DecodeLogError::UnresolvedParent(parent) => {
                write!(f, "Could not resolve parent: {}", parent)
            }
        }
    }
}

impl Error for DecodeLogError {}

/// Canonical function to determine if a hypermap entry is valid.
///
/// This checks a **single name**, not the full path-name. A full path-name
/// is comprised of valid names separated by `.`
pub fn valid_entry(entry: &str, note: bool, fact: bool) -> bool {
    if note && fact {
        return false;
    }
    if note {
        valid_note(entry)
    } else if fact {
        valid_fact(entry)
    } else {
        valid_name(entry)
    }
}

pub fn valid_name(name: &str) -> bool {
    name.is_ascii()
        && name.len() >= 1
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub fn valid_note(note: &str) -> bool {
    note.is_ascii()
        && note.len() >= 2
        && note.chars().next() == Some('~')
        && note
            .chars()
            .skip(1)
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub fn valid_fact(fact: &str) -> bool {
    fact.is_ascii()
        && fact.len() >= 2
        && fact.chars().next() == Some('!')
        && fact
            .chars()
            .skip(1)
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Produce a namehash from a hypermap name.
pub fn namehash(name: &str) -> String {
    let mut node = B256::default();

    let mut labels: Vec<&str> = name.split('.').collect();
    labels.reverse();

    for label in labels.iter() {
        let l = keccak256(label);
        node = keccak256((node, l).abi_encode_packed());
    }
    format!("0x{}", hex::encode(node))
}

/// Decode a mint log from the hypermap into a 'resolved' format.
///
/// Uses [`valid_name()`] to check if the name is valid.
pub fn decode_mint_log(log: &crate::eth::Log) -> Result<Mint, DecodeLogError> {
    let contract::Note::SIGNATURE_HASH = log.topics()[0] else {
        return Err(DecodeLogError::UnexpectedTopic(log.topics()[0]));
    };
    let decoded = contract::Mint::decode_log_data(log.data(), true)
        .map_err(|e| DecodeLogError::DecodeError(e.to_string()))?;
    let name = String::from_utf8_lossy(&decoded.label).to_string();
    if !valid_name(&name) {
        return Err(DecodeLogError::InvalidName(name));
    }
    match resolve_parent(log, None) {
        Some(parent_path) => Ok(Mint { name, parent_path }),
        None => Err(DecodeLogError::UnresolvedParent(name)),
    }
}

/// Decode a note log from the hypermap into a 'resolved' format.
///
/// Uses [`valid_name()`] to check if the name is valid.
pub fn decode_note_log(log: &crate::eth::Log) -> Result<Note, DecodeLogError> {
    let contract::Note::SIGNATURE_HASH = log.topics()[0] else {
        return Err(DecodeLogError::UnexpectedTopic(log.topics()[0]));
    };
    let decoded = contract::Note::decode_log_data(log.data(), true)
        .map_err(|e| DecodeLogError::DecodeError(e.to_string()))?;
    let note = String::from_utf8_lossy(&decoded.label).to_string();
    if !valid_note(&note) {
        return Err(DecodeLogError::InvalidName(note));
    }
    match resolve_parent(log, None) {
        Some(parent_path) => Ok(Note {
            note,
            parent_path,
            data: decoded.data,
        }),
        None => Err(DecodeLogError::UnresolvedParent(note)),
    }
}

pub fn decode_fact_log(log: &crate::eth::Log) -> Result<Fact, DecodeLogError> {
    let contract::Fact::SIGNATURE_HASH = log.topics()[0] else {
        return Err(DecodeLogError::UnexpectedTopic(log.topics()[0]));
    };
    let decoded = contract::Fact::decode_log_data(log.data(), true)
        .map_err(|e| DecodeLogError::DecodeError(e.to_string()))?;
    let fact = String::from_utf8_lossy(&decoded.label).to_string();
    if !valid_fact(&fact) {
        return Err(DecodeLogError::InvalidName(fact));
    }
    match resolve_parent(log, None) {
        Some(parent_path) => Ok(Fact {
            fact,
            parent_path,
            data: decoded.data,
        }),
        None => Err(DecodeLogError::UnresolvedParent(fact)),
    }
}

/// Given a [`crate::eth::Log`] (which must be a log from hypermap), resolve the parent name
/// of the new entry or note.
pub fn resolve_parent(log: &crate::eth::Log, timeout: Option<u64>) -> Option<String> {
    let parent_hash = log.topics()[1].to_string();
    net::get_name(&parent_hash, log.block_number, timeout)
}

/// Given a [`crate::eth::Log`] (which must be a log from hypermap), resolve the full name
/// of the new entry or note.
///
/// Uses [`valid_name()`] to check if the name is valid.
pub fn resolve_full_name(log: &crate::eth::Log, timeout: Option<u64>) -> Option<String> {
    let parent_hash = log.topics()[1].to_string();
    let parent_name = net::get_name(&parent_hash, log.block_number, timeout)?;
    let log_name = match log.topics()[0] {
        contract::Mint::SIGNATURE_HASH => {
            let decoded = contract::Mint::decode_log_data(log.data(), true).unwrap();
            decoded.label
        }
        contract::Note::SIGNATURE_HASH => {
            let decoded = contract::Note::decode_log_data(log.data(), true).unwrap();
            decoded.label
        }
        contract::Fact::SIGNATURE_HASH => {
            let decoded = contract::Fact::decode_log_data(log.data(), true).unwrap();
            decoded.label
        }
        _ => return None,
    };
    let name = String::from_utf8_lossy(&log_name);
    if !valid_entry(
        &name,
        log.topics()[0] == contract::Note::SIGNATURE_HASH,
        log.topics()[0] == contract::Fact::SIGNATURE_HASH,
    ) {
        return None;
    }
    Some(format!("{name}.{parent_name}"))
}

pub fn eth_apply_filter(logs: &[EthLog], filter: &EthFilter) -> anyhow::Result<Vec<EthLog>> {
    let mut matched_logs = Vec::new();

    let (filter_from_block, filter_to_block) = match filter.block_option {
        FilterBlockOption::Range {
            from_block,
            to_block,
        } => {
            let parse_block_num = |bn: Option<BlockNumberOrTag>| -> Option<u64> {
                match bn {
                    Some(BlockNumberOrTag::Number(n)) => Some(n),
                    _ => None,
                }
            };
            (parse_block_num(from_block), parse_block_num(to_block))
        }
        _ => (None, None),
    };

    for log in logs.iter() {
        let mut match_address = filter.address.is_empty();
        if !match_address {
            if filter.address.matches(&log.address()) {
                match_address = true;
            }
        }
        if !match_address {
            continue;
        }

        if let Some(log_bn) = log.block_number {
            if let Some(filter_from) = filter_from_block {
                if log_bn < filter_from {
                    continue;
                }
            }
            if let Some(filter_to) = filter_to_block {
                if log_bn > filter_to {
                    continue;
                }
            }
        } else {
            if filter_from_block.is_some() || filter_to_block.is_some() {
                continue;
            }
        }

        let mut match_topics = true;
        for (i, filter_topic_alternatives) in filter.topics.iter().enumerate() {
            if filter_topic_alternatives.is_empty() {
                continue;
            }

            let log_topic = log.topics().get(i);
            let mut current_topic_matched = false;
            for filter_topic in filter_topic_alternatives.iter() {
                if log_topic == Some(filter_topic) {
                    current_topic_matched = true;
                    break;
                }
            }
            if !current_topic_matched {
                match_topics = false;
                break;
            }
        }

        if match_topics {
            matched_logs.push(log.clone());
        }
    }
    Ok(matched_logs)
}

/// Helper struct for reading from the hypermap.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Hypermap {
    pub provider: Provider,
    address: Address,
}

impl Hypermap {
    /// Creates a new Hypermap instance with a specified address.
    ///
    /// # Arguments
    /// * `provider` - A reference to the Provider.
    /// * `address` - The address of the Hypermap contract.
    pub fn new(provider: Provider, address: Address) -> Self {
        Self { provider, address }
    }

    /// Creates a new Hypermap instance with the default address and chain ID.
    pub fn default(timeout: u64) -> Self {
        let provider = Provider::new(HYPERMAP_CHAIN_ID, timeout);
        Self::new(provider, Address::from_str(HYPERMAP_ADDRESS).unwrap())
    }

    /// Returns the in-use Hypermap contract address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Gets an entry from the Hypermap by its string-formatted name.
    ///
    /// # Parameters
    /// - `path`: The name-path to get from the Hypermap.
    /// # Returns
    /// A `Result<(Address, Address, Option<Bytes>), EthError>` representing the TBA, owner,
    /// and value if the entry exists and is a note.
    pub fn get(&self, path: &str) -> Result<(Address, Address, Option<Bytes>), EthError> {
        let get_call = getCall {
            namehash: FixedBytes::<32>::from_str(&namehash(path))
                .map_err(|_| EthError::InvalidParams)?,
        }
        .abi_encode();

        let tx_req = TransactionRequest::default()
            .input(TransactionInput::new(get_call.into()))
            .to(self.address);

        let res_bytes = self.provider.call(tx_req, None)?;

        let res = getCall::abi_decode_returns(&res_bytes, false)
            .map_err(|_| EthError::RpcMalformedResponse)?;

        let note_data = if res.data == Bytes::default() {
            None
        } else {
            Some(res.data)
        };

        Ok((res.tba, res.owner, note_data))
    }

    /// Gets an entry from the Hypermap by its hash.
    ///
    /// # Parameters
    /// - `entryhash`: The entry to get from the Hypermap.
    /// # Returns
    /// A `Result<(Address, Address, Option<Bytes>), EthError>` representing the TBA, owner,
    /// and value if the entry exists and is a note.
    pub fn get_hash(&self, entryhash: &str) -> Result<(Address, Address, Option<Bytes>), EthError> {
        let get_call = getCall {
            namehash: FixedBytes::<32>::from_str(entryhash).map_err(|_| EthError::InvalidParams)?,
        }
        .abi_encode();

        let tx_req = TransactionRequest::default()
            .input(TransactionInput::new(get_call.into()))
            .to(self.address);

        let res_bytes = self.provider.call(tx_req, None)?;

        let res = getCall::abi_decode_returns(&res_bytes, false)
            .map_err(|_| EthError::RpcMalformedResponse)?;

        let note_data = if res.data == Bytes::default() {
            None
        } else {
            Some(res.data)
        };

        Ok((res.tba, res.owner, note_data))
    }

    /// Gets a namehash from an existing TBA address.
    ///
    /// # Parameters
    /// - `tba`: The TBA to get the namehash of.
    /// # Returns
    /// A `Result<String, EthError>` representing the namehash of the TBA.
    pub fn get_namehash_from_tba(&self, tba: Address) -> Result<String, EthError> {
        let token_call = tokenCall {}.abi_encode();

        let tx_req = TransactionRequest::default()
            .input(TransactionInput::new(token_call.into()))
            .to(tba);

        let res_bytes = self.provider.call(tx_req, None)?;

        let res = tokenCall::abi_decode_returns(&res_bytes, false)
            .map_err(|_| EthError::RpcMalformedResponse)?;

        let namehash: FixedBytes<32> = res.tokenId.into();
        Ok(format!("0x{}", hex::encode(namehash)))
    }

    /// Create a filter for all mint events.
    pub fn mint_filter(&self) -> crate::eth::Filter {
        crate::eth::Filter::new()
            .address(self.address)
            .event(contract::Mint::SIGNATURE)
    }

    /// Create a filter for all note events.
    pub fn note_filter(&self) -> crate::eth::Filter {
        crate::eth::Filter::new()
            .address(self.address)
            .event(contract::Note::SIGNATURE)
    }

    /// Create a filter for all fact events.
    pub fn fact_filter(&self) -> crate::eth::Filter {
        crate::eth::Filter::new()
            .address(self.address)
            .event(contract::Fact::SIGNATURE)
    }

    /// Create a filter for a given set of specific notes. This function will
    /// hash the note labels and use them as the topic3 filter.
    ///
    /// Example:
    /// ```rust
    /// let filter = hypermap.notes_filter(&["~note1", "~note2"]);
    /// ```
    pub fn notes_filter(&self, notes: &[&str]) -> crate::eth::Filter {
        self.note_filter().topic3(
            notes
                .into_iter()
                .map(|note| keccak256(note))
                .collect::<Vec<_>>(),
        )
    }

    /// Create a filter for a given set of specific facts. This function will
    /// hash the fact labels and use them as the topic3 filter.
    ///
    /// Example:
    /// ```rust
    /// let filter = hypermap.facts_filter(&["!fact1", "!fact2"]);
    /// ```
    pub fn facts_filter(&self, facts: &[&str]) -> crate::eth::Filter {
        self.fact_filter().topic3(
            facts
                .into_iter()
                .map(|fact| keccak256(fact))
                .collect::<Vec<_>>(),
        )
    }

    pub fn get_bootstrap_log_cache(
        &self,
        from_block: Option<u64>,
        mut nodes: HashSet<String>,
        chain: Option<String>,
    ) -> anyhow::Result<Vec<LogCache>> {
        print_to_terminal(2,
            &format!("get_bootstrap_log_cache (using GetLogsByRange): from_block={:?}, nodes={:?}, chain={:?}",
            from_block, nodes, chain)
        );

        for default_node in DEFAULT_CACHER_NODES.iter() {
            nodes.insert(default_node.to_string());
        }

        if nodes.is_empty() {
            print_to_terminal(
                1,
                "get_bootstrap_log_cache: No cacher nodes specified or defaulted.",
            );
            return Ok(Vec::new());
        }

        let target_chain_id = chain.unwrap_or_else(|| self.provider.get_chain_id().to_string());
        let mut all_retrieved_log_caches: Vec<LogCache> = Vec::new();
        let request_from_block_val = from_block.unwrap_or(0);

        for node_address_str in nodes {
            let Ok(cacher_process_address) = HyperAddress::from_str(&node_address_str) else {
                print_to_terminal(
                    1,
                    &format!("Invalid cacher node address string: {}", node_address_str),
                );
                continue;
            };

            print_to_terminal(
                2,
                &format!(
                    "Querying cacher node with GetLogsByRange: {}",
                    cacher_process_address.to_string(),
                ),
            );

            let get_logs_by_range_payload = GetLogsByRangeRequest {
                from_block: request_from_block_val,
                to_block: None, // Request all logs from from_block onwards. Cacher will return what it has.
            };
            let cacher_request = CacherRequest::GetLogsByRange(get_logs_by_range_payload);

            let response_msg = Request::to(cacher_process_address.clone())
                .body(serde_json::to_vec(&cacher_request)?)
                .send_and_await_response(CACHER_REQUEST_TIMEOUT_S)?
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Error response from cacher {} for GetLogsByRange: {:?}",
                        cacher_process_address.to_string(),
                        e
                    )
                })?;

            let logs_by_range_result =
                match serde_json::from_slice::<CacherResponse>(response_msg.body())? {
                    CacherResponse::GetLogsByRange(res) => res,
                    _ => {
                        print_to_terminal(
                            1,
                            &format!(
                                "Unexpected response type from cacher {} for GetLogsByRange",
                                cacher_process_address.to_string(),
                            ),
                        );
                        continue;
                    }
                };

            match logs_by_range_result {
                Ok(json_string_of_vec_log_cache) => {
                    if json_string_of_vec_log_cache.is_empty()
                        || json_string_of_vec_log_cache == "[]"
                    {
                        print_to_terminal(
                            2,
                            &format!(
                                "Cacher {} returned no log caches for the range from block {}.",
                                cacher_process_address.to_string(),
                                request_from_block_val,
                            ),
                        );
                        continue;
                    }
                    match serde_json::from_str::<Vec<LogCache>>(&json_string_of_vec_log_cache) {
                        Ok(retrieved_caches) => {
                            for log_cache in retrieved_caches {
                                if log_cache.metadata.chain_id == target_chain_id {
                                    // Further filter: ensure the cache's own from_block isn't completely after what we need,
                                    // and to_block isn't completely before.
                                    // The GetLogsByRange on cacher side should handle this, but double check.
                                    let cache_from = log_cache
                                        .metadata
                                        .from_block
                                        .parse::<u64>()
                                        .unwrap_or(u64::MAX);
                                    let cache_to =
                                        log_cache.metadata.to_block.parse::<u64>().unwrap_or(0);

                                    if cache_to >= request_from_block_val {
                                        // Cache has some data at or after our request_from_block
                                        all_retrieved_log_caches.push(log_cache);
                                    } else {
                                        print_to_terminal(3, &format!("Cache from {} ({} to {}) does not meet request_from_block {}",
                                            cacher_process_address.to_string(), cache_from, cache_to, request_from_block_val));
                                    }
                                } else {
                                    print_to_terminal(1,&format!("LogCache from {} has mismatched chain_id (expected {}, got {}). Skipping.",
                                        cacher_process_address.to_string(), target_chain_id, log_cache.metadata.chain_id));
                                }
                            }
                        }
                        Err(e) => {
                            print_to_terminal(1,&format!("Failed to deserialize Vec<LogCache> from cacher {}: {:?}. JSON: {:.100}",
                                cacher_process_address.to_string(), e, json_string_of_vec_log_cache));
                        }
                    }
                }
                Err(e_str) => {
                    print_to_terminal(
                        1,
                        &format!(
                            "Cacher {} reported error for GetLogsByRange: {}",
                            cacher_process_address.to_string(),
                            e_str,
                        ),
                    );
                }
            }
        }
        print_to_terminal(
            2,
            &format!(
                "Retrieved {} log caches in total using GetLogsByRange.",
                all_retrieved_log_caches.len(),
            ),
        );
        Ok(all_retrieved_log_caches)
    }

    pub fn validate_log_cache(&self, log_cache: &LogCache) -> anyhow::Result<bool> {
        let from_block = log_cache.metadata.from_block.parse::<u64>().map_err(|_| {
            anyhow::anyhow!(
                "Invalid from_block in metadata: {}",
                log_cache.metadata.from_block
            )
        })?;
        let to_block = log_cache.metadata.to_block.parse::<u64>().map_err(|_| {
            anyhow::anyhow!(
                "Invalid to_block in metadata: {}",
                log_cache.metadata.to_block
            )
        })?;

        let mut bytes_to_verify = serde_json::to_vec(&log_cache.logs)
            .map_err(|e| anyhow::anyhow!("Failed to serialize logs for validation: {:?}", e))?;
        bytes_to_verify.extend_from_slice(&from_block.to_be_bytes());
        bytes_to_verify.extend_from_slice(&to_block.to_be_bytes());
        let hashed_data = keccak256(&bytes_to_verify);

        let signature_hex = log_cache.metadata.signature.trim_start_matches("0x");
        let signature_bytes = hex::decode(signature_hex)
            .map_err(|e| anyhow::anyhow!("Failed to decode hex signature: {:?}", e))?;

        Ok(sign::net_key_verify(
            hashed_data.to_vec(),
            &log_cache.metadata.created_by.parse::<HyperAddress>()?,
            signature_bytes,
        )?)
    }

    pub fn get_bootstrap(
        &self,
        from_block: Option<u64>,
        nodes: HashSet<String>,
        chain: Option<String>,
    ) -> anyhow::Result<Vec<EthLog>> {
        print_to_terminal(
            2,
            &format!(
                "get_bootstrap: from_block={:?}, nodes={:?}, chain={:?}",
                from_block, nodes, chain,
            ),
        );
        let log_caches = self.get_bootstrap_log_cache(from_block, nodes, chain)?;

        let mut all_valid_logs: Vec<EthLog> = Vec::new();
        let request_from_block_val = from_block.unwrap_or(0);

        for log_cache in log_caches {
            match self.validate_log_cache(&log_cache) {
                Ok(true) => {
                    for log in log_cache.logs {
                        if let Some(log_block_number) = log.block_number {
                            if log_block_number >= request_from_block_val {
                                all_valid_logs.push(log);
                            }
                        } else {
                            if from_block.is_none() {
                                all_valid_logs.push(log);
                            }
                        }
                    }
                }
                Ok(false) => {
                    print_to_terminal(
                        1,
                        &format!("LogCache validation failed for cache created by {}. Discarding {} logs.",
                        log_cache.metadata.created_by,
                        log_cache.logs.len())
                    );
                }
                Err(e) => {
                    print_to_terminal(
                        1,
                        &format!(
                            "Error validating LogCache from {}: {:?}. Discarding.",
                            log_cache.metadata.created_by, e,
                        ),
                    );
                }
            }
        }

        all_valid_logs.sort_by(|a, b| {
            let block_cmp = a.block_number.cmp(&b.block_number);
            if block_cmp == std::cmp::Ordering::Equal {
                std::cmp::Ordering::Equal
            } else {
                block_cmp
            }
        });

        let mut unique_logs = Vec::new();
        for log in all_valid_logs {
            if !unique_logs.contains(&log) {
                unique_logs.push(log);
            }
        }

        print_to_terminal(
            2,
            &format!(
                "get_bootstrap: Consolidated {} unique logs.",
                unique_logs.len(),
            ),
        );
        Ok(unique_logs)
    }

    pub fn bootstrap(
        &self,
        from_block: Option<u64>,
        filters: Vec<EthFilter>,
        nodes: HashSet<String>,
        chain: Option<String>,
    ) -> anyhow::Result<Vec<Vec<EthLog>>> {
        print_to_terminal(
            2,
            &format!(
                "bootstrap: from_block={:?}, num_filters={}, nodes={:?}, chain={:?}",
                from_block,
                filters.len(),
                nodes,
                chain,
            ),
        );

        let consolidated_logs = self.get_bootstrap(from_block, nodes, chain)?;

        if consolidated_logs.is_empty() {
            print_to_terminal(2,"bootstrap: No logs retrieved after consolidation. Returning empty results for filters.");
            return Ok(filters.iter().map(|_| Vec::new()).collect());
        }

        let mut results_per_filter: Vec<Vec<EthLog>> = Vec::new();
        for filter in filters {
            let filtered_logs = eth_apply_filter(&consolidated_logs, &filter)?;
            results_per_filter.push(filtered_logs);
        }

        print_to_terminal(
            2,
            &format!(
                "bootstrap: Applied {} filters to bootstrapped logs.",
                results_per_filter.len(),
            ),
        );
        Ok(results_per_filter)
    }
}

impl Serialize for ManifestItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ManifestItem", 4)?;
        state.serialize_field("metadata", &self.metadata)?;
        state.serialize_field("is_empty", &self.is_empty)?;
        state.serialize_field("file_hash", &self.file_hash)?;
        state.serialize_field("file_name", &self.file_name)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ManifestItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Metadata,
            IsEmpty,
            FileHash,
            FileName,
        }

        struct ManifestItemVisitor;

        impl<'de> Visitor<'de> for ManifestItemVisitor {
            type Value = ManifestItem;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ManifestItem")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ManifestItem, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut metadata = None;
                let mut is_empty = None;
                let mut file_hash = None;
                let mut file_name = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Metadata => {
                            if metadata.is_some() {
                                return Err(de::Error::duplicate_field("metadata"));
                            }
                            metadata = Some(map.next_value()?);
                        }
                        Field::IsEmpty => {
                            if is_empty.is_some() {
                                return Err(de::Error::duplicate_field("is_empty"));
                            }
                            is_empty = Some(map.next_value()?);
                        }
                        Field::FileHash => {
                            if file_hash.is_some() {
                                return Err(de::Error::duplicate_field("file_hash"));
                            }
                            file_hash = Some(map.next_value()?);
                        }
                        Field::FileName => {
                            if file_name.is_some() {
                                return Err(de::Error::duplicate_field("file_name"));
                            }
                            file_name = Some(map.next_value()?);
                        }
                    }
                }

                let metadata = metadata.ok_or_else(|| de::Error::missing_field("metadata"))?;
                let is_empty = is_empty.ok_or_else(|| de::Error::missing_field("is_empty"))?;
                let file_hash = file_hash.ok_or_else(|| de::Error::missing_field("file_hash"))?;
                let file_name = file_name.ok_or_else(|| de::Error::missing_field("file_name"))?;

                Ok(ManifestItem {
                    metadata,
                    is_empty,
                    file_hash,
                    file_name,
                })
            }
        }

        deserializer.deserialize_struct(
            "ManifestItem",
            &["metadata", "is_empty", "file_hash", "file_name"],
            ManifestItemVisitor,
        )
    }
}

// Manifest implementation
impl Serialize for Manifest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Manifest", 4)?;
        state.serialize_field("items", &self.items)?;
        state.serialize_field("manifest_filename", &self.manifest_filename)?;
        state.serialize_field("chain_id", &self.chain_id)?;
        state.serialize_field("protocol_version", &self.protocol_version)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Manifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Items,
            ManifestFilename,
            ChainId,
            ProtocolVersion,
        }

        struct ManifestVisitor;

        impl<'de> Visitor<'de> for ManifestVisitor {
            type Value = Manifest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Manifest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Manifest, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut items = None;
                let mut manifest_filename = None;
                let mut chain_id = None;
                let mut protocol_version = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Items => {
                            if items.is_some() {
                                return Err(de::Error::duplicate_field("items"));
                            }
                            items = Some(map.next_value()?);
                        }
                        Field::ManifestFilename => {
                            if manifest_filename.is_some() {
                                return Err(de::Error::duplicate_field("manifest_filename"));
                            }
                            manifest_filename = Some(map.next_value()?);
                        }
                        Field::ChainId => {
                            if chain_id.is_some() {
                                return Err(de::Error::duplicate_field("chain_id"));
                            }
                            chain_id = Some(map.next_value()?);
                        }
                        Field::ProtocolVersion => {
                            if protocol_version.is_some() {
                                return Err(de::Error::duplicate_field("protocol_version"));
                            }
                            protocol_version = Some(map.next_value()?);
                        }
                    }
                }

                let items = items.ok_or_else(|| de::Error::missing_field("items"))?;
                let manifest_filename = manifest_filename
                    .ok_or_else(|| de::Error::missing_field("manifest_filename"))?;
                let chain_id = chain_id.ok_or_else(|| de::Error::missing_field("chain_id"))?;
                let protocol_version =
                    protocol_version.ok_or_else(|| de::Error::missing_field("protocol_version"))?;

                Ok(Manifest {
                    items,
                    manifest_filename,
                    chain_id,
                    protocol_version,
                })
            }
        }

        deserializer.deserialize_struct(
            "Manifest",
            &["items", "manifest_filename", "chain_id", "protocol_version"],
            ManifestVisitor,
        )
    }
}

// GetLogsByRangeRequest implementation
impl Serialize for GetLogsByRangeRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("GetLogsByRangeRequest", 2)?;
        state.serialize_field("from_block", &self.from_block)?;
        state.serialize_field("to_block", &self.to_block)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for GetLogsByRangeRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            FromBlock,
            ToBlock,
        }

        struct GetLogsByRangeRequestVisitor;

        impl<'de> Visitor<'de> for GetLogsByRangeRequestVisitor {
            type Value = GetLogsByRangeRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct GetLogsByRangeRequest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<GetLogsByRangeRequest, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut from_block = None;
                let mut to_block = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::FromBlock => {
                            if from_block.is_some() {
                                return Err(de::Error::duplicate_field("from_block"));
                            }
                            from_block = Some(map.next_value()?);
                        }
                        Field::ToBlock => {
                            if to_block.is_some() {
                                return Err(de::Error::duplicate_field("to_block"));
                            }
                            to_block = Some(map.next_value()?);
                        }
                    }
                }

                let from_block =
                    from_block.ok_or_else(|| de::Error::missing_field("from_block"))?;

                Ok(GetLogsByRangeRequest {
                    from_block,
                    to_block,
                })
            }
        }

        deserializer.deserialize_struct(
            "GetLogsByRangeRequest",
            &["from_block", "to_block"],
            GetLogsByRangeRequestVisitor,
        )
    }
}

// CacherStatus implementation
impl Serialize for CacherStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CacherStatus", 7)?;
        state.serialize_field("last_cached_block", &self.last_cached_block)?;
        state.serialize_field("chain_id", &self.chain_id)?;
        state.serialize_field("protocol_version", &self.protocol_version)?;
        state.serialize_field(
            "next_cache_attempt_in_seconds",
            &self.next_cache_attempt_in_seconds,
        )?;
        state.serialize_field("manifest_filename", &self.manifest_filename)?;
        state.serialize_field("log_files_count", &self.log_files_count)?;
        state.serialize_field("our_address", &self.our_address)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for CacherStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            LastCachedBlock,
            ChainId,
            ProtocolVersion,
            NextCacheAttemptInSeconds,
            ManifestFilename,
            LogFilesCount,
            OurAddress,
        }

        struct CacherStatusVisitor;

        impl<'de> Visitor<'de> for CacherStatusVisitor {
            type Value = CacherStatus;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct CacherStatus")
            }

            fn visit_map<V>(self, mut map: V) -> Result<CacherStatus, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut last_cached_block = None;
                let mut chain_id = None;
                let mut protocol_version = None;
                let mut next_cache_attempt_in_seconds = None;
                let mut manifest_filename = None;
                let mut log_files_count = None;
                let mut our_address = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::LastCachedBlock => {
                            if last_cached_block.is_some() {
                                return Err(de::Error::duplicate_field("last_cached_block"));
                            }
                            last_cached_block = Some(map.next_value()?);
                        }
                        Field::ChainId => {
                            if chain_id.is_some() {
                                return Err(de::Error::duplicate_field("chain_id"));
                            }
                            chain_id = Some(map.next_value()?);
                        }
                        Field::ProtocolVersion => {
                            if protocol_version.is_some() {
                                return Err(de::Error::duplicate_field("protocol_version"));
                            }
                            protocol_version = Some(map.next_value()?);
                        }
                        Field::NextCacheAttemptInSeconds => {
                            if next_cache_attempt_in_seconds.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "next_cache_attempt_in_seconds",
                                ));
                            }
                            next_cache_attempt_in_seconds = Some(map.next_value()?);
                        }
                        Field::ManifestFilename => {
                            if manifest_filename.is_some() {
                                return Err(de::Error::duplicate_field("manifest_filename"));
                            }
                            manifest_filename = Some(map.next_value()?);
                        }
                        Field::LogFilesCount => {
                            if log_files_count.is_some() {
                                return Err(de::Error::duplicate_field("log_files_count"));
                            }
                            log_files_count = Some(map.next_value()?);
                        }
                        Field::OurAddress => {
                            if our_address.is_some() {
                                return Err(de::Error::duplicate_field("our_address"));
                            }
                            our_address = Some(map.next_value()?);
                        }
                    }
                }

                let last_cached_block = last_cached_block
                    .ok_or_else(|| de::Error::missing_field("last_cached_block"))?;
                let chain_id = chain_id.ok_or_else(|| de::Error::missing_field("chain_id"))?;
                let protocol_version =
                    protocol_version.ok_or_else(|| de::Error::missing_field("protocol_version"))?;
                let manifest_filename = manifest_filename
                    .ok_or_else(|| de::Error::missing_field("manifest_filename"))?;
                let log_files_count =
                    log_files_count.ok_or_else(|| de::Error::missing_field("log_files_count"))?;
                let our_address =
                    our_address.ok_or_else(|| de::Error::missing_field("our_address"))?;

                Ok(CacherStatus {
                    last_cached_block,
                    chain_id,
                    protocol_version,
                    next_cache_attempt_in_seconds,
                    manifest_filename,
                    log_files_count,
                    our_address,
                })
            }
        }

        deserializer.deserialize_struct(
            "CacherStatus",
            &[
                "last_cached_block",
                "chain_id",
                "protocol_version",
                "next_cache_attempt_in_seconds",
                "manifest_filename",
                "log_files_count",
                "our_address",
            ],
            CacherStatusVisitor,
        )
    }
}

// CacherRequest implementation (enum)
impl Serialize for CacherRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            CacherRequest::GetManifest => {
                let mut state = serializer.serialize_struct("CacherRequest", 1)?;
                state.serialize_field("type", "GetManifest")?;
                state.end()
            }
            CacherRequest::GetLogCacheContent(path) => {
                let mut state = serializer.serialize_struct("CacherRequest", 2)?;
                state.serialize_field("type", "GetLogCacheContent")?;
                state.serialize_field("path", path)?;
                state.end()
            }
            CacherRequest::GetStatus => {
                let mut state = serializer.serialize_struct("CacherRequest", 1)?;
                state.serialize_field("type", "GetStatus")?;
                state.end()
            }
            CacherRequest::GetLogsByRange(request) => {
                let mut state = serializer.serialize_struct("CacherRequest", 2)?;
                state.serialize_field("type", "GetLogsByRange")?;
                state.serialize_field("request", request)?;
                state.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for CacherRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            Type,
            Path,
            Request,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        enum RequestType {
            GetManifest,
            GetLogCacheContent,
            GetStatus,
            GetLogsByRange,
        }

        struct CacherRequestVisitor;

        impl<'de> Visitor<'de> for CacherRequestVisitor {
            type Value = CacherRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct CacherRequest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<CacherRequest, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut request_type = None;
                let mut path = None;
                let mut request = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Type => {
                            if request_type.is_some() {
                                return Err(de::Error::duplicate_field("type"));
                            }
                            request_type = Some(map.next_value()?);
                        }
                        Field::Path => {
                            if path.is_some() {
                                return Err(de::Error::duplicate_field("path"));
                            }
                            path = Some(map.next_value()?);
                        }
                        Field::Request => {
                            if request.is_some() {
                                return Err(de::Error::duplicate_field("request"));
                            }
                            request = Some(map.next_value()?);
                        }
                    }
                }

                let request_type = request_type.ok_or_else(|| de::Error::missing_field("type"))?;

                match request_type {
                    RequestType::GetManifest => Ok(CacherRequest::GetManifest),
                    RequestType::GetLogCacheContent => {
                        let path = path.ok_or_else(|| de::Error::missing_field("path"))?;
                        Ok(CacherRequest::GetLogCacheContent(path))
                    }
                    RequestType::GetStatus => Ok(CacherRequest::GetStatus),
                    RequestType::GetLogsByRange => {
                        let request = request.ok_or_else(|| de::Error::missing_field("request"))?;
                        Ok(CacherRequest::GetLogsByRange(request))
                    }
                }
            }
        }

        deserializer.deserialize_map(CacherRequestVisitor)
    }
}

// CacherResponse implementation (enum)
impl Serialize for CacherResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            CacherResponse::GetManifest(manifest) => {
                let mut state = serializer.serialize_struct("CacherResponse", 2)?;
                state.serialize_field("type", "GetManifest")?;
                state.serialize_field("manifest", manifest)?;
                state.end()
            }
            CacherResponse::GetLogCacheContent(result) => {
                let mut state = serializer.serialize_struct("CacherResponse", 2)?;
                state.serialize_field("type", "GetLogCacheContent")?;
                state.serialize_field("result", result)?;
                state.end()
            }
            CacherResponse::GetStatus(status) => {
                let mut state = serializer.serialize_struct("CacherResponse", 2)?;
                state.serialize_field("type", "GetStatus")?;
                state.serialize_field("status", status)?;
                state.end()
            }
            CacherResponse::GetLogsByRange(result) => {
                let mut state = serializer.serialize_struct("CacherResponse", 2)?;
                state.serialize_field("type", "GetLogsByRange")?;
                state.serialize_field("result", result)?;
                state.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for CacherResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            Type,
            Manifest,
            Result,
            Status,
        }

        #[derive(Deserialize, PartialEq)]
        #[serde(rename_all = "camelCase")]
        enum ResponseType {
            GetManifest,
            GetLogCacheContent,
            GetStatus,
            GetLogsByRange,
        }

        struct CacherResponseVisitor;

        impl<'de> Visitor<'de> for CacherResponseVisitor {
            type Value = CacherResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct CacherResponse")
            }

            fn visit_map<V>(self, mut map: V) -> Result<CacherResponse, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut response_type = None;
                let mut manifest = None;
                let mut result: Option<Result<Option<String>, String>> = None;
                let mut logs_result: Option<Result<String, String>> = None;
                let mut status = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Type => {
                            if response_type.is_some() {
                                return Err(de::Error::duplicate_field("type"));
                            }
                            response_type = Some(map.next_value()?);
                        }
                        Field::Manifest => {
                            if manifest.is_some() {
                                return Err(de::Error::duplicate_field("manifest"));
                            }
                            manifest = Some(map.next_value()?);
                        }
                        Field::Result => {
                            if response_type == Some(ResponseType::GetLogsByRange) {
                                if logs_result.is_some() {
                                    return Err(de::Error::duplicate_field("result"));
                                }
                                logs_result = Some(map.next_value()?);
                            } else {
                                if result.is_some() {
                                    return Err(de::Error::duplicate_field("result"));
                                }
                                result = Some(map.next_value()?);
                            }
                        }
                        Field::Status => {
                            if status.is_some() {
                                return Err(de::Error::duplicate_field("status"));
                            }
                            status = Some(map.next_value()?);
                        }
                    }
                }

                let response_type =
                    response_type.ok_or_else(|| de::Error::missing_field("type"))?;

                match response_type {
                    ResponseType::GetManifest => {
                        let manifest =
                            manifest.ok_or_else(|| de::Error::missing_field("manifest"))?;
                        Ok(CacherResponse::GetManifest(manifest))
                    }
                    ResponseType::GetLogCacheContent => {
                        let result = result.ok_or_else(|| de::Error::missing_field("result"))?;
                        Ok(CacherResponse::GetLogCacheContent(result))
                    }
                    ResponseType::GetStatus => {
                        let status = status.ok_or_else(|| de::Error::missing_field("status"))?;
                        Ok(CacherResponse::GetStatus(status))
                    }
                    ResponseType::GetLogsByRange => {
                        let result =
                            logs_result.ok_or_else(|| de::Error::missing_field("result"))?;
                        Ok(CacherResponse::GetLogsByRange(result))
                    }
                }
            }
        }

        deserializer.deserialize_map(CacherResponseVisitor)
    }
}

impl Serialize for LogsMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("LogsMetadata", 6)?;
        state.serialize_field("chainId", &self.chain_id)?;
        state.serialize_field("fromBlock", &self.from_block)?;
        state.serialize_field("toBlock", &self.to_block)?;
        state.serialize_field("timeCreated", &self.time_created)?;
        state.serialize_field("createdBy", &self.created_by)?;
        state.serialize_field("signature", &self.signature)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for LogsMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            ChainId,
            FromBlock,
            ToBlock,
            TimeCreated,
            CreatedBy,
            Signature,
        }

        struct LogsMetadataVisitor;

        impl<'de> Visitor<'de> for LogsMetadataVisitor {
            type Value = LogsMetadata;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct LogsMetadata")
            }

            fn visit_map<V>(self, mut map: V) -> Result<LogsMetadata, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut chain_id = None;
                let mut from_block = None;
                let mut to_block = None;
                let mut time_created = None;
                let mut created_by = None;
                let mut signature = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::ChainId => {
                            if chain_id.is_some() {
                                return Err(de::Error::duplicate_field("chainId"));
                            }
                            chain_id = Some(map.next_value()?);
                        }
                        Field::FromBlock => {
                            if from_block.is_some() {
                                return Err(de::Error::duplicate_field("fromBlock"));
                            }
                            from_block = Some(map.next_value()?);
                        }
                        Field::ToBlock => {
                            if to_block.is_some() {
                                return Err(de::Error::duplicate_field("toBlock"));
                            }
                            to_block = Some(map.next_value()?);
                        }
                        Field::TimeCreated => {
                            if time_created.is_some() {
                                return Err(de::Error::duplicate_field("timeCreated"));
                            }
                            time_created = Some(map.next_value()?);
                        }
                        Field::CreatedBy => {
                            if created_by.is_some() {
                                return Err(de::Error::duplicate_field("createdBy"));
                            }
                            created_by = Some(map.next_value()?);
                        }
                        Field::Signature => {
                            if signature.is_some() {
                                return Err(de::Error::duplicate_field("signature"));
                            }
                            signature = Some(map.next_value()?);
                        }
                    }
                }

                let chain_id = chain_id.ok_or_else(|| de::Error::missing_field("chainId"))?;
                let from_block = from_block.ok_or_else(|| de::Error::missing_field("fromBlock"))?;
                let to_block = to_block.ok_or_else(|| de::Error::missing_field("toBlock"))?;
                let time_created =
                    time_created.ok_or_else(|| de::Error::missing_field("timeCreated"))?;
                let created_by = created_by.ok_or_else(|| de::Error::missing_field("createdBy"))?;
                let signature = signature.ok_or_else(|| de::Error::missing_field("signature"))?;

                Ok(LogsMetadata {
                    chain_id,
                    from_block,
                    to_block,
                    time_created,
                    created_by,
                    signature,
                })
            }
        }

        deserializer.deserialize_struct(
            "LogsMetadata",
            &[
                "chainId",
                "fromBlock",
                "toBlock",
                "timeCreated",
                "createdBy",
                "signature",
            ],
            LogsMetadataVisitor,
        )
    }
}
