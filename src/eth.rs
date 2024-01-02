use crate::*;
use crate::{Address as uqAddress, Request as uqRequest};
use serde::{Deserialize, Serialize};

pub use ethers_core::types::{
    Address as EthAddress, BlockNumber, Filter, FilterBlockOption, Topic, ValueOrArray, H256, U64,
};

#[derive(Debug, Serialize, Deserialize)]
pub enum EthRequest {
    SubscribeLogs(SubscribeLogs),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubscribeLogs {
    pub filter: Filter,
}

#[derive(Debug)]
pub struct SubscribeLogsRequest {
    pub request: uqRequest,
    pub filter: Filter,
}

impl SubscribeLogsRequest {

    /// Start building a new `SubscribeLogsRequest`. 
    pub fn new() -> Self {
        let request = uqRequest::new().target(uqAddress::new(
            "our",
            ProcessId::new(Some("eth"), "sys", "uqbar"),
        ));

        SubscribeLogsRequest {
            request,
            filter: SubscribeLogsRequest::new(),
        }
    }

    /// Attempt to send the request. 
    pub fn send(mut self) -> anyhow::Result<()> {
        self.request = self
            .request
            .ipc(serde_json::to_vec(&EthRequest::SubscribeLogs(
                SubscribeLogs {
                    filter: self.filter.clone(),
                },
            ))?);
        self.request.send()
    }

    /// Sets the inner filter object
    ///
    /// *NOTE:* ranges are always inclusive
    ///
    /// # Examples
    ///
    /// Match only a specific block
    ///
    /// ```rust
    /// # use process_lib::eth::SubscribeLogsRequest;
    /// # fn main() {
    /// let request = SubscribeLogsRequest::new().select(69u64);
    /// # }
    /// ```
    /// This is the same as `SubscribeLogsRequest::new().from_block(1337u64).to_block(1337u64)`
    ///
    /// Match the latest block only
    ///
    /// ```rust
    /// # use process_lib::eth::{SubscribeLogsRequest, BlockNumber};
    /// # fn main() {
    /// let request = SubscribeLogsRequest::new().select(BlockNumber::Latest);
    /// # }
    /// ```
    ///
    /// Match a block by its hash
    ///
    /// ```rust
    /// # use process_lib::eth::{SubscribeLogsRequest, H256};
    /// # fn main() {
    /// let request = SubscribeLogsRequest::new().select(H256::zero());
    /// # }
    /// ```
    /// This is the same as `at_block_hash`
    ///
    /// Match a range of blocks
    ///
    /// ```rust
    /// # use process_lib::eth::{SubscribeLogsRequest, H256};
    /// # fn main() {
    /// let request = SubscribeLogsRequest::new().select(0u64..100u64);
    /// # }
    /// ```
    ///
    /// Match all blocks in range `(1337..BlockNumber::Latest)`
    ///
    /// ```rust
    /// # use process_lib::eth::{SubscribeLogsRequest, H256};
    /// # fn main() {
    /// let request = SubscribeLogsRequest::new().select(1337u64..);
    /// # }
    /// ```
    ///
    /// Match all blocks in range `(BlockNumber::Earliest..1337)`
    ///
    /// ```rust
    /// # use process_lib::eth::{SubscribeLogsRequest, H256};
    /// # fn main() {
    /// let request = SubscribeLogsRequest::new().select(..1337u64);
    /// # }
    /// ```
    pub fn select(mut self, filter: impl Into<FilterBlockOption>) -> Self {
        self.filter = self.filter.select(filter);
        self
    }

    /// Matches starting from a specific block
    pub fn from_block<T: Into<BlockNumber>>(mut self, block: T) -> Self {
        self.filter = self.filter.from_block(block);
        self
    }

    /// Matches up until a specific block
    pub fn to_block<T: Into<BlockNumber>>(mut self, block: T) -> Self {
        self.filter = self.filter.to_block(block);
        self
    }

    /// Matches a for a specific block hash
    pub fn at_block_hash<T: Into<H256>>(mut self, hash: T) -> Self {
        self.filter = self.filter.at_block_hash(hash);
        self
    }

    /// Sets the SubscribeLogs filter object
    ///
    /// *NOTE:* ranges are always inclusive
    ///
    /// # Examples
    ///
    /// Match only a specific address `("0xAc4b3DacB91461209Ae9d41EC517c2B9Cb1B7DAF")`
    ///
    /// ```rust
    /// # use process_lib::eth::{SubscribeLogsRequest, Address};
    /// # fn main() {
    /// let filter = SubscribeLogsRequest::new().address("0xAc4b3DacB91461209Ae9d41EC517c2B9Cb1B7DAF".parse::<EthAddress>().unwrap());
    /// # }
    /// ```
    ///
    /// Match all addresses in array `(vec!["0xAc4b3DacB91461209Ae9d41EC517c2B9Cb1B7DAF",
    /// "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8"])`
    ///
    /// ```rust
    /// # use process_lib::eth::{SubscribeLogsRequest, EthAddress, ValueOrArray};
    /// # fn main() {
    /// let addresses = vec!["0xAc4b3DacB91461209Ae9d41EC517c2B9Cb1B7DAF".parse::<EthAddress>().unwrap(),"0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8".parse::<EthAddress>().unwrap()];
    /// let filter = SubscribeLogsRequest::new().address(addresses);
    /// # }
    /// ```
    pub fn address<T: Into<ValueOrArray<EthAddress>>>(mut self, address: T) -> Self {
        self.filter = self.filter.address(address);
        self
    }

    /// Given the event signature in string form, it hashes it and adds it to the topics to monitor
    pub fn event(mut self, event_name: &str) -> Self {
        self.filter = self.filter.event(event_name);
        self
    }

    /// Hashes all event signatures and sets them as array to topic0
    pub fn events(mut self, events: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Self {
        self.filter = self.filter.events(events);
        self
    }

    /// Sets topic0 (the event name for non-anonymous events)
    pub fn topic0<T: Into<Topic>>(mut self, topic: T) -> Self {
        self.filter = self.filter.topic0(topic);
        self
    }

    /// Sets the 1st indexed topic
    pub fn topic1<T: Into<Topic>>(mut self, topic: T) -> Self {
        self.filter = self.filter.topic1(topic);
        self
    }

    /// Sets the 2nd indexed topic
    pub fn topic2<T: Into<Topic>>(mut self, topic: T) -> Self {
        self.filter = self.filter.topic2(topic);
        self
    }

    /// Sets the 3rd indexed topic
    pub fn topic3<T: Into<Topic>>(mut self, topic: T) -> Self {
        self.filter = self.filter.topic3(topic);
        self
    }

    pub fn is_paginatable(&self) -> bool {
        self.filter.is_paginatable()
    }

    /// Returns the numeric value of the `toBlock` field
    pub fn get_to_block(&self) -> Option<U64> {
        self.filter.get_to_block()
    }
}
