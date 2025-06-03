use std::fmt;
use std::marker::PhantomData;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use crate::LazyLoadBlob;

/// `LazyLoadBlob` is defined in the wit bindings, but constructors and methods here.
/// A `LazyLoadBlob` is a piece of data that is only optionally loaded into a process
/// (i.e. with `get_blob()`). `LazyLoadBlob` is useful for passing large data in a chain
/// of [`crate::Request`]s or [`crate::Response`]s where intermediate processes in the
/// chain don't need to access the data. In this way, Hyperware saves time and compute
/// since the `LazyLoadBlob` is not sent back and forth across the Wasm boundary needlessly.
impl LazyLoadBlob {
    /// Create a new `LazyLoadBlob`. Takes a mime type and a byte vector.
    pub fn new<T, U>(mime: Option<T>, bytes: U) -> LazyLoadBlob
    where
        T: Into<String>,
        U: Into<Vec<u8>>,
    {
        LazyLoadBlob {
            mime: mime.map(|mime| mime.into()),
            bytes: bytes.into(),
        }
    }
    /// Read the mime type from a `LazyLoadBlob`.
    pub fn mime(&self) -> Option<&str> {
        self.mime.as_ref().map(|mime| mime.as_str())
    }
    /// Read the bytes from a `LazyLoadBlob`.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::default::Default for LazyLoadBlob {
    fn default() -> Self {
        LazyLoadBlob {
            mime: None,
            bytes: Vec::new(),
        }
    }
}

impl std::cmp::PartialEq for LazyLoadBlob {
    fn eq(&self, other: &Self) -> bool {
        self.mime == other.mime && self.bytes == other.bytes
    }
}

impl Serialize for LazyLoadBlob {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Create a struct with 2 fields
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("LazyLoadBlob", 2)?;

        // Serialize mime normally (serde handles Option automatically)
        state.serialize_field("mime", &self.mime)?;

        let base64_data = BASE64.encode(&self.bytes);
        state.serialize_field("bytes", &base64_data)?;

        state.end()
    }
}

// Custom visitor for deserialization
struct LazyLoadBlobVisitor {
    marker: PhantomData<fn() -> LazyLoadBlob>,
}

impl LazyLoadBlobVisitor {
    fn new() -> Self {
        LazyLoadBlobVisitor {
            marker: PhantomData,
        }
    }
}

impl<'de> Visitor<'de> for LazyLoadBlobVisitor {
    type Value = LazyLoadBlob;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a struct with mime and bytes fields")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: de::MapAccess<'de>,
    {
        let mut mime = None;
        let mut bytes_base64 = None;

        // Extract each field from the map
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "mime" => {
                    if mime.is_some() {
                        return Err(de::Error::duplicate_field("mime"));
                    }
                    mime = map.next_value()?;
                }
                "bytes" => {
                    if bytes_base64.is_some() {
                        return Err(de::Error::duplicate_field("bytes"));
                    }
                    bytes_base64 = Some(map.next_value::<String>()?);
                }
                _ => {
                    // Skip unknown fields
                    let _ = map.next_value::<de::IgnoredAny>()?;
                }
            }
        }

        let bytes_base64 = bytes_base64.ok_or_else(|| de::Error::missing_field("bytes"))?;

        let bytes = BASE64
            .decode(bytes_base64.as_bytes())
            .map_err(|err| de::Error::custom(format!("Invalid base64: {}", err)))?;

        Ok(LazyLoadBlob { mime, bytes })
    }
}

impl<'de> Deserialize<'de> for LazyLoadBlob {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "LazyLoadBlob",
            &["mime", "bytes"],
            LazyLoadBlobVisitor::new(),
        )
    }
}
