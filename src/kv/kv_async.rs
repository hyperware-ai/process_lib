use crate::{
    get_blob, hyperapp,
    kv::{Kv, KvAction, KvRequest, KvResponse},
    PackageId, Request,
};
use serde::{de::DeserializeOwned, Serialize};
use std::marker::PhantomData;

impl<K, V> Kv<K, V>
where
    K: Serialize + DeserializeOwned,
    V: Serialize + DeserializeOwned,
{
    /// Get a value.
    pub async fn get(&self, key: &K) -> anyhow::Result<V> {
        let key = serde_json::to_vec(key)?;
        let request = Request::new()
            .target(("our", "kv", "distro", "sys"))
            .body(serde_json::to_vec(&KvRequest {
                package_id: self.package_id.clone(),
                db: self.db.clone(),
                action: KvAction::Get(key),
            })?)
            .expects_response(self.timeout);

        let response = hyperapp::send::<KvResponse>(request).await?;

        match response {
            KvResponse::Get { .. } => {
                let bytes = match get_blob() {
                    Some(bytes) => bytes.bytes,
                    None => return Err(anyhow::anyhow!("kv: no blob")),
                };
                let value = serde_json::from_slice::<V>(&bytes)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize value: {}", e))?;
                Ok(value)
            }
            KvResponse::Err(error) => Err(error.into()),
            _ => Err(anyhow::anyhow!("kv: unexpected response")),
        }
    }

    /// Get a value as a different type T
    pub async fn get_as<T>(&self, key: &K) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
    {
        let key = serde_json::to_vec(key)?;
        let request = Request::new()
            .target(("our", "kv", "distro", "sys"))
            .body(serde_json::to_vec(&KvRequest {
                package_id: self.package_id.clone(),
                db: self.db.clone(),
                action: KvAction::Get(key),
            })?)
            .expects_response(self.timeout);

        let response = hyperapp::send::<KvResponse>(request).await?;

        match response {
            KvResponse::Get { .. } => {
                let bytes = match get_blob() {
                    Some(bytes) => bytes.bytes,
                    None => return Err(anyhow::anyhow!("kv: no blob")),
                };
                let value = serde_json::from_slice::<T>(&bytes)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize value: {}", e))?;
                Ok(value)
            }
            KvResponse::Err(error) => Err(error.into()),
            _ => Err(anyhow::anyhow!("kv: unexpected response")),
        }
    }

    /// Set a value, optionally in a transaction.
    pub async fn set(&self, key: &K, value: &V, tx_id: Option<u64>) -> anyhow::Result<()> {
        let key = serde_json::to_vec(key)?;
        let value = serde_json::to_vec(value)?;
        let request = Request::new()
            .target(("our", "kv", "distro", "sys"))
            .body(serde_json::to_vec(&KvRequest {
                package_id: self.package_id.clone(),
                db: self.db.clone(),
                action: KvAction::Set { key, tx_id },
            })?)
            .blob_bytes(value)
            .expects_response(self.timeout);

        let response = hyperapp::send::<KvResponse>(request).await?;

        match response {
            KvResponse::Ok => Ok(()),
            KvResponse::Err(error) => Err(error.into()),
            _ => Err(anyhow::anyhow!("kv: unexpected response")),
        }
    }

    /// Set a value as a different type T
    pub async fn set_as<T>(&self, key: &K, value: &T, tx_id: Option<u64>) -> anyhow::Result<()>
    where
        T: Serialize,
    {
        let key = serde_json::to_vec(key)?;
        let value = serde_json::to_vec(value)?;
        let request = Request::new()
            .target(("our", "kv", "distro", "sys"))
            .body(serde_json::to_vec(&KvRequest {
                package_id: self.package_id.clone(),
                db: self.db.clone(),
                action: KvAction::Set { key, tx_id },
            })?)
            .blob_bytes(value)
            .expects_response(self.timeout);

        let response = hyperapp::send::<KvResponse>(request).await?;

        match response {
            KvResponse::Ok => Ok(()),
            KvResponse::Err(error) => Err(error.into()),
            _ => Err(anyhow::anyhow!("kv: unexpected response")),
        }
    }

    /// Delete a value, optionally in a transaction.
    pub async fn delete(&self, key: &K, tx_id: Option<u64>) -> anyhow::Result<()> {
        let key = serde_json::to_vec(key)?;
        let request = Request::new()
            .target(("our", "kv", "distro", "sys"))
            .body(serde_json::to_vec(&KvRequest {
                package_id: self.package_id.clone(),
                db: self.db.clone(),
                action: KvAction::Delete { key, tx_id },
            })?)
            .expects_response(self.timeout);

        let response = hyperapp::send::<KvResponse>(request).await?;

        match response {
            KvResponse::Ok => Ok(()),
            KvResponse::Err(error) => Err(error.into()),
            _ => Err(anyhow::anyhow!("kv: unexpected response")),
        }
    }

    /// Delete a value with a different key type
    pub async fn delete_as<T>(&self, key: &T, tx_id: Option<u64>) -> anyhow::Result<()>
    where
        T: Serialize,
    {
        let key = serde_json::to_vec(key)?;
        let request = Request::new()
            .target(("our", "kv", "distro", "sys"))
            .body(serde_json::to_vec(&KvRequest {
                package_id: self.package_id.clone(),
                db: self.db.clone(),
                action: KvAction::Delete { key, tx_id },
            })?)
            .expects_response(self.timeout);

        let response = hyperapp::send::<KvResponse>(request).await?;

        match response {
            KvResponse::Ok => Ok(()),
            KvResponse::Err(error) => Err(error.into()),
            _ => Err(anyhow::anyhow!("kv: unexpected response")),
        }
    }

    /// Begin a transaction.
    pub async fn begin_tx(&self) -> anyhow::Result<u64> {
        let request = Request::new()
            .target(("our", "kv", "distro", "sys"))
            .body(serde_json::to_vec(&KvRequest {
                package_id: self.package_id.clone(),
                db: self.db.clone(),
                action: KvAction::BeginTx,
            })?)
            .expects_response(self.timeout);

        let response = hyperapp::send::<KvResponse>(request).await?;

        match response {
            KvResponse::BeginTx { tx_id } => Ok(tx_id),
            KvResponse::Err(error) => Err(error.into()),
            _ => Err(anyhow::anyhow!("kv: unexpected response")),
        }
    }
}

/// Removes and deletes a kv db.
pub async fn remove_db(
    package_id: PackageId,
    db: &str,
    timeout: Option<u64>,
) -> anyhow::Result<()> {
    let timeout = timeout.unwrap_or(5);

    let request = Request::new()
        .target(("our", "kv", "distro", "sys"))
        .body(serde_json::to_vec(&KvRequest {
            package_id: package_id.clone(),
            db: db.to_string(),
            action: KvAction::RemoveDb,
        })?)
        .expects_response(timeout);

    let response = hyperapp::send::<KvResponse>(request).await?;

    match response {
        KvResponse::Ok => Ok(()),
        KvResponse::Err(error) => Err(error.into()),
        _ => Err(anyhow::anyhow!("kv: unexpected response")),
    }
}

/// Helper function to open a raw bytes key-value store
pub async fn open_raw(
    package_id: PackageId,
    db: &str,
    timeout: Option<u64>,
) -> anyhow::Result<Kv<Vec<u8>, Vec<u8>>> {
    open(package_id, db, timeout).await
}

/// Opens or creates a kv db.
pub async fn open<K, V>(
    package_id: PackageId,
    db: &str,
    timeout: Option<u64>,
) -> anyhow::Result<Kv<K, V>>
where
    K: Serialize + DeserializeOwned,
    V: Serialize + DeserializeOwned,
{
    let timeout = timeout.unwrap_or(5);

    let request = Request::new()
        .target(("our", "kv", "distro", "sys"))
        .body(serde_json::to_vec(&KvRequest {
            package_id: package_id.clone(),
            db: db.to_string(),
            action: KvAction::Open,
        })?)
        .expects_response(timeout);

    let response = hyperapp::send::<KvResponse>(request).await?;

    match response {
        KvResponse::Ok => Ok(Kv {
            package_id,
            db: db.to_string(),
            timeout,
            _marker: PhantomData,
        }),
        KvResponse::Err(error) => Err(error.into()),
        _ => Err(anyhow::anyhow!("kv: unexpected response")),
    }
}
