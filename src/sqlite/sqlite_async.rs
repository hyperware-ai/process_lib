use crate::{
    get_blob, hyperapp,
    sqlite::{Sqlite, SqliteAction, SqliteError, SqliteRequest, SqliteResponse},
    PackageId, Request,
};
use std::collections::HashMap;

impl Sqlite {
    /// Query database. Only allows sqlite read keywords.
    pub async fn read(
        &self,
        query: String,
        params: Vec<serde_json::Value>,
    ) -> anyhow::Result<Vec<HashMap<String, serde_json::Value>>> {
        let request = Request::new()
            .target(("our", "sqlite", "distro", "sys"))
            .body(serde_json::to_vec(&SqliteRequest {
                package_id: self.package_id.clone(),
                db: self.db.clone(),
                action: SqliteAction::Query(query),
            })?)
            .blob_bytes(serde_json::to_vec(&params)?)
            .expects_response(self.timeout);

        let response = hyperapp::send::<SqliteResponse>(request).await?;

        match response {
            SqliteResponse::Read => {
                let blob = get_blob().ok_or_else(|| SqliteError::MalformedRequest)?;
                let values =
                    serde_json::from_slice::<Vec<HashMap<String, serde_json::Value>>>(&blob.bytes)
                        .map_err(|_| SqliteError::MalformedRequest)?;
                Ok(values)
            }
            SqliteResponse::Err(error) => Err(error.into()),
            _ => Err(anyhow::anyhow!(
                "sqlite: unexpected response {:?}",
                response
            )),
        }
    }

    /// Execute a statement. Only allows sqlite write keywords.
    pub async fn write(
        &self,
        statement: String,
        params: Vec<serde_json::Value>,
        tx_id: Option<u64>,
    ) -> anyhow::Result<()> {
        let request = Request::new()
            .target(("our", "sqlite", "distro", "sys"))
            .body(serde_json::to_vec(&SqliteRequest {
                package_id: self.package_id.clone(),
                db: self.db.clone(),
                action: SqliteAction::Write { statement, tx_id },
            })?)
            .blob_bytes(serde_json::to_vec(&params)?)
            .expects_response(self.timeout);

        let response = hyperapp::send::<SqliteResponse>(request).await?;

        match response {
            SqliteResponse::Ok => Ok(()),
            SqliteResponse::Err(error) => Err(error.into()),
            _ => Err(anyhow::anyhow!(
                "sqlite: unexpected response {:?}",
                response
            )),
        }
    }

    /// Begin a transaction.
    pub async fn begin_tx(&self) -> anyhow::Result<u64> {
        let request = Request::new()
            .target(("our", "sqlite", "distro", "sys"))
            .body(serde_json::to_vec(&SqliteRequest {
                package_id: self.package_id.clone(),
                db: self.db.clone(),
                action: SqliteAction::BeginTx,
            })?)
            .expects_response(self.timeout);

        let response = hyperapp::send::<SqliteResponse>(request).await?;

        match response {
            SqliteResponse::BeginTx { tx_id } => Ok(tx_id),
            SqliteResponse::Err(error) => Err(error.into()),
            _ => Err(anyhow::anyhow!(
                "sqlite: unexpected response {:?}",
                response
            )),
        }
    }

    /// Commit a transaction.
    pub async fn commit_tx(&self, tx_id: u64) -> anyhow::Result<()> {
        let request = Request::new()
            .target(("our", "sqlite", "distro", "sys"))
            .body(serde_json::to_vec(&SqliteRequest {
                package_id: self.package_id.clone(),
                db: self.db.clone(),
                action: SqliteAction::Commit { tx_id },
            })?)
            .expects_response(self.timeout);

        let response = hyperapp::send::<SqliteResponse>(request).await?;

        match response {
            SqliteResponse::Ok => Ok(()),
            SqliteResponse::Err(error) => Err(error.into()),
            _ => Err(anyhow::anyhow!(
                "sqlite: unexpected response {:?}",
                response
            )),
        }
    }
}

/// Open or create sqlite database.
pub async fn open(package_id: PackageId, db: &str, timeout: Option<u64>) -> anyhow::Result<Sqlite> {
    let timeout = timeout.unwrap_or(5);

    let request = Request::new()
        .target(("our", "sqlite", "distro", "sys"))
        .body(serde_json::to_vec(&SqliteRequest {
            package_id: package_id.clone(),
            db: db.to_string(),
            action: SqliteAction::Open,
        })?)
        .expects_response(timeout);

    let response = hyperapp::send::<SqliteResponse>(request).await?;

    match response {
        SqliteResponse::Ok => Ok(Sqlite {
            package_id,
            db: db.to_string(),
            timeout,
        }),
        SqliteResponse::Err(error) => Err(error.into()),
        _ => Err(anyhow::anyhow!(
            "sqlite: unexpected response {:?}",
            response
        )),
    }
}

/// Remove and delete sqlite database.
pub async fn remove_db(
    package_id: PackageId,
    db: &str,
    timeout: Option<u64>,
) -> anyhow::Result<()> {
    let timeout = timeout.unwrap_or(5);

    let request = Request::new()
        .target(("our", "sqlite", "distro", "sys"))
        .body(serde_json::to_vec(&SqliteRequest {
            package_id: package_id.clone(),
            db: db.to_string(),
            action: SqliteAction::RemoveDb,
        })?)
        .expects_response(timeout);

    let response = hyperapp::send::<SqliteResponse>(request).await?;

    match response {
        SqliteResponse::Ok => Ok(()),
        SqliteResponse::Err(error) => Err(error.into()),
        _ => Err(anyhow::anyhow!(
            "sqlite: unexpected response {:?}",
            response
        )),
    }
}
