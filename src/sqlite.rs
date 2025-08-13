use crate::PackageId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(not(feature = "hyperapp"))]
mod sqlite_sync;
#[cfg(not(feature = "hyperapp"))]
pub use sqlite_sync::{open, remove_db};

#[cfg(feature = "hyperapp")]
mod sqlite_async;
#[cfg(feature = "hyperapp")]
pub use sqlite_async::{open, remove_db};

/// Actions are sent to a specific SQLite database. `db` is the name,
/// `package_id` is the [`PackageId`] that created the database. Capabilities
/// are checked: you can access another process's database if it has given
/// you the read and/or write capability to do so.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SqliteRequest {
    pub package_id: PackageId,
    pub db: String,
    pub action: SqliteAction,
}

/// IPC Action format representing operations that can be performed on the
/// SQLite runtime module. These actions are included in a [`SqliteRequest`]
/// sent to the `sqlite:distro:sys` runtime module.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SqliteAction {
    /// Opens an existing key-value database or creates a new one if it doesn't exist.
    /// Requires `package_id` in [`SqliteRequest`] to match the package ID of the sender.
    /// The sender will own the database and can remove it with [`SqliteAction::RemoveDb`].
    ///
    /// A successful open will respond with [`SqliteResponse::Ok`]. Any error will be
    /// contained in the [`SqliteResponse::Err`] variant.
    Open,
    /// Permanently deletes the entire key-value database.
    /// Requires `package_id` in [`SqliteRequest`] to match the package ID of the sender.
    /// Only the owner can remove the database.
    ///
    /// A successful remove will respond with [`SqliteResponse::Ok`]. Any error will be
    /// contained in the [`SqliteResponse::Err`] variant.
    RemoveDb,
    /// Executes a write statement (INSERT/UPDATE/DELETE)
    ///
    /// * `statement` - SQL statement to execute
    /// * `tx_id` - Optional transaction ID
    /// * blob: Vec<SqlValue> - Parameters for the SQL statement, where SqlValue can be:
    ///   - null
    ///   - boolean
    ///   - i64
    ///   - f64
    ///   - String
    ///   - Vec<u8> (binary data)
    ///
    /// Using this action requires the sender to have the write capability
    /// for the database.
    ///
    /// A successful write will respond with [`SqliteResponse::Ok`]. Any error will be
    /// contained in the [`SqliteResponse::Err`] variant.
    Write {
        statement: String,
        tx_id: Option<u64>,
    },
    /// Executes a read query (SELECT)
    ///
    /// * blob: Vec<SqlValue> - Parameters for the SQL query, where SqlValue can be:
    ///   - null
    ///   - boolean
    ///   - i64
    ///   - f64
    ///   - String
    ///   - Vec<u8> (binary data)
    ///
    /// Using this action requires the sender to have the read capability
    /// for the database.
    ///
    /// A successful query will respond with [`SqliteResponse::Query`], where the
    /// response blob contains the results of the query. Any error will be contained
    /// in the [`SqliteResponse::Err`] variant.
    Query(String),
    /// Begins a new transaction for atomic operations.
    ///
    /// Sending this will prompt a [`SqliteResponse::BeginTx`] response with the
    /// transaction ID. Any error will be contained in the [`SqliteResponse::Err`] variant.
    BeginTx,
    /// Commits all operations in the specified transaction.
    ///
    /// # Parameters
    /// * `tx_id` - The ID of the transaction to commit
    ///
    /// A successful commit will respond with [`SqliteResponse::Ok`]. Any error will be
    /// contained in the [`SqliteResponse::Err`] variant.
    Commit { tx_id: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SqliteResponse {
    /// Indicates successful completion of an operation.
    /// Sent in response to actions Open, RemoveDb, Write, Query, BeginTx, and Commit.
    Ok,
    /// Returns the results of a query.
    ///
    /// * blob: Vec<Vec<SqlValue>> - Array of rows, where each row contains SqlValue types:
    ///   - null
    ///   - boolean
    ///   - i64
    ///   - f64
    ///   - String
    ///   - Vec<u8> (binary data)
    Read,
    /// Returns the transaction ID for a newly created transaction.
    ///
    /// # Fields
    /// * `tx_id` - The ID of the newly created transaction
    BeginTx { tx_id: u64 },
    /// Indicates an error occurred during the operation.
    Err(SqliteError),
}

/// Used in blobs to represent array row values in SQLite.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SqlValue {
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
    Boolean(bool),
    Null,
}

#[derive(Clone, Debug, Serialize, Deserialize, Error)]
pub enum SqliteError {
    #[error("db [{0}, {1}] does not exist")]
    NoDb(PackageId, String),
    #[error("no transaction {0} found")]
    NoTx(u64),
    #[error("no write capability for requested DB")]
    NoWriteCap,
    #[error("no read capability for requested DB")]
    NoReadCap,
    #[error("request to open or remove DB with mismatching package ID")]
    MismatchingPackageId,
    #[error("failed to generate capability for new DB")]
    AddCapFailed,
    #[error("write statement started with non-existent write keyword")]
    NotAWriteKeyword,
    #[error("read query started with non-existent read keyword")]
    NotAReadKeyword,
    #[error("parameters blob in read/write was misshapen or contained invalid JSON objects")]
    InvalidParameters,
    #[error("sqlite got a malformed request that failed to deserialize")]
    MalformedRequest,
    #[error("rusqlite error: {0}")]
    RusqliteError(String),
    #[error("IO error: {0}")]
    IOError(String),
}

/// The JSON parameters contained in all capabilities issued by `sqlite:distro:sys`.
///
/// # Fields
/// * `kind` - The kind of capability, either [`SqliteCapabilityKind::Read`] or [`SqliteCapabilityKind::Write`]
/// * `db_key` - The database key, a tuple of the [`PackageId`] that created the database and the database name
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SqliteCapabilityParams {
    pub kind: SqliteCapabilityKind,
    pub db_key: (PackageId, String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SqliteCapabilityKind {
    Read,
    Write,
}

/// Sqlite helper struct for a db.
/// Opening or creating a db will give you a `Result<Sqlite>`.
/// You can call it's impl functions to interact with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sqlite {
    pub package_id: PackageId,
    pub db: String,
    pub timeout: u64,
}
