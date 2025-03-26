//! Hyperware process standard library for Rust compiled to Wasm
//! Must be used in context of bindings generated by `hyperware.wit`.
//!
//! This library provides a set of functions for interacting with the hyperware
//! kernel interface, which is a WIT file. The types generated by this file
//! are available in processes via the wit_bindgen macro, if a process needs
//! to use them directly. However, the most convenient way to do most things
//! will be via this library.
//!
//! We define wrappers over the wit bindings to make them easier to use.
//! This library encourages the use of IPC body and metadata types serialized and
//! deserialized to JSON, which is not optimal for performance, but useful
//! for applications that want to maximize composability and introspectability.
//! For blobs, we recommend bincode to serialize and deserialize to bytes.
//!
pub use crate::hyperware::process::standard::*;
use serde_json::Value;

wit_bindgen::generate!({
    path: "hyperware-wit",
    generate_unused_types: true,
    world: "lib",
});

/// Interact with the eth provider module.
pub mod eth;
/// High-level Ethereum utilities for common operations.
pub mod eth_utils;
/// Your process must have the [`Capability`] to message
/// `homepage:homepage:sys` to use this module.
pub mod homepage;
/// Interact with the HTTP server and client modules.
/// Contains types from the `http` crate to use as well.
///
/// Your process must have the [`Capability`] to message and receive messages from
/// `http-server:distro:sys` and/or `http-client:distro:sys` to use this module.
pub mod http;
/// Interact with hypermap, the onchain namespace
pub mod hypermap;
/// The types that the kernel itself uses -- warning -- these will
/// be incompatible with WIT types in some cases, leading to annoying errors.
/// Use only to interact with the kernel or runtime in certain ways.
pub mod kernel_types;
/// Tools for exploring and working with Token-Bound Accounts (TBAs) in Hypermap
//pub mod tba_explorer;
/// Interact with the key_value module
///
/// Your process must have the [`Capability`] to message and receive messages from
/// `kv:distro:sys` to use this module.
pub mod kv;
#[cfg(feature = "logging")]
pub mod logging;
/// Interact with the networking module
/// For configuration, debugging, and creating signatures with networking key.
///
/// Your process must have the [`Capability`] to message and receive messages from
/// `net:distro:sys` to use this module.
pub mod net;
/// Low-level Ethereum signing operations and key management.
pub mod signer;
/// Interact with the sqlite module
///
/// Your process must have the [`Capability] to message and receive messages from
/// `sqlite:distro:sys` to use this module.
pub mod sqlite;
/// Interact with the timer runtime module.
///
/// The `timer:distro:sys` module is public, so no special capabilities needed.
pub mod timer;
/// Interact with the virtual filesystem
///
/// Your process must have the [`Capability`] to message and receive messages from
/// `vfs:distro:sys` to use this module.
pub mod vfs;
/// Ethereum wallet management with transaction preparation and submission.
pub mod wallet;

/// A set of types and macros for writing "script" processes.
pub mod scripting;

mod types;
pub use types::{
    address::{Address, AddressParseError},
    capability::Capability,
    lazy_load_blob::LazyLoadBlob,
    message::{Message, _wit_message_to_message},
    on_exit::OnExit,
    package_id::PackageId,
    process_id::{ProcessId, ProcessIdParseError},
    request::Request,
    response::Response,
    send_error::{SendError, SendErrorKind, _wit_send_error_to_send_error},
};

/// Implement the wit-bindgen specific code that the kernel uses to hook into
/// a process. Write an `init(our: Address)` function and call it with this.
#[macro_export]
macro_rules! call_init {
    ($init_func:ident) => {
        struct Component;
        impl Guest for Component {
            fn init(our: String) {
                let our: Address = our.parse().unwrap();
                $init_func(our);
            }
        }
        export!(Component);
    };
}

/// Override the `println!` macro to print to the terminal.
/// Uses the `print_to_terminal` function from the WIT interface on maximally-verbose
/// mode, i.e., this print will always show up in the terminal. To control
/// the verbosity, use the `print_to_terminal` function directly.
#[macro_export]
macro_rules! println {
    () => {
        $crate::print_to_terminal(0, "\n");
    };
    ($($arg:tt)*) => {{
        $crate::print_to_terminal(0, &format!($($arg)*));
    }};
}

/// Uses the `print_to_terminal` function from the WIT interface on maximally-verbose
/// mode, i.e., this print will always show up in the terminal. To control
/// the verbosity, use the `print_to_terminal` function directly.
#[macro_export]
macro_rules! kiprintln {
    () => {
        $crate::print_to_terminal(0, "\n");
    };
    ($($arg:tt)*) => {{
        $crate::print_to_terminal(0, &format!($($arg)*));
    }};
}

/// Uses the `print_to_terminal` function from the WIT interface on maximally-verbose
/// mode, i.e., this print will always show up in the terminal. To control
/// the verbosity, use the `print_to_terminal` function directly.
///
/// This version of println prepends the name of the process, so developers can see
/// which process within a package is generating the print.
#[macro_export]
macro_rules! process_println {
    () => {
        let our = $crate::our();
        $crate::print_to_terminal(0, format!("{}: ", our.process()).as_str());
    };
    ($($arg:tt)*) => {{
        let our = $crate::our();
        $crate::print_to_terminal(0, format!("{}: {}", our.process(), format!($($arg)*)).as_str());
    }};
}

/// Await the next message sent to this process. The runtime will handle the
/// queueing of incoming messages, and calling this function will provide the next one.
/// Interwoven with incoming messages are errors from the network. If your process
/// attempts to send a message to another node, that message may bounce back with
/// a [`SendError`]. Those should be handled here.
///
/// Example:
/// ```no_run
/// use hyperware_process_lib::{await_message, println};
///
/// loop {
///     match await_message() {
///         Ok(msg) => {
///             println!("Received message: {:?}", msg);
///             // Do something with the message
///         }
///         Err(send_error) => {
///             println!("Error sending message: {:?}", send_error);
///         }
///     }
/// }
/// ```
pub fn await_message() -> Result<Message, SendError> {
    match crate::receive() {
        Ok((source, message)) => Ok(_wit_message_to_message(source, message)),
        Err((send_err, context)) => Err(_wit_send_error_to_send_error(send_err, context)),
    }
}

/// Get the next message body from the message queue, or propagate the error.
pub fn await_next_message_body() -> Result<Vec<u8>, SendError> {
    match await_message() {
        Ok(msg) => Ok(msg.body().to_vec()),
        Err(e) => Err(e.into()),
    }
}

/// Spawn a new process. This function is a wrapper around the standard `spawn()` function
/// provided in `hyperware::process::standard` (which is generated by the WIT file).
pub fn spawn(
    name: Option<&str>,
    wasm_path: &str,
    on_exit: OnExit,
    request_capabilities: Vec<Capability>,
    grant_capabilities: Vec<(ProcessId, Json)>,
    public: bool,
) -> Result<ProcessId, SpawnError> {
    crate::hyperware::process::standard::spawn(
        name,
        wasm_path,
        &on_exit._to_standard().map_err(|_e| SpawnError::NameTaken)?,
        &request_capabilities,
        &grant_capabilities,
        public,
    )
}

/// Create a blob with no MIME type and a generic type, plus a serializer
/// function that turns that type into bytes.
///
/// Example usage:
/// ```no_run
/// use hyperware_process_lib::make_blob;
/// use bincode;
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MyType {
///    field: std::collections::HashMap<String, String>,
///    field_two: std::collections::HashSet<String>,
/// }
///
/// let my_type = MyType {
///    field: std::collections::HashMap::new(),
///    field_two: std::collections::HashSet::new(),
/// };
///
/// make_blob(&my_type, |t| Ok(bincode::serialize(t)?));
/// ```
pub fn make_blob<T, F, E>(blob: &T, serializer: F) -> Result<LazyLoadBlob, E>
where
    F: Fn(&T) -> Result<Vec<u8>, E>,
    E: std::error::Error,
{
    Ok(LazyLoadBlob {
        mime: None,
        bytes: serializer(blob)?,
    })
}

/// Fetch the blob of the most recent message we've received. Returns `None`
/// if that message had no blob. If it does have one, attempt to deserialize
/// it from bytes with the provided function.
///
/// Example:
/// ```no_run
/// use std::collections::{HashMap, HashSet};
/// use hyperware_process_lib::get_typed_blob;
/// use bincode;
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MyType {
///   field: HashMap<String, String>,
///   field_two: HashSet<String>,
/// }
///
/// get_typed_blob(|bytes| bincode::deserialize(bytes)).unwrap_or(MyType {
///     field: HashMap::new(),
///     field_two: HashSet::new(),
/// });
/// ```
pub fn get_typed_blob<T, F, E>(deserializer: F) -> Option<T>
where
    F: Fn(&[u8]) -> Result<T, E>,
    E: std::error::Error,
{
    match crate::get_blob() {
        Some(blob) => match deserializer(&blob.bytes) {
            Ok(thing) => Some(thing),
            Err(_) => None,
        },
        None => None,
    }
}

/// Fetch the persisted state blob associated with this process. This blob is saved
/// using the [`set_state()`] function. Returns `None` if this process has no saved state.
/// If it does, attempt to deserialize it from bytes with the provided function.
///
/// Example:
/// ```no_run
/// use std::collections::{HashMap, HashSet};
/// use hyperware_process_lib::get_typed_state;
/// use bincode;
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MyStateType {
///    field: HashMap<String, String>,
///    field_two: HashSet<String>,
/// }
///
/// get_typed_state(|bytes| bincode::deserialize(bytes)).unwrap_or(MyStateType {
///     field: HashMap::new(),
///     field_two: HashSet::new(),
/// });
/// ```
pub fn get_typed_state<T, F, E>(deserializer: F) -> Option<T>
where
    F: Fn(&[u8]) -> Result<T, E>,
    E: std::error::Error,
{
    match crate::get_state() {
        Some(bytes) => match deserializer(&bytes) {
            Ok(thing) => Some(thing),
            Err(_) => None,
        },
        None => None,
    }
}

/// See if we have the [`Capability`] to message a certain process.
/// Note if you have not saved the [`Capability`], you will not be able to message the other process.
pub fn can_message(address: &Address) -> bool {
    crate::our_capabilities()
        .iter()
        .any(|cap| cap.params == "\"messaging\"" && cap.issuer == *address)
}

/// Get a [`Capability`] in our store
pub fn get_capability(issuer: &Address, params: &str) -> Option<Capability> {
    let params = serde_json::from_str::<Value>(params).unwrap_or_default();
    crate::our_capabilities().into_iter().find(|cap| {
        let cap_params = serde_json::from_str::<Value>(&cap.params).unwrap_or_default();
        cap.issuer == *issuer && params == cap_params
    })
}

/// The `Spawn!()` macro is defined here as a no-op.
/// However, in practice, `kit build` will rewrite it during pre-processing.
///
/// Examples:
/// ```no_run
/// fn init(our: Address) {
///     let parent = our.clone();
///     Spawn!(|parent: Address| {
///         println!("hello from {our}. I am Spawn of {parent}!");
///     });
///     ...
/// }
/// ```
/// will be rewritten by `kit build` to:
/// 1. Generate a new child process within the package that, here, `println!()`s,
///    or, in general, executes the code given by the closure.
/// 2. Replace the code lines in the parent process with [`spawn()`] to start
///    the generated child and send a [`Request()`] to pass in the closure's args.
/// 3. Update the relevant metadata for the package
///    (i.e. `Cargo.toml`, `metadata.json`, etc.).
///
/// More example usage:
///
/// Can pass function call rather than closure:
/// ```no_run
/// fn init(our: Address) {
///     let parent = our.clone();
///     Spawn!(my_function(parent));
///     ...
/// }
/// ```
/// Nested function calls work as expected.
///
/// Can optionally supply subset of [`spawn()`] arguments, namely
/// * name: &str,
/// * on_exit: [`OnExit`],
/// * request_capabilities: Vec<[`Capability`]>,
/// * grant_capabilities: Vec<[`ProcessId`]>,
/// * public: bool,
/// for example:
/// ```no_run
/// fn init(our: Address) {
///     let parent = our.clone();
///     Spawn!(my_function(parent), name: "hello-world", public: true);
///     ...
/// }
/// ```
#[macro_export]
macro_rules! Spawn {
    // Pattern 1: Closure with type-annotated paramters & with no options
    (|$($param:ident : $type:ty),+ $(,)?| $body:block) => {};

    // Pattern 2: Function call with no options
    ($fn_name:ident($($arg:expr),* $(,)?)) => {};

    // Pattern 3: Closure with type-annotated paramters & with options
    (
        |$($param:ident : $type:ty),+ $(,)?| $body:block,
        $(
            $key:ident : $value:expr
            $(,)?
        )*
    ) => {{
        // Validate each key at compile time using nested macro
        $crate::validate_spawn_args!($($key),*);

        // Your implementation here
    }};

    // Pattern 4: Function call with options
    (
        $fn_name:ident($($arg:expr),* $(,)?),
        $(
            $key:ident : $value:expr
            $(,)?
        )*
    ) => {{
        // Validate each key at compile time using nested macro
        $crate::validate_spawn_args!($($key),*);

        // Your implementation here
    }};
}

#[macro_export]
macro_rules! validate_spawn_args {
    // Empty case - no args to validate
    () => {};

    // Validate single argument
    (name) => {};
    (on_exit) => {};
    (request_capabilities) => {};
    (grant_capabilities) => {};
    (public) => {};

    // Recursively validate multiple arguments
    ($first:ident, $($rest:ident),+ $(,)?) => {
        validate_spawn_args!($first);
        validate_spawn_args!($($rest),+);
    };

    // Error case - invalid argument name
    ($invalid:ident $(, $($rest:tt)*)?) => {
        compile_error!(concat!(
            "Invalid Spawn argument '",
            stringify!($invalid),
            "'. Valid options are: name, on_exit, request_capabilities, grant_capabilities, public"
        ));
    };
}
