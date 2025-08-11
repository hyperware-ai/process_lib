use crate::{LazyLoadBlob as KiBlob, Request as KiRequest, Response as KiResponse};
pub use http::StatusCode;
use http::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[cfg(not(feature = "hyperapp"))]
mod server_sync;
#[cfg(feature = "hyperapp")]
mod server_async;

/// [`crate::Request`] received from the `http-server:distro:sys` service as a
/// result of either an HTTP or WebSocket binding, created via [`HttpServerAction`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HttpServerRequest {
    Http(IncomingHttpRequest),
    /// Processes will receive this kind of request when a client connects to them.
    /// If a process does not want this websocket open, they should issue a [`crate::Request`]
    /// containing a [`HttpServerAction::WebSocketClose`] message and this channel ID.
    WebSocketOpen {
        path: String,
        channel_id: u32,
    },
    /// Processes can both SEND and RECEIVE this kind of [`crate::Request`]
    /// (send as [`HttpServerAction::WebSocketPush`]).
    /// When received, will contain the message bytes as [`crate::LazyLoadBlob`].
    WebSocketPush {
        channel_id: u32,
        message_type: WsMessageType,
    },
    /// Receiving will indicate that the client closed the socket. Can be sent to close
    /// from the server-side, as [`type@HttpServerAction::WebSocketClose`].
    WebSocketClose(u32),
}

impl HttpServerRequest {
    /// Parse a byte slice into an [`HttpServerRequest`].
    pub fn from_bytes(bytes: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(bytes)
    }

    /// Filter the general-purpose [`HttpServerRequest`], which contains HTTP requests
    /// and WebSocket messages, into just the HTTP request. Consumes the original request
    /// and returns `None` if the request was WebSocket-related.
    pub fn request(self) -> Option<IncomingHttpRequest> {
        match self {
            HttpServerRequest::Http(req) => Some(req),
            _ => None,
        }
    }
}

/// An HTTP request routed to a process as a result of a binding.
///
/// BODY is stored in the lazy_load_blob, as bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncomingHttpRequest {
    /// will parse to [`std::net::SocketAddr`]
    source_socket_addr: Option<String>,
    /// will parse to [`http::Method`]
    method: String,
    /// will parse to [`url::Url`]
    url: String,
    /// the matching path that was bound
    bound_path: String,
    /// will parse to [`http::HeaderMap`]
    headers: HashMap<String, String>,
    url_params: HashMap<String, String>,
    query_params: HashMap<String, String>,
}

impl IncomingHttpRequest {
    pub fn url(&self) -> Result<url::Url, url::ParseError> {
        url::Url::parse(&self.url)
    }

    pub fn method(&self) -> Result<http::Method, http::method::InvalidMethod> {
        http::Method::from_bytes(self.method.as_bytes())
    }

    pub fn source_socket_addr(&self) -> Result<std::net::SocketAddr, std::net::AddrParseError> {
        match &self.source_socket_addr {
            Some(addr) => addr.parse(),
            None => "".parse(),
        }
    }

    /// Returns the path that was originally bound, with an optional prefix stripped.
    /// The prefix would normally be the process ID as a &str, but it could be anything.
    pub fn bound_path(&self, process_id_to_strip: Option<&str>) -> &str {
        match process_id_to_strip {
            Some(process_id) => self
                .bound_path
                .strip_prefix(&format!("/{}", process_id))
                .unwrap_or(&self.bound_path),
            None => &self.bound_path,
        }
    }

    pub fn path(&self) -> Result<String, url::ParseError> {
        let url = url::Url::parse(&self.url)?;
        // skip the first path segment, which is the process ID.
        let Some(path) = url.path_segments() else {
            return Err(url::ParseError::InvalidDomainCharacter);
        };
        let path = path.skip(1).collect::<Vec<&str>>().join("/");
        Ok(format!("/{}", path))
    }

    pub fn headers(&self) -> HeaderMap {
        let mut header_map = HeaderMap::new();
        for (key, value) in self.headers.iter() {
            let key_bytes = key.as_bytes();
            let Ok(key_name) = HeaderName::from_bytes(key_bytes) else {
                continue;
            };
            let Ok(value_header) = HeaderValue::from_str(&value) else {
                continue;
            };
            header_map.insert(key_name, value_header);
        }
        header_map
    }

    pub fn url_params(&self) -> &HashMap<String, String> {
        &self.url_params
    }

    pub fn query_params(&self) -> &HashMap<String, String> {
        &self.query_params
    }
}

/// The possible message types for [`HttpServerRequest::WebSocketPush`].
/// Ping and Pong are limited to 125 bytes by the WebSockets protocol.
/// Text will be sent as a Text frame, with the [`crate::LazyLoadBlob`] bytes
/// being the UTF-8 encoding of the string. Binary will be sent as a
/// Binary frame containing the unmodified [`crate::LazyLoadBlob`] bytes.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum WsMessageType {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
}

/// [`crate::Request`] type sent to `http-server:distro:sys` in order to configure it.
///
/// If a [`crate::Response`] is expected, all actions will return a [`crate::Response`]
/// with the shape `Result<(), HttpServerActionError>` serialized to JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HttpServerAction {
    /// Bind expects a [`crate::LazyLoadBlob`] if and only if `cache` is TRUE.
    /// The [`crate::LazyLoadBlob`] should be the static file to serve at this path.
    Bind {
        path: String,
        /// Set whether the HTTP request needs a valid login cookie, AKA, whether
        /// the user needs to be logged in to access this path.
        authenticated: bool,
        /// Set whether [`crate::Request`]s can be fielded from anywhere, or only the loopback address.
        local_only: bool,
        /// Set whether to bind the [`crate::LazyLoadBlob`] statically to this path. That is, take the
        /// [`crate::LazyLoadBlob`] bytes and serve them as the response to any request to this path.
        cache: bool,
    },
    /// SecureBind expects a [`crate::LazyLoadBlob`] if and only if `cache` is TRUE. The [`crate::LazyLoadBlob`] should
    /// be the static file to serve at this path.
    ///
    /// SecureBind is the same as Bind, except that it forces requests to be made from
    /// the unique subdomain of the process that bound the path. These requests are
    /// *always* authenticated, and *never* local_only. The purpose of SecureBind is to
    /// serve elements of an app frontend or API in an exclusive manner, such that other
    /// apps installed on this node cannot access them. Since the subdomain is unique, it
    /// will require the user to be logged in separately to the general domain authentication.
    SecureBind {
        path: String,
        /// Set whether to bind the [`crate::LazyLoadBlob`] statically to this path. That is, take the
        /// [`crate::LazyLoadBlob`] bytes and serve them as the response to any request to this path.
        cache: bool,
    },
    /// Unbind a previously-bound HTTP path
    Unbind { path: String },
    /// Bind a path to receive incoming WebSocket connections.
    /// Doesn't need a cache since does not serve assets.
    WebSocketBind {
        path: String,
        authenticated: bool,
        extension: bool,
    },
    /// SecureBind is the same as Bind, except that it forces new connections to be made
    /// from the unique subdomain of the process that bound the path. These are *always*
    /// authenticated. Since the subdomain is unique, it will require the user to be
    /// logged in separately to the general domain authentication.
    WebSocketSecureBind { path: String, extension: bool },
    /// Unbind a previously-bound WebSocket path
    WebSocketUnbind { path: String },
    /// When sent, expects a [`crate::LazyLoadBlob`] containing the WebSocket message bytes to send.
    WebSocketPush {
        channel_id: u32,
        message_type: WsMessageType,
    },
    /// When sent, expects a [`crate::LazyLoadBlob`] containing the WebSocket message bytes to send.
    /// Modifies the [`crate::LazyLoadBlob`] by placing into [`HttpServerAction::WebSocketExtPushData`]` with id taken from
    /// this [`KernelMessage`]` and `hyperware_message_type` set to `desired_reply_type`.
    WebSocketExtPushOutgoing {
        channel_id: u32,
        message_type: WsMessageType,
        desired_reply_type: MessageType,
    },
    /// For communicating with the ext.
    /// Hyperware's http-server sends this to the ext after receiving [`HttpServerAction::WebSocketExtPushOutgoing`].
    /// Upon receiving reply with this type from ext, http-server parses, setting:
    /// * id as given,
    /// * message type as given ([`crate::Request`] or [`crate::Response`]),
    /// * body as [`HttpServerRequest::WebSocketPush`],
    /// * [`crate::LazyLoadBlob`] as given.
    WebSocketExtPushData {
        id: u64,
        hyperware_message_type: MessageType,
        blob: Vec<u8>,
    },
    /// Sending will close a socket the process controls.
    WebSocketClose(u32),
}

/// HTTP Response type that can be shared over Wasm boundary to apps.
/// Respond to [`IncomingHttpRequest`] with this type.
///
/// BODY is stored in the [`crate::LazyLoadBlob`] as bytes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
}

impl HttpResponse {
    pub fn new<T>(status: T) -> Self
    where
        T: Into<u16>,
    {
        Self {
            status: status.into(),
            headers: HashMap::new(),
        }
    }

    pub fn set_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    pub fn header<T, U>(mut self, key: T, value: U) -> Self
    where
        T: Into<String>,
        U: Into<String>,
    {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn set_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }
}

/// Part of the [`crate::Response`] type issued by http-server
#[derive(Clone, Debug, Error, Serialize, Deserialize)]
pub enum HttpServerError {
    #[error("request could not be deserialized to valid HttpServerRequest")]
    MalformedRequest,
    #[error("action expected blob")]
    NoBlob,
    #[error("path binding error: invalid source process")]
    InvalidSourceProcess,
    #[error("WebSocket error: ping/pong message too long")]
    WsPingPongTooLong,
    #[error("WebSocket error: channel not found")]
    WsChannelNotFound,
    /// Not actually issued by `http-server:distro:sys`, just this library
    #[error("timeout")]
    Timeout,
    /// Not actually issued by `http-server:distro:sys`, just this library
    #[error("unexpected response from http-server")]
    UnexpectedResponse,
}

/// Whether the [`HttpServerAction::WebSocketPush`] is [`crate::Request`] or [`crate::Response`].
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum MessageType {
    Request,
    Response,
}

/// A representation of the HTTP server as configured by your process.
#[derive(Clone, Debug)]
pub struct HttpServer {
    pub(crate) http_paths: HashMap<String, HttpBindingConfig>,
    pub(crate) ws_paths: HashMap<String, WsBindingConfig>,
    /// A mapping of WebSocket paths to the channels that are open on them.
    pub(crate) ws_channels: HashMap<String, HashSet<u32>>,
    /// The timeout given for `http-server:distro:sys` to respond to a configuration request.
    pub timeout: u64,
}

/// Configuration for a HTTP binding.
///
/// `authenticated` is set to true by default and means that the HTTP server will
/// require a valid login cookie to access this path.
///
/// `local_only` is set to false by default and means that the HTTP server will
/// only accept requests from the loopback address.
///
/// If `static_content` is set, the HTTP server will serve the static content at the
/// given path. Otherwise, the HTTP server will forward requests on this path to the
/// calling process.
///
/// If `secure_subdomain` is set, the HTTP server will serve requests on this path
/// from the unique subdomain of the process that bound the path. These requests are
/// *always* authenticated, and *never* local_only. The purpose of SecureBind is to
/// serve elements of an app frontend or API in an exclusive manner, such that other
/// apps installed on this node cannot access them. Since the subdomain is unique, it
/// will require the user to be logged in separately to the general domain authentication.
#[derive(Clone, Debug)]
pub struct HttpBindingConfig {
    pub(crate) authenticated: bool,
    pub(crate) local_only: bool,
    pub(crate) secure_subdomain: bool,
    pub(crate) static_content: Option<KiBlob>,
}

impl HttpBindingConfig {
    /// Create a new HttpBindingConfig with default values.
    ///
    /// Authenticated, not local only, not a secure subdomain, no static content.
    pub fn default() -> Self {
        Self {
            authenticated: true,
            local_only: false,
            secure_subdomain: false,
            static_content: None,
        }
    }

    /// Create a new HttpBindingConfig with the given values.
    pub fn new(
        authenticated: bool,
        local_only: bool,
        secure_subdomain: bool,
        static_content: Option<KiBlob>,
    ) -> Self {
        Self {
            authenticated,
            local_only,
            secure_subdomain,
            static_content,
        }
    }

    /// Set whether the HTTP server will require a valid login cookie to access this path.
    pub fn authenticated(mut self, authenticated: bool) -> Self {
        self.authenticated = authenticated;
        self
    }

    /// Set whether the HTTP server will only accept requests from the loopback address.
    pub fn local_only(mut self, local_only: bool) -> Self {
        self.local_only = local_only;
        self
    }

    /// Set whether the HTTP server will serve requests on this path from the unique
    /// subdomain of the process that bound the path. These requests are *always*
    /// authenticated, and *never* local_only. The purpose of SecureBind is to
    /// serve elements of an app frontend or API in an exclusive manner, such that other
    /// apps installed on this node cannot access them. Since the subdomain is unique, it
    /// will require the user to be logged in separately to the general domain authentication.
    pub fn secure_subdomain(mut self, secure_subdomain: bool) -> Self {
        self.secure_subdomain = secure_subdomain;
        self
    }

    /// Set the static content to serve at this path. If set, the HTTP server will
    /// not forward requests on this path to the process, and will instead serve the
    /// static content directly and only in response to  GET requests.
    pub fn static_content(mut self, static_content: Option<KiBlob>) -> Self {
        self.static_content = static_content;
        self
    }
}

/// Configuration for a WebSocket binding.
///
/// `authenticated` is set to true by default and means that the WebSocket server will
/// require a valid login cookie to access this path.
///
/// `extension` is set to false by default and means that the WebSocket will
/// not use the WebSocket extension protocol to connect with a runtime extension.
#[derive(Clone, Copy, Debug)]
pub struct WsBindingConfig {
    pub(crate) authenticated: bool,
    pub(crate) secure_subdomain: bool,
    pub(crate) extension: bool,
}

impl WsBindingConfig {
    /// Create a new WsBindingConfig with default values.
    ///
    /// Authenticated, not a secure subdomain, not an extension.
    pub fn default() -> Self {
        Self {
            authenticated: true,
            secure_subdomain: false,
            extension: false,
        }
    }

    /// Create a new WsBindingConfig with the given values.
    pub fn new(authenticated: bool, secure_subdomain: bool, extension: bool) -> Self {
        Self {
            authenticated,
            secure_subdomain,
            extension,
        }
    }

    /// Set whether the WebSocket server will require a valid login cookie to access this path.
    pub fn authenticated(mut self, authenticated: bool) -> Self {
        self.authenticated = authenticated;
        self
    }

    /// Set whether the WebSocket server will be bound on a secure subdomain.
    pub fn secure_subdomain(mut self, secure_subdomain: bool) -> Self {
        self.secure_subdomain = secure_subdomain;
        self
    }

    /// Set whether the WebSocket server will be used for a runtime extension.
    pub fn extension(mut self, extension: bool) -> Self {
        self.extension = extension;
        self
    }
}


/// Send an HTTP response to an incoming HTTP request ([`HttpServerRequest::Http`]).
pub fn send_response(status: StatusCode, headers: Option<HashMap<String, String>>, body: Vec<u8>) {
    KiResponse::new()
        .body(
            serde_json::to_vec(&HttpResponse {
                status: status.as_u16(),
                headers: headers.unwrap_or_default(),
            })
            .unwrap(),
        )
        .blob_bytes(body)
        .send()
        .unwrap()
}

/// Send a WebSocket push message on an open WebSocket channel.
pub fn send_ws_push(channel_id: u32, message_type: WsMessageType, blob: KiBlob) {
    KiRequest::to(("our", "http-server", "distro", "sys"))
        .body(
            serde_json::to_vec(&HttpServerRequest::WebSocketPush {
                channel_id,
                message_type,
            })
            .unwrap(),
        )
        .blob(blob)
        .send()
        .unwrap()
}

pub fn ws_push_all_channels(
    ws_channels: &HashMap<String, HashSet<u32>>,
    path: &str,
    message_type: WsMessageType,
    blob: KiBlob,
) {
    if let Some(channels) = ws_channels.get(path) {
        channels.iter().for_each(|channel_id| {
            send_ws_push(*channel_id, message_type, blob.clone());
        });
    }
}

/// Guess the MIME type of a file from its extension.
pub fn get_mime_type(filename: &str) -> String {
    let file_path = std::path::Path::new(filename);

    let extension = file_path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("octet-stream");

    mime_guess::from_ext(extension)
        .first_or_octet_stream()
        .to_string()
}
