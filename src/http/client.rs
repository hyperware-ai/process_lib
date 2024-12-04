pub use super::server::{HttpResponse, WsMessageType};
use crate::{get_blob, LazyLoadBlob as KiBlob, Message, Request as KiRequest};
use http::Method;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use thiserror::Error;

/// [`crate::Request`] type sent to the `http-client:distro:sys` service in order to open a
/// WebSocket connection, send a WebSocket message on an existing connection, or
/// send an HTTP request.
///
/// You will receive a [`crate::Response`] with the format `Result<HttpClientResponse, HttpClientError>`.
///
/// Always serialized/deserialized as JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HttpClientAction {
    Http(OutgoingHttpRequest),
    WebSocketOpen {
        url: String,
        headers: HashMap<String, String>,
        channel_id: u32,
    },
    WebSocketPush {
        channel_id: u32,
        message_type: WsMessageType,
    },
    WebSocketClose {
        channel_id: u32,
    },
}

/// HTTP Request type that can be shared over Wasm boundary to apps.
/// This is the one you send to the `http-client:distro:sys` service.
///
/// BODY is stored in the lazy_load_blob, as bytes
///
/// TIMEOUT is stored in the message expect_response value
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutgoingHttpRequest {
    /// must parse to [`http::Method`]
    pub method: String,
    /// must parse to [`http::Version`]
    pub version: Option<String>,
    /// must parse to [`url::Url`]
    pub url: String,
    pub headers: HashMap<String, String>,
}

/// [`crate::Request`] that comes from an open WebSocket client connection in the
/// `http-client:distro:sys` service. Be prepared to receive these after
/// using a [`HttpClientAction::WebSocketOpen`] to open a connection.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum HttpClientRequest {
    WebSocketPush {
        channel_id: u32,
        message_type: WsMessageType,
    },
    WebSocketClose {
        channel_id: u32,
    },
}

/// [`crate::Response`] type received from the `http-client:distro:sys` service after
/// sending a successful [`HttpClientAction`] to it.
#[derive(Debug, Serialize, Deserialize)]
pub enum HttpClientResponse {
    Http(HttpResponse),
    WebSocketAck,
}

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum HttpClientError {
    // HTTP errors
    #[error("http-client: request is not valid HttpClientRequest: {req}.")]
    BadRequest { req: String },
    #[error("http-client: http method not supported: {method}.")]
    BadMethod { method: String },
    #[error("http-client: url could not be parsed: {url}.")]
    BadUrl { url: String },
    #[error("http-client: http version not supported: {version}.")]
    BadVersion { version: String },
    #[error("http-client: failed to execute request {error}.")]
    RequestFailed { error: String },

    // WebSocket errors
    #[error("websocket_client: failed to open connection {url}.")]
    WsOpenFailed { url: String },
    #[error("websocket_client: failed to send message {req}.")]
    WsPushFailed { req: String },
    #[error("websocket_client: failed to close connection {channel_id}.")]
    WsCloseFailed { channel_id: u32 },
}

/// Fire off an HTTP request. If a timeout is given, the response will
/// come in the main event loop, otherwise none will be given.
///
/// Note that the response type is [`type@HttpClientResponse`], which, if
/// it originated from this request, will be of the variant [`type@HttpClientResponse::Http`].
/// It will need to be parsed and the body of the response will be stored in the LazyLoadBlob.
pub fn send_request(
    method: Method,
    url: url::Url,
    headers: Option<HashMap<String, String>>,
    timeout: Option<u64>,
    body: Vec<u8>,
) {
    let req = KiRequest::to(("our", "http-client", "distro", "sys"))
        .body(
            serde_json::to_vec(&HttpClientAction::Http(OutgoingHttpRequest {
                method: method.to_string(),
                version: None,
                url: url.to_string(),
                headers: headers.unwrap_or_default(),
            }))
            .unwrap(),
        )
        .blob_bytes(body);
    if let Some(timeout) = timeout {
        req.expects_response(timeout).send().unwrap()
    } else {
        req.send().unwrap()
    }
}

/// Make an HTTP request using http-client and await its response.
///
/// Returns HTTP response from the `http` crate if successful, with the body type as bytes.
pub fn send_request_await_response(
    method: Method,
    url: url::Url,
    headers: Option<HashMap<String, String>>,
    timeout: u64,
    body: Vec<u8>,
) -> std::result::Result<http::Response<Vec<u8>>, HttpClientError> {
    let res = KiRequest::to(("our", "http-client", "distro", "sys"))
        .body(
            serde_json::to_vec(&HttpClientAction::Http(OutgoingHttpRequest {
                method: method.to_string(),
                version: None,
                url: url.to_string(),
                headers: headers.unwrap_or_default(),
            }))
            .map_err(|e| HttpClientError::BadRequest {
                req: format!("{e:?}"),
            })?,
        )
        .blob_bytes(body)
        .send_and_await_response(timeout)
        .unwrap();
    let Ok(Message::Response { body, .. }) = res else {
        return Err(HttpClientError::RequestFailed {
            error: "http-client timed out".to_string(),
        });
    };
    let resp = match serde_json::from_slice::<
        std::result::Result<HttpClientResponse, HttpClientError>,
    >(&body)
    {
        Ok(Ok(HttpClientResponse::Http(resp))) => resp,
        Ok(Ok(HttpClientResponse::WebSocketAck)) => {
            return Err(HttpClientError::RequestFailed {
                error: "http-client gave unexpected response".to_string(),
            })
        }
        Ok(Err(e)) => return Err(e),
        Err(e) => {
            return Err(HttpClientError::RequestFailed {
                error: format!("http-client gave invalid response: {e:?}"),
            })
        }
    };
    let mut http_response = http::Response::builder()
        .status(http::StatusCode::from_u16(resp.status).unwrap_or_default());
    let headers = http_response.headers_mut().unwrap();
    for (key, value) in &resp.headers {
        let Ok(key) = http::header::HeaderName::from_str(key) else {
            return Err(HttpClientError::RequestFailed {
                error: format!("http-client gave invalid header key: {key}"),
            });
        };
        let Ok(value) = http::header::HeaderValue::from_str(value) else {
            return Err(HttpClientError::RequestFailed {
                error: format!("http-client gave invalid header value: {value}"),
            });
        };
        headers.insert(key, value);
    }
    Ok(http_response
        .body(get_blob().unwrap_or_default().bytes)
        .unwrap())
}

pub fn open_ws_connection(
    url: String,
    headers: Option<HashMap<String, String>>,
    channel_id: u32,
) -> std::result::Result<(), HttpClientError> {
    let Ok(Ok(Message::Response { body, .. })) =
        KiRequest::to(("our", "http-client", "distro", "sys"))
            .body(
                serde_json::to_vec(&HttpClientAction::WebSocketOpen {
                    url: url.clone(),
                    headers: headers.unwrap_or(HashMap::new()),
                    channel_id,
                })
                .unwrap(),
            )
            .send_and_await_response(5)
    else {
        return Err(HttpClientError::WsOpenFailed { url });
    };
    match serde_json::from_slice(&body) {
        Ok(Ok(HttpClientResponse::WebSocketAck)) => Ok(()),
        Ok(Err(e)) => Err(e),
        _ => Err(HttpClientError::WsOpenFailed { url }),
    }
}

/// Send a WebSocket push message on an open WebSocket channel.
pub fn send_ws_client_push(channel_id: u32, message_type: WsMessageType, blob: KiBlob) {
    KiRequest::to(("our", "http-client", "distro", "sys"))
        .body(
            serde_json::to_vec(&HttpClientAction::WebSocketPush {
                channel_id,
                message_type,
            })
            .unwrap(),
        )
        .blob(blob)
        .send()
        .unwrap()
}

/// Close a WebSocket connection.
pub fn close_ws_connection(channel_id: u32) -> std::result::Result<(), HttpClientError> {
    let Ok(Ok(Message::Response { body, .. })) =
        KiRequest::to(("our", "http-client", "distro", "sys"))
            .body(
                serde_json::json!(HttpClientAction::WebSocketClose { channel_id })
                    .to_string()
                    .as_bytes()
                    .to_vec(),
            )
            .send_and_await_response(5)
    else {
        return Err(HttpClientError::WsCloseFailed { channel_id });
    };
    match serde_json::from_slice(&body) {
        Ok(Ok(HttpClientResponse::WebSocketAck)) => Ok(()),
        Ok(Err(e)) => Err(e),
        _ => Err(HttpClientError::WsCloseFailed { channel_id }),
    }
}
