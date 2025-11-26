use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::task::{Context, Poll};

use crate::{
    get_state, http,
    http::server::{HttpBindingConfig, HttpServer, IncomingHttpRequest, WsBindingConfig},
    logging::{error, info},
    set_state, timer, Address, BuildError, LazyLoadBlob, Message, Request, SendError,
};
use futures_channel::{mpsc, oneshot};
use futures_util::task::{waker_ref, ArcWake};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

thread_local! {
    static SPAWN_QUEUE: RefCell<Vec<Pin<Box<dyn Future<Output = ()>>>>> = RefCell::new(Vec::new());

    pub static APP_CONTEXT: RefCell<AppContext> = RefCell::new(AppContext {
        hidden_state: None,
        executor: Executor::new(),
    });

    pub static RESPONSE_REGISTRY: RefCell<HashMap<String, Vec<u8>>> = RefCell::new(HashMap::new());
    pub static CANCELLED_RESPONSES: RefCell<HashSet<String>> = RefCell::new(HashSet::new());

    pub static APP_HELPERS: RefCell<AppHelpers> = RefCell::new(AppHelpers {
        current_server: None,
        current_message: None,
        current_http_context: None,
    });
}

#[derive(Clone)]
pub struct HttpRequestContext {
    pub request: IncomingHttpRequest,
    pub response_headers: HashMap<String, String>,
    pub response_status: http::StatusCode,
}

pub struct AppContext {
    pub hidden_state: Option<HiddenState>,
    pub executor: Executor,
}

pub struct AppHelpers {
    pub current_server: Option<*mut HttpServer>,
    pub current_message: Option<Message>,
    pub current_http_context: Option<HttpRequestContext>,
}

// Access function for the current path
pub fn get_path() -> Option<String> {
    APP_HELPERS.with(|helpers| {
        helpers
            .borrow()
            .current_http_context
            .as_ref()
            .and_then(|ctx| ctx.request.path().ok())
    })
}

// Access function for the current server
pub fn get_server() -> Option<&'static mut HttpServer> {
    APP_HELPERS.with(|ctx| ctx.borrow().current_server.map(|ptr| unsafe { &mut *ptr }))
}

pub fn get_http_request() -> Option<IncomingHttpRequest> {
    APP_HELPERS.with(|helpers| {
        helpers
            .borrow()
            .current_http_context
            .as_ref()
            .map(|ctx| ctx.request.clone())
    })
}

pub fn get_http_method() -> Option<String> {
    APP_HELPERS.with(|helpers| {
        helpers
            .borrow()
            .current_http_context
            .as_ref()
            .and_then(|ctx| ctx.request.method().ok())
            .map(|m| m.to_string())
    })
}

// Get a specific header from the current HTTP request
// Returns None if not in HTTP context or header doesn't exist
pub fn get_request_header(name: &str) -> Option<String> {
    APP_HELPERS.with(|helpers| {
        helpers
            .borrow()
            .current_http_context
            .as_ref()
            .and_then(|ctx| {
                // Convert string to HeaderName using process_lib's re-exported type
                let header_name = http::HeaderName::from_bytes(name.as_bytes()).ok()?;
                ctx.request
                    .headers()
                    .get(&header_name)
                    .and_then(|value| value.to_str().ok())
                    .map(|s| s.to_string())
            })
    })
}

// Get the full URL of the current HTTP request
// Returns None if not in an HTTP context
pub fn get_request_url() -> Option<String> {
    APP_HELPERS.with(|helpers| {
        helpers
            .borrow()
            .current_http_context
            .as_ref()
            .and_then(|ctx| ctx.request.url().ok())
            .map(|url| url.to_string())
    })
}

// Set response headers that will be included in the HTTP response
pub fn set_response_headers(headers: HashMap<String, String>) {
    APP_HELPERS.with(|helpers| {
        if let Some(ctx) = &mut helpers.borrow_mut().current_http_context {
            ctx.response_headers = headers;
        }
    })
}

// Add a single response header
pub fn add_response_header(key: String, value: String) {
    APP_HELPERS.with(|helpers| {
        if let Some(ctx) = &mut helpers.borrow_mut().current_http_context {
            ctx.response_headers.insert(key, value);
        }
    })
}

// Set the HTTP response status code
pub fn set_response_status(status: http::StatusCode) {
    APP_HELPERS.with(|helpers| {
        if let Some(ctx) = &mut helpers.borrow_mut().current_http_context {
            ctx.response_status = status;
        }
    })
}

pub fn clear_http_request_context() {
    APP_HELPERS.with(|helpers| {
        helpers.borrow_mut().current_http_context = None;
    })
}

// Access function for the source address of the current message
pub fn source() -> Address {
    APP_HELPERS.with(|ctx| {
        ctx.borrow()
            .current_message
            .as_ref()
            .expect("No message in current context")
            .source()
            .clone()
    })
}

/// Get the pre-parsed query parameters from the current HTTP request
/// Returns None if not in an HTTP context
/// This accesses the query_params field that Hyperware already parsed (includes URL decoding)
pub fn get_query_params() -> Option<HashMap<String, String>> {
    APP_HELPERS.with(|helpers| {
        helpers
            .borrow()
            .current_http_context
            .as_ref()
            .map(|ctx| ctx.request.query_params().clone())
    })
}

pub struct Executor {
    tasks: Vec<Pin<Box<dyn Future<Output = ()>>>>,
}

struct ExecutorWakeFlag {
    triggered: AtomicBool,
}

impl ExecutorWakeFlag {
    fn new() -> Self {
        Self {
            triggered: AtomicBool::new(false),
        }
    }

    fn take(&self) -> bool {
        self.triggered.swap(false, Ordering::SeqCst)
    }
}

impl ArcWake for ExecutorWakeFlag {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.triggered.store(true, Ordering::SeqCst);
    }
}

pub struct JoinHandle<T> {
    receiver: oneshot::Receiver<T>,
}

impl<T> Future for JoinHandle<T> {
    type Output = Result<T, oneshot::Canceled>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let receiver = &mut self.get_mut().receiver;
        Pin::new(receiver).poll(cx)
    }
}

pub fn spawn<T>(fut: impl Future<Output = T> + 'static) -> JoinHandle<T>
where
    T: 'static,
{
    let (sender, receiver) = oneshot::channel();
    SPAWN_QUEUE.with(|queue| {
        queue.borrow_mut().push(Box::pin(async move {
            let result = fut.await;
            let _ = sender.send(result);
        }));
    });
    JoinHandle { receiver }
}

impl Executor {
    pub fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    pub fn poll_all_tasks(&mut self) {
        let wake_flag = Arc::new(ExecutorWakeFlag::new());
        loop {
            // Drain any newly spawned tasks into our task list
            SPAWN_QUEUE.with(|queue| {
                self.tasks.append(&mut queue.borrow_mut());
            });

            // Poll all tasks, collecting completed ones.
            // Put waker into context so tasks can wake the executor if needed.
            let mut completed = Vec::new();
            {
                let waker = waker_ref(&wake_flag);
                let mut ctx = Context::from_waker(&waker);

                for i in 0..self.tasks.len() {
                    if let Poll::Ready(()) = self.tasks[i].as_mut().poll(&mut ctx) {
                        completed.push(i);
                    }
                }
            }

            // Remove completed tasks immediately to prevent re-polling
            for idx in completed.into_iter().rev() {
                let _ = self.tasks.remove(idx);
            }

            // Check if there are new tasks spawned during polling
            let has_new_tasks = SPAWN_QUEUE.with(|queue| !queue.borrow().is_empty());
            // Check if any task woke the executor that needs to be re-polled
            let was_woken = wake_flag.take();

            if !has_new_tasks && !was_woken {
                break;
            }
        }
    }
}
struct ResponseFuture {
    correlation_id: String,
    // Capture HTTP context at creation time
    http_context: Option<HttpRequestContext>,
    resolved: bool,
}

impl ResponseFuture {
    fn new(correlation_id: String) -> Self {
        // Capture current HTTP context when future is created (at .await point)
        let http_context =
            APP_HELPERS.with(|helpers| helpers.borrow().current_http_context.clone());

        Self {
            correlation_id,
            http_context,
            resolved: false,
        }
    }
}

impl Future for ResponseFuture {
    type Output = Vec<u8>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let maybe_bytes = RESPONSE_REGISTRY.with(|registry| {
            let mut registry_mut = registry.borrow_mut();
            registry_mut.remove(&this.correlation_id)
        });

        if let Some(bytes) = maybe_bytes {
            this.resolved = true;

            // Restore this future's captured context
            if let Some(ref context) = this.http_context {
                APP_HELPERS.with(|helpers| {
                    helpers.borrow_mut().current_http_context = Some(context.clone());
                });
            }

            Poll::Ready(bytes)
        } else {
            Poll::Pending
        }
    }
}

impl Drop for ResponseFuture {
    fn drop(&mut self) {
        // We want to avoid cleaning up after successful responses
        if self.resolved {
            return;
        }

        RESPONSE_REGISTRY.with(|registry| {
            registry.borrow_mut().remove(&self.correlation_id);
        });

        CANCELLED_RESPONSES.with(|set| {
            set.borrow_mut().insert(self.correlation_id.clone());
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Error)]
pub enum AppSendError {
    #[error("SendError: {0}")]
    SendError(SendError),
    #[error("BuildError: {0}")]
    BuildError(BuildError),
}

pub async fn sleep(sleep_ms: u64) -> Result<(), AppSendError> {
    let request = Request::to(("our", "timer", "distro", "sys"))
        .body(timer::TimerAction::SetTimer(sleep_ms))
        .expects_response((sleep_ms / 1_000) + 1);

    let correlation_id = Uuid::new_v4().to_string();
    if let Err(e) = request.context(correlation_id.as_bytes().to_vec()).send() {
        return Err(AppSendError::BuildError(e));
    }

    let _ = ResponseFuture::new(correlation_id).await;

    return Ok(());
}

pub async fn send<R>(request: Request) -> Result<R, AppSendError>
where
    R: serde::de::DeserializeOwned,
{
    let request = if request.timeout.is_some() {
        request
    } else {
        request.expects_response(30)
    };

    let correlation_id = Uuid::new_v4().to_string();
    if let Err(e) = request.context(correlation_id.as_bytes().to_vec()).send() {
        return Err(AppSendError::BuildError(e));
    }

    let response_bytes = ResponseFuture::new(correlation_id).await;
    if let Ok(r) = serde_json::from_slice::<R>(&response_bytes) {
        return Ok(r);
    }

    match serde_json::from_slice::<SendError>(&response_bytes) {
        Ok(e) => Err(AppSendError::SendError(e)),
        Err(err) => {
            error!(
                "Failed to deserialize response in send(): {} (payload: {:?})",
                err, response_bytes
            );
            Err(AppSendError::BuildError(BuildError::NoBody))
        }
    }
}

pub async fn send_rmp<R>(request: Request) -> Result<R, AppSendError>
where
    R: serde::de::DeserializeOwned,
{
    let request = if request.timeout.is_some() {
        request
    } else {
        request.expects_response(30)
    };

    let correlation_id = Uuid::new_v4().to_string();
    if let Err(e) = request.context(correlation_id.as_bytes().to_vec()).send() {
        return Err(AppSendError::BuildError(e));
    }

    let response_bytes = ResponseFuture::new(correlation_id).await;
    if let Ok(r) = rmp_serde::from_slice::<R>(&response_bytes) {
        return Ok(r);
    }

    match rmp_serde::from_slice::<SendError>(&response_bytes) {
        Ok(e) => Err(AppSendError::SendError(e)),
        Err(err) => {
            error!(
                "Failed to deserialize response in send_rmp(): {} (payload: {:?})",
                err, response_bytes
            );
            Err(AppSendError::BuildError(BuildError::NoBody))
        }
    }
}

// Enum defining the state persistance behaviour
#[derive(Clone)]
pub enum SaveOptions {
    // Never Persist State
    Never,
    // Persist State Every Message
    EveryMessage,
    // Persist State Every N Messages
    EveryNMessage(u64),
    // Persist State Every N Seconds
    EveryNSeconds(u64),
    // Persist State Only If Changed
    OnDiff,
}
pub struct HiddenState {
    save_config: SaveOptions,
    message_count: u64,
    old_state: Option<Vec<u8>>, // Stores the serialized state from before message processing
}

impl HiddenState {
    pub fn new(save_config: SaveOptions) -> Self {
        Self {
            save_config,
            message_count: 0,
            old_state: None,
        }
    }

    fn should_save_state(&mut self) -> bool {
        match self.save_config {
            SaveOptions::Never => false,
            SaveOptions::EveryMessage => true,
            SaveOptions::EveryNMessage(n) => {
                self.message_count += 1;
                if self.message_count >= n {
                    self.message_count = 0;
                    true
                } else {
                    false
                }
            }
            SaveOptions::EveryNSeconds(_) => false, // Handled by timer instead
            SaveOptions::OnDiff => false, // Will be handled separately with state comparison
        }
    }
}

// TODO: We need a timer macro again.

/// Store a snapshot of the current state before processing a message
/// This is used for OnDiff save option to compare state before and after
/// Only stores if old_state is None (i.e., first time or after a save)
pub fn store_old_state<S>(state: &S)
where
    S: serde::Serialize,
{
    APP_CONTEXT.with(|ctx| {
        let mut ctx_mut = ctx.borrow_mut();
        if let Some(ref mut hidden_state) = ctx_mut.hidden_state {
            if matches!(hidden_state.save_config, SaveOptions::OnDiff)
                && hidden_state.old_state.is_none()
            {
                if let Ok(s_bytes) = rmp_serde::to_vec(state) {
                    hidden_state.old_state = Some(s_bytes);
                }
            }
        }
    });
}

/// Trait that must be implemented by application state types
pub trait State {
    /// Creates a new instance of the state.
    fn new() -> Self;
}

/// Initialize state from persisted storage or create new if none exists
/// TODO: Delete?
pub fn initialize_state<S>() -> S
where
    S: serde::de::DeserializeOwned + Default,
{
    match get_state() {
        Some(bytes) => match rmp_serde::from_slice::<S>(&bytes) {
            Ok(state) => state,
            Err(e) => {
                panic!("error deserializing existing state: {e}. We're panicking because we don't want to nuke state by setting it to a new instance.");
            }
        },
        None => {
            info!("no existing state, creating new one");
            S::default()
        }
    }
}

pub fn setup_server(
    ui_config: Option<&HttpBindingConfig>,
    ui_path: Option<String>,
    endpoints: &[Binding],
) -> http::server::HttpServer {
    let mut server = http::server::HttpServer::new(5);

    if let Some(ui) = ui_config {
        if let Err(e) = server.serve_ui(
            &ui_path.unwrap_or_else(|| "ui".to_string()),
            vec!["/"],
            ui.clone(),
        ) {
            panic!("failed to serve UI: {e}. Make sure that a ui folder is in /pkg");
        }
    }

    // Verify no duplicate paths
    let mut seen_paths = std::collections::HashSet::new();
    for endpoint in endpoints.iter() {
        let path = match endpoint {
            Binding::Http { path, .. } => path,
            Binding::Ws { path, .. } => path,
        };
        if !seen_paths.insert(path) {
            panic!("duplicate path found: {}", path);
        }
    }

    for endpoint in endpoints {
        match endpoint {
            Binding::Http { path, config } => {
                server
                    .bind_http_path(path.to_string(), config.clone())
                    .expect("failed to serve API path");
            }
            Binding::Ws { path, config } => {
                server
                    .bind_ws_path(path.to_string(), config.clone())
                    .expect("failed to bind WS path");
            }
        }
    }

    server
}

/// Pretty prints a SendError in a more readable format
pub fn pretty_print_send_error(error: &SendError) {
    let kind = &error.kind;
    let target = &error.target;

    // Try to decode body as UTF-8 string, fall back to showing as bytes
    let body = String::from_utf8(error.message.body().to_vec())
        .map(|s| format!("\"{}\"", s))
        .unwrap_or_else(|_| format!("{:?}", error.message.body()));

    // Try to decode context as UTF-8 string
    let context = error
        .context
        .as_ref()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned());

    error!(
        "SendError {{
    kind: {:?},
    target: {},
    body: {},
    context: {}
}}",
        kind,
        target,
        body,
        context
            .map(|s| format!("\"{}\"", s))
            .unwrap_or("None".to_string())
    );
}

// For demonstration, we'll define them all in one place.
// Make sure the signatures match the real function signatures you require!
pub fn no_init_fn<S>(_state: &mut S) {
    // does nothing
}

pub fn no_ws_handler<S>(
    _state: &mut S,
    _server: &mut http::server::HttpServer,
    _channel_id: u32,
    _msg_type: http::server::WsMessageType,
    _blob: LazyLoadBlob,
) {
    // does nothing
}

pub fn no_http_api_call<S>(_state: &mut S, _req: ()) {
    // does nothing
}

pub fn no_local_request<S>(_msg: &Message, _state: &mut S, _req: ()) {
    // does nothing
}

pub fn no_remote_request<S>(_msg: &Message, _state: &mut S, _req: ()) {
    // does nothing
}

#[derive(Clone, Debug)]
pub enum Binding {
    Http {
        path: &'static str,
        config: HttpBindingConfig,
    },
    Ws {
        path: &'static str,
        config: WsBindingConfig,
    },
}

pub fn maybe_save_state<S>(state: &S)
where
    S: serde::Serialize,
{
    APP_CONTEXT.with(|ctx| {
        let mut ctx_mut = ctx.borrow_mut();
        if let Some(ref mut hidden_state) = ctx_mut.hidden_state {
            let should_save = if matches!(hidden_state.save_config, SaveOptions::OnDiff) {
                // For OnDiff, compare current state with old state
                if let Ok(current_bytes) = rmp_serde::to_vec(state) {
                    let state_changed = match &hidden_state.old_state {
                        Some(old_bytes) => old_bytes != &current_bytes,
                        None => true, // If no old state, consider it changed
                    };

                    if state_changed {
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                hidden_state.should_save_state()
            };

            if should_save {
                if let Ok(s_bytes) = rmp_serde::to_vec(state) {
                    let _ = set_state(&s_bytes);

                    // Clear old_state after saving so it can be set again on next message
                    if matches!(hidden_state.save_config, SaveOptions::OnDiff) {
                        hidden_state.old_state = None;
                    }
                }
            }
        }
    });
}
