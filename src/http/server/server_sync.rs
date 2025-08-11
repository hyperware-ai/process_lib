use crate::{
    get_blob,
    http::server::{
        get_mime_type, ws_push_all_channels, HttpBindingConfig, HttpResponse, HttpServer,
        HttpServerAction, HttpServerError, HttpServerRequest, IncomingHttpRequest, WsBindingConfig,
        WsMessageType,
    },
    last_blob,
    vfs::{FileType, VfsAction, VfsRequest, VfsResponse},
    LazyLoadBlob as KiBlob, Message, Request as KiRequest, Response as KiResponse,
};
use std::collections::{HashMap, HashSet};

impl HttpServer {
    /// Create a new HttpServer with the given timeout.
    pub fn new(timeout: u64) -> Self {
        Self {
            http_paths: HashMap::new(),
            ws_paths: HashMap::new(),
            ws_channels: HashMap::new(),
            timeout,
        }
    }

    /// Register a new path with the HTTP server configured using [`HttpBindingConfig`].
    pub fn bind_http_path<T>(
        &mut self,
        path: T,
        config: HttpBindingConfig,
    ) -> Result<(), HttpServerError>
    where
        T: Into<String>,
    {
        let path: String = path.into();
        let cache = config.static_content.is_some();
        let req = KiRequest::to(("our", "http-server", "distro", "sys")).body(
            serde_json::to_vec(&if config.secure_subdomain {
                HttpServerAction::SecureBind {
                    path: path.clone(),
                    cache,
                }
            } else {
                HttpServerAction::Bind {
                    path: path.clone(),
                    authenticated: config.authenticated,
                    local_only: config.local_only,
                    cache,
                }
            })
            .unwrap(),
        );
        let res = match config.static_content.clone() {
            Some(static_content) => req
                .blob(static_content)
                .send_and_await_response(self.timeout),
            None => req.send_and_await_response(self.timeout),
        };
        let Ok(Message::Response { body, .. }) = res.unwrap() else {
            return Err(HttpServerError::Timeout);
        };
        let Ok(resp) = serde_json::from_slice::<Result<(), HttpServerError>>(&body) else {
            return Err(HttpServerError::UnexpectedResponse);
        };
        if resp.is_ok() {
            self.http_paths.insert(path, config);
        }
        resp
    }

    /// Register a new path with the HTTP server configured using [`WsBindingConfig`].
    pub fn bind_ws_path<T>(
        &mut self,
        path: T,
        config: WsBindingConfig,
    ) -> Result<(), HttpServerError>
    where
        T: Into<String>,
    {
        let path: String = path.into();
        let res = KiRequest::to(("our", "http-server", "distro", "sys"))
            .body(if config.secure_subdomain {
                serde_json::to_vec(&HttpServerAction::WebSocketSecureBind {
                    path: path.clone(),
                    extension: config.extension,
                })
                .unwrap()
            } else {
                serde_json::to_vec(&HttpServerAction::WebSocketBind {
                    path: path.clone(),
                    authenticated: config.authenticated,
                    extension: config.extension,
                })
                .unwrap()
            })
            .send_and_await_response(self.timeout);
        let Ok(Message::Response { body, .. }) = res.unwrap() else {
            return Err(HttpServerError::Timeout);
        };
        let Ok(resp) = serde_json::from_slice::<Result<(), HttpServerError>>(&body) else {
            return Err(HttpServerError::UnexpectedResponse);
        };
        if resp.is_ok() {
            self.ws_paths.insert(path, config);
        }
        resp
    }

    /// Register a new path with the HTTP server, and serve a static file from it.
    /// The server will respond to GET requests on this path with the given file.
    pub fn bind_http_static_path<T>(
        &mut self,
        path: T,
        authenticated: bool,
        local_only: bool,
        content_type: Option<String>,
        content: Vec<u8>,
    ) -> Result<(), HttpServerError>
    where
        T: Into<String>,
    {
        let path: String = path.into();
        let res = KiRequest::to(("our", "http-server", "distro", "sys"))
            .body(
                serde_json::to_vec(&HttpServerAction::Bind {
                    path: path.clone(),
                    authenticated,
                    local_only,
                    cache: true,
                })
                .unwrap(),
            )
            .blob(crate::hyperware::process::standard::LazyLoadBlob {
                mime: content_type.clone(),
                bytes: content.clone(),
            })
            .send_and_await_response(self.timeout)
            .unwrap();
        let Ok(Message::Response { body, .. }) = res else {
            return Err(HttpServerError::Timeout);
        };
        let Ok(resp) = serde_json::from_slice::<Result<(), HttpServerError>>(&body) else {
            return Err(HttpServerError::UnexpectedResponse);
        };
        if resp.is_ok() {
            self.http_paths.insert(
                path,
                HttpBindingConfig {
                    authenticated,
                    local_only,
                    secure_subdomain: false,
                    static_content: Some(KiBlob {
                        mime: content_type,
                        bytes: content,
                    }),
                },
            );
        }
        resp
    }

    /// Register a new path with the HTTP server. This will cause the HTTP server to
    /// forward any requests on this path to the calling process.
    ///
    /// Instead of binding at just a path, this function tells the HTTP server to
    /// generate a *subdomain* with our package ID (with non-ascii-alphanumeric
    /// characters converted to `-`, although will not be needed if package ID is
    /// a genuine hypermap entry) and bind at that subdomain.
    pub fn secure_bind_http_path<T>(&mut self, path: T) -> Result<(), HttpServerError>
    where
        T: Into<String>,
    {
        let path: String = path.into();
        let res = KiRequest::to(("our", "http-server", "distro", "sys"))
            .body(
                serde_json::to_vec(&HttpServerAction::SecureBind {
                    path: path.clone(),
                    cache: false,
                })
                .unwrap(),
            )
            .send_and_await_response(self.timeout)
            .unwrap();
        let Ok(Message::Response { body, .. }) = res else {
            return Err(HttpServerError::Timeout);
        };
        let Ok(resp) = serde_json::from_slice::<Result<(), HttpServerError>>(&body) else {
            return Err(HttpServerError::UnexpectedResponse);
        };
        if resp.is_ok() {
            self.http_paths.insert(
                path,
                HttpBindingConfig {
                    authenticated: true,
                    local_only: false,
                    secure_subdomain: true,
                    static_content: None,
                },
            );
        }
        resp
    }

    /// Register a new WebSocket path with the HTTP server. Any client connections
    /// made on this path will be forwarded to this process.
    ///
    /// Instead of binding at just a path, this function tells the HTTP server to
    /// generate a *subdomain* with our package ID (with non-ascii-alphanumeric
    /// characters converted to `-`, although will not be needed if package ID is
    /// a genuine hypermap entry) and bind at that subdomain.
    pub fn secure_bind_ws_path<T>(&mut self, path: T) -> Result<(), HttpServerError>
    where
        T: Into<String>,
    {
        let path: String = path.into();
        let res = KiRequest::to(("our", "http-server", "distro", "sys"))
            .body(
                serde_json::to_vec(&HttpServerAction::WebSocketSecureBind {
                    path: path.clone(),
                    extension: false,
                })
                .unwrap(),
            )
            .send_and_await_response(self.timeout);
        let Ok(Message::Response { body, .. }) = res.unwrap() else {
            return Err(HttpServerError::Timeout);
        };
        let Ok(resp) = serde_json::from_slice::<Result<(), HttpServerError>>(&body) else {
            return Err(HttpServerError::UnexpectedResponse);
        };
        if resp.is_ok() {
            self.ws_paths.insert(
                path,
                WsBindingConfig {
                    authenticated: true,
                    secure_subdomain: true,
                    extension: false,
                },
            );
        }
        resp
    }

    /// Modify a previously-bound HTTP path.
    pub fn modify_http_path<T>(
        &mut self,
        path: &str,
        config: HttpBindingConfig,
    ) -> Result<(), HttpServerError>
    where
        T: Into<String>,
    {
        let entry = self
            .http_paths
            .get_mut(path)
            .ok_or(HttpServerError::MalformedRequest)?;
        let res = KiRequest::to(("our", "http-server", "distro", "sys"))
            .body(
                serde_json::to_vec(&HttpServerAction::Bind {
                    path: path.to_string(),
                    authenticated: config.authenticated,
                    local_only: config.local_only,
                    cache: true,
                })
                .unwrap(),
            )
            .send_and_await_response(self.timeout)
            .unwrap();
        let Ok(Message::Response { body, .. }) = res else {
            return Err(HttpServerError::Timeout);
        };
        let Ok(resp) = serde_json::from_slice::<Result<(), HttpServerError>>(&body) else {
            return Err(HttpServerError::UnexpectedResponse);
        };
        if resp.is_ok() {
            entry.authenticated = config.authenticated;
            entry.local_only = config.local_only;
            entry.secure_subdomain = config.secure_subdomain;
            entry.static_content = config.static_content;
        }
        resp
    }

    /// Modify a previously-bound WS path
    pub fn modify_ws_path(
        &mut self,
        path: &str,
        config: WsBindingConfig,
    ) -> Result<(), HttpServerError> {
        let entry = self
            .ws_paths
            .get_mut(path)
            .ok_or(HttpServerError::MalformedRequest)?;
        let res = KiRequest::to(("our", "http-server", "distro", "sys"))
            .body(if entry.secure_subdomain {
                serde_json::to_vec(&HttpServerAction::WebSocketSecureBind {
                    path: path.to_string(),
                    extension: config.extension,
                })
                .unwrap()
            } else {
                serde_json::to_vec(&HttpServerAction::WebSocketBind {
                    path: path.to_string(),
                    authenticated: config.authenticated,
                    extension: config.extension,
                })
                .unwrap()
            })
            .send_and_await_response(self.timeout)
            .unwrap();
        let Ok(Message::Response { body, .. }) = res else {
            return Err(HttpServerError::Timeout);
        };
        let Ok(resp) = serde_json::from_slice::<Result<(), HttpServerError>>(&body) else {
            return Err(HttpServerError::UnexpectedResponse);
        };
        if resp.is_ok() {
            entry.authenticated = config.authenticated;
            entry.secure_subdomain = config.secure_subdomain;
            entry.extension = config.extension;
        }
        resp
    }

    /// Unbind a previously-bound HTTP path.
    pub fn unbind_http_path<T>(&mut self, path: T) -> Result<(), HttpServerError>
    where
        T: Into<String>,
    {
        let path: String = path.into();
        let res = KiRequest::to(("our", "http-server", "distro", "sys"))
            .body(serde_json::to_vec(&HttpServerAction::Unbind { path: path.clone() }).unwrap())
            .send_and_await_response(self.timeout)
            .unwrap();
        let Ok(Message::Response { body, .. }) = res else {
            return Err(HttpServerError::Timeout);
        };
        let Ok(resp) = serde_json::from_slice::<Result<(), HttpServerError>>(&body) else {
            return Err(HttpServerError::UnexpectedResponse);
        };
        if resp.is_ok() {
            self.http_paths.remove(&path);
        }
        resp
    }

    /// Unbind a previously-bound WebSocket path.
    pub fn unbind_ws_path<T>(&mut self, path: T) -> Result<(), HttpServerError>
    where
        T: Into<String>,
    {
        let path: String = path.into();
        let res = KiRequest::to(("our", "http-server", "distro", "sys"))
            .body(
                serde_json::to_vec(&HttpServerAction::WebSocketUnbind { path: path.clone() })
                    .unwrap(),
            )
            .send_and_await_response(self.timeout)
            .unwrap();
        let Ok(Message::Response { body, .. }) = res else {
            return Err(HttpServerError::Timeout);
        };
        let Ok(resp) = serde_json::from_slice::<Result<(), HttpServerError>>(&body) else {
            return Err(HttpServerError::UnexpectedResponse);
        };
        if resp.is_ok() {
            self.ws_paths.remove(&path);
        }
        resp
    }

    /// Serve a file from the given directory within our package drive at the given paths.
    ///
    /// The directory is relative to the `pkg` folder within this package's drive.
    ///
    /// The config `static_content` field will be ignored in favor of the file content.
    /// An error will be returned if the file does not exist.
    pub fn serve_file(
        &mut self,
        file_path: &str,
        paths: Vec<&str>,
        config: HttpBindingConfig,
    ) -> Result<(), HttpServerError> {
        let our = crate::our();
        let _res = KiRequest::to(("our", "vfs", "distro", "sys"))
            .body(
                serde_json::to_vec(&VfsRequest {
                    path: format!(
                        "/{}/pkg/{}",
                        our.package_id(),
                        file_path.trim_start_matches('/')
                    ),
                    action: VfsAction::Read,
                })
                .map_err(|_| HttpServerError::MalformedRequest)?,
            )
            .send_and_await_response(self.timeout)
            .unwrap();

        let Some(mut blob) = get_blob() else {
            return Err(HttpServerError::NoBlob);
        };

        let content_type = get_mime_type(&file_path);
        blob.mime = Some(content_type);

        for path in paths {
            self.bind_http_path(path, config.clone().static_content(Some(blob.clone())))?;
        }

        Ok(())
    }

    /// Serve a file from the given absolute directory.
    ///
    /// The config `static_content` field will be ignored in favor of the file content.
    /// An error will be returned if the file does not exist.
    pub fn serve_file_raw_path(
        &mut self,
        file_path: &str,
        paths: Vec<&str>,
        config: HttpBindingConfig,
    ) -> Result<(), HttpServerError> {
        let _res = KiRequest::to(("our", "vfs", "distro", "sys"))
            .body(
                serde_json::to_vec(&VfsRequest {
                    path: file_path.to_string(),
                    action: VfsAction::Read,
                })
                .map_err(|_| HttpServerError::MalformedRequest)?,
            )
            .send_and_await_response(self.timeout)
            .unwrap();

        let Some(mut blob) = get_blob() else {
            return Err(HttpServerError::NoBlob);
        };

        let content_type = get_mime_type(&file_path);
        blob.mime = Some(content_type);

        for path in paths {
            self.bind_http_path(path, config.clone().static_content(Some(blob.clone())))?;
        }

        Ok(())
    }

    /// Helper function to traverse a UI directory and apply an operation to each file.
    /// This is used by both serve_ui and unserve_ui to avoid code duplication.
    fn traverse_ui_directory<F>(
        &mut self,
        directory: &str,
        roots: &[&str],
        mut file_handler: F,
    ) -> Result<(), HttpServerError>
    where
        F: FnMut(&mut Self, &str, &[&str], bool) -> Result<(), HttpServerError>,
    {
        let our = crate::our();
        let initial_path = format!("{}/pkg/{}", our.package_id(), directory);

        let mut queue = std::collections::VecDeque::new();
        queue.push_back(initial_path.clone());

        while let Some(path) = queue.pop_front() {
            let Ok(directory_response) = KiRequest::to(("our", "vfs", "distro", "sys"))
                .body(
                    serde_json::to_vec(&VfsRequest {
                        path,
                        action: VfsAction::ReadDir,
                    })
                    .unwrap(),
                )
                .send_and_await_response(self.timeout)
                .unwrap()
            else {
                return Err(HttpServerError::MalformedRequest);
            };

            let directory_body = serde_json::from_slice::<VfsResponse>(directory_response.body())
                .map_err(|_e| HttpServerError::UnexpectedResponse)?;

            // determine if it's a file or a directory and handle appropriately
            let VfsResponse::ReadDir(directory_info) = directory_body else {
                return Err(HttpServerError::UnexpectedResponse);
            };

            for entry in directory_info {
                match entry.file_type {
                    FileType::Directory => {
                        // push the directory onto the queue
                        queue.push_back(entry.path);
                    }
                    FileType::File => {
                        let relative_path = entry.path.replace(&initial_path, "");
                        let is_index = entry.path.ends_with("index.html");

                        // Call the handler with the file path and whether it's an index file
                        file_handler(self, &entry.path, &[relative_path.as_str()], is_index)?;

                        // If it's an index file, also handle the root paths
                        if is_index {
                            for root in roots {
                                file_handler(self, &entry.path, &[root], true)?;
                            }
                        }
                    }
                    _ => {
                        // ignore symlinks and other
                    }
                }
            }
        }

        Ok(())
    }

    /// Serve static files from a given directory by binding all of them
    /// in http-server to their filesystem path.
    ///
    /// The directory is relative to the `pkg` folder within this package's drive.
    ///
    /// The config `static_content` field will be ignored in favor of the files' contents.
    /// An error will be returned if the file does not exist.
    pub fn serve_ui(
        &mut self,
        directory: &str,
        roots: Vec<&str>,
        config: HttpBindingConfig,
    ) -> Result<(), HttpServerError> {
        self.traverse_ui_directory(directory, &roots, |server, file_path, paths, _is_index| {
            server.serve_file_raw_path(file_path, paths.to_vec(), config.clone())
        })
    }

    /// Unserve static files from a given directory by unbinding all of them
    /// from http-server that were previously bound by serve_ui.
    ///
    /// The directory is relative to the `pkg` folder within this package's drive.
    ///
    /// This mirrors the logic of serve_ui but calls unbind_http_path instead.
    pub fn unserve_ui(&mut self, directory: &str, roots: Vec<&str>) -> Result<(), HttpServerError> {
        self.traverse_ui_directory(directory, &roots, |server, _file_path, paths, _is_index| {
            // Unbind each path that was bound
            for path in paths {
                server.unbind_http_path(*path)?;
            }
            Ok(())
        })
    }

    /// Handle a WebSocket open event from the HTTP server.
    pub fn handle_websocket_open(&mut self, path: &str, channel_id: u32) {
        self.ws_channels
            .entry(path.to_string())
            .or_insert(HashSet::new())
            .insert(channel_id);
    }

    /// Handle a WebSocket close event from the HTTP server.
    pub fn handle_websocket_close(&mut self, channel_id: u32) {
        self.ws_channels.iter_mut().for_each(|(_, channels)| {
            channels.remove(&channel_id);
        });
    }

    pub fn parse_request(&self, body: &[u8]) -> Result<HttpServerRequest, HttpServerError> {
        let request = serde_json::from_slice::<HttpServerRequest>(body)
            .map_err(|_| HttpServerError::MalformedRequest)?;
        Ok(request)
    }

    /// Handle an incoming request from the HTTP server.
    pub fn handle_request(
        &mut self,
        server_request: HttpServerRequest,
        mut http_handler: impl FnMut(IncomingHttpRequest) -> (HttpResponse, Option<KiBlob>),
        mut ws_handler: impl FnMut(u32, WsMessageType, KiBlob),
    ) {
        match server_request {
            HttpServerRequest::Http(http_request) => {
                let (response, blob) = http_handler(http_request);
                let response = KiResponse::new().body(serde_json::to_vec(&response).unwrap());
                if let Some(blob) = blob {
                    response.blob(blob).send().unwrap();
                } else {
                    response.send().unwrap();
                }
            }
            HttpServerRequest::WebSocketPush {
                channel_id,
                message_type,
            } => ws_handler(channel_id, message_type, last_blob().unwrap_or_default()),
            HttpServerRequest::WebSocketOpen { path, channel_id } => {
                self.handle_websocket_open(&path, channel_id);
            }
            HttpServerRequest::WebSocketClose(channel_id) => {
                self.handle_websocket_close(channel_id);
            }
        }
    }

    /// Push a WebSocket message to all channels on a given path.
    pub fn ws_push_all_channels(&self, path: &str, message_type: WsMessageType, blob: KiBlob) {
        ws_push_all_channels(&self.ws_channels, path, message_type, blob);
    }

    pub fn get_ws_channels(&self) -> HashMap<String, HashSet<u32>> {
        self.ws_channels.clone()
    }

    /// Register multiple paths with the HTTP server using the same configuration.
    /// The security setting is determined by the `secure_subdomain` field in `HttpBindingConfig`.
    /// All paths must be bound successfully, or none will be bound. If any path
    /// fails to bind, all previously bound paths will be unbound before returning
    /// the error.
    pub fn bind_multiple_http_paths<T: Into<String>>(
        &mut self,
        paths: Vec<T>,
        config: HttpBindingConfig,
    ) -> Result<(), HttpServerError> {
        let mut bound_paths = Vec::new();

        for path in paths {
            let path_str = path.into();
            let result = match config.secure_subdomain {
                true => self.secure_bind_http_path(path_str.clone()),
                false => self.bind_http_path(path_str.clone(), config.clone()),
            };

            match result {
                // If binding succeeds, add the path to the list of bound paths
                Ok(_) => bound_paths.push(path_str),
                // If binding fails, unbind all previously bound paths
                Err(e) => {
                    for bound_path in bound_paths {
                        let _ = self.unbind_http_path(&bound_path);
                    }
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}
