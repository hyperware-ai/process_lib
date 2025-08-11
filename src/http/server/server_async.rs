use crate::{
    http::server::{
        HttpBindingConfig, HttpServer, HttpServerAction, HttpServerError,
        WsBindingConfig,
    },
    hyperapp, LazyLoadBlob as KiBlob, Request as KiRequest,
};
use std::collections::{HashMap, HashSet};

impl HttpServer {
    pub fn new(timeout: u64) -> Self {
        Self {
            http_paths: HashMap::new(),
            ws_paths: HashMap::new(),
            ws_channels: HashMap::new(),
            timeout,
        }
    }

    pub async fn bind_http_path<T>(
        &mut self,
        path: T,
        config: HttpBindingConfig,
    ) -> Result<(), HttpServerError>
    where
        T: Into<String>,
    {
        let path: String = path.into();
        let cache = config.static_content.is_some();
        let req = KiRequest::to(("our", "http-server", "distro", "sys"))
            .body(
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
            )
            .expects_response(self.timeout);

        let req = match config.static_content.clone() {
            Some(static_content) => req.blob(static_content),
            None => req,
        };

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(req).await.map_err(|_| HttpServerError::Timeout)?;
        let resp = serde_json::from_slice::<Result<(), HttpServerError>>(&resp_bytes)
            .map_err(|_| HttpServerError::UnexpectedResponse)?;

        if resp.is_ok() {
            self.http_paths.insert(path, config);
        }
        resp
    }

    pub async fn bind_ws_path<T>(
        &mut self,
        path: T,
        config: WsBindingConfig,
    ) -> Result<(), HttpServerError>
    where
        T: Into<String>,
    {
        let path: String = path.into();
        let req = KiRequest::to(("our", "http-server", "distro", "sys"))
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
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(req).await.map_err(|_| HttpServerError::Timeout)?;
        let resp = serde_json::from_slice::<Result<(), HttpServerError>>(&resp_bytes)
            .map_err(|_| HttpServerError::UnexpectedResponse)?;

        if resp.is_ok() {
            self.ws_paths.insert(path, config);
        }
        resp
    }

    pub async fn bind_http_static_path<T>(
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
        let req = KiRequest::to(("our", "http-server", "distro", "sys"))
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
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(req).await.map_err(|_| HttpServerError::Timeout)?;
        let resp = serde_json::from_slice::<Result<(), HttpServerError>>(&resp_bytes)
            .map_err(|_| HttpServerError::UnexpectedResponse)?;

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

    pub async fn secure_bind_http_path<T>(&mut self, path: T) -> Result<(), HttpServerError>
    where
        T: Into<String>,
    {
        let path: String = path.into();
        let req = KiRequest::to(("our", "http-server", "distro", "sys"))
            .body(
                serde_json::to_vec(&HttpServerAction::SecureBind {
                    path: path.clone(),
                    cache: false,
                })
                .unwrap(),
            )
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(req).await.map_err(|_| HttpServerError::Timeout)?;
        let resp = serde_json::from_slice::<Result<(), HttpServerError>>(&resp_bytes)
            .map_err(|_| HttpServerError::UnexpectedResponse)?;

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

    pub async fn secure_bind_ws_path<T>(&mut self, path: T) -> Result<(), HttpServerError>
    where
        T: Into<String>,
    {
        let path: String = path.into();
        let req = KiRequest::to(("our", "http-server", "distro", "sys"))
            .body(
                serde_json::to_vec(&HttpServerAction::WebSocketSecureBind {
                    path: path.clone(),
                    extension: false,
                })
                .unwrap(),
            )
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(req).await.map_err(|_| HttpServerError::Timeout)?;
        let resp = serde_json::from_slice::<Result<(), HttpServerError>>(&resp_bytes)
            .map_err(|_| HttpServerError::UnexpectedResponse)?;

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

    pub async fn modify_http_path<T>(
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
        let req = KiRequest::to(("our", "http-server", "distro", "sys"))
            .body(
                serde_json::to_vec(&HttpServerAction::Bind {
                    path: path.to_string(),
                    authenticated: config.authenticated,
                    local_only: config.local_only,
                    cache: true,
                })
                .unwrap(),
            )
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(req).await.map_err(|_| HttpServerError::Timeout)?;
        let resp = serde_json::from_slice::<Result<(), HttpServerError>>(&resp_bytes)
            .map_err(|_| HttpServerError::UnexpectedResponse)?;

        if resp.is_ok() {
            entry.authenticated = config.authenticated;
            entry.local_only = config.local_only;
            entry.secure_subdomain = config.secure_subdomain;
            entry.static_content = config.static_content;
        }
        resp
    }

    pub async fn modify_ws_path(
        &mut self,
        path: &str,
        config: WsBindingConfig,
    ) -> Result<(), HttpServerError> {
        let entry = self
            .ws_paths
            .get_mut(path)
            .ok_or(HttpServerError::MalformedRequest)?;
        let req = KiRequest::to(("our", "http-server", "distro", "sys"))
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
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(req).await.map_err(|_| HttpServerError::Timeout)?;
        let resp = serde_json::from_slice::<Result<(), HttpServerError>>(&resp_bytes)
            .map_err(|_| HttpServerError::UnexpectedResponse)?;

        if resp.is_ok() {
            entry.authenticated = config.authenticated;
            entry.secure_subdomain = config.secure_subdomain;
            entry.extension = config.extension;
        }
        resp
    }

    pub async fn unbind_http_path<T>(&mut self, path: T) -> Result<(), HttpServerError>
    where
        T: Into<String>,
    {
        let path: String = path.into();
        let req = KiRequest::to(("our", "http-server", "distro", "sys"))
            .body(serde_json::to_vec(&HttpServerAction::Unbind { path: path.clone() }).unwrap())
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(req).await.map_err(|_| HttpServerError::Timeout)?;
        let resp = serde_json::from_slice::<Result<(), HttpServerError>>(&resp_bytes)
            .map_err(|_| HttpServerError::UnexpectedResponse)?;

        if resp.is_ok() {
            self.http_paths.remove(&path);
        }
        resp
    }

    pub async fn unbind_ws_path<T>(&mut self, path: T) -> Result<(), HttpServerError>
    where
        T: Into<String>,
    {
        let path: String = path.into();
        let req = KiRequest::to(("our", "http-server", "distro", "sys"))
            .body(
                serde_json::to_vec(&HttpServerAction::WebSocketUnbind { path: path.clone() })
                    .unwrap(),
            )
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(req).await.map_err(|_| HttpServerError::Timeout)?;
        let resp = serde_json::from_slice::<Result<(), HttpServerError>>(&resp_bytes)
            .map_err(|_| HttpServerError::UnexpectedResponse)?;

        if resp.is_ok() {
            self.ws_paths.remove(&path);
        }
        resp
    }

    pub async fn serve_file(
        &mut self,
        file_path: &str,
        paths: Vec<&str>,
        config: HttpBindingConfig,
    ) -> Result<(), HttpServerError> {
        use crate::vfs::{VfsAction, VfsRequest};
        use crate::get_blob;
        
        let our = crate::our();
        let req = KiRequest::to(("our", "vfs", "distro", "sys"))
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
            .expects_response(self.timeout);

        let _res = hyperapp::send_rmp::<Vec<u8>>(req).await.map_err(|_| HttpServerError::Timeout)?;

        let Some(mut blob) = get_blob() else {
            return Err(HttpServerError::NoBlob);
        };

        let content_type = get_mime_type(&file_path);
        blob.mime = Some(content_type);

        for path in paths {
            self.bind_http_path(path, config.clone().static_content(Some(blob.clone()))).await?;
        }

        Ok(())
    }

    pub async fn serve_file_raw_path(
        &mut self,
        file_path: &str,
        paths: Vec<&str>,
        config: HttpBindingConfig,
    ) -> Result<(), HttpServerError> {
        use crate::vfs::{VfsAction, VfsRequest};
        use crate::get_blob;
        
        let req = KiRequest::to(("our", "vfs", "distro", "sys"))
            .body(
                serde_json::to_vec(&VfsRequest {
                    path: file_path.to_string(),
                    action: VfsAction::Read,
                })
                .map_err(|_| HttpServerError::MalformedRequest)?,
            )
            .expects_response(self.timeout);

        let _res = hyperapp::send_rmp::<Vec<u8>>(req).await.map_err(|_| HttpServerError::Timeout)?;

        let Some(mut blob) = get_blob() else {
            return Err(HttpServerError::NoBlob);
        };

        let content_type = get_mime_type(&file_path);
        blob.mime = Some(content_type);

        for path in paths {
            self.bind_http_path(path, config.clone().static_content(Some(blob.clone()))).await?;
        }

        Ok(())
    }


    pub async fn serve_ui(
        &mut self,
        directory: &str,
        roots: Vec<&str>,
        config: HttpBindingConfig,
    ) -> Result<(), HttpServerError> {
        use crate::vfs::{FileType, VfsAction, VfsRequest, VfsResponse};

        let our = crate::our();
        let initial_path = format!("{}/pkg/{}", our.package_id(), directory);

        let mut queue = std::collections::VecDeque::new();
        queue.push_back(initial_path.clone());

        while let Some(path) = queue.pop_front() {
            let req = crate::Request::to(("our", "vfs", "distro", "sys"))
                .body(
                    serde_json::to_vec(&VfsRequest {
                        path,
                        action: VfsAction::ReadDir,
                    })
                    .unwrap(),
                )
                .expects_response(self.timeout);

            let directory_response = hyperapp::send_rmp::<Vec<u8>>(req).await.map_err(|_| HttpServerError::Timeout)?;
            let directory_body = serde_json::from_slice::<VfsResponse>(&directory_response)
                .map_err(|_e| HttpServerError::UnexpectedResponse)?;

            let VfsResponse::ReadDir(directory_info) = directory_body else {
                return Err(HttpServerError::UnexpectedResponse);
            };

            for entry in directory_info {
                match entry.file_type {
                    FileType::Directory => {
                        queue.push_back(entry.path);
                    }
                    FileType::File => {
                        let relative_path = entry.path.replace(&initial_path, "");
                        let is_index = entry.path.ends_with("index.html");

                        self.serve_file_raw_path(&entry.path, vec![relative_path.as_str()], config.clone()).await?;

                        if is_index {
                            for root in &roots {
                                self.serve_file_raw_path(&entry.path, vec![root], config.clone()).await?;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    pub async fn unserve_ui(&mut self, directory: &str, roots: Vec<&str>) -> Result<(), HttpServerError> {
        use crate::vfs::{FileType, VfsAction, VfsRequest, VfsResponse};

        let our = crate::our();
        let initial_path = format!("{}/pkg/{}", our.package_id(), directory);

        let mut queue = std::collections::VecDeque::new();
        queue.push_back(initial_path.clone());

        while let Some(path) = queue.pop_front() {
            let req = crate::Request::to(("our", "vfs", "distro", "sys"))
                .body(
                    serde_json::to_vec(&VfsRequest {
                        path,
                        action: VfsAction::ReadDir,
                    })
                    .unwrap(),
                )
                .expects_response(self.timeout);

            let directory_response = hyperapp::send_rmp::<Vec<u8>>(req).await.map_err(|_| HttpServerError::Timeout)?;
            let directory_body = serde_json::from_slice::<VfsResponse>(&directory_response)
                .map_err(|_e| HttpServerError::UnexpectedResponse)?;

            let VfsResponse::ReadDir(directory_info) = directory_body else {
                return Err(HttpServerError::UnexpectedResponse);
            };

            for entry in directory_info {
                match entry.file_type {
                    FileType::Directory => {
                        queue.push_back(entry.path);
                    }
                    FileType::File => {
                        let relative_path = entry.path.replace(&initial_path, "");
                        let is_index = entry.path.ends_with("index.html");

                        self.unbind_http_path(relative_path.as_str()).await?;

                        if is_index {
                            for root in &roots {
                                self.unbind_http_path(*root).await?;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    pub fn handle_websocket_open(&mut self, path: &str, channel_id: u32) {
        self.ws_channels
            .entry(path.to_string())
            .or_insert(HashSet::new())
            .insert(channel_id);
    }

    pub fn handle_websocket_close(&mut self, channel_id: u32) {
        self.ws_channels.iter_mut().for_each(|(_, channels)| {
            channels.remove(&channel_id);
        });
    }
}

fn get_mime_type(path: &str) -> String {
    let ext = path.split('.').last().unwrap_or("");
    match ext {
        "html" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }.to_string()
}