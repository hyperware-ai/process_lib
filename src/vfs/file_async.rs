use super::{
    parse_response, vfs_request, FileMetadata, SeekFrom, VfsAction, VfsError, VfsResponse,
};
use crate::{get_blob, hyperapp, PackageId};

#[derive(serde::Deserialize, serde::Serialize)]
pub struct FileAsync {
    pub path: String,
    pub timeout: u64,
}

impl FileAsync {
    pub fn new<T: Into<String>>(path: T, timeout: u64) -> Self {
        Self {
            path: path.into(),
            timeout,
        }
    }

    pub async fn read(&self) -> Result<Vec<u8>, VfsError> {
        let request = vfs_request(&self.path, VfsAction::Read)
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::Read => {
                let data = match get_blob() {
                    Some(bytes) => bytes.bytes,
                    None => {
                        return Err(VfsError::ParseError {
                            error: "no blob".to_string(),
                            path: self.path.clone(),
                        })
                    }
                };
                Ok(data)
            }
            VfsResponse::Err(e) => Err(e.into()),
            _ => Err(VfsError::ParseError {
                error: "unexpected response".to_string(),
                path: self.path.clone(),
            }),
        }
    }

    pub async fn read_into(&self, buffer: &mut [u8]) -> Result<usize, VfsError> {
        let request = vfs_request(&self.path, VfsAction::Read)
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::Read => {
                let data = get_blob().unwrap_or_default().bytes;
                let len = std::cmp::min(data.len(), buffer.len());
                buffer[..len].copy_from_slice(&data[..len]);
                Ok(len)
            }
            VfsResponse::Err(e) => Err(e.into()),
            _ => Err(VfsError::ParseError {
                error: "unexpected response".to_string(),
                path: self.path.clone(),
            }),
        }
    }

    pub async fn read_at(&self, buffer: &mut [u8]) -> Result<usize, VfsError> {
        let length = buffer.len() as u64;

        let request = vfs_request(&self.path, VfsAction::ReadExact { length })
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::Read => {
                let data = get_blob().unwrap_or_default().bytes;
                let len = std::cmp::min(data.len(), buffer.len());
                buffer[..len].copy_from_slice(&data[..len]);
                Ok(len)
            }
            VfsResponse::Err(e) => Err(e.into()),
            _ => Err(VfsError::ParseError {
                error: "unexpected response".to_string(),
                path: self.path.clone(),
            }),
        }
    }

    pub async fn read_to_end(&self) -> Result<Vec<u8>, VfsError> {
        let request = vfs_request(&self.path, VfsAction::ReadToEnd)
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::Read => Ok(get_blob().unwrap_or_default().bytes),
            VfsResponse::Err(e) => Err(e),
            _ => Err(VfsError::ParseError {
                error: "unexpected response".to_string(),
                path: self.path.clone(),
            }),
        }
    }

    pub async fn read_to_string(&self) -> Result<String, VfsError> {
        let request = vfs_request(&self.path, VfsAction::ReadToString)
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::ReadToString(s) => Ok(s),
            VfsResponse::Err(e) => Err(e),
            _ => Err(VfsError::ParseError {
                error: "unexpected response".to_string(),
                path: self.path.clone(),
            }),
        }
    }

    pub async fn write(&self, buffer: &[u8]) -> Result<(), VfsError> {
        let request = vfs_request(&self.path, VfsAction::Write)
            .blob_bytes(buffer)
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::Ok => Ok(()),
            VfsResponse::Err(e) => Err(e),
            _ => Err(VfsError::ParseError {
                error: "unexpected response".to_string(),
                path: self.path.clone(),
            }),
        }
    }

    pub async fn write_all(&mut self, buffer: &[u8]) -> Result<(), VfsError> {
        let request = vfs_request(&self.path, VfsAction::WriteAll)
            .blob_bytes(buffer)
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::Ok => Ok(()),
            VfsResponse::Err(e) => Err(e),
            _ => Err(VfsError::ParseError {
                error: "unexpected response".to_string(),
                path: self.path.clone(),
            }),
        }
    }

    pub async fn append(&mut self, buffer: &[u8]) -> Result<(), VfsError> {
        let request = vfs_request(&self.path, VfsAction::Append)
            .blob_bytes(buffer)
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::Ok => Ok(()),
            VfsResponse::Err(e) => Err(e),
            _ => Err(VfsError::ParseError {
                error: "unexpected response".to_string(),
                path: self.path.clone(),
            }),
        }
    }

    pub async fn seek(&mut self, pos: SeekFrom) -> Result<u64, VfsError> {
        let request = vfs_request(&self.path, VfsAction::Seek(pos))
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::SeekFrom {
                new_offset: new_pos,
            } => Ok(new_pos),
            VfsResponse::Err(e) => Err(e),
            _ => Err(VfsError::ParseError {
                error: "unexpected response".to_string(),
                path: self.path.clone(),
            }),
        }
    }

    pub async fn copy(&mut self, path: &str) -> Result<FileAsync, VfsError> {
        let request = vfs_request(
            &self.path,
            VfsAction::CopyFile {
                new_path: path.to_string(),
            },
        )
        .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::Ok => Ok(FileAsync {
                path: path.to_string(),
                timeout: self.timeout,
            }),
            VfsResponse::Err(e) => Err(e),
            _ => Err(VfsError::ParseError {
                error: "unexpected response".to_string(),
                path: self.path.clone(),
            }),
        }
    }

    pub async fn set_len(&mut self, size: u64) -> Result<(), VfsError> {
        let request = vfs_request(&self.path, VfsAction::SetLen(size))
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::Ok => Ok(()),
            VfsResponse::Err(e) => Err(e),
            _ => Err(VfsError::ParseError {
                error: "unexpected response".to_string(),
                path: self.path.clone(),
            }),
        }
    }

    pub async fn metadata(&self) -> Result<FileMetadata, VfsError> {
        let request = vfs_request(&self.path, VfsAction::Metadata)
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::Metadata(metadata) => Ok(metadata),
            VfsResponse::Err(e) => Err(e),
            _ => Err(VfsError::ParseError {
                error: "unexpected response".to_string(),
                path: self.path.clone(),
            }),
        }
    }

    pub async fn sync_all(&self) -> Result<(), VfsError> {
        let request = vfs_request(&self.path, VfsAction::SyncAll)
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::Ok => Ok(()),
            VfsResponse::Err(e) => Err(e),
            _ => Err(VfsError::ParseError {
                error: "unexpected response".to_string(),
                path: self.path.clone(),
            }),
        }
    }
}

impl Drop for FileAsync {
    fn drop(&mut self) {
        vfs_request(&self.path, VfsAction::CloseFile)
            .send()
            .unwrap();
    }
}

pub async fn create_drive_async(
    package_id: PackageId,
    drive: &str,
    timeout: Option<u64>,
) -> Result<String, VfsError> {
    let timeout = timeout.unwrap_or(5);
    let path = format!("/{}/{}", package_id, drive);

    let request = vfs_request(&path, VfsAction::CreateDrive)
        .expects_response(timeout);

    let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
        .await
        .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

    match parse_response(&resp_bytes)? {
        VfsResponse::Ok => Ok(path),
        VfsResponse::Err(e) => Err(e),
        _ => Err(VfsError::ParseError {
            error: "unexpected response".to_string(),
            path,
        }),
    }
}

pub async fn open_file_async(path: &str, create: bool, timeout: Option<u64>) -> Result<FileAsync, VfsError> {
    let timeout = timeout.unwrap_or(5);

    let request = vfs_request(path, VfsAction::OpenFile { create })
        .expects_response(timeout);

    let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
        .await
        .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

    match parse_response(&resp_bytes)? {
        VfsResponse::Ok => Ok(FileAsync {
            path: path.to_string(),
            timeout,
        }),
        VfsResponse::Err(e) => Err(e),
        _ => Err(VfsError::ParseError {
            error: "unexpected response".to_string(),
            path: path.to_string(),
        }),
    }
}

pub async fn create_file_async(path: &str, timeout: Option<u64>) -> Result<FileAsync, VfsError> {
    let timeout = timeout.unwrap_or(5);

    let request = vfs_request(path, VfsAction::CreateFile)
        .expects_response(timeout);

    let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
        .await
        .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

    match parse_response(&resp_bytes)? {
        VfsResponse::Ok => Ok(FileAsync {
            path: path.to_string(),
            timeout,
        }),
        VfsResponse::Err(e) => Err(e),
        _ => Err(VfsError::ParseError {
            error: "unexpected response".to_string(),
            path: path.to_string(),
        }),
    }
}

pub async fn remove_file_async(path: &str, timeout: Option<u64>) -> Result<(), VfsError> {
    let timeout = timeout.unwrap_or(5);

    let request = vfs_request(path, VfsAction::RemoveFile)
        .expects_response(timeout);

    let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
        .await
        .map_err(|e| VfsError::SendError(crate::SendErrorKind::Timeout))?;

    match parse_response(&resp_bytes)? {
        VfsResponse::Ok => Ok(()),
        VfsResponse::Err(e) => Err(e.into()),
        _ => Err(VfsError::ParseError {
            error: "unexpected response".to_string(),
            path: path.to_string(),
        }),
    }
}