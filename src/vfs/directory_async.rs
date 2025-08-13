use super::{parse_response, vfs_request, DirEntry, FileType, VfsAction, VfsError, VfsResponse};
use crate::hyperapp;

pub struct DirectoryAsync {
    pub path: String,
    pub timeout: u64,
}

impl DirectoryAsync {
    pub async fn read(&self) -> Result<Vec<DirEntry>, VfsError> {
        let request = vfs_request(&self.path, VfsAction::ReadDir)
            .expects_response(self.timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|_| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::ReadDir(entries) => Ok(entries),
            VfsResponse::Err(e) => Err(e),
            _ => Err(VfsError::ParseError {
                error: "unexpected response".to_string(),
                path: self.path.clone(),
            }),
        }
    }
}

pub async fn open_dir_async(path: &str, create: bool, timeout: Option<u64>) -> Result<DirectoryAsync, VfsError> {
    let timeout = timeout.unwrap_or(5);
    if !create {
        let request = vfs_request(path, VfsAction::Metadata)
            .expects_response(timeout);

        let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
            .await
            .map_err(|_| VfsError::SendError(crate::SendErrorKind::Timeout))?;

        match parse_response(&resp_bytes)? {
            VfsResponse::Metadata(m) => {
                if m.file_type != FileType::Directory {
                    return Err(VfsError::IOError(
                        "entry at path is not a directory".to_string(),
                    ));
                }
            }
            VfsResponse::Err(e) => return Err(e),
            _ => {
                return Err(VfsError::ParseError {
                    error: "unexpected response".to_string(),
                    path: path.to_string(),
                })
            }
        }

        return Ok(DirectoryAsync {
            path: path.to_string(),
            timeout,
        });
    }

    let request = vfs_request(path, VfsAction::CreateDirAll)
        .expects_response(timeout);

    let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
        .await
        .map_err(|_| VfsError::SendError(crate::SendErrorKind::Timeout))?;

    match parse_response(&resp_bytes)? {
        VfsResponse::Ok => Ok(DirectoryAsync {
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

pub async fn remove_dir_async(path: &str, timeout: Option<u64>) -> Result<(), VfsError> {
    let timeout = timeout.unwrap_or(5);

    let request = vfs_request(path, VfsAction::RemoveDir)
        .expects_response(timeout);

    let resp_bytes = hyperapp::send_rmp::<Vec<u8>>(request)
        .await
        .map_err(|_| VfsError::SendError(crate::SendErrorKind::Timeout))?;

    match parse_response(&resp_bytes)? {
        VfsResponse::Ok => Ok(()),
        VfsResponse::Err(e) => Err(e),
        _ => Err(VfsError::ParseError {
            error: "unexpected response".to_string(),
            path: path.to_string(),
        }),
    }
}