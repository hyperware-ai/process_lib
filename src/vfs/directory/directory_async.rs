use crate::{
    hyperapp,
    vfs::{vfs_request, VfsAction, VfsError, VfsResponse, parse_response},
    Request,
};

/// Removes a dir at path, errors if path not found or path is not a `Directory`.
pub async fn remove_dir_async(path: &str, timeout: Option<u64>) -> Result<(), VfsError> {
    let timeout = timeout.unwrap_or(5);

    let request = vfs_request(path, VfsAction::RemoveDir).expects_response(timeout);
    
    let response = hyperapp::send::<VfsResponse>(request).await.map_err(|_| VfsError::SendError(crate::SendErrorKind::Timeout))?;

    match response {
        VfsResponse::Ok => Ok(()),
        VfsResponse::Err(e) => Err(e),
        _ => Err(VfsError::ParseError {
            error: "unexpected response".to_string(),
            path: path.to_string(),
        }),
    }
}