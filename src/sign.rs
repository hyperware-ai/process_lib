use crate::{last_blob, Address, Request};
// TODO: use WIT types

pub fn net_key_sign(message: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    Request::to(("our", "sign", "sign", "sys"))
        .body("\"NetKeySign\"")
        .blob_bytes(message)
        .send_and_await_response(10)??;
    Ok(last_blob().unwrap().bytes)
}

pub fn net_key_verify(
    message: Vec<u8>,
    signer: &Address,
    signature: Vec<u8>,
) -> anyhow::Result<bool> {
    let response = Request::to(("our", "sign", "sign", "sys"))
        .body(
            serde_json::json!({
                "NetKeyVerify": {
                    "node": signer,
                    "signature": signature,
                }
            })
            .to_string(),
        )
        .blob_bytes(message)
        .send_and_await_response(10)??;

    let response: serde_json::Value = serde_json::from_slice(response.body())?;
    let serde_json::Value::Bool(response) = response["NetKeyVerify"] else {
        return Err(anyhow::anyhow!(
            "unexpected response from sign:sign:sys: {response}"
        ));
    };

    Ok(response)
}
