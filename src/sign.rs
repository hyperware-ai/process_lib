use std::fmt;

use serde::{
    de::{self, MapAccess, Visitor},
    ser::{SerializeMap, SerializeStruct},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::hyperware::process::sign::{
    NetKeyVerifyRequest, Request as SignRequest, Response as SignResponse,
};
use crate::{last_blob, Address, Request};

pub fn net_key_sign(message: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let response = Request::to(("our", "sign", "sign", "sys"))
        .body(serde_json::to_vec(&SignRequest::NetKeySign).unwrap())
        .blob_bytes(message)
        .send_and_await_response(10)??;

    let SignResponse::NetKeySign = serde_json::from_slice(response.body())? else {
        return Err(anyhow::anyhow!(
            "unexpected response from sign:sign:sys: {}",
            String::from_utf8(response.body().into()).unwrap_or_default(),
        ));
    };

    Ok(last_blob().unwrap().bytes)
}

pub fn net_key_verify(
    message: Vec<u8>,
    signer: &Address,
    signature: Vec<u8>,
) -> anyhow::Result<bool> {
    let response = Request::to(("our", "sign", "sign", "sys"))
        .body(
            serde_json::to_vec(&SignRequest::NetKeyVerify(NetKeyVerifyRequest {
                node: signer.to_string(),
                signature,
            }))
            .unwrap(),
        )
        .blob_bytes(message)
        .send_and_await_response(10)??;

    let SignResponse::NetKeyVerify(response) = serde_json::from_slice(response.body())? else {
        return Err(anyhow::anyhow!(
            "unexpected response from sign:sign:sys: {}",
            String::from_utf8(response.body().into()).unwrap_or_default(),
        ));
    };

    Ok(response)
}

impl Serialize for NetKeyVerifyRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("NetKeyVerifyRequest", 2)?;
        state.serialize_field("node", &self.node)?;
        state.serialize_field("signature", &self.signature)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for NetKeyVerifyRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Node,
            Signature,
        }

        struct NetKeyVerifyRequestVisitor;

        impl<'de> Visitor<'de> for NetKeyVerifyRequestVisitor {
            type Value = NetKeyVerifyRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct NetKeyVerifyRequest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<NetKeyVerifyRequest, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut node = None;
                let mut signature = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Node => {
                            if node.is_some() {
                                return Err(de::Error::duplicate_field("node"));
                            }
                            node = Some(map.next_value()?);
                        }
                        Field::Signature => {
                            if signature.is_some() {
                                return Err(de::Error::duplicate_field("signature"));
                            }
                            signature = Some(map.next_value()?);
                        }
                    }
                }

                let node = node.ok_or_else(|| de::Error::missing_field("node"))?;
                let signature = signature.ok_or_else(|| de::Error::missing_field("signature"))?;

                Ok(NetKeyVerifyRequest { node, signature })
            }
        }

        deserializer.deserialize_struct(
            "NetKeyVerifyRequest",
            &["node", "signature"],
            NetKeyVerifyRequestVisitor,
        )
    }
}

impl Serialize for SignRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            SignRequest::NetKeySign => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("NetKeySign", &())?;
                map.end()
            }
            SignRequest::NetKeyVerify(request) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("NetKeyVerify", request)?;
                map.end()
            }
            SignRequest::NetKeyMakeMessage => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("NetKeyMakeMessage", &())?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for SignRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SignRequestVisitor;

        impl<'de> Visitor<'de> for SignRequestVisitor {
            type Value = SignRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with a single key representing the SignRequest variant")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let (variant, value) = map
                    .next_entry::<String, serde_json::Value>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                match variant.as_str() {
                    "NetKeySign" => Ok(SignRequest::NetKeySign),
                    "NetKeyVerify" => {
                        let request = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(SignRequest::NetKeyVerify(request))
                    }
                    "NetKeyMakeMessage" => Ok(SignRequest::NetKeyMakeMessage),
                    _ => Err(de::Error::unknown_variant(
                        &variant,
                        &["NetKeySign", "NetKeyVerify", "NetKeyMakeMessage"],
                    )),
                }
            }
        }

        deserializer.deserialize_map(SignRequestVisitor)
    }
}

impl Serialize for SignResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            SignResponse::NetKeySign => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("NetKeySign", &())?;
                map.end()
            }
            SignResponse::NetKeyVerify(valid) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("NetKeyVerify", valid)?;
                map.end()
            }
            SignResponse::NetKeyMakeMessage => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("NetKeyMakeMessage", &())?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for SignResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SignResponseVisitor;

        impl<'de> Visitor<'de> for SignResponseVisitor {
            type Value = SignResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with a single key representing the SignResponse variant")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let (variant, value) = map
                    .next_entry::<String, serde_json::Value>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                match variant.as_str() {
                    "NetKeySign" => Ok(SignResponse::NetKeySign),
                    "NetKeyVerify" => {
                        let valid = serde_json::from_value(value).map_err(de::Error::custom)?;
                        Ok(SignResponse::NetKeyVerify(valid))
                    }
                    "NetKeyMakeMessage" => Ok(SignResponse::NetKeyMakeMessage),
                    _ => Err(de::Error::unknown_variant(
                        &variant,
                        &["NetKeySign", "NetKeyVerify", "NetKeyMakeMessage"],
                    )),
                }
            }
        }

        deserializer.deserialize_map(SignResponseVisitor)
    }
}
