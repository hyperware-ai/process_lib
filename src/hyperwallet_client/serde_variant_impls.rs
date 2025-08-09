use crate::hyperware::process::hyperwallet as wit;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeStruct};
use serde::Deserialize;

// ============================================================================
// HyperwalletRequest variant type
// ============================================================================

impl Serialize for wit::HyperwalletRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use wit::HyperwalletRequest::*;

        let mut state = serializer.serialize_struct("HyperwalletRequest", 2)?;

        match self {
            Handshake(data) => {
                state.serialize_field("type", "Handshake")?;
                state.serialize_field("data", data)?;
            }
            UnlockWallet(data) => {
                state.serialize_field("type", "UnlockWallet")?;
                state.serialize_field("data", data)?;
            }
            UpdateSpendingLimits(data) => {
                state.serialize_field("type", "UpdateSpendingLimits")?;
                state.serialize_field("data", data)?;
            }
            CreateWallet(data) => {
                state.serialize_field("type", "CreateWallet")?;
                state.serialize_field("data", data)?;
            }
            ImportWallet(data) => {
                state.serialize_field("type", "ImportWallet")?;
                state.serialize_field("data", data)?;
            }
            DeleteWallet(data) => {
                state.serialize_field("type", "DeleteWallet")?;
                state.serialize_field("data", data)?;
            }
            RenameWallet(data) => {
                state.serialize_field("type", "RenameWallet")?;
                state.serialize_field("data", data)?;
            }
            ExportWallet(data) => {
                state.serialize_field("type", "ExportWallet")?;
                state.serialize_field("data", data)?;
            }
            ListWallets => {
                state.serialize_field("type", "ListWallets")?;
                state.serialize_field("data", &serde_json::Value::Null)?;
            }
            GetWalletInfo(data) => {
                state.serialize_field("type", "GetWalletInfo")?;
                state.serialize_field("data", data)?;
            }
            SendEth(data) => {
                state.serialize_field("type", "SendEth")?;
                state.serialize_field("data", data)?;
            }
            SendToken(data) => {
                state.serialize_field("type", "SendToken")?;
                state.serialize_field("data", data)?;
            }
            ApproveToken(data) => {
                state.serialize_field("type", "ApproveToken")?;
                state.serialize_field("data", data)?;
            }
            GetBalance(data) => {
                state.serialize_field("type", "GetBalance")?;
                state.serialize_field("data", data)?;
            }
            GetTokenBalance(data) => {
                state.serialize_field("type", "GetTokenBalance")?;
                state.serialize_field("data", data)?;
            }
            CallContract(data) => {
                state.serialize_field("type", "CallContract")?;
                state.serialize_field("data", data)?;
            }
            SignTransaction(data) => {
                state.serialize_field("type", "SignTransaction")?;
                state.serialize_field("data", data)?;
            }
            SignMessage(data) => {
                state.serialize_field("type", "SignMessage")?;
                state.serialize_field("data", data)?;
            }
            BuildAndSignUserOperationForPayment(data) => {
                state.serialize_field("type", "BuildAndSignUserOperationForPayment")?;
                state.serialize_field("data", data)?;
            }
            SubmitUserOperation(data) => {
                state.serialize_field("type", "SubmitUserOperation")?;
                state.serialize_field("data", data)?;
            }
            GetUserOperationReceipt(data) => {
                state.serialize_field("type", "GetUserOperationReceipt")?;
                state.serialize_field("data", data)?;
            }
            GetTransactionHistory(data) => {
                state.serialize_field("type", "GetTransactionHistory")?;
                state.serialize_field("data", data)?;
            }
            EstimateGas(data) => {
                state.serialize_field("type", "EstimateGas")?;
                state.serialize_field("data", data)?;
            }
            GetGasPrice => {
                state.serialize_field("type", "GetGasPrice")?;
                state.serialize_field("data", &serde_json::Value::Null)?;
            }
            GetTransactionReceipt(data) => {
                state.serialize_field("type", "GetTransactionReceipt")?;
                state.serialize_field("data", data)?;
            }
            BuildUserOperation(data) => {
                state.serialize_field("type", "BuildUserOperation")?;
                state.serialize_field("data", data)?;
            }
            SignUserOperation(data) => {
                state.serialize_field("type", "SignUserOperation")?;
                state.serialize_field("data", data)?;
            }
            BuildAndSignUserOperation(data) => {
                state.serialize_field("type", "BuildAndSignUserOperation")?;
                state.serialize_field("data", data)?;
            }
            EstimateUserOperationGas(data) => {
                state.serialize_field("type", "EstimateUserOperationGas")?;
                state.serialize_field("data", data)?;
            }
            ConfigurePaymaster(data) => {
                state.serialize_field("type", "ConfigurePaymaster")?;
                state.serialize_field("data", data)?;
            }
            ExecuteViaTba(data) => {
                state.serialize_field("type", "ExecuteViaTba")?;
                state.serialize_field("data", data)?;
            }
            CheckTbaOwnership(data) => {
                state.serialize_field("type", "CheckTbaOwnership")?;
                state.serialize_field("data", data)?;
            }
            SetupTbaDelegation(data) => {
                state.serialize_field("type", "SetupTbaDelegation")?;
                state.serialize_field("data", data)?;
            }
            CreateNote(data) => {
                state.serialize_field("type", "CreateNote")?;
                state.serialize_field("data", data)?;
            }
            ReadNote(data) => {
                state.serialize_field("type", "ReadNote")?;
                state.serialize_field("data", data)?;
            }
            ResolveIdentity(data) => {
                state.serialize_field("type", "ResolveIdentity")?;
                state.serialize_field("data", data)?;
            }
            SetupDelegation(data) => {
                state.serialize_field("type", "SetupDelegation")?;
                state.serialize_field("data", data)?;
            }
            VerifyDelegation(data) => {
                state.serialize_field("type", "VerifyDelegation")?;
                state.serialize_field("data", data)?;
            }
            MintEntry(data) => {
                state.serialize_field("type", "MintEntry")?;
                state.serialize_field("data", data)?;
            }
            SetWalletLimits(data) => {
                state.serialize_field("type", "SetWalletLimits")?;
                state.serialize_field("data", data)?;
            }
        }

        state.end()
    }
}

impl<'a> Deserialize<'a> for wit::HyperwalletRequest {
    fn deserialize<D>(deserializer: D) -> Result<wit::HyperwalletRequest, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        struct HyperwalletRequestVisitor;

        impl<'de> Visitor<'de> for HyperwalletRequestVisitor {
            type Value = wit::HyperwalletRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a HyperwalletRequest variant")
            }

            fn visit_map<V>(self, mut map: V) -> Result<wit::HyperwalletRequest, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut variant_type = None;
                let mut data = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => {
                            if variant_type.is_some() {
                                return Err(de::Error::duplicate_field("type"));
                            }
                            variant_type = Some(map.next_value::<String>()?);
                        }
                        "data" => {
                            if data.is_some() {
                                return Err(de::Error::duplicate_field("data"));
                            }
                            data = Some(map.next_value::<serde_json::Value>()?);
                        }
                        _ => {
                            let _ = map.next_value::<serde_json::Value>()?;
                        }
                    }
                }

                let variant_type = variant_type.ok_or_else(|| de::Error::missing_field("type"))?;

                use wit::HyperwalletRequest::*;
                match variant_type.as_str() {
                    "Handshake" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let step = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!("Failed to deserialize HandshakeStep: {}", e))
                        })?;
                        Ok(Handshake(step))
                    }
                    "ImportWallet" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize ImportWalletRequest: {}",
                                e
                            ))
                        })?;
                        Ok(ImportWallet(req))
                    }
                    "DeleteWallet" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize DeleteWalletRequest: {}",
                                e
                            ))
                        })?;
                        Ok(DeleteWallet(req))
                    }
                    "RenameWallet" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize RenameWalletRequest: {}",
                                e
                            ))
                        })?;
                        Ok(RenameWallet(req))
                    }
                    "ExportWallet" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize ExportWalletRequest: {}",
                                e
                            ))
                        })?;
                        Ok(ExportWallet(req))
                    }
                    "UnlockWallet" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize UnlockWalletRequest: {}",
                                e
                            ))
                        })?;
                        Ok(UnlockWallet(req))
                    }
                    "CreateWallet" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize CreateWalletRequest: {}",
                                e
                            ))
                        })?;
                        Ok(CreateWallet(req))
                    }
                    "ListWallets" => Ok(ListWallets),
                    "GetWalletInfo" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize GetWalletInfoRequest: {}",
                                e
                            ))
                        })?;
                        Ok(GetWalletInfo(req))
                    }
                    "SendEth" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize SendEthRequest: {}",
                                e
                            ))
                        })?;
                        Ok(SendEth(req))
                    }
                    "SendToken" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize SendTokenRequest: {}",
                                e
                            ))
                        })?;
                        Ok(SendToken(req))
                    }
                    "ApproveToken" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize ApproveTokenRequest: {}",
                                e
                            ))
                        })?;
                        Ok(ApproveToken(req))
                    }
                    "GetBalance" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize GetBalanceRequest: {}",
                                e
                            ))
                        })?;
                        Ok(GetBalance(req))
                    }
                    "GetTokenBalance" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize GetTokenBalanceRequest: {}",
                                e
                            ))
                        })?;
                        Ok(GetTokenBalance(req))
                    }
                    "CallContract" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize CallContractRequest: {}",
                                e
                            ))
                        })?;
                        Ok(CallContract(req))
                    }
                    "SignTransaction" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize SignTransactionRequest: {}",
                                e
                            ))
                        })?;
                        Ok(SignTransaction(req))
                    }
                    "SignMessage" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize SignMessageRequest: {}",
                                e
                            ))
                        })?;
                        Ok(SignMessage(req))
                    }
                    "GetTransactionHistory" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize GetTransactionHistoryRequest: {}",
                                e
                            ))
                        })?;
                        Ok(GetTransactionHistory(req))
                    }
                    "EstimateGas" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize EstimateGasRequest: {}",
                                e
                            ))
                        })?;
                        Ok(EstimateGas(req))
                    }
                    "GetGasPrice" => Ok(GetGasPrice),
                    "GetTransactionReceipt" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize GetTransactionReceiptRequest: {}",
                                e
                            ))
                        })?;
                        Ok(GetTransactionReceipt(req))
                    }
                    "BuildAndSignUserOperationForPayment" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize BuildAndSignUserOperationForPaymentRequest: {}",
                                e
                            ))
                        })?;
                        Ok(BuildAndSignUserOperationForPayment(req))
                    }
                    "SubmitUserOperation" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize SubmitUserOperationRequest: {}",
                                e
                            ))
                        })?;
                        Ok(SubmitUserOperation(req))
                    }
                    "GetUserOperationReceipt" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize GetUserOperationReceiptRequest: {}",
                                e
                            ))
                        })?;
                        Ok(GetUserOperationReceipt(req))
                    }
                    "SetWalletLimits" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize SetWalletLimitsRequest: {}",
                                e
                            ))
                        })?;
                        Ok(SetWalletLimits(req))
                    }
                    "BuildUserOperation" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize BuildUserOperationRequest: {}",
                                e
                            ))
                        })?;
                        Ok(BuildUserOperation(req))
                    }
                    "SignUserOperation" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize SignUserOperationRequest: {}",
                                e
                            ))
                        })?;
                        Ok(SignUserOperation(req))
                    }
                    "BuildAndSignUserOperation" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize BuildAndSignUserOperationRequest: {}",
                                e
                            ))
                        })?;
                        Ok(BuildAndSignUserOperation(req))
                    }
                    "EstimateUserOperationGas" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize EstimateUserOperationGasRequest: {}",
                                e
                            ))
                        })?;
                        Ok(EstimateUserOperationGas(req))
                    }
                    "ConfigurePaymaster" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize ConfigurePaymasterRequest: {}",
                                e
                            ))
                        })?;
                        Ok(ConfigurePaymaster(req))
                    }
                    "ExecuteViaTba" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize ExecuteViaTbaRequest: {}",
                                e
                            ))
                        })?;
                        Ok(ExecuteViaTba(req))
                    }
                    "CheckTbaOwnership" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize CheckTbaOwnershipRequest: {}",
                                e
                            ))
                        })?;
                        Ok(CheckTbaOwnership(req))
                    }
                    "SetupTbaDelegation" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize SetupTbaDelegationRequest: {}",
                                e
                            ))
                        })?;
                        Ok(SetupTbaDelegation(req))
                    }
                    "CreateNote" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize CreateNoteRequest: {}",
                                e
                            ))
                        })?;
                        Ok(CreateNote(req))
                    }
                    "ReadNote" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize ReadNoteRequest: {}",
                                e
                            ))
                        })?;
                        Ok(ReadNote(req))
                    }
                    "ResolveIdentity" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize ResolveIdentityRequest: {}",
                                e
                            ))
                        })?;
                        Ok(ResolveIdentity(req))
                    }
                    "SetupDelegation" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize SetupDelegationRequest: {}",
                                e
                            ))
                        })?;
                        Ok(SetupDelegation(req))
                    }
                    "VerifyDelegation" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize VerifyDelegationRequest: {}",
                                e
                            ))
                        })?;
                        Ok(VerifyDelegation(req))
                    }
                    "MintEntry" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let req = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize MintEntryRequest: {}",
                                e
                            ))
                        })?;
                        Ok(MintEntry(req))
                    }
                    _ => {
                        // For unimplemented variants, return an error with helpful message
                        Err(de::Error::unknown_variant(
                            &variant_type,
                            &[
                                "Handshake",
                                "ImportWallet",
                                "DeleteWallet",
                                "RenameWallet",
                                "ExportWallet",
                                "UnlockWallet",
                                "CreateWallet",
                                "ListWallets",
                                "GetWalletInfo",
                                "SendEth",
                                "SendToken",
                                "ApproveToken",
                                "GetBalance",
                                "GetTokenBalance",
                                "CallContract",
                                "SignTransaction",
                                "SignMessage",
                                "GetTransactionHistory",
                                "EstimateGas",
                                "GetGasPrice",
                                "GetTransactionReceipt",
                                "BuildAndSignUserOperationForPayment",
                                "SubmitUserOperation",
                                "GetUserOperationReceipt",
                                "BuildUserOperation",
                                "SignUserOperation",
                                "BuildAndSignUserOperation",
                                "EstimateUserOperationGas",
                                "ConfigurePaymaster",
                                "ExecuteViaTba",
                                "CheckTbaOwnership",
                                "SetupTbaDelegation",
                                "CreateNote",
                                "ReadNote",
                                "ResolveIdentity",
                                "SetupDelegation",
                                "VerifyDelegation",
                                "MintEntry",
                            ],
                        ))
                    }
                }
            }
        }

        const FIELDS: &[&str] = &["type", "data"];
        deserializer.deserialize_struct("HyperwalletRequest", FIELDS, HyperwalletRequestVisitor)
    }
}

// ============================================================================
// HyperwalletResponseData variant type
// ============================================================================

impl Serialize for wit::HyperwalletResponseData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use wit::HyperwalletResponseData::*;

        let mut state = serializer.serialize_struct("HyperwalletResponseData", 2)?;

        match self {
            Handshake(data) => {
                state.serialize_field("type", "Handshake")?;
                state.serialize_field("data", data)?;
            }
            UnlockWallet(data) => {
                state.serialize_field("type", "UnlockWallet")?;
                state.serialize_field("data", data)?;
            }
            CreateWallet(data) => {
                state.serialize_field("type", "CreateWallet")?;
                state.serialize_field("data", data)?;
            }
            ImportWallet(data) => {
                state.serialize_field("type", "ImportWallet")?;
                state.serialize_field("data", data)?;
            }
            DeleteWallet(data) => {
                state.serialize_field("type", "DeleteWallet")?;
                state.serialize_field("data", data)?;
            }
            ExportWallet(data) => {
                state.serialize_field("type", "ExportWallet")?;
                state.serialize_field("data", data)?;
            }
            ListWallets(data) => {
                state.serialize_field("type", "ListWallets")?;
                state.serialize_field("data", data)?;
            }
            GetWalletInfo(data) => {
                state.serialize_field("type", "GetWalletInfo")?;
                state.serialize_field("data", data)?;
            }
            GetBalance(data) => {
                state.serialize_field("type", "GetBalance")?;
                state.serialize_field("data", data)?;
            }
            GetTokenBalance(data) => {
                state.serialize_field("type", "GetTokenBalance")?;
                state.serialize_field("data", data)?;
            }
            SendEth(data) => {
                state.serialize_field("type", "SendEth")?;
                state.serialize_field("data", data)?;
            }
            SendToken(data) => {
                state.serialize_field("type", "SendToken")?;
                state.serialize_field("data", data)?;
            }
            BuildAndSignUserOperationForPayment(data) => {
                state.serialize_field("type", "BuildAndSignUserOperationForPayment")?;
                state.serialize_field("data", data)?;
            }
            SubmitUserOperation(data) => {
                state.serialize_field("type", "SubmitUserOperation")?;
                state.serialize_field("data", data)?;
            }
            GetUserOperationReceipt(data) => {
                state.serialize_field("type", "GetUserOperationReceipt")?;
                state.serialize_field("data", data)?;
            }
            CreateNote(data) => {
                state.serialize_field("type", "CreateNote")?;
                state.serialize_field("data", data)?;
            }
            ExecuteViaTba(data) => {
                state.serialize_field("type", "ExecuteViaTba")?;
                state.serialize_field("data", data)?;
            }
            CheckTbaOwnership(data) => {
                state.serialize_field("type", "CheckTbaOwnership")?;
                state.serialize_field("data", data)?;
            }
            SetWalletLimits(data) => {
                state.serialize_field("type", "SetWalletLimits")?;
                state.serialize_field("data", data)?;
            }
        }

        state.end()
    }
}

impl<'a> Deserialize<'a> for wit::HyperwalletResponseData {
    fn deserialize<D>(deserializer: D) -> Result<wit::HyperwalletResponseData, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        struct HyperwalletResponseDataVisitor;

        impl<'de> Visitor<'de> for HyperwalletResponseDataVisitor {
            type Value = wit::HyperwalletResponseData;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a HyperwalletResponseData variant")
            }

            fn visit_map<V>(self, mut map: V) -> Result<wit::HyperwalletResponseData, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut variant_type = None;
                let mut data = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => {
                            if variant_type.is_some() {
                                return Err(de::Error::duplicate_field("type"));
                            }
                            variant_type = Some(map.next_value::<String>()?);
                        }
                        "data" => {
                            if data.is_some() {
                                return Err(de::Error::duplicate_field("data"));
                            }
                            data = Some(map.next_value::<serde_json::Value>()?);
                        }
                        _ => {
                            let _ = map.next_value::<serde_json::Value>()?;
                        }
                    }
                }

                let variant_type = variant_type.ok_or_else(|| de::Error::missing_field("type"))?;

                use wit::HyperwalletResponseData::*;
                match variant_type.as_str() {
                    "Handshake" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let step = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!("Failed to deserialize HandshakeStep: {}", e))
                        })?;
                        Ok(Handshake(step))
                    }
                    "ImportWallet" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize ImportWalletResponse: {}",
                                e
                            ))
                        })?;
                        Ok(ImportWallet(response))
                    }
                    "DeleteWallet" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize DeleteWalletResponse: {}",
                                e
                            ))
                        })?;
                        Ok(DeleteWallet(response))
                    }
                    "ExportWallet" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize ExportWalletResponse: {}",
                                e
                            ))
                        })?;
                        Ok(ExportWallet(response))
                    }
                    "ListWallets" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize ListWalletsResponse: {}",
                                e
                            ))
                        })?;
                        Ok(ListWallets(response))
                    }
                    "GetWalletInfo" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize GetWalletInfoResponse: {}",
                                e
                            ))
                        })?;
                        Ok(GetWalletInfo(response))
                    }
                    "CreateWallet" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize CreateWalletResponse: {}",
                                e
                            ))
                        })?;
                        Ok(CreateWallet(response))
                    }
                    "UnlockWallet" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize UnlockWalletResponse: {}",
                                e
                            ))
                        })?;
                        Ok(UnlockWallet(response))
                    }
                    "SendEth" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize SendEthResponse: {}",
                                e
                            ))
                        })?;
                        Ok(SendEth(response))
                    }
                    "SendToken" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize SendTokenResponse: {}",
                                e
                            ))
                        })?;
                        Ok(SendToken(response))
                    }
                    "BuildAndSignUserOperationForPayment" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize BuildAndSignUserOperationResponse: {}",
                                e
                            ))
                        })?;
                        Ok(BuildAndSignUserOperationForPayment(response))
                    }
                    "SubmitUserOperation" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize SubmitUserOperationResponse: {}",
                                e
                            ))
                        })?;
                        Ok(SubmitUserOperation(response))
                    }
                    "GetUserOperationReceipt" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize UserOperationReceiptResponse: {}",
                                e
                            ))
                        })?;
                        Ok(GetUserOperationReceipt(response))
                    }
                    "GetBalance" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize GetBalanceResponse: {}",
                                e
                            ))
                        })?;
                        Ok(GetBalance(response))
                    }
                    "GetTokenBalance" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize GetTokenBalanceResponse: {}",
                                e
                            ))
                        })?;
                        Ok(GetTokenBalance(response))
                    }
                    "SetWalletLimits" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize SetWalletLimitsResponse: {}",
                                e
                            ))
                        })?;
                        Ok(SetWalletLimits(response))
                    }
                    "CreateNote" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize CreateNoteResponse: {}",
                                e
                            ))
                        })?;
                        Ok(CreateNote(response))
                    }
                    "ExecuteViaTba" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize ExecuteViaTbaResponse: {}",
                                e
                            ))
                        })?;
                        Ok(ExecuteViaTba(response))
                    }
                    "CheckTbaOwnership" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let response = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize CheckTbaOwnershipResponse: {}",
                                e
                            ))
                        })?;
                        Ok(CheckTbaOwnership(response))
                    }
                    _ => {
                        // For unimplemented variants, return an error with helpful message
                        Err(de::Error::unknown_variant(
                            &variant_type,
                            &[
                                "Handshake",
                                "ImportWallet",
                                "DeleteWallet",
                                "ExportWallet",
                                "ListWallets",
                                "GetWalletInfo",
                                "CreateWallet",
                                "UnlockWallet",
                                "SendEth",
                                "SendToken",
                                "BuildAndSignUserOperationForPayment",
                                "SubmitUserOperation",
                                "GetUserOperationReceipt",
                                "GetBalance",
                                "GetTokenBalance",
                                "CreateNote",
                                "ExecuteViaTba",
                                "CheckTbaOwnership",
                            ],
                        ))
                    }
                }
            }
        }

        const FIELDS: &[&str] = &["type", "data"];
        deserializer.deserialize_struct(
            "HyperwalletResponseData",
            FIELDS,
            HyperwalletResponseDataVisitor,
        )
    }
}
