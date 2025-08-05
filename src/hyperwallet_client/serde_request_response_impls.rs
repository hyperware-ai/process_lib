use crate::hyperware::process::hyperwallet as wit;
use serde::de::{self};
use serde::ser::Serialize;
use serde::Deserialize;

// Create a macro to generate stub implementations for request/response types
macro_rules! impl_stub_serde {
    ($type:ty, $name:literal) => {
        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                // For now, serialize as debug representation
                let json_val = serde_json::json!({
                    "type": $name,
                    "data": format!("{:?}", self)
                });
                json_val.serialize(serializer)
            }
        }

        impl<'a> Deserialize<'a> for $type {
            fn deserialize<D>(deserializer: D) -> Result<$type, D::Error>
            where
                D: serde::de::Deserializer<'a>,
            {
                let _val = serde_json::Value::deserialize(deserializer)?;
                Err(de::Error::custom(concat!($name, " deserialization not yet implemented")))
            }
        }
    };
}

// Request types
impl_stub_serde!(
    wit::UpdateSpendingLimitsRequest,
    "UpdateSpendingLimitsRequest"
);
impl_stub_serde!(wit::ImportWalletRequest, "ImportWalletRequest");
impl_stub_serde!(wit::DeleteWalletRequest, "DeleteWalletRequest");
impl_stub_serde!(wit::RenameWalletRequest, "RenameWalletRequest");
impl_stub_serde!(wit::ExportWalletRequest, "ExportWalletRequest");
impl_stub_serde!(wit::GetWalletInfoRequest, "GetWalletInfoRequest");
impl_stub_serde!(wit::SendEthRequest, "SendEthRequest");
impl_stub_serde!(wit::SendTokenRequest, "SendTokenRequest");
impl_stub_serde!(wit::ApproveTokenRequest, "ApproveTokenRequest");
impl_stub_serde!(wit::GetBalanceRequest, "GetBalanceRequest");
impl_stub_serde!(wit::GetTokenBalanceRequest, "GetTokenBalanceRequest");
impl_stub_serde!(wit::CallContractRequest, "CallContractRequest");
impl_stub_serde!(wit::SignTransactionRequest, "SignTransactionRequest");
impl_stub_serde!(wit::SignMessageRequest, "SignMessageRequest");
impl_stub_serde!(
    wit::BuildAndSignUserOperationForPaymentRequest,
    "BuildAndSignUserOperationForPaymentRequest"
);
impl_stub_serde!(
    wit::SubmitUserOperationRequest,
    "SubmitUserOperationRequest"
);
impl_stub_serde!(
    wit::GetUserOperationReceiptRequest,
    "GetUserOperationReceiptRequest"
);
impl_stub_serde!(
    wit::GetTransactionHistoryRequest,
    "GetTransactionHistoryRequest"
);
impl_stub_serde!(wit::EstimateGasRequest, "EstimateGasRequest");

// Response types
impl_stub_serde!(wit::UnlockWalletResponse, "UnlockWalletResponse");
impl_stub_serde!(wit::CreateWalletResponse, "CreateWalletResponse");
impl_stub_serde!(wit::ImportWalletResponse, "ImportWalletResponse");
impl_stub_serde!(wit::DeleteWalletResponse, "DeleteWalletResponse");
impl_stub_serde!(wit::ExportWalletResponse, "ExportWalletResponse");
impl_stub_serde!(wit::ListWalletsResponse, "ListWalletsResponse");
impl_stub_serde!(wit::GetWalletInfoResponse, "GetWalletInfoResponse");
impl_stub_serde!(wit::GetBalanceResponse, "GetBalanceResponse");
impl_stub_serde!(wit::GetTokenBalanceResponse, "GetTokenBalanceResponse");
impl_stub_serde!(wit::SendEthResponse, "SendEthResponse");
impl_stub_serde!(wit::SendTokenResponse, "SendTokenResponse");
impl_stub_serde!(
    wit::BuildAndSignUserOperationResponse,
    "BuildAndSignUserOperationResponse"
);
impl_stub_serde!(
    wit::SubmitUserOperationResponse,
    "SubmitUserOperationResponse"
);
impl_stub_serde!(
    wit::UserOperationReceiptResponse,
    "UserOperationReceiptResponse"
);

// Other request types
impl_stub_serde!(
    wit::GetTransactionReceiptRequest,
    "GetTransactionReceiptRequest"
);
impl_stub_serde!(wit::BuildUserOperationRequest, "BuildUserOperationRequest");
impl_stub_serde!(wit::SignUserOperationRequest, "SignUserOperationRequest");
impl_stub_serde!(
    wit::BuildAndSignUserOperationRequest,
    "BuildAndSignUserOperationRequest"
);
impl_stub_serde!(
    wit::EstimateUserOperationGasRequest,
    "EstimateUserOperationGasRequest"
);
impl_stub_serde!(wit::ConfigurePaymasterRequest, "ConfigurePaymasterRequest");
impl_stub_serde!(wit::ExecuteViaTbaRequest, "ExecuteViaTbaRequest");
impl_stub_serde!(wit::CheckTbaOwnershipRequest, "CheckTbaOwnershipRequest");
impl_stub_serde!(wit::SetupTbaDelegationRequest, "SetupTbaDelegationRequest");
impl_stub_serde!(wit::CreateNoteRequest, "CreateNoteRequest");
impl_stub_serde!(wit::ReadNoteRequest, "ReadNoteRequest");
impl_stub_serde!(wit::ResolveIdentityRequest, "ResolveIdentityRequest");
impl_stub_serde!(wit::SetupDelegationRequest, "SetupDelegationRequest");
impl_stub_serde!(wit::VerifyDelegationRequest, "VerifyDelegationRequest");
impl_stub_serde!(wit::MintEntryRequest, "MintEntryRequest");

// Other response types
impl_stub_serde!(wit::CreateNoteResponse, "CreateNoteResponse");
impl_stub_serde!(wit::ExecuteViaTbaResponse, "ExecuteViaTbaResponse");
impl_stub_serde!(wit::CheckTbaOwnershipResponse, "CheckTbaOwnershipResponse");

// Other types that may need serde
impl_stub_serde!(wit::Balance, "Balance");
impl_stub_serde!(wit::Wallet, "Wallet");
impl_stub_serde!(wit::WalletSpendingLimits, "WalletSpendingLimits");
