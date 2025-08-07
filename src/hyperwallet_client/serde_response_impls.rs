// Proper serde implementations for request/response types

use crate::hyperware::process::hyperwallet as wit;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};

// ============== REQUEST TYPES ==============

// ImportWalletRequest
impl Serialize for wit::ImportWalletRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("ImportWalletRequest", 3)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("private_key", &self.private_key)?;
        state.serialize_field("password", &self.password)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::ImportWalletRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            name: String,
            private_key: String,
            password: Option<String>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::ImportWalletRequest {
            name: h.name,
            private_key: h.private_key,
            password: h.password,
        })
    }
}

// DeleteWalletRequest
impl Serialize for wit::DeleteWalletRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("DeleteWalletRequest", 1)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::DeleteWalletRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            wallet_id: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::DeleteWalletRequest {
            wallet_id: h.wallet_id,
        })
    }
}

// RenameWalletRequest
impl Serialize for wit::RenameWalletRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("RenameWalletRequest", 2)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.serialize_field("new_name", &self.new_name)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::RenameWalletRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            wallet_id: String,
            new_name: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::RenameWalletRequest {
            wallet_id: h.wallet_id,
            new_name: h.new_name,
        })
    }
}

// ExportWalletRequest
impl Serialize for wit::ExportWalletRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("ExportWalletRequest", 2)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.serialize_field("password", &self.password)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::ExportWalletRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            wallet_id: String,
            password: Option<String>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::ExportWalletRequest {
            wallet_id: h.wallet_id,
            password: h.password,
        })
    }
}

// GetWalletInfoRequest
impl Serialize for wit::GetWalletInfoRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("GetWalletInfoRequest", 1)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::GetWalletInfoRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            wallet_id: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::GetWalletInfoRequest {
            wallet_id: h.wallet_id,
        })
    }
}

// SendEthRequest
impl Serialize for wit::SendEthRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SendEthRequest", 3)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.serialize_field("to", &self.to)?;
        state.serialize_field("amount", &self.amount)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::SendEthRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            wallet_id: String,
            to: String,
            amount: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::SendEthRequest {
            wallet_id: h.wallet_id,
            to: h.to,
            amount: h.amount,
        })
    }
}

// SendTokenRequest
impl Serialize for wit::SendTokenRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SendTokenRequest", 4)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.serialize_field("token_address", &self.token_address)?;
        state.serialize_field("to", &self.to)?;
        state.serialize_field("amount", &self.amount)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::SendTokenRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            wallet_id: String,
            token_address: String,
            to: String,
            amount: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::SendTokenRequest {
            wallet_id: h.wallet_id,
            token_address: h.token_address,
            to: h.to,
            amount: h.amount,
        })
    }
}

// GetBalanceRequest
impl Serialize for wit::GetBalanceRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("GetBalanceRequest", 1)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::GetBalanceRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            wallet_id: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::GetBalanceRequest {
            wallet_id: h.wallet_id,
        })
    }
}

// GetTokenBalanceRequest
impl Serialize for wit::GetTokenBalanceRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("GetTokenBalanceRequest", 2)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.serialize_field("token_address", &self.token_address)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::GetTokenBalanceRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            wallet_id: String,
            token_address: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::GetTokenBalanceRequest {
            wallet_id: h.wallet_id,
            token_address: h.token_address,
        })
    }
}

// BuildAndSignUserOperationForPaymentRequest
impl Serialize for wit::BuildAndSignUserOperationForPaymentRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state =
            serializer.serialize_struct("BuildAndSignUserOperationForPaymentRequest", 7)?;
        state.serialize_field("eoa_wallet_id", &self.eoa_wallet_id)?;
        state.serialize_field("tba_address", &self.tba_address)?;
        state.serialize_field("target", &self.target)?;
        state.serialize_field("call_data", &self.call_data)?;
        state.serialize_field("use_paymaster", &self.use_paymaster)?;
        state.serialize_field("paymaster_config", &self.paymaster_config)?;
        state.serialize_field("password", &self.password)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::BuildAndSignUserOperationForPaymentRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            eoa_wallet_id: String,
            tba_address: String,
            target: String,
            call_data: String,
            use_paymaster: bool,
            paymaster_config: Option<wit::PaymasterConfig>,
            password: Option<String>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::BuildAndSignUserOperationForPaymentRequest {
            eoa_wallet_id: h.eoa_wallet_id,
            tba_address: h.tba_address,
            target: h.target,
            call_data: h.call_data,
            use_paymaster: h.use_paymaster,
            paymaster_config: h.paymaster_config,
            password: h.password,
        })
    }
}

// SubmitUserOperationRequest
impl Serialize for wit::SubmitUserOperationRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SubmitUserOperationRequest", 3)?;
        state.serialize_field("signed_user_operation", &self.signed_user_operation)?;
        state.serialize_field("entry_point", &self.entry_point)?;
        state.serialize_field("bundler_url", &self.bundler_url)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::SubmitUserOperationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            signed_user_operation: String,
            entry_point: String,
            bundler_url: Option<String>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::SubmitUserOperationRequest {
            signed_user_operation: h.signed_user_operation,
            entry_point: h.entry_point,
            bundler_url: h.bundler_url,
        })
    }
}

// GetUserOperationReceiptRequest
impl Serialize for wit::GetUserOperationReceiptRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("GetUserOperationReceiptRequest", 1)?;
        state.serialize_field("user_op_hash", &self.user_op_hash)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::GetUserOperationReceiptRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            user_op_hash: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::GetUserOperationReceiptRequest {
            user_op_hash: h.user_op_hash,
        })
    }
}

// ============== RESPONSE TYPES ==============

// CreateWalletResponse
impl Serialize for wit::CreateWalletResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("CreateWalletResponse", 3)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.serialize_field("address", &self.address)?;
        state.serialize_field("name", &self.name)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::CreateWalletResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            wallet_id: String,
            address: String,
            name: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::CreateWalletResponse {
            wallet_id: h.wallet_id,
            address: h.address,
            name: h.name,
        })
    }
}

// ImportWalletResponse
impl Serialize for wit::ImportWalletResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("ImportWalletResponse", 3)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.serialize_field("address", &self.address)?;
        state.serialize_field("name", &self.name)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::ImportWalletResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            wallet_id: String,
            address: String,
            name: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::ImportWalletResponse {
            wallet_id: h.wallet_id,
            address: h.address,
            name: h.name,
        })
    }
}

// DeleteWalletResponse
impl Serialize for wit::DeleteWalletResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("DeleteWalletResponse", 3)?;
        state.serialize_field("success", &self.success)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.serialize_field("message", &self.message)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::DeleteWalletResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            success: bool,
            wallet_id: String,
            message: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::DeleteWalletResponse {
            success: h.success,
            wallet_id: h.wallet_id,
            message: h.message,
        })
    }
}

// ExportWalletResponse
impl Serialize for wit::ExportWalletResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("ExportWalletResponse", 2)?;
        state.serialize_field("address", &self.address)?;
        state.serialize_field("private_key", &self.private_key)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::ExportWalletResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            address: String,
            private_key: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::ExportWalletResponse {
            address: h.address,
            private_key: h.private_key,
        })
    }
}

// ListWalletsResponse
impl Serialize for wit::ListWalletsResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("ListWalletsResponse", 3)?;
        state.serialize_field("process", &self.process)?;
        state.serialize_field("wallets", &self.wallets)?;
        state.serialize_field("total", &self.total)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::ListWalletsResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            process: String,
            wallets: Vec<wit::Wallet>,
            total: u64,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::ListWalletsResponse {
            process: h.process,
            wallets: h.wallets,
            total: h.total,
        })
    }
}

// GetWalletInfoResponse
impl Serialize for wit::GetWalletInfoResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("GetWalletInfoResponse", 5)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.serialize_field("address", &self.address)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("chain_id", &self.chain_id)?;
        state.serialize_field("is_locked", &self.is_locked)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::GetWalletInfoResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            wallet_id: String,
            address: String,
            name: String,
            chain_id: u64,
            is_locked: bool,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::GetWalletInfoResponse {
            wallet_id: h.wallet_id,
            address: h.address,
            name: h.name,
            chain_id: h.chain_id,
            is_locked: h.is_locked,
        })
    }
}

// GetBalanceResponse
impl Serialize for wit::GetBalanceResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("GetBalanceResponse", 3)?;
        state.serialize_field("balance", &self.balance)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.serialize_field("chain_id", &self.chain_id)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::GetBalanceResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            balance: wit::Balance,
            wallet_id: String,
            chain_id: u64,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::GetBalanceResponse {
            balance: h.balance,
            wallet_id: h.wallet_id,
            chain_id: h.chain_id,
        })
    }
}

// GetTokenBalanceResponse
impl Serialize for wit::GetTokenBalanceResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("GetTokenBalanceResponse", 3)?;
        state.serialize_field("balance", &self.balance)?;
        state.serialize_field("formatted", &self.formatted)?;
        state.serialize_field("decimals", &self.decimals)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::GetTokenBalanceResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            balance: String,
            formatted: Option<String>,
            decimals: Option<u8>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::GetTokenBalanceResponse {
            balance: h.balance,
            formatted: h.formatted,
            decimals: h.decimals,
        })
    }
}

// SendEthResponse
impl Serialize for wit::SendEthResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SendEthResponse", 5)?;
        state.serialize_field("tx_hash", &self.tx_hash)?;
        state.serialize_field("from_address", &self.from_address)?;
        state.serialize_field("to_address", &self.to_address)?;
        state.serialize_field("amount", &self.amount)?;
        state.serialize_field("chain_id", &self.chain_id)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::SendEthResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            tx_hash: String,
            from_address: String,
            to_address: String,
            amount: String,
            chain_id: u64,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::SendEthResponse {
            tx_hash: h.tx_hash,
            from_address: h.from_address,
            to_address: h.to_address,
            amount: h.amount,
            chain_id: h.chain_id,
        })
    }
}

// SendTokenResponse
impl Serialize for wit::SendTokenResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SendTokenResponse", 6)?;
        state.serialize_field("tx_hash", &self.tx_hash)?;
        state.serialize_field("from_address", &self.from_address)?;
        state.serialize_field("to_address", &self.to_address)?;
        state.serialize_field("token_address", &self.token_address)?;
        state.serialize_field("amount", &self.amount)?;
        state.serialize_field("chain_id", &self.chain_id)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::SendTokenResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            tx_hash: String,
            from_address: String,
            to_address: String,
            token_address: String,
            amount: String,
            chain_id: u64,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::SendTokenResponse {
            tx_hash: h.tx_hash,
            from_address: h.from_address,
            to_address: h.to_address,
            token_address: h.token_address,
            amount: h.amount,
            chain_id: h.chain_id,
        })
    }
}

// UnlockWalletResponse
impl Serialize for wit::UnlockWalletResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("UnlockWalletResponse", 3)?;
        state.serialize_field("success", &self.success)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.serialize_field("message", &self.message)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::UnlockWalletResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            success: bool,
            wallet_id: String,
            message: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::UnlockWalletResponse {
            success: h.success,
            wallet_id: h.wallet_id,
            message: h.message,
        })
    }
}

// BuildAndSignUserOperationResponse
impl Serialize for wit::BuildAndSignUserOperationResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("BuildAndSignUserOperationResponse", 3)?;
        state.serialize_field("signed_user_operation", &self.signed_user_operation)?;
        state.serialize_field("entry_point", &self.entry_point)?;
        state.serialize_field("ready_to_submit", &self.ready_to_submit)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::BuildAndSignUserOperationResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            signed_user_operation: String,
            entry_point: String,
            ready_to_submit: bool,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::BuildAndSignUserOperationResponse {
            signed_user_operation: h.signed_user_operation,
            entry_point: h.entry_point,
            ready_to_submit: h.ready_to_submit,
        })
    }
}

// SubmitUserOperationResponse
impl Serialize for wit::SubmitUserOperationResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SubmitUserOperationResponse", 1)?;
        state.serialize_field("user_op_hash", &self.user_op_hash)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::SubmitUserOperationResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            user_op_hash: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::SubmitUserOperationResponse {
            user_op_hash: h.user_op_hash,
        })
    }
}

// UserOperationReceiptResponse
impl Serialize for wit::UserOperationReceiptResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("UserOperationReceiptResponse", 3)?;
        state.serialize_field("receipt", &self.receipt)?;
        state.serialize_field("user_op_hash", &self.user_op_hash)?;
        state.serialize_field("status", &self.status)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::UserOperationReceiptResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            receipt: Option<String>,
            user_op_hash: String,
            status: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::UserOperationReceiptResponse {
            receipt: h.receipt,
            user_op_hash: h.user_op_hash,
            status: h.status,
        })
    }
}

// ============== SUPPORTING TYPES ==============

// Balance
impl Serialize for wit::Balance {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Balance", 2)?;
        state.serialize_field("formatted", &self.formatted)?;
        state.serialize_field("raw", &self.raw)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::Balance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            formatted: String,
            raw: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::Balance {
            formatted: h.formatted,
            raw: h.raw,
        })
    }
}

// Wallet
impl Serialize for wit::Wallet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Wallet", 7)?;
        state.serialize_field("address", &self.address)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("chain_id", &self.chain_id)?;
        state.serialize_field("encrypted", &self.encrypted)?;
        state.serialize_field("created_at", &self.created_at)?;
        state.serialize_field("last_used", &self.last_used)?;
        state.serialize_field("spending_limits", &self.spending_limits)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::Wallet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            address: String,
            name: Option<String>,
            chain_id: u64,
            encrypted: bool,
            created_at: Option<String>,
            last_used: Option<String>,
            spending_limits: Option<wit::WalletSpendingLimits>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::Wallet {
            address: h.address,
            name: h.name,
            chain_id: h.chain_id,
            encrypted: h.encrypted,
            created_at: h.created_at,
            last_used: h.last_used,
            spending_limits: h.spending_limits,
        })
    }
}

// WalletSpendingLimits
impl Serialize for wit::WalletSpendingLimits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("WalletSpendingLimits", 6)?;
        state.serialize_field("max_per_call", &self.max_per_call)?;
        state.serialize_field("max_total", &self.max_total)?;
        state.serialize_field("currency", &self.currency)?;
        state.serialize_field("total_spent", &self.total_spent)?;
        state.serialize_field("set_at", &self.set_at)?;
        state.serialize_field("updated_at", &self.updated_at)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::WalletSpendingLimits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            max_per_call: Option<String>,
            max_total: Option<String>,
            currency: String,
            total_spent: String,
            set_at: Option<String>,
            updated_at: Option<String>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::WalletSpendingLimits {
            max_per_call: h.max_per_call,
            max_total: h.max_total,
            currency: h.currency,
            total_spent: h.total_spent,
            set_at: h.set_at,
            updated_at: h.updated_at,
        })
    }
}

// ============== MISSING REQUEST TYPES ==============

// UpdateSpendingLimitsRequest
impl Serialize for wit::UpdateSpendingLimitsRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("UpdateSpendingLimitsRequest", 1)?;
        state.serialize_field("new_limits", &self.new_limits)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::UpdateSpendingLimitsRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            new_limits: wit::SpendingLimits,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::UpdateSpendingLimitsRequest {
            new_limits: h.new_limits,
        })
    }
}

// ApproveTokenRequest
impl Serialize for wit::ApproveTokenRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("ApproveTokenRequest", 3)?;
        state.serialize_field("token_address", &self.token_address)?;
        state.serialize_field("spender", &self.spender)?;
        state.serialize_field("amount", &self.amount)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::ApproveTokenRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            token_address: String,
            spender: String,
            amount: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::ApproveTokenRequest {
            token_address: h.token_address,
            spender: h.spender,
            amount: h.amount,
        })
    }
}

// CallContractRequest
impl Serialize for wit::CallContractRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("CallContractRequest", 3)?;
        state.serialize_field("to", &self.to)?;
        state.serialize_field("data", &self.data)?;
        state.serialize_field("value", &self.value)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::CallContractRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            to: String,
            data: String,
            value: Option<String>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::CallContractRequest {
            to: h.to,
            data: h.data,
            value: h.value,
        })
    }
}

// SignTransactionRequest
impl Serialize for wit::SignTransactionRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SignTransactionRequest", 6)?;
        state.serialize_field("to", &self.to)?;
        state.serialize_field("value", &self.value)?;
        state.serialize_field("data", &self.data)?;
        state.serialize_field("gas_limit", &self.gas_limit)?;
        state.serialize_field("gas_price", &self.gas_price)?;
        state.serialize_field("nonce", &self.nonce)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::SignTransactionRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            to: String,
            value: String,
            data: Option<String>,
            gas_limit: Option<String>,
            gas_price: Option<String>,
            nonce: Option<u64>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::SignTransactionRequest {
            to: h.to,
            value: h.value,
            data: h.data,
            gas_limit: h.gas_limit,
            gas_price: h.gas_price,
            nonce: h.nonce,
        })
    }
}

// MessageType enum (needed for SignMessageRequest)
impl Serialize for wit::MessageType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            wit::MessageType::PlainText => {
                serializer.serialize_unit_variant("MessageType", 0, "plain_text")
            }
            wit::MessageType::Eip191 => {
                serializer.serialize_unit_variant("MessageType", 1, "eip191")
            }
            wit::MessageType::Eip712(data) => {
                use serde::ser::SerializeStructVariant;
                let mut state =
                    serializer.serialize_struct_variant("MessageType", 2, "eip712", 1)?;
                state.serialize_field("data", data)?;
                state.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for wit::MessageType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum MessageTypeHelper {
            PlainText,
            Eip191,
            Eip712 { data: wit::Eip712Data },
        }

        match MessageTypeHelper::deserialize(deserializer)? {
            MessageTypeHelper::PlainText => Ok(wit::MessageType::PlainText),
            MessageTypeHelper::Eip191 => Ok(wit::MessageType::Eip191),
            MessageTypeHelper::Eip712 { data } => Ok(wit::MessageType::Eip712(data)),
        }
    }
}

// Eip712Data struct (needed for MessageType::Eip712)
impl Serialize for wit::Eip712Data {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Eip712Data", 2)?;
        state.serialize_field("domain", &self.domain)?;
        state.serialize_field("types", &self.types)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::Eip712Data {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            domain: String,
            types: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::Eip712Data {
            domain: h.domain,
            types: h.types,
        })
    }
}

// SignMessageRequest
impl Serialize for wit::SignMessageRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SignMessageRequest", 2)?;
        state.serialize_field("message", &self.message)?;
        state.serialize_field("message_type", &self.message_type)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::SignMessageRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            message: String,
            message_type: wit::MessageType,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::SignMessageRequest {
            message: h.message,
            message_type: h.message_type,
        })
    }
}

// GetTransactionHistoryRequest
impl Serialize for wit::GetTransactionHistoryRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("GetTransactionHistoryRequest", 4)?;
        state.serialize_field("limit", &self.limit)?;
        state.serialize_field("offset", &self.offset)?;
        state.serialize_field("from_block", &self.from_block)?;
        state.serialize_field("to_block", &self.to_block)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::GetTransactionHistoryRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            limit: Option<u32>,
            offset: Option<u32>,
            from_block: Option<u64>,
            to_block: Option<u64>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::GetTransactionHistoryRequest {
            limit: h.limit,
            offset: h.offset,
            from_block: h.from_block,
            to_block: h.to_block,
        })
    }
}

// EstimateGasRequest
impl Serialize for wit::EstimateGasRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("EstimateGasRequest", 3)?;
        state.serialize_field("to", &self.to)?;
        state.serialize_field("data", &self.data)?;
        state.serialize_field("value", &self.value)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::EstimateGasRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            to: String,
            data: Option<String>,
            value: Option<String>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::EstimateGasRequest {
            to: h.to,
            data: h.data,
            value: h.value,
        })
    }
}

// GetTransactionReceiptRequest
impl Serialize for wit::GetTransactionReceiptRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("GetTransactionReceiptRequest", 1)?;
        state.serialize_field("tx_hash", &self.tx_hash)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::GetTransactionReceiptRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            tx_hash: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::GetTransactionReceiptRequest { tx_hash: h.tx_hash })
    }
}

// BuildUserOperationRequest
impl Serialize for wit::BuildUserOperationRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("BuildUserOperationRequest", 3)?;
        state.serialize_field("target", &self.target)?;
        state.serialize_field("call_data", &self.call_data)?;
        state.serialize_field("value", &self.value)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::BuildUserOperationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            target: String,
            call_data: String,
            value: Option<String>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::BuildUserOperationRequest {
            target: h.target,
            call_data: h.call_data,
            value: h.value,
        })
    }
}

// SignUserOperationRequest
impl Serialize for wit::SignUserOperationRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SignUserOperationRequest", 2)?;
        state.serialize_field("unsigned_user_operation", &self.unsigned_user_operation)?;
        state.serialize_field("entry_point", &self.entry_point)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::SignUserOperationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            unsigned_user_operation: String,
            entry_point: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::SignUserOperationRequest {
            unsigned_user_operation: h.unsigned_user_operation,
            entry_point: h.entry_point,
        })
    }
}

// BuildAndSignUserOperationRequest
impl Serialize for wit::BuildAndSignUserOperationRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("BuildAndSignUserOperationRequest", 4)?;
        state.serialize_field("target", &self.target)?;
        state.serialize_field("call_data", &self.call_data)?;
        state.serialize_field("value", &self.value)?;
        state.serialize_field("entry_point", &self.entry_point)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::BuildAndSignUserOperationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            target: String,
            call_data: String,
            value: Option<String>,
            entry_point: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::BuildAndSignUserOperationRequest {
            target: h.target,
            call_data: h.call_data,
            value: h.value,
            entry_point: h.entry_point,
        })
    }
}

// EstimateUserOperationGasRequest
impl Serialize for wit::EstimateUserOperationGasRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("EstimateUserOperationGasRequest", 2)?;
        state.serialize_field("user_operation", &self.user_operation)?;
        state.serialize_field("entry_point", &self.entry_point)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::EstimateUserOperationGasRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            user_operation: String,
            entry_point: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::EstimateUserOperationGasRequest {
            user_operation: h.user_operation,
            entry_point: h.entry_point,
        })
    }
}

// ConfigurePaymasterRequest
impl Serialize for wit::ConfigurePaymasterRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("ConfigurePaymasterRequest", 4)?;
        state.serialize_field("paymaster_address", &self.paymaster_address)?;
        state.serialize_field("paymaster_data", &self.paymaster_data)?;
        state.serialize_field("verification_gas_limit", &self.verification_gas_limit)?;
        state.serialize_field("post_op_gas_limit", &self.post_op_gas_limit)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::ConfigurePaymasterRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            paymaster_address: String,
            paymaster_data: Option<String>,
            verification_gas_limit: String,
            post_op_gas_limit: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::ConfigurePaymasterRequest {
            paymaster_address: h.paymaster_address,
            paymaster_data: h.paymaster_data,
            verification_gas_limit: h.verification_gas_limit,
            post_op_gas_limit: h.post_op_gas_limit,
        })
    }
}

// ExecuteViaTbaRequest
impl Serialize for wit::ExecuteViaTbaRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("ExecuteViaTbaRequest", 4)?;
        state.serialize_field("tba_address", &self.tba_address)?;
        state.serialize_field("target", &self.target)?;
        state.serialize_field("call_data", &self.call_data)?;
        state.serialize_field("value", &self.value)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::ExecuteViaTbaRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            tba_address: String,
            target: String,
            call_data: String,
            value: Option<String>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::ExecuteViaTbaRequest {
            tba_address: h.tba_address,
            target: h.target,
            call_data: h.call_data,
            value: h.value,
        })
    }
}

// CheckTbaOwnershipRequest
impl Serialize for wit::CheckTbaOwnershipRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("CheckTbaOwnershipRequest", 2)?;
        state.serialize_field("tba_address", &self.tba_address)?;
        state.serialize_field("signer_address", &self.signer_address)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::CheckTbaOwnershipRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            tba_address: String,
            signer_address: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::CheckTbaOwnershipRequest {
            tba_address: h.tba_address,
            signer_address: h.signer_address,
        })
    }
}

// SetupTbaDelegationRequest
impl Serialize for wit::SetupTbaDelegationRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SetupTbaDelegationRequest", 3)?;
        state.serialize_field("tba_address", &self.tba_address)?;
        state.serialize_field("delegate_address", &self.delegate_address)?;
        state.serialize_field("permissions", &self.permissions)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::SetupTbaDelegationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            tba_address: String,
            delegate_address: String,
            permissions: Vec<String>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::SetupTbaDelegationRequest {
            tba_address: h.tba_address,
            delegate_address: h.delegate_address,
            permissions: h.permissions,
        })
    }
}

// CreateNoteRequest
impl Serialize for wit::CreateNoteRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("CreateNoteRequest", 2)?;
        state.serialize_field("note_data", &self.note_data)?;
        state.serialize_field("metadata", &self.metadata)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::CreateNoteRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            note_data: String,
            metadata: Option<String>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::CreateNoteRequest {
            note_data: h.note_data,
            metadata: h.metadata,
        })
    }
}

// ReadNoteRequest
impl Serialize for wit::ReadNoteRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("ReadNoteRequest", 1)?;
        state.serialize_field("note_id", &self.note_id)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::ReadNoteRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            note_id: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::ReadNoteRequest { note_id: h.note_id })
    }
}

// ResolveIdentityRequest
impl Serialize for wit::ResolveIdentityRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("ResolveIdentityRequest", 1)?;
        state.serialize_field("entry_name", &self.entry_name)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::ResolveIdentityRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            entry_name: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::ResolveIdentityRequest {
            entry_name: h.entry_name,
        })
    }
}

// SetupDelegationRequest
impl Serialize for wit::SetupDelegationRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SetupDelegationRequest", 3)?;
        state.serialize_field("delegate_address", &self.delegate_address)?;
        state.serialize_field("permissions", &self.permissions)?;
        state.serialize_field("expiry", &self.expiry)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::SetupDelegationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            delegate_address: String,
            permissions: Vec<String>,
            expiry: Option<u64>,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::SetupDelegationRequest {
            delegate_address: h.delegate_address,
            permissions: h.permissions,
            expiry: h.expiry,
        })
    }
}

// VerifyDelegationRequest
impl Serialize for wit::VerifyDelegationRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("VerifyDelegationRequest", 3)?;
        state.serialize_field("delegate_address", &self.delegate_address)?;
        state.serialize_field("signature", &self.signature)?;
        state.serialize_field("message", &self.message)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::VerifyDelegationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            delegate_address: String,
            signature: String,
            message: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::VerifyDelegationRequest {
            delegate_address: h.delegate_address,
            signature: h.signature,
            message: h.message,
        })
    }
}

// MintEntryRequest
impl Serialize for wit::MintEntryRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("MintEntryRequest", 2)?;
        state.serialize_field("entry_name", &self.entry_name)?;
        state.serialize_field("metadata", &self.metadata)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::MintEntryRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            entry_name: String,
            metadata: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::MintEntryRequest {
            entry_name: h.entry_name,
            metadata: h.metadata,
        })
    }
}

// ============== MISSING RESPONSE TYPES ==============

// CreateNoteResponse
impl Serialize for wit::CreateNoteResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("CreateNoteResponse", 3)?;
        state.serialize_field("note_id", &self.note_id)?;
        state.serialize_field("content_hash", &self.content_hash)?;
        state.serialize_field("created_at", &self.created_at)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::CreateNoteResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            note_id: String,
            content_hash: String,
            created_at: u64,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::CreateNoteResponse {
            note_id: h.note_id,
            content_hash: h.content_hash,
            created_at: h.created_at,
        })
    }
}

// ExecuteViaTbaResponse
impl Serialize for wit::ExecuteViaTbaResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("ExecuteViaTbaResponse", 4)?;
        state.serialize_field("tx_hash", &self.tx_hash)?;
        state.serialize_field("tba_address", &self.tba_address)?;
        state.serialize_field("target_address", &self.target_address)?;
        state.serialize_field("success", &self.success)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::ExecuteViaTbaResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            tx_hash: String,
            tba_address: String,
            target_address: String,
            success: bool,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::ExecuteViaTbaResponse {
            tx_hash: h.tx_hash,
            tba_address: h.tba_address,
            target_address: h.target_address,
            success: h.success,
        })
    }
}

// CheckTbaOwnershipResponse
impl Serialize for wit::CheckTbaOwnershipResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("CheckTbaOwnershipResponse", 3)?;
        state.serialize_field("tba_address", &self.tba_address)?;
        state.serialize_field("owner_address", &self.owner_address)?;
        state.serialize_field("is_owned", &self.is_owned)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::CheckTbaOwnershipResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            tba_address: String,
            owner_address: String,
            is_owned: bool,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::CheckTbaOwnershipResponse {
            tba_address: h.tba_address,
            owner_address: h.owner_address,
            is_owned: h.is_owned,
        })
    }
}

// PaymasterConfig
impl Serialize for wit::PaymasterConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PaymasterConfig", 4)?;
        state.serialize_field("is_circle_paymaster", &self.is_circle_paymaster)?;
        state.serialize_field("paymaster_address", &self.paymaster_address)?;
        state.serialize_field(
            "paymaster_verification_gas",
            &self.paymaster_verification_gas,
        )?;
        state.serialize_field("paymaster_post_op_gas", &self.paymaster_post_op_gas)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for wit::PaymasterConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            is_circle_paymaster: bool,
            paymaster_address: String,
            paymaster_verification_gas: String,
            paymaster_post_op_gas: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(wit::PaymasterConfig {
            is_circle_paymaster: h.is_circle_paymaster,
            paymaster_address: h.paymaster_address,
            paymaster_verification_gas: h.paymaster_verification_gas,
            paymaster_post_op_gas: h.paymaster_post_op_gas,
        })
    }
}
