use crate::hyperware::process::hyperwallet as wit;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeStruct};
use serde::Deserialize;

// ============================================================================
// HyperwalletMessage
// ============================================================================

impl Serialize for wit::HyperwalletMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("HyperwalletMessage", 2)?;
        state.serialize_field("request", &self.request)?;
        state.serialize_field("session_id", &self.session_id)?;
        state.end()
    }
}

impl<'a> Deserialize<'a> for wit::HyperwalletMessage {
    fn deserialize<D>(deserializer: D) -> Result<wit::HyperwalletMessage, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Request,
            SessionId,
        }

        struct HyperwalletMessageVisitor;

        impl<'de> Visitor<'de> for HyperwalletMessageVisitor {
            type Value = wit::HyperwalletMessage;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct HyperwalletMessage")
            }

            fn visit_map<V>(self, mut map: V) -> Result<wit::HyperwalletMessage, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut request = None;
                let mut session_id = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Request => {
                            if request.is_some() {
                                return Err(de::Error::duplicate_field("request"));
                            }
                            request = Some(map.next_value()?);
                        }
                        Field::SessionId => {
                            if session_id.is_some() {
                                return Err(de::Error::duplicate_field("session_id"));
                            }
                            session_id = Some(map.next_value()?);
                        }
                    }
                }

                let request = request.ok_or_else(|| de::Error::missing_field("request"))?;
                let session_id =
                    session_id.ok_or_else(|| de::Error::missing_field("session_id"))?;

                Ok(wit::HyperwalletMessage {
                    request,
                    session_id,
                })
            }
        }

        const FIELDS: &[&str] = &["request", "session_id"];
        deserializer.deserialize_struct("HyperwalletMessage", FIELDS, HyperwalletMessageVisitor)
    }
}

// ============================================================================
// HyperwalletResponse
// ============================================================================

impl Serialize for wit::HyperwalletResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("HyperwalletResponse", 4)?;
        state.serialize_field("success", &self.success)?;
        state.serialize_field("data", &self.data)?;
        state.serialize_field("error", &self.error)?;
        state.serialize_field("request_id", &self.request_id)?;
        state.end()
    }
}

impl<'a> Deserialize<'a> for wit::HyperwalletResponse {
    fn deserialize<D>(deserializer: D) -> Result<wit::HyperwalletResponse, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Success,
            Data,
            Error,
            RequestId,
        }

        struct HyperwalletResponseVisitor;

        impl<'de> Visitor<'de> for HyperwalletResponseVisitor {
            type Value = wit::HyperwalletResponse;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct HyperwalletResponse")
            }

            fn visit_map<V>(self, mut map: V) -> Result<wit::HyperwalletResponse, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut success = None;
                let mut data = None;
                let mut error = None;
                let mut request_id = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Success => {
                            if success.is_some() {
                                return Err(de::Error::duplicate_field("success"));
                            }
                            success = Some(map.next_value()?);
                        }
                        Field::Data => {
                            if data.is_some() {
                                return Err(de::Error::duplicate_field("data"));
                            }
                            data = map.next_value()?;
                        }
                        Field::Error => {
                            if error.is_some() {
                                return Err(de::Error::duplicate_field("error"));
                            }
                            error = map.next_value()?;
                        }
                        Field::RequestId => {
                            if request_id.is_some() {
                                return Err(de::Error::duplicate_field("request_id"));
                            }
                            request_id = map.next_value()?;
                        }
                    }
                }

                let success = success.ok_or_else(|| de::Error::missing_field("success"))?;

                Ok(wit::HyperwalletResponse {
                    success,
                    data,
                    error,
                    request_id,
                })
            }
        }

        const FIELDS: &[&str] = &["success", "data", "error", "request_id"];
        deserializer.deserialize_struct("HyperwalletResponse", FIELDS, HyperwalletResponseVisitor)
    }
}

// ============================================================================
// OperationError
// ============================================================================

impl Serialize for wit::OperationError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("OperationError", 3)?;
        state.serialize_field("code", &self.code)?;
        state.serialize_field("message", &self.message)?;
        state.serialize_field("details", &self.details)?;
        state.end()
    }
}

impl<'a> Deserialize<'a> for wit::OperationError {
    fn deserialize<D>(deserializer: D) -> Result<wit::OperationError, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Code,
            Message,
            Details,
        }

        struct OperationErrorVisitor;

        impl<'de> Visitor<'de> for OperationErrorVisitor {
            type Value = wit::OperationError;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct OperationError")
            }

            fn visit_map<V>(self, mut map: V) -> Result<wit::OperationError, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut code = None;
                let mut message = None;
                let mut details = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Code => {
                            if code.is_some() {
                                return Err(de::Error::duplicate_field("code"));
                            }
                            code = Some(map.next_value()?);
                        }
                        Field::Message => {
                            if message.is_some() {
                                return Err(de::Error::duplicate_field("message"));
                            }
                            message = Some(map.next_value()?);
                        }
                        Field::Details => {
                            if details.is_some() {
                                return Err(de::Error::duplicate_field("details"));
                            }
                            // Accept Option<String>: null -> None
                            details = map.next_value()?;
                        }
                    }
                }

                let code = code.ok_or_else(|| de::Error::missing_field("code"))?;
                let message = message.ok_or_else(|| de::Error::missing_field("message"))?;

                Ok(wit::OperationError {
                    code,
                    message,
                    details,
                })
            }
        }

        const FIELDS: &[&str] = &["code", "message", "details"];
        deserializer.deserialize_struct("OperationError", FIELDS, OperationErrorVisitor)
    }
}

// ============================================================================
// ErrorCode enum
// ============================================================================

impl Serialize for wit::ErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(match self {
            wit::ErrorCode::InternalError => "InternalError",
            wit::ErrorCode::InvalidParams => "InvalidParams",
            wit::ErrorCode::InvalidOperation => "InvalidOperation",
            wit::ErrorCode::PermissionDenied => "PermissionDenied",
            wit::ErrorCode::WalletNotFound => "WalletNotFound",
            wit::ErrorCode::WalletLocked => "WalletLocked",
            wit::ErrorCode::AuthenticationFailed => "AuthenticationFailed",
            wit::ErrorCode::InsufficientFunds => "InsufficientFunds",
            wit::ErrorCode::SpendingLimitExceeded => "SpendingLimitExceeded",
            wit::ErrorCode::BlockchainError => "BlockchainError",
            wit::ErrorCode::ChainNotAllowed => "ChainNotAllowed",
            wit::ErrorCode::OperationNotSupported => "OperationNotSupported",
            wit::ErrorCode::VersionMismatch => "VersionMismatch",
        })
    }
}

impl<'a> Deserialize<'a> for wit::ErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<wit::ErrorCode, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "InternalError" => Ok(wit::ErrorCode::InternalError),
            "InvalidParams" => Ok(wit::ErrorCode::InvalidParams),
            "InvalidOperation" => Ok(wit::ErrorCode::InvalidOperation),
            "PermissionDenied" => Ok(wit::ErrorCode::PermissionDenied),
            "WalletNotFound" => Ok(wit::ErrorCode::WalletNotFound),
            "WalletLocked" => Ok(wit::ErrorCode::WalletLocked),
            "AuthenticationFailed" => Ok(wit::ErrorCode::AuthenticationFailed),
            "InsufficientFunds" => Ok(wit::ErrorCode::InsufficientFunds),
            "SpendingLimitExceeded" => Ok(wit::ErrorCode::SpendingLimitExceeded),
            "BlockchainError" => Ok(wit::ErrorCode::BlockchainError),
            "ChainNotAllowed" => Ok(wit::ErrorCode::ChainNotAllowed),
            "OperationNotSupported" => Ok(wit::ErrorCode::OperationNotSupported),
            "VersionMismatch" => Ok(wit::ErrorCode::VersionMismatch),
            _ => Err(de::Error::unknown_variant(
                &s,
                &[
                    "InternalError",
                    "InvalidParams",
                    "InvalidOperation",
                    "PermissionDenied",
                    "WalletNotFound",
                    "WalletLocked",
                    "AuthenticationFailed",
                    "InsufficientFunds",
                    "SpendingLimitExceeded",
                    "BlockchainError",
                    "ChainNotAllowed",
                    "OperationNotSupported",
                    "VersionMismatch",
                ],
            )),
        }
    }
} // ============================================================================
  // Request Types (Records)
  // ============================================================================

// CreateWalletRequest
impl Serialize for wit::CreateWalletRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        // Only include password when present to avoid sending null
        let field_count = if self.password.is_some() { 2 } else { 1 };
        let mut state = serializer.serialize_struct("CreateWalletRequest", field_count)?;
        state.serialize_field("name", &self.name)?;
        if let Some(ref pwd) = self.password {
            state.serialize_field("password", pwd)?;
        }
        state.end()
    }
}

impl<'a> Deserialize<'a> for wit::CreateWalletRequest {
    fn deserialize<D>(deserializer: D) -> Result<wit::CreateWalletRequest, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Name,
            Password,
        }

        struct CreateWalletRequestVisitor;

        impl<'de> Visitor<'de> for CreateWalletRequestVisitor {
            type Value = wit::CreateWalletRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct CreateWalletRequest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<wit::CreateWalletRequest, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut name = None;
                let mut password = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Name => {
                            if name.is_some() {
                                return Err(de::Error::duplicate_field("name"));
                            }
                            name = Some(map.next_value()?);
                        }
                        Field::Password => {
                            if password.is_some() {
                                return Err(de::Error::duplicate_field("password"));
                            }
                            password = Some(map.next_value()?);
                        }
                    }
                }

                let name = name.ok_or_else(|| de::Error::missing_field("name"))?;

                Ok(wit::CreateWalletRequest { name, password })
            }
        }

        const FIELDS: &[&str] = &["name", "password"];
        deserializer.deserialize_struct("CreateWalletRequest", FIELDS, CreateWalletRequestVisitor)
    }
}

// UnlockWalletRequest
impl Serialize for wit::UnlockWalletRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("UnlockWalletRequest", 3)?;
        state.serialize_field("session_id", &self.session_id)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.serialize_field("password", &self.password)?;
        state.end()
    }
}

impl<'a> Deserialize<'a> for wit::UnlockWalletRequest {
    fn deserialize<D>(deserializer: D) -> Result<wit::UnlockWalletRequest, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            SessionId,
            WalletId,
            Password,
        }

        struct UnlockWalletRequestVisitor;

        impl<'de> Visitor<'de> for UnlockWalletRequestVisitor {
            type Value = wit::UnlockWalletRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct UnlockWalletRequest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<wit::UnlockWalletRequest, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut session_id = None;
                let mut wallet_id = None;
                let mut password = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::SessionId => {
                            if session_id.is_some() {
                                return Err(de::Error::duplicate_field("session_id"));
                            }
                            session_id = Some(map.next_value()?);
                        }
                        Field::WalletId => {
                            if wallet_id.is_some() {
                                return Err(de::Error::duplicate_field("wallet_id"));
                            }
                            wallet_id = Some(map.next_value()?);
                        }
                        Field::Password => {
                            if password.is_some() {
                                return Err(de::Error::duplicate_field("password"));
                            }
                            password = Some(map.next_value()?);
                        }
                    }
                }

                let session_id =
                    session_id.ok_or_else(|| de::Error::missing_field("session_id"))?;
                let wallet_id = wallet_id.ok_or_else(|| de::Error::missing_field("wallet_id"))?;
                let password = password.ok_or_else(|| de::Error::missing_field("password"))?;

                Ok(wit::UnlockWalletRequest {
                    session_id,
                    wallet_id,
                    password,
                })
            }
        }

        const FIELDS: &[&str] = &["session_id", "wallet_id", "password"];
        deserializer.deserialize_struct("UnlockWalletRequest", FIELDS, UnlockWalletRequestVisitor)
    }
}

// ============================================================================
// Operation enum
// ============================================================================

impl Serialize for wit::Operation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use wit::Operation::*;
        serializer.serialize_str(match self {
            Handshake => "Handshake",
            UnlockWallet => "UnlockWallet",
            RegisterProcess => "RegisterProcess",
            UpdateSpendingLimits => "UpdateSpendingLimits",
            CreateWallet => "CreateWallet",
            ImportWallet => "ImportWallet",
            DeleteWallet => "DeleteWallet",
            RenameWallet => "RenameWallet",
            ExportWallet => "ExportWallet",
            EncryptWallet => "EncryptWallet",
            DecryptWallet => "DecryptWallet",
            GetWalletInfo => "GetWalletInfo",
            ListWallets => "ListWallets",
            SetWalletLimits => "SetWalletLimits",
            SendEth => "SendEth",
            SendToken => "SendToken",
            ApproveToken => "ApproveToken",
            CallContract => "CallContract",
            SignTransaction => "SignTransaction",
            SignMessage => "SignMessage",
            ExecuteViaTba => "ExecuteViaTba",
            CheckTbaOwnership => "CheckTbaOwnership",
            SetupTbaDelegation => "SetupTbaDelegation",
            BuildAndSignUserOperationForPayment => "BuildAndSignUserOperationForPayment",
            SubmitUserOperation => "SubmitUserOperation",
            BuildUserOperation => "BuildUserOperation",
            SignUserOperation => "SignUserOperation",
            BuildAndSignUserOperation => "BuildAndSignUserOperation",
            EstimateUserOperationGas => "EstimateUserOperationGas",
            GetUserOperationReceipt => "GetUserOperationReceipt",
            ConfigurePaymaster => "ConfigurePaymaster",
            ResolveIdentity => "ResolveIdentity",
            CreateNote => "CreateNote",
            ReadNote => "ReadNote",
            SetupDelegation => "SetupDelegation",
            VerifyDelegation => "VerifyDelegation",
            MintEntry => "MintEntry",
            GetBalance => "GetBalance",
            GetTokenBalance => "GetTokenBalance",
            GetTransactionHistory => "GetTransactionHistory",
            EstimateGas => "EstimateGas",
            GetGasPrice => "GetGasPrice",
            GetTransactionReceipt => "GetTransactionReceipt",
            BatchOperations => "BatchOperations",
            ScheduleOperation => "ScheduleOperation",
            CancelOperation => "CancelOperation",
        })
    }
}

impl<'a> Deserialize<'a> for wit::Operation {
    fn deserialize<D>(deserializer: D) -> Result<wit::Operation, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        let s = String::deserialize(deserializer)?;
        use wit::Operation::*;
        match s.as_str() {
            "Handshake" => Ok(Handshake),
            "UnlockWallet" => Ok(UnlockWallet),
            "RegisterProcess" => Ok(RegisterProcess),
            "UpdateSpendingLimits" => Ok(UpdateSpendingLimits),
            "CreateWallet" => Ok(CreateWallet),
            "ImportWallet" => Ok(ImportWallet),
            "DeleteWallet" => Ok(DeleteWallet),
            "RenameWallet" => Ok(RenameWallet),
            "ExportWallet" => Ok(ExportWallet),
            "EncryptWallet" => Ok(EncryptWallet),
            "DecryptWallet" => Ok(DecryptWallet),
            "GetWalletInfo" => Ok(GetWalletInfo),
            "ListWallets" => Ok(ListWallets),
            "SetWalletLimits" => Ok(SetWalletLimits),
            "SendEth" => Ok(SendEth),
            "SendToken" => Ok(SendToken),
            "ApproveToken" => Ok(ApproveToken),
            "CallContract" => Ok(CallContract),
            "SignTransaction" => Ok(SignTransaction),
            "SignMessage" => Ok(SignMessage),
            "ExecuteViaTba" => Ok(ExecuteViaTba),
            "CheckTbaOwnership" => Ok(CheckTbaOwnership),
            "SetupTbaDelegation" => Ok(SetupTbaDelegation),
            "BuildAndSignUserOperationForPayment" => Ok(BuildAndSignUserOperationForPayment),
            "SubmitUserOperation" => Ok(SubmitUserOperation),
            "BuildUserOperation" => Ok(BuildUserOperation),
            "SignUserOperation" => Ok(SignUserOperation),
            "BuildAndSignUserOperation" => Ok(BuildAndSignUserOperation),
            "EstimateUserOperationGas" => Ok(EstimateUserOperationGas),
            "GetUserOperationReceipt" => Ok(GetUserOperationReceipt),
            "ConfigurePaymaster" => Ok(ConfigurePaymaster),
            "ResolveIdentity" => Ok(ResolveIdentity),
            "CreateNote" => Ok(CreateNote),
            "ReadNote" => Ok(ReadNote),
            "SetupDelegation" => Ok(SetupDelegation),
            "VerifyDelegation" => Ok(VerifyDelegation),
            "MintEntry" => Ok(MintEntry),
            "GetBalance" => Ok(GetBalance),
            "GetTokenBalance" => Ok(GetTokenBalance),
            "GetTransactionHistory" => Ok(GetTransactionHistory),
            "EstimateGas" => Ok(EstimateGas),
            "GetGasPrice" => Ok(GetGasPrice),
            "GetTransactionReceipt" => Ok(GetTransactionReceipt),
            "BatchOperations" => Ok(BatchOperations),
            "ScheduleOperation" => Ok(ScheduleOperation),
            "CancelOperation" => Ok(CancelOperation),
            _ => Err(de::Error::unknown_variant(&s, &[])),
        }
    }
}

// ============================================================================
// ProcessPermissions
// ============================================================================

impl Serialize for wit::ProcessPermissions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("ProcessPermissions", 5)?;
        state.serialize_field("address", &self.address)?;
        state.serialize_field("allowed_operations", &self.allowed_operations)?;
        state.serialize_field("spending_limits", &self.spending_limits)?;
        state.serialize_field("updatable_settings", &self.updatable_settings)?;
        state.serialize_field("registered_at", &self.registered_at)?;
        state.end()
    }
}

impl<'a> Deserialize<'a> for wit::ProcessPermissions {
    fn deserialize<D>(deserializer: D) -> Result<wit::ProcessPermissions, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Address,
            AllowedOperations,
            SpendingLimits,
            UpdatableSettings,
            RegisteredAt,
        }

        struct ProcessPermissionsVisitor;

        impl<'de> Visitor<'de> for ProcessPermissionsVisitor {
            type Value = wit::ProcessPermissions;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct ProcessPermissions")
            }

            fn visit_map<V>(self, mut map: V) -> Result<wit::ProcessPermissions, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut address = None;
                let mut allowed_operations = None;
                let mut spending_limits = None;
                let mut updatable_settings = None;
                let mut registered_at = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Address => {
                            if address.is_some() {
                                return Err(de::Error::duplicate_field("address"));
                            }
                            address = Some(map.next_value()?);
                        }
                        Field::AllowedOperations => {
                            if allowed_operations.is_some() {
                                return Err(de::Error::duplicate_field("allowed_operations"));
                            }
                            allowed_operations = Some(map.next_value()?);
                        }
                        Field::SpendingLimits => {
                            if spending_limits.is_some() {
                                return Err(de::Error::duplicate_field("spending_limits"));
                            }
                            spending_limits = Some(map.next_value()?);
                        }
                        Field::UpdatableSettings => {
                            if updatable_settings.is_some() {
                                return Err(de::Error::duplicate_field("updatable_settings"));
                            }
                            updatable_settings = Some(map.next_value()?);
                        }
                        Field::RegisteredAt => {
                            if registered_at.is_some() {
                                return Err(de::Error::duplicate_field("registered_at"));
                            }
                            registered_at = Some(map.next_value()?);
                        }
                    }
                }

                let address = address.ok_or_else(|| de::Error::missing_field("address"))?;
                let allowed_operations = allowed_operations
                    .ok_or_else(|| de::Error::missing_field("allowed_operations"))?;
                let registered_at =
                    registered_at.ok_or_else(|| de::Error::missing_field("registered_at"))?;

                Ok(wit::ProcessPermissions {
                    address,
                    allowed_operations,
                    spending_limits,
                    updatable_settings: updatable_settings.unwrap_or_default(),
                    registered_at,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "address",
            "allowed_operations",
            "spending_limits",
            "updatable_settings",
            "registered_at",
        ];
        deserializer.deserialize_struct("ProcessPermissions", FIELDS, ProcessPermissionsVisitor)
    }
}

// ============================================================================
// SpendingLimits
// ============================================================================

impl Serialize for wit::SpendingLimits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("SpendingLimits", 7)?;
        state.serialize_field("per_tx_eth", &self.per_tx_eth)?;
        state.serialize_field("daily_eth", &self.daily_eth)?;
        state.serialize_field("per_tx_usdc", &self.per_tx_usdc)?;
        state.serialize_field("daily_usdc", &self.daily_usdc)?;
        state.serialize_field("daily_reset_at", &self.daily_reset_at)?;
        state.serialize_field("spent_today_eth", &self.spent_today_eth)?;
        state.serialize_field("spent_today_usdc", &self.spent_today_usdc)?;
        state.end()
    }
}

impl<'a> Deserialize<'a> for wit::SpendingLimits {
    fn deserialize<D>(deserializer: D) -> Result<wit::SpendingLimits, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            PerTxEth,
            DailyEth,
            PerTxUsdc,
            DailyUsdc,
            DailyResetAt,
            SpentTodayEth,
            SpentTodayUsdc,
        }

        struct SpendingLimitsVisitor;

        impl<'de> Visitor<'de> for SpendingLimitsVisitor {
            type Value = wit::SpendingLimits;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct SpendingLimits")
            }

            fn visit_map<V>(self, mut map: V) -> Result<wit::SpendingLimits, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut per_tx_eth = None;
                let mut daily_eth = None;
                let mut per_tx_usdc = None;
                let mut daily_usdc = None;
                let mut daily_reset_at = None;
                let mut spent_today_eth = None;
                let mut spent_today_usdc = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::PerTxEth => {
                            if per_tx_eth.is_some() {
                                return Err(de::Error::duplicate_field("per_tx_eth"));
                            }
                            per_tx_eth = Some(map.next_value()?);
                        }
                        Field::DailyEth => {
                            if daily_eth.is_some() {
                                return Err(de::Error::duplicate_field("daily_eth"));
                            }
                            daily_eth = Some(map.next_value()?);
                        }
                        Field::PerTxUsdc => {
                            if per_tx_usdc.is_some() {
                                return Err(de::Error::duplicate_field("per_tx_usdc"));
                            }
                            per_tx_usdc = Some(map.next_value()?);
                        }
                        Field::DailyUsdc => {
                            if daily_usdc.is_some() {
                                return Err(de::Error::duplicate_field("daily_usdc"));
                            }
                            daily_usdc = Some(map.next_value()?);
                        }
                        Field::DailyResetAt => {
                            if daily_reset_at.is_some() {
                                return Err(de::Error::duplicate_field("daily_reset_at"));
                            }
                            daily_reset_at = Some(map.next_value()?);
                        }
                        Field::SpentTodayEth => {
                            if spent_today_eth.is_some() {
                                return Err(de::Error::duplicate_field("spent_today_eth"));
                            }
                            spent_today_eth = Some(map.next_value()?);
                        }
                        Field::SpentTodayUsdc => {
                            if spent_today_usdc.is_some() {
                                return Err(de::Error::duplicate_field("spent_today_usdc"));
                            }
                            spent_today_usdc = Some(map.next_value()?);
                        }
                    }
                }

                let daily_reset_at =
                    daily_reset_at.ok_or_else(|| de::Error::missing_field("daily_reset_at"))?;
                let spent_today_eth =
                    spent_today_eth.ok_or_else(|| de::Error::missing_field("spent_today_eth"))?;
                let spent_today_usdc =
                    spent_today_usdc.ok_or_else(|| de::Error::missing_field("spent_today_usdc"))?;

                Ok(wit::SpendingLimits {
                    per_tx_eth,
                    daily_eth,
                    per_tx_usdc,
                    daily_usdc,
                    daily_reset_at,
                    spent_today_eth,
                    spent_today_usdc,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "per_tx_eth",
            "daily_eth",
            "per_tx_usdc",
            "daily_usdc",
            "daily_reset_at",
            "spent_today_eth",
            "spent_today_usdc",
        ];
        deserializer.deserialize_struct("SpendingLimits", FIELDS, SpendingLimitsVisitor)
    }
}

// ============================================================================
// UpdatableSetting enum
// ============================================================================

impl Serialize for wit::UpdatableSetting {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use wit::UpdatableSetting::*;
        serializer.serialize_str(match self {
            SpendingLimits => "SpendingLimits",
        })
    }
}

impl<'a> Deserialize<'a> for wit::UpdatableSetting {
    fn deserialize<D>(deserializer: D) -> Result<wit::UpdatableSetting, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        let s = String::deserialize(deserializer)?;
        use wit::UpdatableSetting::*;
        match s.as_str() {
            "SpendingLimits" => Ok(SpendingLimits),
            _ => Err(de::Error::unknown_variant(&s, &["SpendingLimits"])),
        }
    }
}

// ============================================================================
// HandshakeStep variant type
// ============================================================================

impl Serialize for wit::HandshakeStep {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use wit::HandshakeStep::*;

        match self {
            ClientHello(data) => {
                let mut state = serializer.serialize_struct("HandshakeStep", 2)?;
                state.serialize_field("type", "ClientHello")?;
                state.serialize_field("data", data)?;
                state.end()
            }
            ServerWelcome(data) => {
                let mut state = serializer.serialize_struct("HandshakeStep", 2)?;
                state.serialize_field("type", "ServerWelcome")?;
                state.serialize_field("data", data)?;
                state.end()
            }
            Register(data) => {
                let mut state = serializer.serialize_struct("HandshakeStep", 2)?;
                state.serialize_field("type", "Register")?;
                state.serialize_field("data", data)?;
                state.end()
            }
            Complete(data) => {
                let mut state = serializer.serialize_struct("HandshakeStep", 2)?;
                state.serialize_field("type", "Complete")?;
                state.serialize_field("data", data)?;
                state.end()
            }
        }
    }
}

impl<'a> Deserialize<'a> for wit::HandshakeStep {
    fn deserialize<D>(deserializer: D) -> Result<wit::HandshakeStep, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        struct HandshakeStepVisitor;

        impl<'de> Visitor<'de> for HandshakeStepVisitor {
            type Value = wit::HandshakeStep;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a HandshakeStep variant")
            }

            fn visit_map<V>(self, mut map: V) -> Result<wit::HandshakeStep, V::Error>
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

                use wit::HandshakeStep::*;
                match variant_type.as_str() {
                    "ClientHello" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let hello = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!("Failed to deserialize ClientHello: {}", e))
                        })?;
                        Ok(ClientHello(hello))
                    }
                    "ServerWelcome" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let welcome = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!("Failed to deserialize ServerWelcome: {}", e))
                        })?;
                        Ok(ServerWelcome(welcome))
                    }
                    "Register" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let register = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize RegisterRequest: {}",
                                e
                            ))
                        })?;
                        Ok(Register(register))
                    }
                    "Complete" => {
                        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                        let complete = serde_json::from_value(data).map_err(|e| {
                            de::Error::custom(format!(
                                "Failed to deserialize CompleteHandshake: {}",
                                e
                            ))
                        })?;
                        Ok(Complete(complete))
                    }
                    _ => Err(de::Error::unknown_variant(
                        &variant_type,
                        &["ClientHello", "ServerWelcome", "Register", "Complete"],
                    )),
                }
            }
        }

        const FIELDS: &[&str] = &["type", "data"];
        deserializer.deserialize_struct("HandshakeStep", FIELDS, HandshakeStepVisitor)
    }
}

// ClientHello
impl Serialize for wit::ClientHello {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("ClientHello", 2)?;
        state.serialize_field("client_version", &self.client_version)?;
        state.serialize_field("client_name", &self.client_name)?;
        state.end()
    }
}

impl<'a> Deserialize<'a> for wit::ClientHello {
    fn deserialize<D>(deserializer: D) -> Result<wit::ClientHello, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            ClientVersion,
            ClientName,
        }

        struct ClientHelloVisitor;

        impl<'de> Visitor<'de> for ClientHelloVisitor {
            type Value = wit::ClientHello;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct ClientHello")
            }

            fn visit_map<V>(self, mut map: V) -> Result<wit::ClientHello, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut client_version = None;
                let mut client_name = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::ClientVersion => {
                            if client_version.is_some() {
                                return Err(de::Error::duplicate_field("client_version"));
                            }
                            client_version = Some(map.next_value()?);
                        }
                        Field::ClientName => {
                            if client_name.is_some() {
                                return Err(de::Error::duplicate_field("client_name"));
                            }
                            client_name = Some(map.next_value()?);
                        }
                    }
                }

                let client_version =
                    client_version.ok_or_else(|| de::Error::missing_field("client_version"))?;
                let client_name =
                    client_name.ok_or_else(|| de::Error::missing_field("client_name"))?;

                Ok(wit::ClientHello {
                    client_version,
                    client_name,
                })
            }
        }

        const FIELDS: &[&str] = &["client_version", "client_name"];
        deserializer.deserialize_struct("ClientHello", FIELDS, ClientHelloVisitor)
    }
}

// ServerWelcome
impl Serialize for wit::ServerWelcome {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("ServerWelcome", 4)?;
        state.serialize_field("server_version", &self.server_version)?;
        state.serialize_field("supported_operations", &self.supported_operations)?;
        state.serialize_field("supported_chains", &self.supported_chains)?;
        state.serialize_field("features", &self.features)?;
        state.end()
    }
}

impl<'a> Deserialize<'a> for wit::ServerWelcome {
    fn deserialize<D>(deserializer: D) -> Result<wit::ServerWelcome, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            ServerVersion,
            SupportedOperations,
            SupportedChains,
            Features,
        }

        struct ServerWelcomeVisitor;

        impl<'de> Visitor<'de> for ServerWelcomeVisitor {
            type Value = wit::ServerWelcome;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct ServerWelcome")
            }

            fn visit_map<V>(self, mut map: V) -> Result<wit::ServerWelcome, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut server_version = None;
                let mut supported_operations = None;
                let mut supported_chains = None;
                let mut features = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::ServerVersion => {
                            if server_version.is_some() {
                                return Err(de::Error::duplicate_field("server_version"));
                            }
                            server_version = Some(map.next_value()?);
                        }
                        Field::SupportedOperations => {
                            if supported_operations.is_some() {
                                return Err(de::Error::duplicate_field("supported_operations"));
                            }
                            supported_operations = Some(map.next_value()?);
                        }
                        Field::SupportedChains => {
                            if supported_chains.is_some() {
                                return Err(de::Error::duplicate_field("supported_chains"));
                            }
                            supported_chains = Some(map.next_value()?);
                        }
                        Field::Features => {
                            if features.is_some() {
                                return Err(de::Error::duplicate_field("features"));
                            }
                            features = Some(map.next_value()?);
                        }
                    }
                }

                let server_version =
                    server_version.ok_or_else(|| de::Error::missing_field("server_version"))?;
                let supported_operations = supported_operations
                    .ok_or_else(|| de::Error::missing_field("supported_operations"))?;
                let supported_chains =
                    supported_chains.ok_or_else(|| de::Error::missing_field("supported_chains"))?;
                let features = features.ok_or_else(|| de::Error::missing_field("features"))?;

                Ok(wit::ServerWelcome {
                    server_version,
                    supported_operations,
                    supported_chains,
                    features,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "server_version",
            "supported_operations",
            "supported_chains",
            "features",
        ];
        deserializer.deserialize_struct("ServerWelcome", FIELDS, ServerWelcomeVisitor)
    }
}

// RegisterRequest
impl Serialize for wit::RegisterRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("RegisterRequest", 2)?;
        state.serialize_field("required_operations", &self.required_operations)?;
        state.serialize_field("spending_limits", &self.spending_limits)?;
        state.end()
    }
}

impl<'a> Deserialize<'a> for wit::RegisterRequest {
    fn deserialize<D>(deserializer: D) -> Result<wit::RegisterRequest, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            RequiredOperations,
            SpendingLimits,
        }

        struct RegisterRequestVisitor;

        impl<'de> Visitor<'de> for RegisterRequestVisitor {
            type Value = wit::RegisterRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct RegisterRequest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<wit::RegisterRequest, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut required_operations = None;
                let mut spending_limits = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::RequiredOperations => {
                            if required_operations.is_some() {
                                return Err(de::Error::duplicate_field("required_operations"));
                            }
                            required_operations = Some(map.next_value()?);
                        }
                        Field::SpendingLimits => {
                            if spending_limits.is_some() {
                                return Err(de::Error::duplicate_field("spending_limits"));
                            }
                            spending_limits = Some(map.next_value()?);
                        }
                    }
                }

                let required_operations = required_operations
                    .ok_or_else(|| de::Error::missing_field("required_operations"))?;

                Ok(wit::RegisterRequest {
                    required_operations,
                    spending_limits,
                })
            }
        }

        const FIELDS: &[&str] = &["required_operations", "spending_limits"];
        deserializer.deserialize_struct("RegisterRequest", FIELDS, RegisterRequestVisitor)
    }
}

// CompleteHandshake
impl Serialize for wit::CompleteHandshake {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("CompleteHandshake", 2)?;
        state.serialize_field("session_id", &self.session_id)?;
        state.serialize_field("registered_permissions", &self.registered_permissions)?;
        state.end()
    }
}

impl<'a> Deserialize<'a> for wit::CompleteHandshake {
    fn deserialize<D>(deserializer: D) -> Result<wit::CompleteHandshake, D::Error>
    where
        D: serde::de::Deserializer<'a>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            SessionId,
            RegisteredPermissions,
        }

        struct CompleteHandshakeVisitor;

        impl<'de> Visitor<'de> for CompleteHandshakeVisitor {
            type Value = wit::CompleteHandshake;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct CompleteHandshake")
            }

            fn visit_map<V>(self, mut map: V) -> Result<wit::CompleteHandshake, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut session_id = None;
                let mut registered_permissions = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::SessionId => {
                            if session_id.is_some() {
                                return Err(de::Error::duplicate_field("session_id"));
                            }
                            session_id = Some(map.next_value()?);
                        }
                        Field::RegisteredPermissions => {
                            if registered_permissions.is_some() {
                                return Err(de::Error::duplicate_field("registered_permissions"));
                            }
                            registered_permissions = Some(map.next_value()?);
                        }
                    }
                }

                let session_id =
                    session_id.ok_or_else(|| de::Error::missing_field("session_id"))?;
                let registered_permissions = registered_permissions
                    .ok_or_else(|| de::Error::missing_field("registered_permissions"))?;

                Ok(wit::CompleteHandshake {
                    session_id,
                    registered_permissions,
                })
            }
        }

        const FIELDS: &[&str] = &["session_id", "registered_permissions"];
        deserializer.deserialize_struct("CompleteHandshake", FIELDS, CompleteHandshakeVisitor)
    }
}
