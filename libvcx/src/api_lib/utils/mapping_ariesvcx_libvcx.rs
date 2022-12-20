use aries_vcx::errors::error::{VcxError, VcxErrorKind, VcxResult};
use crate::api_lib::utils::libvcx_error::{LibvcxError, LibvcxErrorKind, LibvcxResult};

pub fn map_ariesvcx_result<T>(result: VcxResult<T>) -> LibvcxResult<T> {
    match result {
        Ok(val) => Ok(val),
        Err(err) => Err(err.into())
    }
}

impl From<VcxError> for LibvcxError {
    fn from(error: VcxError) -> LibvcxError {
        LibvcxError {
            kind: error.kind().into(),
            msg: error.to_string(),
        }
    }
}

impl From<VcxErrorKind> for LibvcxErrorKind {
    fn from(kind: VcxErrorKind) -> Self {
        match kind {
            VcxErrorKind::InvalidState => LibvcxErrorKind::InvalidState,
            VcxErrorKind::InvalidConfiguration => LibvcxErrorKind::InvalidConfiguration,
            VcxErrorKind::InvalidHandle => LibvcxErrorKind::InvalidHandle,
            VcxErrorKind::InvalidJson => LibvcxErrorKind::InvalidJson,
            VcxErrorKind::InvalidOption => LibvcxErrorKind::InvalidOption,
            VcxErrorKind::InvalidMessagePack => LibvcxErrorKind::InvalidMessagePack,
            VcxErrorKind::ObjectCacheError => LibvcxErrorKind::ObjectCacheError,
            VcxErrorKind::NotReady => LibvcxErrorKind::NotReady,
            VcxErrorKind::IOError => LibvcxErrorKind::IOError,
            VcxErrorKind::LibindyInvalidStructure => LibvcxErrorKind::LibindyInvalidStructure,
            VcxErrorKind::TimeoutLibindy => LibvcxErrorKind::TimeoutLibindy,
            VcxErrorKind::InvalidLibindyParam => LibvcxErrorKind::InvalidLibindyParam,
            VcxErrorKind::AlreadyInitialized => LibvcxErrorKind::AlreadyInitialized,
            VcxErrorKind::ActionNotSupported => LibvcxErrorKind::ActionNotSupported,
            VcxErrorKind::InvalidInput => LibvcxErrorKind::InvalidInput,
            VcxErrorKind::UnimplementedFeature => LibvcxErrorKind::UnimplementedFeature,
            VcxErrorKind::CreateConnection => LibvcxErrorKind::CreateConnection,
            VcxErrorKind::InvalidConnectionHandle => LibvcxErrorKind::InvalidConnectionHandle,
            VcxErrorKind::InvalidInviteDetail => LibvcxErrorKind::InvalidInviteDetail,
            VcxErrorKind::InvalidRedirectDetail => LibvcxErrorKind::InvalidRedirectDetail,
            VcxErrorKind::DeleteConnection => LibvcxErrorKind::DeleteConnection,
            VcxErrorKind::GeneralConnectionError => LibvcxErrorKind::GeneralConnectionError,
            VcxErrorKind::NoPaymentInformation => LibvcxErrorKind::NoPaymentInformation,
            VcxErrorKind::InsufficientTokenAmount => LibvcxErrorKind::InsufficientTokenAmount,
            VcxErrorKind::InvalidPaymentAddress => LibvcxErrorKind::InvalidPaymentAddress,
            VcxErrorKind::CreateCredDef => LibvcxErrorKind::CreateCredDef,
            VcxErrorKind::CredDefAlreadyCreated => LibvcxErrorKind::CredDefAlreadyCreated,
            VcxErrorKind::InvalidCredDefHandle => LibvcxErrorKind::InvalidCredDefHandle,
            VcxErrorKind::RevDeltaNotFound => LibvcxErrorKind::RevDeltaNotFound,
            VcxErrorKind::RevDeltaFailedToClear => LibvcxErrorKind::RevDeltaFailedToClear,
            VcxErrorKind::CreateRevRegDef => LibvcxErrorKind::CreateRevRegDef,
            VcxErrorKind::InvalidRevocationDetails => LibvcxErrorKind::InvalidRevocationDetails,
            VcxErrorKind::InvalidRevocationEntry => LibvcxErrorKind::InvalidRevocationEntry,
            VcxErrorKind::InvalidRevocationTimestamp => LibvcxErrorKind::InvalidRevocationTimestamp,
            VcxErrorKind::RevRegDefNotFound => LibvcxErrorKind::RevRegDefNotFound,
            VcxErrorKind::InvalidCredentialHandle => LibvcxErrorKind::InvalidCredentialHandle,
            VcxErrorKind::CreateCredentialRequest => LibvcxErrorKind::CreateCredentialRequest,
            VcxErrorKind::InvalidIssuerCredentialHandle => LibvcxErrorKind::InvalidIssuerCredentialHandle,
            VcxErrorKind::InvalidCredentialRequest => LibvcxErrorKind::InvalidCredentialRequest,
            VcxErrorKind::InvalidCredential => LibvcxErrorKind::InvalidCredential,
            VcxErrorKind::InvalidAttributesStructure => LibvcxErrorKind::InvalidAttributesStructure,
            VcxErrorKind::InvalidProofHandle => LibvcxErrorKind::InvalidProofHandle,
            VcxErrorKind::InvalidDisclosedProofHandle => LibvcxErrorKind::InvalidDisclosedProofHandle,
            VcxErrorKind::InvalidProof => LibvcxErrorKind::InvalidProof,
            VcxErrorKind::InvalidSchema => LibvcxErrorKind::InvalidSchema,
            VcxErrorKind::InvalidProofCredentialData => LibvcxErrorKind::InvalidProofCredentialData,
            VcxErrorKind::CreateProof => LibvcxErrorKind::CreateProof,
            VcxErrorKind::InvalidProofRequest => LibvcxErrorKind::InvalidProofRequest,
            VcxErrorKind::CreateSchema => LibvcxErrorKind::CreateSchema,
            VcxErrorKind::InvalidSchemaHandle => LibvcxErrorKind::InvalidSchemaHandle,
            VcxErrorKind::InvalidSchemaSeqNo => LibvcxErrorKind::InvalidSchemaSeqNo,
            VcxErrorKind::DuplicationSchema => LibvcxErrorKind::DuplicationSchema,
            VcxErrorKind::UnknownSchemaRejection => LibvcxErrorKind::UnknownSchemaRejection,
            VcxErrorKind::CreatePublicAgent => LibvcxErrorKind::CreatePublicAgent,
            VcxErrorKind::CreateOutOfBand => LibvcxErrorKind::CreateOutOfBand,
            VcxErrorKind::InvalidGenesisTxnPath => LibvcxErrorKind::InvalidGenesisTxnPath,
            VcxErrorKind::CreatePoolConfig => LibvcxErrorKind::CreatePoolConfig,
            VcxErrorKind::PoolLedgerConnect => LibvcxErrorKind::PoolLedgerConnect,
            VcxErrorKind::InvalidLedgerResponse => LibvcxErrorKind::InvalidLedgerResponse,
            VcxErrorKind::NoPoolOpen => LibvcxErrorKind::NoPoolOpen,
            VcxErrorKind::PostMessageFailed => LibvcxErrorKind::PostMessageFailed,
            VcxErrorKind::WalletCreate => LibvcxErrorKind::WalletCreate,
            VcxErrorKind::MissingWalletName => LibvcxErrorKind::MissingWalletName,
            VcxErrorKind::MissingExportedWalletPath => LibvcxErrorKind::MissingExportedWalletPath,
            VcxErrorKind::MissingBackupKey => LibvcxErrorKind::MissingBackupKey,
            VcxErrorKind::WalletAccessFailed => LibvcxErrorKind::WalletAccessFailed,
            VcxErrorKind::InvalidWalletHandle => LibvcxErrorKind::InvalidWalletHandle,
            VcxErrorKind::DuplicationWallet => LibvcxErrorKind::DuplicationWallet,
            VcxErrorKind::WalletRecordNotFound => LibvcxErrorKind::WalletRecordNotFound,
            VcxErrorKind::DuplicationWalletRecord => LibvcxErrorKind::DuplicationWalletRecord,
            VcxErrorKind::WalletNotFound => LibvcxErrorKind::WalletNotFound,
            VcxErrorKind::WalletAlreadyOpen => LibvcxErrorKind::WalletAlreadyOpen,
            VcxErrorKind::MissingWalletKey => LibvcxErrorKind::MissingWalletKey,
            VcxErrorKind::DuplicationMasterSecret => LibvcxErrorKind::DuplicationMasterSecret,
            VcxErrorKind::DuplicationDid => LibvcxErrorKind::DuplicationDid,
            VcxErrorKind::LoggingError => LibvcxErrorKind::LoggingError,
            VcxErrorKind::EncodeError => LibvcxErrorKind::EncodeError,
            VcxErrorKind::UnknownError => LibvcxErrorKind::UnknownError,
            VcxErrorKind::InvalidDid => LibvcxErrorKind::InvalidDid,
            VcxErrorKind::InvalidVerkey => LibvcxErrorKind::InvalidVerkey,
            VcxErrorKind::InvalidNonce => LibvcxErrorKind::InvalidNonce,
            VcxErrorKind::InvalidUrl => LibvcxErrorKind::InvalidUrl,
            VcxErrorKind::MissingPaymentMethod => LibvcxErrorKind::MissingPaymentMethod,
            VcxErrorKind::SerializationError => LibvcxErrorKind::SerializationError,
            VcxErrorKind::NotBase58 => LibvcxErrorKind::NotBase58,
            VcxErrorKind::ParsingError => LibvcxErrorKind::ParsingError,
            VcxErrorKind::InvalidHttpResponse => LibvcxErrorKind::InvalidHttpResponse,
            VcxErrorKind::NoEndpoint => LibvcxErrorKind::NoEndpoint,
            VcxErrorKind::InvalidMessages => LibvcxErrorKind::InvalidMessages,
            VcxErrorKind::CreateAgent => LibvcxErrorKind::CreateAgent,
            VcxErrorKind::Common(num) => LibvcxErrorKind::Common(num),
            VcxErrorKind::LibndyError(num) => LibvcxErrorKind::LibndyError(num),
            VcxErrorKind::UnknownLibndyError => LibvcxErrorKind::UnknownLibndyError,
            VcxErrorKind::NoAgentInformation => LibvcxErrorKind::NoAgentInformation,
            VcxErrorKind::InvalidMessageFormat => LibvcxErrorKind::InvalidMessageFormat,
            VcxErrorKind::PoisonedLock => LibvcxErrorKind::PoisonedLock,
        }
    }
}
