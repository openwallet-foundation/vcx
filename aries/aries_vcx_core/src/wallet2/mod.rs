use async_trait::async_trait;
use futures::stream::BoxStream;

use crate::errors::error::VcxCoreResult;

pub enum SigType {
    EdDSA,
    ES256,
    ES256K,
    ES384,
}

impl From<SigType> for &str {
    fn from(value: SigType) -> Self {
        match value {
            SigType::EdDSA => "eddsa",
            SigType::ES256 => "es256",
            SigType::ES256K => "es256k",
            SigType::ES384 => "es384",
        }
    }
}

#[async_trait]
pub trait Wallet: RecordWallet + DidWallet {}

#[async_trait]
pub trait DidWallet {
    type DidAttrs;
    type CreatedDid;
    type DidKey;
    type KeyAttrs;

    async fn create_key(&self, key_attrs: Self::KeyAttrs) -> VcxCoreResult<()>;

    async fn create_did(&self, attrs: Self::DidAttrs) -> VcxCoreResult<Self::CreatedDid>;

    async fn did_key(&self, did: &str) -> VcxCoreResult<Self::DidKey>;

    async fn replace_did_key(&self, did: &str) -> VcxCoreResult<Self::DidKey>;

    async fn sign(&self, verkey_name: &str, msg: &[u8], sig_type: SigType) -> VcxCoreResult<Vec<u8>>;

    async fn verify(&self, vk: &str, msg: &[u8], signature: &[u8], sig_type: SigType) -> VcxCoreResult<bool>;
}

#[async_trait]
pub trait RecordWallet {
    type Record;
    type RecordId;
    type FoundRecord;
    type SearchFilter;

    async fn add_record(&self, record: Self::Record) -> VcxCoreResult<()>;

    async fn get_record(&self, id: &Self::RecordId) -> VcxCoreResult<Self::FoundRecord>;

    async fn update_record(&self, update: Self::Record) -> VcxCoreResult<()>;

    async fn delete_record(&self, id: &Self::RecordId) -> VcxCoreResult<()>;

    async fn search_record(&self, filter: Self::SearchFilter) -> VcxCoreResult<BoxStream<VcxCoreResult<Self::FoundRecord>>>;
}
