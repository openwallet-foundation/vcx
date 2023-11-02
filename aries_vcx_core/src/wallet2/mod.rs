#[cfg(feature = "vdrtools_wallet")]
pub mod vdrtools;

use async_trait::async_trait;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};

use crate::errors::error::VcxCoreResult;

#[async_trait]
pub trait Wallet {
    type Record: Send + Sync;
    type RecordId;
    type SearchFilter<'a>: Send + Sync;

    async fn add(&self, record: Self::Record) -> VcxCoreResult<()>;

    async fn get<R>(&self, id: &Self::RecordId) -> VcxCoreResult<R>
    where
        R: WalletRecord<Self, RecordId = Self::RecordId>;

    async fn update(&self, update: Self::Record) -> VcxCoreResult<()>;

    async fn delete<R>(&self, id: &Self::RecordId) -> VcxCoreResult<()>
    where
        R: WalletRecord<Self, RecordId = Self::RecordId>;

    async fn search<'a, R>(
        &'a self,
        filter: Self::SearchFilter<'_>,
    ) -> VcxCoreResult<BoxStream<'a, VcxCoreResult<R>>>
    where
        R: WalletRecord<Self> + Send + Sync + 'a;

    async fn create_did(
        &self,
        seed: Option<&str>,
        method_name: Option<&str>,
    ) -> VcxCoreResult<(String, String)>;

    async fn did_key(&self, did: &str) -> VcxCoreResult<String>;

    async fn replace_did_key(&self, did: &str) -> VcxCoreResult<String>;

    async fn sign(&self, verkey: &str, msg: &[u8]) -> VcxCoreResult<Vec<u8>>;

    async fn verify(&self, vk: &str, msg: &[u8], signature: &[u8]) -> VcxCoreResult<bool>;

    async fn pack_message(
        &self,
        sender_vk: Option<&str>,
        receiver_keys: &[String],
        msg: &[u8],
    ) -> VcxCoreResult<Vec<u8>>;

    async fn unpack_message(&self, msg: &[u8]) -> VcxCoreResult<UnpackMessageOutput>;
}

pub trait WalletRecord<W: Wallet + ?Sized> {
    const RECORD_TYPE: &'static str;

    type RecordId;

    fn into_wallet_record(self, id: Self::RecordId) -> VcxCoreResult<W::Record>;

    fn from_wallet_record(record: W::Record) -> VcxCoreResult<Self>
    where
        Self: Sized;
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct UnpackMessageOutput {
    pub message: String,
    pub recipient_verkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_verkey: Option<String>,
}
