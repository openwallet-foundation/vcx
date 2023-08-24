use std::fmt::Debug;

use async_trait::async_trait;
use indy_vdr::ledger::constants::UpdateRole;
use serde::Serialize;

use crate::errors::error::VcxCoreResult;

pub trait IndyLedgerTypes: Debug + Send + Sync {
    type Schema;

    type CredDef;

    type RevRegDef;

    type RevRegDelta;

    type RevReg;
}

#[async_trait]
pub trait IndyLedgerRead2: IndyLedgerTypes {
    async fn get_attr(&self, target_did: &str, attr_name: &str) -> VcxCoreResult<String>;
    async fn get_nym(&self, did: &str) -> VcxCoreResult<String>;
    async fn get_txn_author_agreement(&self) -> VcxCoreResult<Option<String>>;
    async fn get_ledger_txn(&self, seq_no: i32, submitter_did: Option<&str>) -> VcxCoreResult<String>;
    async fn get_schema(&self, schema_id: &str, submitter_did: Option<&str>) -> VcxCoreResult<Self::Schema>;
    async fn get_cred_def(&self, cred_def_id: &str, submitter_did: Option<&str>) -> VcxCoreResult<Self::CredDef>;
    async fn get_rev_reg_def_json(&self, rev_reg_id: &str) -> VcxCoreResult<Self::RevRegDef>;
    async fn get_rev_reg_delta_json(
        &self,
        rev_reg_id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> VcxCoreResult<(String, Self::RevRegDelta, u64)>;
    async fn get_rev_reg(&self, rev_reg_id: &str, timestamp: u64) -> VcxCoreResult<(String, Self::RevReg, u64)>;
    fn get_txn_author_agreement_options(&self) -> VcxCoreResult<Option<TxnAuthrAgrmtOptions>>;
}

#[async_trait]
pub trait IndyLedgerWrite2: IndyLedgerTypes {
    async fn publish_nym(
        &self,
        submitter_did: &str,
        target_did: &str,
        verkey: Option<&str>,
        data: Option<&str>,
        role: Option<&str>,
    ) -> VcxCoreResult<String>;
    async fn set_endorser(&self, submitter_did: &str, request: &str, endorser: &str) -> VcxCoreResult<String>;
    async fn endorse_transaction(&self, endorser_did: &str, request_json: &str) -> VcxCoreResult<()>;
    async fn add_attr(&self, target_did: &str, attrib_json: &str) -> VcxCoreResult<String>;
    async fn write_did(
        &self,
        submitter_did: &str,
        target_did: &str,
        target_vk: &str,
        role: Option<UpdateRole>,
        alias: Option<String>,
    ) -> VcxCoreResult<String>;
    async fn publish_schema(
        &self,
        schema: &Self::Schema,
        submitter_did: &str,
        endorser_did: Option<String>,
    ) -> VcxCoreResult<()>;
    async fn publish_cred_def(&self, cred_def: &Self::CredDef, submitter_did: &str) -> VcxCoreResult<()>;
    async fn publish_rev_reg_def(&self, rev_reg_def: &Self::RevRegDef, submitter_did: &str) -> VcxCoreResult<()>;
    async fn publish_rev_reg_delta(
        &self,
        rev_reg_id: &str,
        rev_reg_delta: &Self::RevRegDelta,
        submitter_did: &str,
    ) -> VcxCoreResult<()>;
    fn set_txn_author_agreement_options(&self, taa_options: TxnAuthrAgrmtOptions) -> VcxCoreResult<()>;
}

#[async_trait]
pub trait IndyLedgerRead: Debug + Send + Sync {
    async fn get_attr(&self, target_did: &str, attr_name: &str) -> VcxCoreResult<String>;
    async fn get_nym(&self, did: &str) -> VcxCoreResult<String>;
    async fn get_txn_author_agreement(&self) -> VcxCoreResult<Option<String>>;
    async fn get_ledger_txn(&self, seq_no: i32, submitter_did: Option<&str>) -> VcxCoreResult<String>;
}

#[async_trait]
pub trait IndyLedgerWrite: Debug + Send + Sync {
    async fn publish_nym(
        &self,
        submitter_did: &str,
        target_did: &str,
        verkey: Option<&str>,
        data: Option<&str>,
        role: Option<&str>,
    ) -> VcxCoreResult<String>;
    async fn set_endorser(&self, submitter_did: &str, request: &str, endorser: &str) -> VcxCoreResult<String>;
    async fn endorse_transaction(&self, endorser_did: &str, request_json: &str) -> VcxCoreResult<()>;
    async fn add_attr(&self, target_did: &str, attrib_json: &str) -> VcxCoreResult<String>;
    async fn write_did(
        &self,
        submitter_did: &str,
        target_did: &str,
        target_vk: &str,
        role: Option<UpdateRole>,
        alias: Option<String>,
    ) -> VcxCoreResult<String>;
}

#[async_trait]
pub trait AnoncredsLedgerRead: Debug + Send + Sync {
    async fn get_schema(&self, schema_id: &str, submitter_did: Option<&str>) -> VcxCoreResult<String>;
    async fn get_cred_def(&self, cred_def_id: &str, submitter_did: Option<&str>) -> VcxCoreResult<String>;
    async fn get_rev_reg_def_json(&self, rev_reg_id: &str) -> VcxCoreResult<String>;
    async fn get_rev_reg_delta_json(
        &self,
        rev_reg_id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> VcxCoreResult<(String, String, u64)>;
    async fn get_rev_reg(&self, rev_reg_id: &str, timestamp: u64) -> VcxCoreResult<(String, String, u64)>;
}

#[async_trait]
pub trait AnoncredsLedgerWrite: Debug + Send + Sync {
    async fn publish_schema(
        &self,
        schema_json: &str,
        submitter_did: &str,
        endorser_did: Option<String>,
    ) -> VcxCoreResult<()>;
    async fn publish_cred_def(&self, cred_def_json: &str, submitter_did: &str) -> VcxCoreResult<()>;
    async fn publish_rev_reg_def(&self, rev_reg_def: &str, submitter_did: &str) -> VcxCoreResult<()>;
    async fn publish_rev_reg_delta(
        &self,
        rev_reg_id: &str,
        rev_reg_entry_json: &str,
        submitter_did: &str,
    ) -> VcxCoreResult<()>;
}

pub trait TaaConfigurator: Debug + Send + Sync {
    fn set_txn_author_agreement_options(&self, taa_options: TxnAuthrAgrmtOptions) -> VcxCoreResult<()>;
    fn get_txn_author_agreement_options(&self) -> VcxCoreResult<Option<TxnAuthrAgrmtOptions>>;
}

#[derive(Clone, Serialize)]
pub struct TxnAuthrAgrmtOptions {
    pub text: String,
    pub version: String,
    pub mechanism: String,
}
