use vdrtools::{Locator, DidValue};

use vdrtools::{PoolHandle, WalletHandle};
use crate::error::{VcxError, VcxErrorKind, VcxResult};
use crate::utils::constants::{CRED_DEF_ID, CRED_DEF_JSON, DEFAULT_SERIALIZE_VERSION};
use crate::utils::serialization::ObjectWithVersion;

use crate::global::settings;
use crate::indy::ledger::transactions::{
    build_cred_def_request, check_response,sign_and_submit_to_ledger
};

// consider relocating
pub async fn publish_cred_def(
    wallet_handle: WalletHandle,
    pool_handle: PoolHandle,
    issuer_did: &str,
    cred_def_json: &str,
) -> VcxResult<()> {
    trace!(
        "publish_cred_def >>> issuer_did: {}, cred_def_json: {}",
        issuer_did,
        cred_def_json
    );
    if settings::indy_mocks_enabled() {
        debug!("publish_cred_def >>> mocked success");
        return Ok(());
    }
    let cred_def_req = build_cred_def_request(issuer_did, cred_def_json).await?;
    let response = sign_and_submit_to_ledger(wallet_handle, pool_handle, issuer_did, &cred_def_req).await?;
    check_response(&response)
}

// consider relocating
pub async fn libindy_create_and_store_credential_def(
    wallet_handle: WalletHandle,
    issuer_did: &str,
    schema_json: &str,
    tag: &str,
    sig_type: Option<&str>,
    config_json: &str,
) -> VcxResult<(String, String)> {

    let res = Locator::instance()
        .issuer_controller
        .create_and_store_credential_definition(
            wallet_handle,
            DidValue(issuer_did.into()),
            serde_json::from_str(schema_json)?,
            tag.into(),
            sig_type.map(|s| s.into()),
            serde_json::from_str(config_json)?,
        ).await?;

    Ok(res)
}
