use std::sync::Arc;

use aries_vcx::common::primitives::credential_schema::Schema;
use aries_vcx::core::profile::profile::Profile;
use aries_vcx::errors::error::VcxResult;
use aries_vcx::global::settings;
use aries_vcx::global::settings::{init_issuer_config, DEFAULT_LINK_SECRET_ALIAS};
use aries_vcx::protocols::connection::pairwise_info::PairwiseInfo;
use aries_vcx::utils::constants::TRUSTEE_SEED;
use aries_vcx::utils::devsetup::{dev_build_featured_profile, dev_setup_wallet_indy};
use aries_vcx_core::wallet::indy::wallet::get_verkey_from_wallet;
use aries_vcx_core::wallet::indy::IndySdkWallet;

pub struct Faber {
    pub profile: Arc<dyn Profile>,
    pub institution_did: String,
    pub schema: Schema,
    // todo: get rid of this, if we need vkey somewhere, we can get it from wallet, we can instead store public_did
    pub pairwise_info: PairwiseInfo,
    pub genesis_file_path: String,
}

pub async fn create_faber(genesis_file_path: String) -> Faber {
    let (public_did, wallet_handle) = dev_setup_wallet_indy(TRUSTEE_SEED).await;
    let wallet = Arc::new(IndySdkWallet::new(wallet_handle));
    let profile = dev_build_featured_profile(genesis_file_path.clone(), wallet).await;
    profile
        .inject_anoncreds()
        .prover_create_link_secret(DEFAULT_LINK_SECRET_ALIAS)
        .await
        .unwrap();
    Faber::setup(profile, genesis_file_path, public_did).await
}

impl Faber {
    pub async fn setup(profile: Arc<dyn Profile>, genesis_file_path: String, institution_did: String) -> Faber {
        settings::reset_config_values_ariesvcx().unwrap();

        // todo: can delete following?
        init_issuer_config(&institution_did).unwrap();
        let pairwise_info = PairwiseInfo::create(&profile.inject_wallet()).await.unwrap();

        let faber = Faber {
            genesis_file_path,
            profile,
            institution_did,
            schema: Schema::default(),
            pairwise_info,
        };
        faber
    }

    pub fn public_did(&self) -> &str {
        &self.institution_did
    }

    pub async fn get_verkey_from_wallet(&self, did: &str) -> String {
        get_verkey_from_wallet(self.profile.inject_wallet().get_wallet_handle(), did)
            .await
            .unwrap()
    }

    pub async fn create_schema(&mut self) -> VcxResult<()> {
        let data = vec!["name", "date", "degree", "empty_param"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let name: String = aries_vcx::utils::random::generate_random_schema_name();
        let version: String = String::from("1.0");

        self.schema = Schema::create(
            &self.profile.inject_anoncreds(),
            "",
            &self.institution_did,
            &name,
            &version,
            &data,
        )
        .await?
        .publish(&self.profile.inject_anoncreds_ledger_write(), None)
        .await?;
        Ok(())
    }
}
