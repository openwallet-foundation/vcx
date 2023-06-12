use aries_vcx_core::indy::{self, wallet::WalletConfig};
use vdrtools::{types::domain::wallet::Record, IndyError, Locator, WalletHandle};

// pub const CATEGORY_LINK_SECRET: &str = "VCX_LINK_SECRET";

// pub const CATEGORY_CREDENTIAL: &str = "VCX_CREDENTIAL";
// pub const CATEGORY_CRED_DEF: &str = "VCX_CRED_DEF";
// pub const CATEGORY_CRED_KEY_CORRECTNESS_PROOF: &str = "VCX_CRED_KEY_CORRECTNESS_PROOF";
// pub const CATEGORY_CRED_DEF_PRIV: &str = "VCX_CRED_DEF_PRIV";
// pub const CATEGORY_CRED_SCHEMA: &str = "VCX_CRED_SCHEMA";

// // Category used for mapping a cred_def_id to a schema_id
// pub const CATEGORY_CRED_MAP_SCHEMA_ID: &str = "VCX_CRED_MAP_SCHEMA_ID";

// pub const CATEGORY_REV_REG: &str = "VCX_REV_REG";
// pub const CATEGORY_REV_REG_DELTA: &str = "VCX_REV_REG_DELTA";
// pub const CATEGORY_REV_REG_INFO: &str = "VCX_REV_REG_INFO";
// pub const CATEGORY_REV_REG_DEF: &str = "VCX_REV_REG_DEF";
// pub const CATEGORY_REV_REG_DEF_PRIV: &str = "VCX_REV_REG_DEF_PRIV";

/// Contains the logic for record mapping and migration.
fn migrate_record(record: Record) -> Result<Record, IndyError> {
    println!("{record:?}");
    Ok(record)
}

/// Exports the wallet given through the [`WalletHandle`] to the given path,
/// encrypting it with the given key.
///
/// The backup file is then imported into a wallet given by [`RestoreWalletConfigs`]
/// and the records get migrated before storage.
pub async fn migrate_wallet(wallet_handle: WalletHandle, wallet_config: &WalletConfig) -> Result<(), String> {
    println!("Migrating wallet");

    let new_wh = indy::wallet::create_and_open_wallet(wallet_config)
        .await
        .map_err(|ref e| format!("{e}"))?;

    Locator::instance()
        .wallet_controller
        .migrate(wallet_handle, new_wh, migrate_record)
        .await
        .map_err(|ref e| format!("{e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use aries_vcx_core::indy::wallet::WalletConfig;

    use super::*;
    use std::{env, fs};

    #[tokio::test]
    async fn test_migration() {
        let wallet_name = "wallet_test_migration".to_owned();
        let wallet_key = "8dvfYSt5d1taSd6yJdpjq4emkwsPDDLYxkNFysFD2cZY".to_owned();
        let wallet_key_derivation = "RAW".to_owned();

        let mut config_wallet = WalletConfig {
            wallet_name,
            wallet_key: wallet_key.clone(),
            wallet_key_derivation: wallet_key_derivation.clone(),
            wallet_type: None,
            storage_config: None,
            storage_credentials: None,
            rekey: None,
            rekey_derivation_method: None,
        };

        let wallet_handle = indy::wallet::open_wallet(&config_wallet).await.unwrap();

        let backup_file_path = env::temp_dir().join("wallet.bkup").to_str().unwrap().to_owned();
        let backup_key = "super_secret_backup_key_that_no_one_will_ever_ever_guess".to_owned();

        let new_wallet_name = "new_better_wallet".to_owned();

        let mut new_config_wallet = WalletConfig {
            wallet_name: new_wallet_name,
            wallet_key: wallet_key.clone(),
            wallet_key_derivation,
            wallet_type: None,
            storage_config: None,
            storage_credentials: None,
            rekey: None,
            rekey_derivation_method: None,
        };

        if let Ok(()) = migrate_wallet(wallet_handle, &new_config_wallet).await {
            indy::wallet::delete_wallet(&config_wallet).await.ok();
            indy::wallet::delete_wallet(&new_config_wallet).await.ok();
        }
    }
}
