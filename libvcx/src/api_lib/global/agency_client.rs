use std::ops::Deref;
use std::sync::{RwLock, RwLockWriteGuard};

use aries_vcx::agency_client::agency_client::AgencyClient;
use aries_vcx::agency_client::configuration::AgencyClientConfig;
use aries_vcx::plugins::wallet::agency_client_wallet::ToBaseAgencyClientWallet;
use crate::api_lib::utils::libvcx_error::LibvcxResult;

use super::profile::get_main_wallet;

lazy_static! {
    pub static ref AGENCY_CLIENT: RwLock<AgencyClient> = RwLock::new(AgencyClient::new());
}

pub fn get_main_agency_client_mut() -> LibvcxResult<RwLockWriteGuard<'static, AgencyClient>> {
    let agency_client = AGENCY_CLIENT.write()?;
    Ok(agency_client)
}

pub fn get_main_agency_client() -> LibvcxResult<AgencyClient> {
    let agency_client = AGENCY_CLIENT.read()?.deref().clone();
    Ok(agency_client)
}

pub fn create_agency_client_for_main_wallet(config: &AgencyClientConfig) -> LibvcxResult<()> {
    let client = get_main_agency_client()?.configure(get_main_wallet().to_base_agency_client_wallet(), config)?;
    set_main_agency_client(client);
    Ok(())
}

pub fn reset_main_agency_client() {
    trace!("reset_agency_client >>>");
    let mut agency_client = AGENCY_CLIENT.write().unwrap();
    *agency_client = AgencyClient::new();
}

pub fn set_main_agency_client(new_agency_client: AgencyClient) {
    trace!("set_main_agency_client >>>");
    let mut agency_client = AGENCY_CLIENT.write().unwrap();
    *agency_client = new_agency_client;
}
