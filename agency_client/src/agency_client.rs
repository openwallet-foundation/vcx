use crate::agency_settings;
use crate::error::AgencyClientResult;
use crate::provision::AgencyClientConfig;
use crate::testing::mocking;
use crate::utils::error_utils;

#[derive(Default, Deserialize, Clone)]
pub struct AgencyClient {
    wallet_handle: i32,
    pub agency_url: String,
    pub agency_did: String,
    pub agency_pwdid: String,
    pub agency_vk: String,
    pub agent_pwdid: String,
    pub agent_vk: String,
    pub my_pwdid: String,
    pub my_vk: String,
}

// pub fn validate_optional_config_val<F, S, E>(val: Option<&String>, err: AgencyClientErrorKind, closure: F) -> AgencyClientResult<u32>
//     where F: Fn(&str) -> Result<S, E> {
//     if val.is_none() { return Ok(error_utils::SUCCESS.code_num); }
//
//     closure(val.as_ref().ok_or(AgencyClientError::from(AgencyClientErrorKind::InvalidConfiguration))?)
//         .or(Err(AgencyClientError::from(err)))?;
//
//     Ok(error_utils::SUCCESS.code_num)
// }
//
// pub fn validate_mandotory_config_val<F, S, E>(val: &str, err: AgencyClientErrorKind, closure: F) -> AgencyClientResult<u32>
//     where F: Fn(&str) -> Result<S, E> {
//     closure(val)
//         .or(Err(AgencyClientError::from(err)))?;
//
//     Ok(error_utils::SUCCESS.code_num)
// }
//

impl AgencyClient {
    pub fn get_wallet_handle(&self) -> i32 { self.wallet_handle }
    pub fn get_agency_url_config(&self) -> String { self.agency_url.clone() }
    pub fn get_agency_url_full(&self) -> String {
        format!("{}/agency/msg", self.agency_url.clone())
    }

    pub fn get_agency_did(&self) -> String { self.agency_did.clone() }
    pub fn get_agency_pwdid(&self) -> String { self.agency_pwdid.clone() }
    pub fn get_agency_vk(&self) -> String { self.agency_vk.clone() }

    pub fn get_agent_pwdid(&self) -> String { self.agent_pwdid.clone() }
    pub fn get_agent_vk(&self) -> String { self.agent_vk.clone() }

    pub fn get_my_pwdid(&self) -> String { self.my_pwdid.clone() }
    pub fn get_my_vk(&self) -> String { self.my_vk.clone() }

    pub fn set_wallet_handle(&mut self, wh: i32) {
        self.wallet_handle = wh;
        crate::utils::wallet::set_wallet_handle(indy::WalletHandle(wh));
    }

    pub fn reset_wallet_handle(&mut self) {
        self.wallet_handle = indy::INVALID_WALLET_HANDLE.0;
        crate::utils::wallet::reset_wallet_handle();
    }
    pub fn set_agency_url(&mut self, url: &str) {
        self.agency_url = url.to_string();
    }
    pub fn set_agency_did(&mut self, did: &str) {
        self.agency_did = did.to_string();
    }
    pub fn set_agency_vk(&mut self, vk: &str) {
        self.agency_vk = vk.to_string();
    }
    pub fn set_agent_pwdid(&mut self, pwdid: &str) {
        self.agent_pwdid = pwdid.to_string();
    }
    pub fn set_agent_vk(&mut self, vk: &str) {
        self.agent_vk = vk.to_string();
    }
    pub fn set_my_pwdid(&mut self, pwdid: &str) {
        self.my_pwdid = pwdid.to_string();
    }
    pub fn set_my_vk(&mut self, vk: &str) {
        self.my_vk = vk.to_string();
    }

    pub fn enable_test_mode(&self) { mocking::enable_agency_mocks() }
    pub fn disable_test_mode(&self) { mocking::disable_agency_mocks() }

    pub fn configure(&mut self, config: &AgencyClientConfig, validate: bool) -> AgencyClientResult<u32> {
        warn!("AgencyClient::process_config_string >>> config {:?}, validate: {:?}", config, validate);

        // todo: enable validation
        // if (validate) {
        // agency_settings::validate_mandotory_config_val(&self.agency_did, AgencyClientErrorKind::InvalidDid, validation::validate_did)?;
        // agency_settings::validate_mandotory_config_val(&self.agency_vk, AgencyClientErrorKind::InvalidVerkey, validation::validate_verkey)?;
        //
        // agency_settings::validate_mandotory_config_val(&self.my_pwdid, AgencyClientErrorKind::InvalidDid, validation::validate_did)?;
        // agency_settings::validate_mandotory_config_val(&self.my_vk, AgencyClientErrorKind::InvalidVerkey, validation::validate_verkey)?;
        //
        // agency_settings::validate_mandotory_config_val(&self.agent_pwdid, AgencyClientErrorKind::InvalidDid, validation::validate_did)?;
        // agency_settings::validate_mandotory_config_val(&self.agent_vk, AgencyClientErrorKind::InvalidVerkey, validation::validate_verkey)?;
        //
        // agency_settings::validate_mandotory_config_val(&self.agency_url, AgencyClientErrorKind::InvalidUrl, Url::parse)?;
        // }

        self.set_agency_url(&config.agency_endpoint);
        self.set_agency_did(&config.agency_did);
        self.set_agency_vk(&config.agency_verkey);
        self.set_agent_pwdid(&config.remote_to_sdk_did);
        self.set_agent_vk(&config.remote_to_sdk_verkey);
        self.set_my_pwdid(&config.sdk_to_remote_did);
        self.set_my_vk(&config.sdk_to_remote_verkey);

        Ok(error_utils::SUCCESS.code_num)
    }

    // TODO: This should be implemented in the module doing the tests
    pub fn set_testing_defaults_agency(&mut self) -> u32 {
        trace!("set_testing_defaults_agency >>>");

        let default_did = "VsKV7grR1BUE29mG2Fm2kX";
        let default_verkey = "Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR";
        let default_url = "http://127.0.0.1:8080";

        self.set_agency_url(default_url);
        self.set_agency_did(default_did);
        self.set_agency_vk(default_verkey);
        self.set_agent_pwdid(default_did);
        self.set_agent_vk(default_verkey);
        self.set_my_pwdid(default_did);
        self.set_my_vk(default_verkey);

        error_utils::SUCCESS.code_num
    }

    pub fn new() -> AgencyClientResult<Self> {
        let agency_client = Self::default();
        Ok(agency_client)
    }

    // pub fn new(config: &str, wallet_handle: i32, validate: bool) -> AgencyClientResult<Self> {
    //     let mut agency_client = Self::default();
    //     agency_client.process_config_string(config, wallet_handle, validate)?;
    //     Ok(agency_client)
    // }
}
