use std::sync::Arc;

use aries_vcx_core::{
    anoncreds::{base_anoncreds::BaseAnonCreds, credx_anoncreds::IndyCredxAnonCreds},
    ledger::{
        base_ledger::BaseLedger, indy_vdr_ledger::IndyVdrLedger, request_submitter::vdr_proxy::VdrProxySubmitter,
    },
    wallet::base_wallet::BaseWallet,
    VdrProxyClient,
};

use super::profile::Profile;

#[derive(Debug)]
pub struct VdrProxyProfile {
    wallet: Arc<dyn BaseWallet>,
    ledger: Arc<dyn BaseLedger>,
    anoncreds: Arc<dyn BaseAnonCreds>,
}

impl VdrProxyProfile {
    pub fn new(wallet: Arc<dyn BaseWallet>, client: VdrProxyClient) -> Self {
        let submitter = Arc::new(VdrProxySubmitter::new(Arc::new(client)));
        let ledger = Arc::new(IndyVdrLedger::new(wallet.clone(), submitter));
        let anoncreds = Arc::new(IndyCredxAnonCreds::new(Arc::clone(&wallet)));
        VdrProxyProfile {
            wallet,
            ledger,
            anoncreds,
        }
    }
}

impl Profile for VdrProxyProfile {
    fn inject_ledger(self: Arc<Self>) -> Arc<dyn BaseLedger> {
        Arc::clone(&self.ledger)
    }

    fn inject_anoncreds(self: Arc<Self>) -> Arc<dyn BaseAnonCreds> {
        Arc::clone(&self.anoncreds)
    }

    fn inject_wallet(&self) -> Arc<dyn BaseWallet> {
        Arc::clone(&self.wallet)
    }
}
