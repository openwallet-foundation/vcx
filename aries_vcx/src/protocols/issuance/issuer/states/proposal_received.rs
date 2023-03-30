use crate::{protocols::issuance::issuer::states::offer_sent::OfferSentState, handlers::util::OfferInfo};
use messages2::msg_fields::protocols::cred_issuance::{propose_credential::ProposeCredential, offer_credential::OfferCredential};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProposalReceivedState {
    pub credential_proposal: ProposeCredential,
    pub offer_info: Option<OfferInfo>,
}

impl ProposalReceivedState {
    pub fn new(credential_proposal: ProposeCredential, offer_info: Option<OfferInfo>) -> Self {
        Self {
            credential_proposal,
            offer_info,
        }
    }
}

impl From<(OfferCredential, OfferInfo)> for OfferSentState {
    fn from((offer, offer_info): (OfferCredential, OfferInfo)) -> Self {
        trace!("SM is now in OfferSent state");
        OfferSentState {
            offer,
            cred_data: offer_info.credential_json,
            rev_reg_id: offer_info.rev_reg_id,
            tails_file: offer_info.tails_file,
        }
    }
}
