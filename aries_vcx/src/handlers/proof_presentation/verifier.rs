use std::collections::HashMap;

use std::sync::Arc;

use agency_client::agency_client::AgencyClient;
use aries_vcx_core::anoncreds::base_anoncreds::BaseAnonCreds;
use aries_vcx_core::ledger::base_ledger::AnoncredsLedgerRead;
use aries_vcx_core::wallet::base_wallet::BaseWallet;
use messages::msg_fields::protocols::notification::Notification;
use messages::msg_fields::protocols::present_proof::present::Presentation;
use messages::msg_fields::protocols::present_proof::propose::ProposePresentation;
use messages::msg_fields::protocols::present_proof::request::RequestPresentation;
use messages::msg_fields::protocols::present_proof::PresentProof;
use messages::msg_fields::protocols::report_problem::ProblemReport;
use messages::msg_parts::MsgParts;
use messages::AriesMessage;

use crate::common::proofs::proof_request::PresentationRequestData;
use crate::errors::error::prelude::*;
use crate::handlers::connection::mediated_connection::MediatedConnection;
use crate::handlers::util::get_attach_as_string;
use crate::protocols::proof_presentation::verifier::messages::VerifierMessages;
use crate::protocols::proof_presentation::verifier::state_machine::{VerifierSM, VerifierState};
use crate::protocols::proof_presentation::verifier::verification_status::PresentationVerificationStatus;
use crate::protocols::SendClosure;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Verifier {
    verifier_sm: VerifierSM,
}

impl Verifier {
    pub fn create(source_id: &str) -> VcxResult<Self> {
        trace!("Verifier::create >>> source_id: {:?}", source_id);

        Ok(Self {
            verifier_sm: VerifierSM::new(source_id),
        })
    }

    pub fn create_from_request(source_id: String, presentation_request: &PresentationRequestData) -> VcxResult<Self> {
        trace!(
            "Verifier::create_from_request >>> source_id: {:?}, presentation_request: {:?}",
            source_id,
            presentation_request
        );
        let verifier_sm = VerifierSM::from_request(&source_id, presentation_request)?;
        Ok(Self { verifier_sm })
    }

    pub fn create_from_proposal(source_id: &str, presentation_proposal: &ProposePresentation) -> VcxResult<Self> {
        trace!(
            "Issuer::create_from_proposal >>> source_id: {:?}, presentation_proposal: {:?}",
            source_id,
            presentation_proposal
        );
        Ok(Self {
            verifier_sm: VerifierSM::from_proposal(source_id, presentation_proposal),
        })
    }

    pub fn get_source_id(&self) -> String {
        self.verifier_sm.source_id()
    }

    pub fn get_state(&self) -> VerifierState {
        self.verifier_sm.get_state()
    }

    pub async fn send_presentation_request(&mut self, send_message: SendClosure) -> VcxResult<()> {
        if self.verifier_sm.get_state() == VerifierState::PresentationRequestSet {
            let offer = self.verifier_sm.presentation_request_msg()?.into();
            send_message(offer).await?;
            self.verifier_sm = self.verifier_sm.clone().mark_presentation_request_msg_sent()?;
        }
        Ok(())
    }

    pub async fn send_presentation_ack(&mut self, send_message: SendClosure) -> VcxResult<()> {
        trace!("Verifier::send_presentation_ack >>>");
        self.verifier_sm = self.verifier_sm.clone().send_presentation_ack(send_message).await?;
        Ok(())
    }

    // todo: verification and sending ack should be separate apis
    pub async fn verify_presentation(
        &mut self,
        ledger: &Arc<dyn AnoncredsLedgerRead>,
        anoncreds: &Arc<dyn BaseAnonCreds>,
        presentation: Presentation,
        send_message: SendClosure,
    ) -> VcxResult<()> {
        trace!("Verifier::verify_presentation >>>");
        self.verifier_sm = self
            .verifier_sm
            .clone()
            .verify_presentation(ledger, anoncreds, presentation, send_message)
            .await?;
        Ok(())
    }

    pub fn set_request(
        &mut self,
        presentation_request_data: PresentationRequestData,
        comment: Option<String>,
    ) -> VcxResult<()> {
        trace!(
            "Verifier::set_request >>> presentation_request_data: {:?}, comment: ${:?}",
            presentation_request_data,
            comment
        );
        self.verifier_sm = self
            .verifier_sm
            .clone()
            .set_request(&presentation_request_data, comment)?;
        Ok(())
    }

    pub fn mark_presentation_request_msg_sent(&mut self) -> VcxResult<()> {
        trace!("Verifier::mark_presentation_request_msg_sent >>>");
        self.verifier_sm = self.verifier_sm.clone().mark_presentation_request_msg_sent()?;
        Ok(())
    }

    pub fn get_presentation_request_msg(&self) -> VcxResult<RequestPresentation> {
        self.verifier_sm.presentation_request_msg()
    }

    pub fn get_presentation_request_attachment(&self) -> VcxResult<String> {
        let pres_req = &self.verifier_sm.presentation_request_msg()?;
        Ok(get_attach_as_string!(pres_req.content.request_presentations_attach))
    }

    pub fn get_presentation_request(&self) -> VcxResult<RequestPresentation> {
        self.verifier_sm.presentation_request_msg()
    }

    pub fn get_presentation_msg(&self) -> VcxResult<Presentation> {
        self.verifier_sm.get_presentation_msg()
    }

    pub fn get_verification_status(&self) -> PresentationVerificationStatus {
        self.verifier_sm.get_verification_status()
    }

    pub fn get_presentation_attachment(&self) -> VcxResult<String> {
        let presentation = &self.verifier_sm.get_presentation_msg()?;
        Ok(get_attach_as_string!(presentation.content.presentations_attach))
    }

    pub fn get_presentation_proposal(&self) -> VcxResult<ProposePresentation> {
        self.verifier_sm.presentation_proposal()
    }

    pub fn get_thread_id(&self) -> VcxResult<String> {
        Ok(self.verifier_sm.thread_id())
    }

    pub async fn process_aries_msg(
        &mut self,
        ledger: &Arc<dyn AnoncredsLedgerRead>,
        anoncreds: &Arc<dyn BaseAnonCreds>,
        message: AriesMessage,
        send_message: Option<SendClosure>,
    ) -> VcxResult<()> {
        let verifier_sm = match message {
            AriesMessage::PresentProof(PresentProof::ProposePresentation(proposal)) => {
                self.verifier_sm.clone().receive_presentation_proposal(proposal)?
            }
            AriesMessage::PresentProof(PresentProof::Presentation(presentation)) => {
                let send_message = send_message.ok_or(AriesVcxError::from_msg(
                    AriesVcxErrorKind::InvalidState,
                    "Attempted to call undefined send_message callback",
                ))?;
                self.verifier_sm
                    .clone()
                    .verify_presentation(ledger, anoncreds, presentation, send_message)
                    .await?
            }
            AriesMessage::ReportProblem(report) => {
                self.verifier_sm.clone().receive_presentation_request_reject(report)?
            }
            AriesMessage::Notification(Notification::ProblemReport(report)) => {
                let MsgParts {
                    id,
                    content,
                    decorators,
                } = report;
                let report = ProblemReport::with_decorators(id, content.0, decorators);
                self.verifier_sm.clone().receive_presentation_request_reject(report)?
            }
            AriesMessage::PresentProof(PresentProof::ProblemReport(report)) => {
                let MsgParts {
                    id,
                    content,
                    decorators,
                } = report;
                let report = ProblemReport::with_decorators(id, content.0, decorators);
                self.verifier_sm.clone().receive_presentation_request_reject(report)?
            }
            _ => self.verifier_sm.clone(),
        };
        self.verifier_sm = verifier_sm;
        Ok(())
    }

    pub fn progressable_by_message(&self) -> bool {
        self.verifier_sm.progressable_by_message()
    }

    pub async fn decline_presentation_proposal<'a>(
        &'a mut self,
        send_message: SendClosure,
        reason: &'a str,
    ) -> VcxResult<()> {
        trace!("Verifier::decline_presentation_proposal >>> reason: {:?}", reason);
        self.verifier_sm = self
            .verifier_sm
            .clone()
            .reject_presentation_proposal(reason.to_string(), send_message)
            .await?;
        Ok(())
    }
}

// #[cfg(test)]
// mod unit_tests {
//     use crate::core::profile::vdrtools_profile::VdrtoolsProfile;
//     use crate::utils::constants::{REQUESTED_ATTRS, REQUESTED_PREDICATES};
//     use crate::utils::devsetup::*;
//     use crate::utils::mockdata::mock_settings::MockBuilder;
//     use aries_vcx_core::{INVALID_POOL_HANDLE, INVALID_WALLET_HANDLE};
//     use messages::a2a::A2AMessage;
//     use messages::protocols::proof_presentation::presentation::test_utils::_presentation;

//     use super::*;

//     async fn _verifier() -> Verifier {
//         let presentation_request_data = PresentationRequestData::create(&_dummy_profile(), "1")
//             .await
//             .unwrap()
//             .set_requested_attributes_as_string(REQUESTED_ATTRS.to_owned())
//             .unwrap()
//             .set_requested_predicates_as_string(REQUESTED_PREDICATES.to_owned())
//             .unwrap()
//             .set_not_revoked_interval(r#"{"support_revocation":false}"#.to_string())
//             .unwrap();
//         Verifier::create_from_request("1".to_string(), &presentation_request_data).unwrap()
//     }

//     pub fn _send_message() -> Option<SendClosure> {
//         Some(Box::new(|_: A2AMessage| Box::pin(async { VcxResult::Ok(()) })))
//     }

//     impl Verifier {
//         async fn to_presentation_request_sent_state(&mut self) {
//             self.send_presentation_request(_send_message().unwrap()).await.unwrap();
//         }

//         async fn to_finished_state(&mut self) {
//             self.to_presentation_request_sent_state().await;
//             self.step(
//                 &_dummy_profile(),
//                 VerifierMessages::VerifyPresentation(_presentation()),
//                 _send_message(),
//             )
//             .await
//             .unwrap();
//         }
//     }

//     #[tokio::test]
//     async fn test_get_presentation() {
//         let _setup = SetupMocks::init();
//         let _mock_builder = MockBuilder::init().set_mock_result_for_validate_indy_proof(Ok(true));
//         let mut verifier = _verifier().await;
//         verifier.to_finished_state().await;
//         let presentation = verifier.get_presentation_msg().unwrap();
//         assert_eq!(presentation, _presentation());
//         assert_eq!(verifier.get_state(), VerifierState::Finished);
//     }
// }
