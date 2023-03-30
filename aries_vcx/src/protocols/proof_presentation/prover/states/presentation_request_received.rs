use std::sync::Arc;

use messages2::decorators::attachment::AttachmentType;
use messages2::msg_fields::protocols::present_proof::present::Presentation;
use messages2::msg_fields::protocols::present_proof::request::{
    RequestPresentation, RequestPresentationContent, RequestPresentationDecorators,
};
use messages2::msg_fields::protocols::report_problem::ProblemReport;
use uuid::Uuid;

use crate::common::proofs::prover::prover::generate_indy_proof;
use crate::core::profile::profile::Profile;
use crate::errors::error::prelude::*;
use crate::handlers::util::Status;
use crate::protocols::proof_presentation::prover::states::finished::FinishedState;
use crate::protocols::proof_presentation::prover::states::presentation_preparation_failed::PresentationPreparationFailedState;
use crate::protocols::proof_presentation::prover::states::presentation_prepared::PresentationPreparedState;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresentationRequestReceived {
    pub presentation_request: RequestPresentation,
}

impl Default for PresentationRequestReceived {
    fn default() -> Self {
        let id = Uuid::new_v4().to_string();
        let content = RequestPresentationContent::new(Vec::new());
        let decorators = RequestPresentationDecorators::default();

        Self {
            presentation_request: RequestPresentation::with_decorators(id, content, decorators),
        }
    }
}

impl PresentationRequestReceived {
    pub fn new(presentation_request: RequestPresentation) -> Self {
        Self { presentation_request }
    }

    pub async fn build_presentation(
        &self,
        profile: &Arc<dyn Profile>,
        credentials: &str,
        self_attested_attrs: &str,
    ) -> VcxResult<String> {
        let attach = self.presentation_request.content.request_presentations_attach.get(0);

        let Some(AttachmentType::Json(attach_json)) = attach.map(|a| &a.data.content) else {
                return Err(AriesVcxError::from_msg(
                    AriesVcxErrorKind::SerializationError,
                    format!("Attachment is not JSON: {:?}", attach),
                ));
            };
        let proof_req_data_json = attach_json.to_string();

        generate_indy_proof(profile, credentials, self_attested_attrs, &proof_req_data_json).await
    }
}

impl From<(PresentationRequestReceived, ProblemReport)> for PresentationPreparationFailedState {
    fn from((state, problem_report): (PresentationRequestReceived, ProblemReport)) -> Self {
        trace!("transit state from PresentationRequestReceived to PresentationPreparationFailedState");
        PresentationPreparationFailedState {
            presentation_request: state.presentation_request,
            problem_report,
        }
    }
}

impl From<(PresentationRequestReceived, Presentation)> for PresentationPreparedState {
    fn from((state, presentation): (PresentationRequestReceived, Presentation)) -> Self {
        trace!("transit state from PresentationRequestReceived to PresentationPreparedState");
        PresentationPreparedState {
            presentation_request: state.presentation_request,
            presentation,
        }
    }
}

impl From<PresentationRequestReceived> for FinishedState {
    fn from(state: PresentationRequestReceived) -> Self {
        trace!("Prover: transit state from PresentationRequestReceived to FinishedState");
        FinishedState {
            presentation_request: Some(state.presentation_request),
            presentation: None,
            status: Status::Success,
        }
    }
}

impl From<(PresentationRequestReceived, ProblemReport)> for FinishedState {
    fn from((state, problem_report): (PresentationRequestReceived, ProblemReport)) -> Self {
        trace!("Prover: transit state from PresentationRequestReceived to FinishedState");
        FinishedState {
            presentation_request: Some(state.presentation_request),
            presentation: None,
            status: Status::Declined(problem_report),
        }
    }
}
