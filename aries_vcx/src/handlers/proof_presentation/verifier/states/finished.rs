use crate::handlers::proof_presentation::verifier::state_machine::RevocationStatus;
use crate::messages::proof_presentation::presentation::Presentation;
use crate::messages::proof_presentation::presentation_request::PresentationRequest;
use crate::messages::status::Status;
use crate::messages::error::ProblemReport;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FinishedState {
    pub presentation_request: Option<PresentationRequest>,
    pub presentation: Option<Presentation>,
    pub status: Status,
    pub revocation_status: Option<RevocationStatus>,
}

impl From<ProblemReport> for FinishedState {
    fn from(problem_report: ProblemReport) -> Self {
        trace!("transit state to FinishedState due to a problem");
        FinishedState {
            presentation_request: None,
            presentation: None,
            status: Status::Failed(problem_report),
            revocation_status: None,
        }
    }
}
