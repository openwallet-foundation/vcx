use futures::future::BoxFuture;

use crate::error::prelude::*;
use crate::handlers::connection::connection::ConnectionState;
use crate::handlers::issuance::holder::HolderState;
use crate::handlers::issuance::issuer::IssuerState;
use crate::handlers::proof_presentation::prover::ProverState;
use crate::handlers::proof_presentation::verifier::VerifierState;
use crate::messages::a2a::A2AMessage;
use crate::protocols::connection::invitee::state_machine::InviteeState;
use crate::protocols::connection::inviter::state_machine::InviterState;

pub mod connection;
pub mod issuance;
pub mod proof_presentation;
pub mod out_of_band;

pub type SendClosure = Box<dyn Fn(A2AMessage) -> BoxFuture<'static, VcxResult<()>> + Send + Sync>;

impl From<ConnectionState> for u32 {
    fn from(state: ConnectionState) -> u32 {
        match state {
            ConnectionState::Inviter(inviter_state) => {
                match inviter_state {
                    InviterState::Initial => 0,
                    InviterState::Invited => 1,
                    InviterState::Requested => 2,
                    InviterState::Responded => 3,
                    InviterState::Completed => 4,
                }
            }
            ConnectionState::Invitee(invitee_state) => {
                match invitee_state {
                    InviteeState::Initial => 0,
                    InviteeState::Invited => 1,
                    InviteeState::Requested => 2,
                    InviteeState::Responded => 3,
                    InviteeState::Completed => 4,
                }
            }
        }
    }
}

impl From<HolderState> for u32 {
    fn from(state: HolderState) -> u32 {
        match state {
            HolderState::Initial => 0,
            HolderState::ProposalSent => 1,
            HolderState::OfferReceived => 2,
            HolderState::RequestSent => 3,
            HolderState::Finished => 4,
            HolderState::Failed => 5
        }
    }
}

impl From<IssuerState> for u32 {
    fn from(state: IssuerState) -> u32 {
        match state {
            IssuerState::Initial => 0,
            IssuerState::ProposalReceived => 1,
            IssuerState::OfferSet => 2,
            IssuerState::OfferSent => 3,
            IssuerState::RequestReceived => 4,
            IssuerState::CredentialSent => 5,
            IssuerState::Finished => 6,
            IssuerState::Failed => 7,
        }
    }
}

impl From<ProverState> for u32 {
    fn from(state: ProverState) -> u32 {
        match state {
            ProverState::Initial => 0,
            ProverState::PresentationProposalSent => 1,
            ProverState::PresentationRequestReceived => 2,
            ProverState::PresentationPrepared => 3,
            ProverState::PresentationPreparationFailed => 4,
            ProverState::PresentationSent => 5,
            ProverState::Finished => 6,
            ProverState::Failed => 7
        }
    }
}

impl From<VerifierState> for u32 {
    fn from(state: VerifierState) -> u32 {
        match state {
            VerifierState::Initial => 0,
            VerifierState::PresentationRequestSet => 1,
            VerifierState::PresentationProposalReceived => 2,
            VerifierState::PresentationRequestSent => 3,
            VerifierState::Finished => 4,
            VerifierState::Failed => 5
        }
    }
}
