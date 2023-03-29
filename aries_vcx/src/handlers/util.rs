use messages2::{
    msg_fields::protocols::{
        connection::{invitation::Invitation, Connection, ConnectionData},
        cred_issuance::CredentialIssuance,
        discover_features::DiscoverFeatures,
        out_of_band::{invitation::Invitation as OobInvitation, OutOfBand},
        present_proof::PresentProof,
        report_problem::ProblemReport,
        revocation::Revocation,
        trust_ping::TrustPing,
    },
    AriesMessage,
};

use crate::errors::error::{AriesVcxError, AriesVcxErrorKind, VcxResult};

macro_rules! matches_thread_id {
    ($msg:expr, $id:expr) => {
        $msg.decorators.thread.thid == $id || $msg.decorators.thread.pthid.as_deref() == Some($id)
    };
}

macro_rules! matches_opt_thread_id {
    ($msg:expr, $id:expr) => {
        $msg.decorators.thread.as_ref().map(|t| t.thid.as_str()) == Some($id)
            || $msg.decorators.thread.as_ref().map(|t| t.pthid.as_deref()).flatten() == Some($id)
    };
}

pub(crate) use matches_opt_thread_id;
pub(crate) use matches_thread_id;

pub fn verify_thread_id(thread_id: &str, message: &AriesMessage) -> VcxResult<()> {
    let is_match = match message {
        AriesMessage::BasicMessage(msg) => matches_opt_thread_id!(msg, thread_id),
        AriesMessage::Connection(Connection::Invitation(Invitation::Public(msg))) => msg.id == thread_id,
        AriesMessage::Connection(Connection::Invitation(Invitation::Pairwise(msg))) => msg.id == thread_id,
        AriesMessage::Connection(Connection::Invitation(Invitation::PairwiseDID(msg))) => msg.id == thread_id,
        AriesMessage::Connection(Connection::ProblemReport(msg)) => matches_thread_id!(msg, thread_id),
        AriesMessage::Connection(Connection::Request(msg)) => matches_opt_thread_id!(msg, thread_id),
        AriesMessage::Connection(Connection::Response(msg)) => matches_thread_id!(msg, thread_id),
        AriesMessage::CredentialIssuance(CredentialIssuance::Ack(msg)) => matches_thread_id!(msg, thread_id),
        AriesMessage::CredentialIssuance(CredentialIssuance::IssueCredential(msg)) => {
            matches_thread_id!(msg, thread_id)
        }
        AriesMessage::CredentialIssuance(CredentialIssuance::OfferCredential(msg)) => {
            matches_opt_thread_id!(msg, thread_id)
        }
        AriesMessage::CredentialIssuance(CredentialIssuance::ProposeCredential(msg)) => {
            matches_opt_thread_id!(msg, thread_id)
        }
        AriesMessage::CredentialIssuance(CredentialIssuance::RequestCredential(msg)) => {
            matches_opt_thread_id!(msg, thread_id)
        }
        AriesMessage::DiscoverFeatures(DiscoverFeatures::Query(msg)) => msg.id == thread_id,
        AriesMessage::DiscoverFeatures(DiscoverFeatures::Disclose(msg)) => matches_thread_id!(msg, thread_id),
        AriesMessage::Notification(msg) => matches_thread_id!(msg, thread_id),
        AriesMessage::OutOfBand(OutOfBand::Invitation(msg)) => msg.id == thread_id,
        AriesMessage::OutOfBand(OutOfBand::HandshakeReuse(msg)) => matches_thread_id!(msg, thread_id),
        AriesMessage::OutOfBand(OutOfBand::HandshakeReuseAccepted(msg)) => matches_thread_id!(msg, thread_id),
        AriesMessage::PresentProof(PresentProof::Ack(msg)) => matches_thread_id!(msg, thread_id),
        AriesMessage::PresentProof(PresentProof::Presentation(msg)) => matches_thread_id!(msg, thread_id),
        AriesMessage::PresentProof(PresentProof::ProposePresentation(msg)) => matches_opt_thread_id!(msg, thread_id),
        AriesMessage::PresentProof(PresentProof::RequestPresentation(msg)) => matches_opt_thread_id!(msg, thread_id),
        AriesMessage::ReportProblem(msg) => matches_opt_thread_id!(msg, thread_id),
        AriesMessage::Revocation(Revocation::Revoke(msg)) => matches_opt_thread_id!(msg, thread_id),
        AriesMessage::Revocation(Revocation::Ack(msg)) => matches_thread_id!(msg, thread_id),
        AriesMessage::Routing(msg) => msg.id == thread_id,
        AriesMessage::TrustPing(TrustPing::Ping(msg)) => matches_opt_thread_id!(msg, thread_id),
        AriesMessage::TrustPing(TrustPing::PingResponse(msg)) => matches_thread_id!(msg, thread_id),
    };

    if !is_match {
        return Err(AriesVcxError::from_msg(
            AriesVcxErrorKind::InvalidJson,
            format!(
                "Cannot handle message {:?}: thread id does not match, expected {:?}",
                message, thread_id
            ),
        ));
    };

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttachmentId {
    #[serde(rename = "libindy-cred-offer-0")]
    CredentialOffer,
    #[serde(rename = "libindy-cred-request-0")]
    CredentialRequest,
    #[serde(rename = "libindy-cred-0")]
    Credential,
    #[serde(rename = "libindy-request-presentation-0")]
    PresentationRequest,
    #[serde(rename = "libindy-presentation-0")]
    Presentation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum AnyInvitation {
    Con(Invitation),
    Oob(OobInvitation),
}

// todo: this is shared by multiple protocols to express different things - needs to be split
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Status {
    Undefined,
    Success,
    Failed(ProblemReport),
    Declined(ProblemReport),
}

impl Status {
    pub fn code(&self) -> u32 {
        match self {
            Status::Undefined => 0,
            Status::Success => 1,
            Status::Failed(_) => 2,
            Status::Declined(_) => 3,
        }
    }
}

