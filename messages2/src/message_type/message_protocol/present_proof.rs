use derive_more::{From, TryInto};
use messages_macros::MessageType;
use strum_macros::{AsRefStr, EnumString};
use transitive::TransitiveFrom;

use crate::{
    error::{MsgTypeError, MsgTypeResult},
    message_type::actor::Actor,
    message_type::registry::get_supported_version,
};

use super::{
    traits::{MajorVersion, MessageKind, MinorVersion, ProtocolName},
    Protocol,
};

#[derive(Copy, Clone, Debug, From, TryInto, PartialEq, MessageType)]
#[semver(family = "present-proof")]
pub enum PresentProof {
    V1(PresentProofV1),
}

#[derive(Copy, Clone, Debug, From, TryInto, PartialEq, TransitiveFrom, MessageType)]
#[transitive(into(all(PresentProof, Protocol)))]
#[semver(major = 1, parent = "PresentProof", actors(Actor::Prover, Actor::Verifier))]
pub enum PresentProofV1 {
    V1_0(PresentProofV1_0),
}

#[derive(Copy, Clone, Debug, PartialEq, TransitiveFrom, MessageType)]
#[transitive(into(all(PresentProofV1, PresentProof, Protocol)))]
#[semver(minor = 0, parent = "PresentProofV1")]
pub struct PresentProofV1_0;

#[derive(Copy, Clone, Debug, AsRefStr, EnumString, PartialEq, MessageType)]
#[strum(serialize_all = "kebab-case")]
#[semver(parent = "PresentProofV1_0")]
pub enum PresentProofV1_0Kind {
    ProposePresentation,
    RequestPresentation,
    Presentation,
    PresentationPreview,
    Ack,
}
