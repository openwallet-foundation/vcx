use derive_more::From;
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

#[derive(Copy, Clone, Debug, From, PartialEq, MessageType)]
#[semver(family = "trust_ping")]
pub enum TrustPing {
    V1(TrustPingV1),
}

#[derive(Copy, Clone, Debug, From, PartialEq, TransitiveFrom, MessageType)]
#[transitive(into(all(TrustPing, Protocol)))]
#[semver(major = 1, parent = "TrustPing", actors(Actor::Sender, Actor::Receiver))]
pub enum TrustPingV1 {
    V1_0(TrustPingV1_0),
}

#[derive(Copy, Clone, Debug, PartialEq, TransitiveFrom, MessageType)]
#[transitive(into(all(TrustPingV1, TrustPing, Protocol)))]
#[semver(minor = 0, parent = "TrustPingV1")]
pub struct TrustPingV1_0;

#[derive(Copy, Clone, Debug, AsRefStr, EnumString, PartialEq, MessageType)]
#[strum(serialize_all = "kebab-case")]
#[semver(parent = "TrustPingV1_0")]
pub enum TrustPingV1_0Kind {
    Ping,
    #[strum(serialize = "ping_response")]
    PingResponse,
}
