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
#[semver(family = "report-problem")]
pub enum ReportProblem {
    V1(ReportProblemV1),
}

#[derive(Copy, Clone, Debug, From, PartialEq, TransitiveFrom, MessageType)]
#[transitive(into(all(ReportProblem, Protocol)))]
#[semver(major = 1, parent = "ReportProblem", actors(Actor::Notified, Actor::Notifier))]
pub enum ReportProblemV1 {
    V1_0(ReportProblemV1_0),
}

#[derive(Copy, Clone, Debug, PartialEq, TransitiveFrom, MessageType)]
#[transitive(into(all(ReportProblemV1, ReportProblem, Protocol)))]
#[semver(minor = 0, parent = "ReportProblemV1")]
pub struct ReportProblemV1_0;

#[derive(Copy, Clone, Debug, AsRefStr, EnumString, PartialEq, MessageType)]
#[strum(serialize_all = "kebab-case")]
#[semver(parent = "ReportProblemV1_0")]
pub enum ReportProblemV1_0Kind {
    ProblemReport,
}
