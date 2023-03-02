use messages_macros::MessageContent;
use serde::{Deserialize, Serialize};

use crate::{
    decorators::{Thread, Timing},
    message_type::message_family::discover_features::DiscoverFeaturesV1_0,
    protocols::traits::MessageKind,
};

#[derive(Clone, Debug, Deserialize, Serialize, MessageContent)]
#[message(kind = "DiscoverFeaturesV1_0::Disclose")]
pub struct Disclose {
    pub protocols: Vec<ProtocolDescriptor>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DiscloseDecorators {
    #[serde(rename = "~thread")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread: Option<Thread>,
    #[serde(rename = "~timing")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<Timing>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ProtocolDescriptor {
    pub pid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<()>>,
}
