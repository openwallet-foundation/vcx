use std::collections::HashMap;

use messages_macros::Message;
use serde::{Deserialize, Serialize};

use crate::{message_type::message_family::report_problem::{ReportProblem, ReportProblemV1, ReportProblemV1_0}, decorators::{Timing, Thread}};

use super::traits::ConcreteMessage;

#[derive(Clone, Debug, Deserialize, Serialize, Message)]
#[message(kind = "ReportProblem::V1(ReportProblemV1::V1_0(ReportProblemV1_0::ProblemReport))")]
pub struct ProblemReport {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "~thread")]
    pub thread: Option<Thread>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub who_retries: Option<WhoRetries>,
    #[serde(rename = "tracking-uri")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracking_uri: Option<String>,
    #[serde(rename = "escalation-uri")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation_uri: Option<String>,
    #[serde(rename = "fix-hint")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_hint: Option<FixHint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<Impact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noticed_time: Option<String>,
    #[serde(rename = "where")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem_items: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(rename = "~timing")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<Timing>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Description {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub en: Option<String>,
    pub code: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WhoRetries {
    #[serde(rename = "me")]
    Me,
    #[serde(rename = "you")]
    You,
    #[serde(rename = "both")]
    Both,
    #[serde(rename = "none")]
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixHint {
    en: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Impact {
    #[serde(rename = "message")]
    Message,
    #[serde(rename = "thread")]
    Thread,
    #[serde(rename = "connection")]
    Connection,
}
