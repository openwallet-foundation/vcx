use std::{collections::HashMap, fmt::Display};

use messages_macros::MessageContent;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use strum_macros::{AsRefStr, EnumString};
use url::Url;

use crate::{
    decorators::{localization::FieldLocalization, thread::Thread, timing::Timing},
    message::Message,
    msg_types::types::report_problem::ReportProblemV1_0Kind,
};

pub type ProblemReport = Message<ProblemReportContent, ProblemReportDecorators>;

#[derive(Clone, Debug, Deserialize, Serialize, MessageContent, Default, PartialEq)]
#[message(kind = "ReportProblemV1_0Kind::ProblemReport")]
pub struct ProblemReportContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem_items: Option<Vec<HashMap<String, String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub who_retries: Option<WhoRetries>,
    #[serde(rename = "fix-hint")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<Impact>,
    #[serde(rename = "where")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Where>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noticed_time: Option<String>,
    #[serde(rename = "tracking-uri")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracking_uri: Option<Url>,
    #[serde(rename = "escalation-uri")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation_uri: Option<Url>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ProblemReportDecorators {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "~thread")]
    pub thread: Option<Thread>,
    #[serde(rename = "~timing")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<Timing>,
    #[serde(rename = "description~l10n")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description_locale: Option<FieldLocalization>,
    #[serde(rename = "fix-hint~l10n")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_hint_locale: Option<FieldLocalization>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WhoRetries {
    Me,
    You,
    Both,
    None,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Impact {
    MessageContent,
    Thread,
    Connection,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Where {
    pub party: WhereParty,
    pub location: String,
}

impl Display for Where {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} - {}", self.party.as_ref(), self.location.as_str())
    }
}

impl Serialize for Where {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Where {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let err_closure = |val: &str| D::Error::custom(format!("invalid where field: {val}"));

        let where_str = <&str>::deserialize(deserializer)?;
        let mut iter = where_str.split(" - ");

        let party = iter
            .next()
            .ok_or_else(|| err_closure(where_str))?
            .try_into()
            .map_err(D::Error::custom)?;

        let location = iter.next().ok_or_else(|| err_closure(where_str))?.to_owned();

        Ok(Where { party, location })
    }
}

#[derive(AsRefStr, Debug, Copy, Clone, Serialize, Deserialize, EnumString, PartialEq)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum WhereParty {
    Me,
    You,
    Other,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{decorators::thread::tests::make_extended_thread, misc::test_utils};

    #[test]
    fn test_minimal_problem_report() {
        let content = ProblemReportContent::default();
        let decorators = ProblemReportDecorators::default();

        let json = json!({});

        test_utils::test_msg::<ProblemReportContent, _, _>(content, decorators, json);
    }

    #[test]
    fn test_extensive_problem_report() {
        let mut content = ProblemReportContent::default();
        content.description = Some("test_description".to_owned());
        content.who_retries = Some(WhoRetries::Me);

        let mut decorators = ProblemReportDecorators::default();
        decorators.thread = Some(make_extended_thread());

        let json = json!({
            "description": content.description,
            "who_retries": content.who_retries,
            "~thread": decorators.thread
        });

        test_utils::test_msg::<ProblemReportContent, _, _>(content, decorators, json);
    }
}
