use messages_macros::MessageContent;
use serde::{Deserialize, Serialize};

use crate::{
    decorators::{attachment::Attachment, thread::Thread, timing::Timing},
    message::Message,
    msg_types::types::cred_issuance::CredentialIssuanceV1_0,
};

pub type RequestCredential = Message<RequestCredentialContent, RequestCredentialDecorators>;

#[derive(Clone, Debug, Deserialize, Serialize, MessageContent, PartialEq)]
#[message(kind = "CredentialIssuanceV1_0::RequestCredential")]
pub struct RequestCredentialContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(rename = "requests~attach")]
    pub requests_attach: Vec<Attachment>,
}

impl RequestCredentialContent {
    pub fn new(requests_attach: Vec<Attachment>) -> Self {
        Self {
            comment: None,
            requests_attach,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default, PartialEq)]
pub struct RequestCredentialDecorators {
    #[serde(rename = "~thread")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread: Option<Thread>,
    #[serde(rename = "~timing")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<Timing>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{
        decorators::{attachment::tests::make_extended_attachment, thread::tests::make_extended_thread},
        misc::test_utils,
    };

    #[test]
    fn test_minimal_request_cred() {
        let content = RequestCredentialContent::new(vec![make_extended_attachment()]);

        let decorators = RequestCredentialDecorators::default();

        let json = json!({
            "requests~attach": content.requests_attach,
        });

        test_utils::test_msg::<RequestCredentialContent, _, _>(content, decorators, json);
    }

    #[test]
    fn test_extensive_request_cred() {
        let mut content = RequestCredentialContent::new(vec![make_extended_attachment()]);
        content.comment = Some("test_comment".to_owned());

        let mut decorators = RequestCredentialDecorators::default();
        decorators.thread = Some(make_extended_thread());

        let json = json!({
            "requests~attach": content.requests_attach,
            "comment": content.comment,
            "~thread": decorators.thread
        });

        test_utils::test_msg::<RequestCredentialContent, _, _>(content, decorators, json);
    }
}
