use crate::messages::a2a::{A2AMessage, MessageId};
use crate::messages::a2a::message_family::MessageFamilies;
use crate::messages::a2a::message_type::MessageType;
use crate::messages::mime_type::MimeType;
use crate::messages::thread::Thread;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Default)]
pub struct PresentationProposal {
    #[serde(rename = "@id")]
    pub id: MessageId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub presentation_proposal: PresentationPreview,
    #[serde(rename = "~thread")]
    pub thread: Thread,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Default)]
pub struct PresentationPreview {
    #[serde(rename = "@type")]
    #[serde(default = "default_presentation_preview_type")]
    pub _type: MessageType,
    pub attributes: Vec<Attribute>,
    pub predicates: Vec<Predicate>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Attribute {
    pub name: String,
    pub cred_def_id: Option<String>,
    #[serde(rename = "mime-type")]
    pub mime_type: Option<MimeType>,
    pub value: Option<String>,
    pub filter: Option<Vec<::serde_json::Value>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Predicate {
    pub name: String,
    pub cred_def_id: Option<String>,
    pub predicate: String,
    pub threshold: i64,
    pub filter: Option<Vec<::serde_json::Value>>,
}

fn default_presentation_preview_type() -> MessageType {
    MessageType::build(MessageFamilies::CredentialIssuance, "presentation-preview")
}

impl PresentationProposal {
    pub fn create() -> Self {
        PresentationProposal::default()
    }

    pub fn set_id(mut self, id: &str) -> Self {
        self.id = MessageId(id.to_string());
        self
    }

    pub fn set_comment(mut self, comment: String) -> Self {
        self.comment = Some(comment);
        self
    }

    pub fn set_presentation_preview(mut self, presentation_preview: PresentationPreview) -> PresentationProposal {
        self.presentation_proposal = presentation_preview;
        self
    }
}

threadlike!(PresentationProposal);
a2a_message!(PresentationProposal);

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Default)]
pub struct PresentationProposalData {
    pub attributes: Vec<Attribute>,
    pub predicates: Vec<Predicate>,
    pub comment: Option<String>,
}

impl PresentationProposalData {
    pub fn create() -> Self {
        Self::default()
    }

    pub fn add_attribute(mut self, attr: Attribute) -> Self {
        self.attributes.push(attr);
        self
    }

    pub fn set_comment(mut self, comment: String) -> Self {
        self.comment = Some(comment);
        self
    }

    pub fn add_predicate(mut self, pred: Predicate) -> Self {
        self.predicates.push(pred);
        self
    }
}

impl From<PresentationProposalData> for PresentationProposal {
    fn from(data: PresentationProposalData) -> Self {
        Self {
            comment: data.comment,
            presentation_proposal: PresentationPreview {
                attributes: data.attributes,
                predicates: data.predicates,
                ..PresentationPreview::default()
            },
            ..Self::default()
        }
    }
}

#[cfg(feature = "test_utils")]
pub mod test_utils {
    use crate::messages::proof_presentation::presentation_request::test_utils::thread;

    use super::*;

    fn _attachment() -> ::serde_json::Value {
        json!({"presentation": {}})
    }

    pub fn _comment() -> String {
        String::from("comment")
    }

    pub fn _presentation_preview() -> PresentationPreview {
        PresentationPreview {
            attributes: vec![Attribute {
                name: String::from("name"),
                cred_def_id: None,
                mime_type: None,
                value: None,
                filter: None,
            }],
            predicates: vec![],
            ..Default::default()
        }
    }

    pub fn _presentation_proposal() -> PresentationProposal {
        PresentationProposal {
            id: MessageId::id(),
            comment: Some(_comment()),
            thread: thread(),
            presentation_proposal: _presentation_preview(),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "general_test")]
pub mod tests {
    use crate::messages::proof_presentation::presentation_proposal::test_utils::*;
    use crate::messages::proof_presentation::presentation_request::test_utils::thread_id;

    use super::*;

    #[test]
    #[cfg(feature = "general_test")]
    fn test_presentation_proposal_build_works() {
        let presentation_proposal: PresentationProposal = PresentationProposal::default()
            .set_comment(_comment())
            .set_thread_id(&thread_id())
            .set_presentation_preview(_presentation_preview());

        assert_eq!(_presentation_proposal(), presentation_proposal);
    }
}
