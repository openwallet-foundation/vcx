use crate::handlers::out_of_band::{OutOfBand, GoalCode, HandshakeProtocol};
use crate::messages::attachment::AttachmentId;
use crate::messages::connection::service::ServiceResolvable;
use crate::messages::a2a::A2AMessage;
use crate::messages::a2a::message_type::MessageType;
use crate::messages::a2a::message_family::MessageFamilies;
use crate::error::prelude::*;

#[derive(Default, Debug, PartialEq, Clone)]
pub struct OutOfBandSender {
    pub oob: OutOfBand
}

impl OutOfBandSender {
    pub fn create() -> Self {
        Self::default()
    }

    pub fn set_label(mut self, label: &str) -> Self {
        self.oob.label = Some(label.to_string());
        self
    }

    pub fn set_goal_code(mut self, goal_code: &GoalCode) -> Self {
        self.oob.goal_code = Some(goal_code.clone());
        self
    }

    pub fn set_goal(mut self, goal: &str) -> Self {
        self.oob.goal = Some(goal.to_string());
        self
    }

    pub fn append_service(mut self, service: &ServiceResolvable) -> Self {
        self.oob.services.push(service.clone());
        self
    }

    pub fn append_handshake_protocol(mut self, protocol: &HandshakeProtocol) -> VcxResult<Self> {
        let new_protocol = match protocol {
            HandshakeProtocol::ConnectionV1 => MessageType::build(MessageFamilies::Connections, ""),
            HandshakeProtocol::DidExchangeV1 => { return Err(VcxError::from(VcxErrorKind::ActionNotSupported)) }
        };
        match self.oob.handshake_protocols {
            Some(ref mut protocols) => {
                protocols.push(new_protocol);
            }
            None =>  {
                self.oob.handshake_protocols = Some(vec![new_protocol]);
            }
        };
        Ok(self)
    }

    pub fn append_a2a_message(mut self, msg: A2AMessage) -> VcxResult<Self> {
        let (attach_id, attach) = match msg {
            A2AMessage::PresentationRequest(request) => {
                (AttachmentId::PresentationRequest, json!(&request).to_string())
            }
            A2AMessage::CredentialOffer(offer) => {
                 (AttachmentId::CredentialOffer, json!(&offer).to_string())
            }
            _ => {
                error!("Appended message type {:?} is not allowed.", msg);
                return Err(VcxError::from_msg(
                    VcxErrorKind::InvalidMessageFormat,
                    format!("Appended message type {:?} is not allowed.", msg))
                )
            }
        };
        self.oob.requests_attach.add_base64_encoded_json_attachment(attach_id, ::serde_json::Value::String(attach))?;
        Ok(self)
    }

    pub fn to_a2a_message(&self) -> A2AMessage {
        self.oob.to_a2a_message()
    }

    pub fn to_string(&self) -> VcxResult<String> {
        self.oob.to_string()
    }

    pub fn from_string(oob_data: &str) -> VcxResult<Self> {
        Ok(Self {
            oob: OutOfBand::from_string(oob_data)?
        })
    }
}
