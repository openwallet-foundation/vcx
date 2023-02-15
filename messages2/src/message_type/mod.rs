pub mod message_family;
mod prefix;

use std::str::FromStr;

use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::MsgTypeError;

use self::{message_family::traits::ResolveMajorVersion, prefix::Prefix};

pub use self::message_family::MessageFamily;

#[derive(PartialEq)]
pub struct MessageType {
    prefix: Prefix,
    pub family: MessageFamily,
}

impl MessageType {
    pub fn new(prefix: Prefix, family: MessageFamily) -> Self {
        Self { prefix, family }
    }
}

impl<T> From<T> for MessageType
where
    MessageFamily: From<T>,
{
    fn from(value: T) -> Self {
        let family = MessageFamily::from(value);
        Self::new(Prefix::default(), family)
    }
}

impl FromStr for MessageType {
    type Err = MsgTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // The type is segmented by forward slashes, but the HTTPS
        // prefix includes two as well (https://), so we'll accommodate that
        // when we skip elements from the split string.
        //
        // We always skip at least one element, the prefix itself.
        //
        // While we're at it we can also store the Prefix itself.
        let (prefix, skip_slash) = match s {
            _ if s.starts_with(Prefix::DID_COM_ORG_PREFIX) => Ok((Prefix::DidCommOrg, 3)),
            _ if s.starts_with(Prefix::DID_SOV_PREFIX) => Ok((Prefix::DidSov, 1)),
            _ => Err(MsgTypeError::unknown_prefix(s.to_owned())),
        }?;

        // We'll get the next components in order
        let mut iter = s.split('/').skip(skip_slash);

        let family = MessageFamily::next_part(&mut iter, "family")?;
        let version = MessageFamily::next_part(&mut iter, "protocol version")?;
        let kind = MessageFamily::next_part(&mut iter, "message kind")?;

        // We'll parse the version to its major and minor parts
        let mut version_iter = version.split('.');

        let major = MessageFamily::next_part(&mut version_iter, "protocol major version")?.parse()?;
        let minor = MessageFamily::next_part(&mut version_iter, "protocol minor version")?.parse()?;

        let msg_family = MessageFamily::from_parts(family, major, minor, kind)?;
        let msg_type = MessageType::new(prefix, msg_family);

        Ok(msg_type)
    }
}

impl<'de> Deserialize<'de> for MessageType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let type_str = <&str>::deserialize(deserializer)?;
        type_str
            .parse()
            .map_err(|e| D::Error::custom(format!("Message type {type_str}; {e}")))
    }
}

impl Serialize for MessageType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let prefix = self.prefix.as_ref();
        let (family, major, minor, kind) = match &self.family {
            MessageFamily::Routing(v) => v.as_msg_type_parts(),
            MessageFamily::Connection(v) => v.as_msg_type_parts(),
            MessageFamily::Revocation(v) => v.as_msg_type_parts(),
            MessageFamily::CredentialIssuance(v) => v.as_msg_type_parts(),
            MessageFamily::ReportProblem(v) => v.as_msg_type_parts(),
            MessageFamily::PresentProof(v) => v.as_msg_type_parts(),
            MessageFamily::TrustPing(v) => v.as_msg_type_parts(),
            MessageFamily::DiscoverFeatures(v) => v.as_msg_type_parts(),
            MessageFamily::BasicMessage(v) => v.as_msg_type_parts(),
            MessageFamily::OutOfBand(v) => v.as_msg_type_parts(),
        };

        serializer.serialize_str(&format!("{prefix}/{family}/{major}.{minor}/{kind}"))
    }
}


#[cfg(test)]
mod tests {
    use crate::message_type::message_family::basic_message::{BasicMessage, BasicMessageV1_0};
    use crate::message_type::message_family::connection::ConnectionV1_0;
    use super::*;

    #[test]
    fn from_string_basicmessage() {
        let msg_type = MessageType::from_str("https://didcomm.org/basicmessage/1.0/message").unwrap();
        assert_eq!(msg_type.prefix, Prefix::DidCommOrg);
        // This From conversion is generated using transient_from! macro
        let family: MessageFamily = BasicMessageV1_0::Message.into();
        assert_eq!(msg_type.family, family);
    }

    #[test]
    fn from_string_connections() {
        let msg_type = MessageType::from_str("https://didcomm.org/connections/1.0/invitation").unwrap();
        assert_eq!(msg_type.prefix, Prefix::DidCommOrg);
        assert_eq!(msg_type.family, ConnectionV1_0::Invitation.into());
        let msg_type = MessageType::from_str("https://didcomm.org/connections/1.0/request").unwrap();
        assert_eq!(msg_type.prefix, Prefix::DidCommOrg);
        assert_eq!(msg_type.family, ConnectionV1_0::Request.into());
        let msg_type = MessageType::from_str("https://didcomm.org/connections/1.0/response").unwrap();
        assert_eq!(msg_type.prefix, Prefix::DidCommOrg);
        assert_eq!(msg_type.family, ConnectionV1_0::Response.into());
        let msg_type = MessageType::from_str("https://didcomm.org/connections/1.0/problem_report").unwrap();
        assert_eq!(msg_type.prefix, Prefix::DidCommOrg);
        assert_eq!(msg_type.family, ConnectionV1_0::ProblemReport.into());
    }
}
