#![allow(clippy::or_fun_call)]
#![allow(clippy::module_inception)]
#![allow(clippy::derive_partial_eq_without_eq)]
#![allow(clippy::new_without_default)]
#![allow(clippy::inherent_to_string)]
#![allow(clippy::large_enum_variant)]

pub mod decorators;
pub mod error;
pub mod misc;
pub mod msg_fields;
pub mod msg_parts;
pub mod msg_types;

use derive_more::From;
use display_as_json::Display;
use misc::utils;
use msg_fields::protocols::{
    cred_issuance::{v1::CredentialIssuanceV1, v2::CredentialIssuanceV2, CredentialIssuance},
    did_exchange::{v1_0::DidExchangeV1_0, v1_1::DidExchangeV1_1, DidExchange},
    pickup::Pickup,
    present_proof::{v2::PresentProofV2, PresentProof},
};
use msg_types::{
    cred_issuance::CredentialIssuanceType,
    present_proof::PresentProofType,
    protocols::did_exchange::{DidExchangeType, DidExchangeTypeV1},
    report_problem::ReportProblemTypeV1_0,
    routing::RoutingTypeV1_0,
    MsgWithType,
};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    msg_fields::{
        protocols::{
            basic_message::BasicMessage, connection::Connection,
            coordinate_mediation::CoordinateMediation, discover_features::DiscoverFeatures,
            notification::Notification, out_of_band::OutOfBand, present_proof::v1::PresentProofV1,
            report_problem::ProblemReport, revocation::Revocation, routing::Forward,
            trust_ping::TrustPing,
        },
        traits::DelayedSerde,
    },
    msg_types::{
        basic_message::BasicMessageTypeV1_0,
        protocols::{
            basic_message::{BasicMessageType, BasicMessageTypeV1},
            report_problem::{ReportProblemType, ReportProblemTypeV1},
            routing::{RoutingType, RoutingTypeV1},
        },
        MessageType, Protocol,
    },
};

/// Enum that can represent any message of the implemented protocols.
///
/// It abstracts away the `@type` field and uses it to determine how
/// to deserialize the input into the correct message type.
///
/// It also automatically appends the correct `@type` field when serializing
/// a message.
#[derive(Clone, Debug, Display, From, PartialEq)]
pub enum AriesMessage {
    Routing(Forward),
    Connection(Connection),
    Revocation(Revocation),
    CredentialIssuance(CredentialIssuance),
    ReportProblem(ProblemReport),
    PresentProof(PresentProof),
    TrustPing(TrustPing),
    DiscoverFeatures(DiscoverFeatures),
    BasicMessage(BasicMessage),
    OutOfBand(OutOfBand),
    Notification(Notification),
    Pickup(Pickup),
    CoordinateMediation(CoordinateMediation),
    DidExchange(DidExchange),
}

impl DelayedSerde for AriesMessage {
    type MsgType<'a> = MessageType<'a>;

    /// Match on every protocol variant and either:
    /// - call the equivalent type's [`DelayedSerde::delayed_deserialize`]
    /// - handle the message kind and directly deserialize to the proper type
    ///
    /// The second option is employed simply because some protocols only have one message
    /// and one version (at least right now) and there's no point in crowding the codebase
    /// with one variant enums or the like.
    fn delayed_deserialize<'de, D>(
        msg_type: Self::MsgType<'de>,
        deserializer: D,
    ) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let MessageType {
            protocol,
            kind: kind_str,
        } = msg_type;

        match protocol {
            Protocol::RoutingType(msg_type) => {
                let kind = match msg_type {
                    RoutingType::V1(RoutingTypeV1::V1_0(kind)) => kind.kind_from_str(kind_str),
                };

                match kind.map_err(D::Error::custom)? {
                    RoutingTypeV1_0::Forward => Forward::deserialize(deserializer).map(From::from),
                }
            }
            Protocol::ConnectionType(msg_type) => {
                Connection::delayed_deserialize((msg_type, kind_str), deserializer).map(From::from)
            }
            Protocol::SignatureType(_) => Err(utils::not_standalone_msg::<D>(kind_str)),
            Protocol::RevocationType(msg_type) => {
                Revocation::delayed_deserialize((msg_type, kind_str), deserializer).map(From::from)
            }
            Protocol::CredentialIssuanceType(CredentialIssuanceType::V1(msg_type)) => {
                CredentialIssuanceV1::delayed_deserialize(
                    (CredentialIssuanceType::V1(msg_type), kind_str),
                    deserializer,
                )
                .map(|x| AriesMessage::from(CredentialIssuance::V1(x)))
            }
            Protocol::CredentialIssuanceType(CredentialIssuanceType::V2(msg_type)) => {
                CredentialIssuanceV2::delayed_deserialize(
                    (CredentialIssuanceType::V2(msg_type), kind_str),
                    deserializer,
                )
                .map(|x| AriesMessage::from(CredentialIssuance::V2(x)))
            }
            Protocol::ReportProblemType(msg_type) => {
                let kind = match msg_type {
                    ReportProblemType::V1(ReportProblemTypeV1::V1_0(kind)) => {
                        kind.kind_from_str(kind_str)
                    }
                };

                match kind.map_err(D::Error::custom)? {
                    ReportProblemTypeV1_0::ProblemReport => {
                        ProblemReport::deserialize(deserializer).map(From::from)
                    }
                }
            }
            Protocol::PresentProofType(PresentProofType::V1(msg_type)) => {
                PresentProofV1::delayed_deserialize(
                    (PresentProofType::V1(msg_type), kind_str),
                    deserializer,
                )
                .map(|x| AriesMessage::from(PresentProof::V1(x)))
            }
            Protocol::PresentProofType(PresentProofType::V2(msg_type)) => {
                PresentProofV2::delayed_deserialize(
                    (PresentProofType::V2(msg_type), kind_str),
                    deserializer,
                )
                .map(|x| AriesMessage::from(PresentProof::V2(x)))
            }
            Protocol::TrustPingType(msg_type) => {
                TrustPing::delayed_deserialize((msg_type, kind_str), deserializer).map(From::from)
            }
            Protocol::DiscoverFeaturesType(msg_type) => {
                DiscoverFeatures::delayed_deserialize((msg_type, kind_str), deserializer)
                    .map(From::from)
            }
            Protocol::BasicMessageType(msg_type) => {
                let kind = match msg_type {
                    BasicMessageType::V1(BasicMessageTypeV1::V1_0(kind)) => {
                        kind.kind_from_str(kind_str)
                    }
                };

                match kind.map_err(D::Error::custom)? {
                    BasicMessageTypeV1_0::Message => {
                        BasicMessage::deserialize(deserializer).map(From::from)
                    }
                }
            }
            Protocol::OutOfBandType(msg_type) => {
                OutOfBand::delayed_deserialize((msg_type, kind_str), deserializer).map(From::from)
            }
            Protocol::NotificationType(msg_type) => {
                Notification::delayed_deserialize((msg_type, kind_str), deserializer)
                    .map(From::from)
            }
            Protocol::PickupType(msg_type) => {
                Pickup::delayed_deserialize((msg_type, kind_str), deserializer).map(From::from)
            }
            Protocol::CoordinateMediationType(msg_type) => {
                CoordinateMediation::delayed_deserialize((msg_type, kind_str), deserializer)
                    .map(From::from)
            }
            Protocol::DidExchangeType(DidExchangeType::V1(DidExchangeTypeV1::V1_0(msg_type))) => {
                DidExchangeV1_0::delayed_deserialize((msg_type, kind_str), deserializer)
                    .map(|x| AriesMessage::from(DidExchange::V1_0(x)))
            }
            Protocol::DidExchangeType(DidExchangeType::V1(DidExchangeTypeV1::V1_1(msg_type))) => {
                DidExchangeV1_1::delayed_deserialize((msg_type, kind_str), deserializer)
                    .map(|x| AriesMessage::from(DidExchange::V1_1(x)))
            }
        }
    }

    fn delayed_serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Routing(v) => MsgWithType::from(v).serialize(serializer),
            Self::Connection(v) => v.delayed_serialize(serializer),
            Self::Revocation(v) => v.delayed_serialize(serializer),
            Self::CredentialIssuance(CredentialIssuance::V1(v)) => v.delayed_serialize(serializer),
            Self::CredentialIssuance(CredentialIssuance::V2(v)) => v.delayed_serialize(serializer),
            Self::ReportProblem(v) => MsgWithType::from(v).serialize(serializer),
            Self::PresentProof(PresentProof::V1(v)) => v.delayed_serialize(serializer),
            Self::PresentProof(PresentProof::V2(v)) => v.delayed_serialize(serializer),
            Self::TrustPing(v) => v.delayed_serialize(serializer),
            Self::DiscoverFeatures(v) => v.delayed_serialize(serializer),
            Self::BasicMessage(v) => MsgWithType::from(v).serialize(serializer),
            Self::OutOfBand(v) => v.delayed_serialize(serializer),
            Self::Notification(v) => v.delayed_serialize(serializer),
            Self::Pickup(v) => v.delayed_serialize(serializer),
            Self::CoordinateMediation(v) => v.delayed_serialize(serializer),
            Self::DidExchange(DidExchange::V1_0(v)) => v.delayed_serialize(serializer),
            Self::DidExchange(DidExchange::V1_1(v)) => v.delayed_serialize(serializer),
        }
    }
}

/// Custom [`Deserialize`] impl for [`AriesMessage`] to use the `@type` as internal tag,
/// but deserialize it to a [`MessageType`].
///
/// For readability, the [`MessageType`] matching is done in the
/// [`DelayedSerde::delayed_deserialize`] method.
impl<'de> Deserialize<'de> for AriesMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use std::borrow::Cow;

        /// Helper that will only deserialize the message type and buffer the
        /// rest of the fields (borrowing where possible).
        #[derive(Deserialize)]
        struct TypeAndContent<'a> {
            #[serde(rename = "@type")]
            #[serde(borrow)]
            msg_type: Cow<'a, str>,
            #[serde(flatten)]
            content: serde_value::Value,
        }

        let TypeAndContent { msg_type, content } = TypeAndContent::deserialize(deserializer)?;

        // Parse the message type field to get the protocol and message kind
        let msg_type = msg_type.as_ref().try_into().map_err(D::Error::custom)?;

        // The content is serde_value::Value, which can be deserialized using ValueDeserializer
        let deserializer = serde_value::ValueDeserializer::<D::Error>::new(content);

        Self::delayed_deserialize(msg_type, deserializer)
    }
}

impl Serialize for AriesMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.delayed_serialize(serializer)
    }
}
