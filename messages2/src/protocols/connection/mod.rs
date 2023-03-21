pub mod invitation;
pub mod problem_report;
pub mod request;
pub mod response;

use std::str::FromStr;

use derive_more::From;
use serde::{de::Error, Deserializer, Serializer};

use self::{
    invitation::Invitation,
    problem_report::{ProblemReportContent, ProblemReportDecorators},
    request::{RequestContent, RequestDecorators},
    response::{ResponseContent, ResponseDecorators},
};
pub use self::{problem_report::ProblemReport, request::Request, response::Response};
use crate::{
    misc::utils::{self, transit_to_aries_msg},
    msg_types::types::connection::{Connection as ConnectionKind, ConnectionV1, ConnectionV1_0},
    protocols::traits::DelayedSerde,
};

#[derive(Clone, Debug, From, PartialEq)]
pub enum Connection {
    Invitation(Invitation),
    Request(Request),
    Response(Response),
    ProblemReport(ProblemReport),
}

impl DelayedSerde for Connection {
    type MsgType<'a> = (ConnectionKind, &'a str);

    fn delayed_deserialize<'de, D>(msg_type: Self::MsgType<'de>, deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (major, kind) = msg_type;
        let ConnectionKind::V1(major) = major;
        let ConnectionV1::V1_0(_minor) = major;
        let kind = ConnectionV1_0::from_str(kind).map_err(D::Error::custom)?;

        match kind {
            ConnectionV1_0::Invitation => Invitation::delayed_deserialize(kind, deserializer).map(From::from),
            ConnectionV1_0::Request => Request::delayed_deserialize(kind, deserializer).map(From::from),
            ConnectionV1_0::Response => Response::delayed_deserialize(kind, deserializer).map(From::from),
            ConnectionV1_0::ProblemReport => ProblemReport::delayed_deserialize(kind, deserializer).map(From::from),
            ConnectionV1_0::Ed25519Sha512Single => Err(utils::not_standalone_msg::<D>(kind.as_ref())),
        }
    }

    fn delayed_serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Invitation(v) => v.delayed_serialize(serializer),
            Self::Request(v) => v.delayed_serialize(serializer),
            Self::Response(v) => v.delayed_serialize(serializer),
            Self::ProblemReport(v) => v.delayed_serialize(serializer),
        }
    }
}

transit_to_aries_msg!(RequestContent: RequestDecorators, Connection);
transit_to_aries_msg!(ResponseContent: ResponseDecorators, Connection);
transit_to_aries_msg!(ProblemReportContent: ProblemReportDecorators, Connection);
