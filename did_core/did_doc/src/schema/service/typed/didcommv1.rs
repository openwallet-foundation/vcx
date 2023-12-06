use std::collections::HashMap;

use serde::Serialize;
use url::Url;

use crate::{
    error::DidDocumentSovError,
    schema::{
        service::{
            extra_fields::{didcommv1::ExtraFieldsDidCommV1, ServiceKeyKind},
            typed::{ServiceType, TypedService},
            Service,
        },
        types::uri::Uri,
        utils::OneOrList,
    },
};

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ServiceDidCommV1 {
    #[serde(flatten)]
    service: TypedService<ExtraFieldsDidCommV1>,
}

impl ServiceDidCommV1 {
    // remove this in favor of new_2, we should keep "ExtraFields" type internal only
    // exposing any new types is burden on the user
    pub fn new(id: Uri, service_endpoint: Url, extra: ExtraFieldsDidCommV1) -> Self {
        Self {
            service: TypedService::<ExtraFieldsDidCommV1> {
                id,
                service_type: OneOrList::One(ServiceType::DIDCommV1.to_string()),
                service_endpoint,
                extra,
            },
        }
    }

    pub fn new_2(
        id: Uri,
        service_endpoint: Url,
        priority: u32,
        recipient_keys: Vec<ServiceKeyKind>,
        routing_keys: Vec<ServiceKeyKind>,
    ) -> Self {
        let extra = ExtraFieldsDidCommV1::builder()
            .set_priority(priority)
            .set_recipient_keys(recipient_keys)
            .set_routing_keys(routing_keys)
            .build();
        Self {
            service: TypedService::<ExtraFieldsDidCommV1> {
                id,
                service_type: OneOrList::One(ServiceType::DIDCommV1.to_string()),
                service_endpoint,
                extra,
            },
        }
    }

    pub fn id(&self) -> &Uri {
        self.service.id()
    }

    pub fn service_type(&self) -> ServiceType {
        ServiceType::DIDCommV1
    }

    pub fn service_endpoint(&self) -> Url {
        self.service.service_endpoint().clone()
    }

    pub fn extra(&self) -> &ExtraFieldsDidCommV1 {
        self.service.extra()
    }
}

impl TryFrom<ServiceDidCommV1> for Service {
    type Error = DidDocumentSovError;

    fn try_from(did_comm_service: ServiceDidCommV1) -> Result<Self, Self::Error> {
        let mut extra_fields = HashMap::new();
        extra_fields.insert(
            "priority".to_string(),
            serde_json::Value::from(did_comm_service.extra().priority()),
        );
        extra_fields.insert(
            "recipientKeys".to_string(),
            serde_json::to_value(did_comm_service.extra().recipient_keys())?,
        );
        extra_fields.insert(
            "routingKeys".to_string(),
            serde_json::to_value(did_comm_service.extra().routing_keys())?,
        );
        extra_fields.insert(
            "accept".to_string(),
            serde_json::to_value(did_comm_service.extra().accept())?,
        );

        Ok(Service::new(
            did_comm_service.id().clone(),
            did_comm_service.service_endpoint(),
            OneOrList::List(vec![ServiceType::DIDCommV1]),
            extra_fields,
        ))
    }
}
