use std::sync::Arc;

use async_trait::async_trait;
use did_resolver::{
    did_parser::ParsedDID,
    error::GenericError,
    shared_types::media_type::MediaType,
    traits::resolvable::{
        resolution_options::DIDResolutionOptions, resolution_output::DIDResolutionOutput,
        DIDResolvable,
    },
};

use crate::{error::DIDSovError, reader::AttrReader};

use super::utils::{is_valid_sovrin_did_id, ledger_response_to_ddo};

pub struct DIDSovResolver {
    ledger: Arc<dyn AttrReader>,
}

impl DIDSovResolver {
    pub fn new(ledger: Arc<dyn AttrReader>) -> Self {
        DIDSovResolver { ledger }
    }
}

#[async_trait]
impl DIDResolvable for DIDSovResolver {
    async fn resolve(
        &self,
        parsed_did: &ParsedDID,
        options: &DIDResolutionOptions,
    ) -> Result<DIDResolutionOutput, GenericError> {
        if let Some(accept) = options.accept() {
            if accept != &MediaType::DidJson {
                return Err(Box::new(DIDSovError::RepresentationNotSupported(
                    accept.to_string(),
                )));
            }
        }
        if parsed_did.method() != "sov" {
            return Err(Box::new(DIDSovError::MethodNotSupported(
                parsed_did.method().to_string(),
            )));
        }
        if !is_valid_sovrin_did_id(parsed_did.id()) {
            return Err(Box::new(DIDSovError::InvalidDID(
                parsed_did.id().to_string(),
            )));
        }
        let did = parsed_did.did();
        let ledger_response = self.ledger.get_attr(did, "endpoint").await?;
        ledger_response_to_ddo(did, &ledger_response)
            .await
            .map_err(|err| err.into())
    }
}
