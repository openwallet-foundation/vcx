use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use public_key::{Key, KeyType};
use serde::{Deserialize, Deserializer, Serialize};

use did_doc::{
    did_parser::{Did, DidUrl},
    schema::{
        did_doc::DidDocument,
        service::Service,
        verification_method::{VerificationMethod, VerificationMethodType},
    },
};
use serde_json::{json, Value};

use crate::{
    extra_fields::ExtraFieldsSov,
    service::{legacy::ServiceLegacy, ServiceType},
};

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct LegacyDidDoc {
    id: Did,
    #[serde(default)]
    #[serde(rename = "publicKey")]
    public_key: Vec<LegacyKeyAgreement>,
    #[serde(default)]
    authentication: Vec<LegacyAuthentication>,
    service: Vec<ServiceLegacy>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct LegacyKeyAgreement {
    id: String,
    #[serde(rename = "type")]
    verification_method_type: String,
    controller: String,
    #[serde(rename = "publicKeyBase58")]
    public_key_base_58: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct LegacyAuthentication {
    #[serde(rename = "type")]
    verification_method_type: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}

fn legacy_public_key_to_verification_method(value: &LegacyKeyAgreement) -> Result<VerificationMethod, String> {
    let LegacyKeyAgreement {
        id,
        verification_method_type: _,
        controller,
        public_key_base_58,
    } = value;
    // SAFETY: Not used for derefencing anyways + DDO contains did
    let id = DidUrl::parse(id.clone()).unwrap_or_default();
    // SAFETY: DDO contains did
    let controller = Did::parse(controller.clone()).unwrap_or_default();
    // TODO:
    let verification_method_type = VerificationMethodType::X25519KeyAgreementKey2019;

    Ok(VerificationMethod::builder(id, controller, verification_method_type)
        .add_public_key_base58(public_key_base_58.clone())
        .build())
}

fn legacy_authentication_to_verification_method(
    legacy_authentication: &LegacyAuthentication,
    did: Did,
    legacy_public_keys: &[LegacyKeyAgreement],
) -> Result<VerificationMethod, String> {
    let verification_method_type = VerificationMethodType::Ed25519VerificationKey2018;

    // If it's a reference, resolve it. We might want to just include reference, but this is easier
    // to do safely.
    let (public_key_base_58, did_url) = if let Some(fragment) = legacy_authentication.public_key.split('#').last() {
        (
            legacy_public_keys
                .iter()
                .find(|pk| pk.id.ends_with(fragment))
                .ok_or_else(|| format!("Public key with id {} not found", fragment))?
                .public_key_base_58
                .clone(),
            DidUrl::from_fragment(fragment.to_string()).unwrap(),
        )
    } else {
        // TODO: Do some sanity checks
        (legacy_authentication.public_key.clone(), did.clone().into())
    };

    Ok(VerificationMethod::builder(did_url, did, verification_method_type)
        .add_public_key_base58(public_key_base_58)
        .build())
}

fn resolve_legacy_authentication_key(
    legacy_authentication: &LegacyAuthentication,
    legacy_public_keys: &[LegacyKeyAgreement],
) -> Result<String, String> {
    if let Some(fragment) = legacy_authentication.public_key.split('#').last() {
        Ok(legacy_public_keys
            .iter()
            .find(|pk| pk.id.ends_with(fragment))
            .ok_or_else(|| format!("Public key with id {} not found", fragment))?
            .public_key_base_58
            .clone())
    } else {
        Ok(legacy_authentication.public_key.clone())
    }
}

// https://github.com/TimoGlastra/legacy-did-transformation
fn construct_peer_did(legacy_ddo: &LegacyDidDoc) -> Result<Did, String> {
    let mut did = "did:peer:2".to_string();
    let mut authentication_fingerprints = vec![];

    for auth in &legacy_ddo.authentication {
        let resolved_legacy_authentication_key = match auth.verification_method_type.as_str() {
            "Ed25519SignatureAuthentication2018" => resolve_legacy_authentication_key(auth, &legacy_ddo.public_key)?,
            "Ed25519Signature2018" => auth.public_key.clone(),
            _ => {
                continue;
            }
        };

        let fingerprint = Key::from_base58(&resolved_legacy_authentication_key, KeyType::Ed25519)
            .map_err(|err| {
                format!(
                    "Error converting legacy authentication key to new key: {:?}, error: {:?}",
                    auth, err
                )
            })?
            .fingerprint();
        authentication_fingerprints.push(fingerprint);
    }

    for vm in &legacy_ddo.public_key {
        if vm.verification_method_type != "Ed25519Signature2018" {
            continue;
        }

        let fingerprint = Key::from_base58(vm.public_key_base_58.as_str(), KeyType::Ed25519)
            .map_err(|err| {
                format!(
                    "Error converting legacy public key to new key: {:?}, error: {:?}",
                    vm, err
                )
            })?
            .fingerprint();
        if !authentication_fingerprints.contains(&fingerprint) {
            authentication_fingerprints.push(fingerprint);
        }
    }

    for fingerprint in authentication_fingerprints {
        did.push_str(&format!(".V{}", fingerprint));
    }

    for s in &legacy_ddo.service {
        if s.service_type() != ServiceType::Legacy {
            continue;
        }
        let service = json!({
            "priority": s.extra().priority(),
            "r": s.extra().routing_keys(),
            "recipientKeys": s.extra().recipient_keys(),
            "s": s.service_endpoint(),
            "t": s.service_type(),
        });
        let service_encoded = STANDARD_NO_PAD.encode(serde_json::to_vec(&service).map_err(|err| {
            format!(
                "Error encoding legacy service to base64: {:?}, error: {:?}",
                service, err
            )
        })?);
        did.push_str(&format!(".S{}", service_encoded));
    }

    Did::parse(did).map_err(|err| format!("Error parsing peer did, error: {:?}", err))
}

fn convert_legacy_ddo_to_new(legacy_ddo: LegacyDidDoc) -> Result<DidDocument<ExtraFieldsSov>, String> {
    let did = construct_peer_did(&legacy_ddo)?;

    let mut builder = DidDocument::builder(did);

    // TODO: We usually added just "recipient key", which was used both in publicKey and authentication.
    // When constructing new DDO, we probably want to add just verification method for each recipient key,
    // and then all other properties should contain reference to (each?) verification method.
    for vm in &legacy_ddo.public_key {
        builder = builder.add_key_agreement(legacy_public_key_to_verification_method(&vm)?);
    }

    for auth in &legacy_ddo.authentication {
        builder = builder.add_verification_method(legacy_authentication_to_verification_method(
            &auth,
            legacy_ddo.id.clone(),
            &legacy_ddo.public_key,
        )?);
    }

    for service in &legacy_ddo.service {
        builder = builder.add_service(TryInto::<Service<ExtraFieldsSov>>::try_into(service.clone()).map_err(
            |err| {
                format!(
                    "Error converting legacy service to new service: {:?}, error: {:?}",
                    service, err
                )
            },
        )?);
    }

    Ok(builder.build())
}

pub fn deserialize_legacy_or_new<'de, D>(deserializer: D) -> Result<DidDocument<ExtraFieldsSov>, D::Error>
where
    D: Deserializer<'de>,
{
    let val = Value::deserialize(deserializer)?;

    match serde_json::from_value::<LegacyDidDoc>(val.clone()) {
        Ok(legacy_doc) => Ok(convert_legacy_ddo_to_new(legacy_doc).map_err(serde::de::Error::custom)?),
        Err(_err) => {
            println!("Error deserializing legacy did doc: {:?}", _err);
            serde_json::from_value::<DidDocument<ExtraFieldsSov>>(val).map_err(serde::de::Error::custom)
        }
    }
}
