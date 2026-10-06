use async_trait::async_trait;
use did_doc::schema::{
    contexts,
    did_doc::DidDocument,
    types::jsonwebkey::JsonWebKey,
    verification_method::{PublicKeyField, VerificationMethod, VerificationMethodType},
};
use did_parser_nom::{Did, DidUrl};
use did_resolver::{
    error::GenericError,
    traits::resolvable::{
        resolution_metadata::DidResolutionMetadata, resolution_output::DidResolutionOutput,
        DidResolvable,
    },
};
use serde::{Deserialize, Serialize};

use did_key::DidKey;

use crate::error::DidKeyResolutionError;

#[derive(Default)]
pub struct DidKeyResolver;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum PublicKeyFormat {
    Multikey,
    JsonWebKey2020,
    Ed25519VerificationKey2020,
    X25519KeyAgreementKey2020,
}

impl PublicKeyFormat {
    fn verification_method_type(self) -> VerificationMethodType {
        match self {
            Self::Multikey => VerificationMethodType::Multikey,
            Self::JsonWebKey2020 => VerificationMethodType::JsonWebKey2020,
            Self::Ed25519VerificationKey2020 => VerificationMethodType::Ed25519VerificationKey2020,
            Self::X25519KeyAgreementKey2020 => VerificationMethodType::X25519KeyAgreementKey2020,
        }
    }
}

impl std::fmt::Display for PublicKeyFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.verification_method_type().fmt(formatter)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DidKeyResolutionOptions {
    pub public_key_format: PublicKeyFormat,
    pub enable_encryption_key_derivation: bool,
    pub enable_experimental_public_key_types: bool,
    pub default_context: Vec<String>,
}

impl Default for DidKeyResolutionOptions {
    fn default() -> Self {
        Self {
            public_key_format: PublicKeyFormat::Multikey,
            enable_encryption_key_derivation: false,
            enable_experimental_public_key_types: false,
            default_context: vec![contexts::W3C_DID_V1.to_string()],
        }
    }
}

impl DidKeyResolver {
    pub fn new() -> Self {
        Self
    }
}

enum VerificationPurpose {
    Signing,
    Encryption,
}

fn create_verification_method(
    did: &Did,
    key: &public_key::Key,
    public_key_format: PublicKeyFormat,
    purpose: VerificationPurpose,
) -> Result<(DidUrl, VerificationMethod), DidKeyResolutionError> {
    if matches!(
        (public_key_format, &purpose),
        (
            PublicKeyFormat::Ed25519VerificationKey2020,
            VerificationPurpose::Encryption
        ) | (
            PublicKeyFormat::X25519KeyAgreementKey2020,
            VerificationPurpose::Signing
        )
    ) {
        return Err(DidKeyResolutionError::InvalidPublicKeyType(
            public_key_format.to_string(),
        ));
    }
    if public_key_format == PublicKeyFormat::Ed25519VerificationKey2020
        && key.key_type() != &public_key::KeyType::Ed25519
    {
        return Err(DidKeyResolutionError::InvalidPublicKeyType(format!(
            "{public_key_format} for {}",
            key.key_type()
        )));
    }
    if public_key_format == PublicKeyFormat::X25519KeyAgreementKey2020
        && key.key_type() != &public_key::KeyType::X25519
    {
        return Err(DidKeyResolutionError::InvalidPublicKeyType(format!(
            "{public_key_format} for {}",
            key.key_type()
        )));
    }
    let multibase_value = key.fingerprint();
    let verification_method_id: DidUrl = format!("{did}#{multibase_value}").parse()?;
    let verification_method_type = public_key_format.verification_method_type();
    let public_key = match public_key_format {
        PublicKeyFormat::Multikey
        | PublicKeyFormat::Ed25519VerificationKey2020
        | PublicKeyFormat::X25519KeyAgreementKey2020 => PublicKeyField::Multibase {
            public_key_multibase: multibase_value,
        },
        PublicKeyFormat::JsonWebKey2020 => PublicKeyField::Jwk {
            public_key_jwk: JsonWebKey::new(&key.to_jwk()?)?,
        },
    };

    Ok((
        verification_method_id.clone(),
        VerificationMethod::builder()
            .id(verification_method_id)
            .controller(did.clone())
            .verification_method_type(verification_method_type)
            .public_key(public_key)
            .build(),
    ))
}

#[async_trait]
impl DidResolvable for DidKeyResolver {
    type DidResolutionOptions = DidKeyResolutionOptions;

    async fn resolve(
        &self,
        did: &Did,
        options: &Self::DidResolutionOptions,
    ) -> Result<DidResolutionOutput, GenericError> {
        let Some(method) = did.method() else {
            return Err(Box::new(DidKeyResolutionError::InvalidDid));
        };
        if method != "key" {
            return Err(Box::new(DidKeyResolutionError::MethodNotSupported(
                method.to_string(),
            )));
        }
        let did_key = DidKey::parse(did.did().to_string()).map_err(DidKeyResolutionError::from)?;
        let key = did_key.key();

        let expected_key_length = match key.key_type() {
            public_key::KeyType::Ed25519 | public_key::KeyType::X25519 => 32,
            public_key::KeyType::P256 => 33,
            public_key::KeyType::P384 => 49,
            key_type => {
                return Err(Box::new(DidKeyResolutionError::UnsupportedKeyType(
                    *key_type,
                )))
            }
        };
        if key.key().len() != expected_key_length {
            return Err(Box::new(DidKeyResolutionError::InvalidPublicKeyLength {
                key_type: *key.key_type(),
                expected: expected_key_length,
                actual: key.key().len(),
            }));
        }
        if matches!(
            key.key_type(),
            public_key::KeyType::P256 | public_key::KeyType::P384
        ) {
            // JWK conversion imports the EC point, even when publishing Multikey.
            let _ = key
                .to_jwk()
                .map_err(DidKeyResolutionError::InvalidPublicKey)?;
        }

        let mut did_document = DidDocument::new(did.clone());

        if key.key_type() == &public_key::KeyType::X25519 {
            let (verification_method_id, verification_method) = create_verification_method(
                did,
                key,
                options.public_key_format,
                VerificationPurpose::Encryption,
            )?;
            did_document.add_verification_method(verification_method);
            did_document.add_key_agreement_ref(verification_method_id);
        } else {
            let (verification_method_id, verification_method) = create_verification_method(
                did,
                key,
                options.public_key_format,
                VerificationPurpose::Signing,
            )?;
            did_document.add_verification_method(verification_method);
            did_document.add_authentication_ref(verification_method_id.clone());
            did_document.add_assertion_method_ref(verification_method_id.clone());
            did_document.add_capability_invocation_ref(verification_method_id.clone());
            did_document.add_capability_delegation_ref(verification_method_id);
        }

        if options.enable_encryption_key_derivation {
            let encryption_key = key.derive_x25519().map_err(DidKeyResolutionError::from)?;
            let (encryption_method_id, encryption_method) = create_verification_method(
                did,
                &encryption_key,
                options.public_key_format,
                VerificationPurpose::Encryption,
            )?;
            did_document.add_verification_method(encryption_method);
            did_document.add_key_agreement_ref(encryption_method_id);
        }

        let mut context = options.default_context.clone();
        let verification_method_type = options.public_key_format.verification_method_type();
        let method_context = verification_method_type.context_for_type();
        if !context.iter().any(|value| value == method_context) {
            context.push(method_context.to_string());
        }
        did_document.set_extra_field("@context".to_string(), serde_json::json!(context));

        let resolution_metadata = DidResolutionMetadata::builder()
            .content_type("application/did+ld+json".to_string())
            .build();

        Ok(DidResolutionOutput::builder(did_document)
            .did_resolution_metadata(resolution_metadata)
            .build())
    }
}
