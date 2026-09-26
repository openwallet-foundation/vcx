use did_parser_nom::Did;
use did_resolver::{
    error::GenericError,
    traits::resolvable::{resolution_output::DidResolutionOutput, DidResolvable},
};
use did_resolver_key::{
    error::DidKeyResolutionError,
    resolver::{DidKeyResolutionOptions, DidKeyResolver, PublicKeyFormat},
};
use public_key::{KeyType, PublicKeyError};
use serde_json::{json, Value};

const ED25519_DID: &str = "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP";
const ED25519_FINGERPRINT: &str = "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP";
const DERIVATION_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const DERIVATION_FINGERPRINT: &str = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const DERIVED_X25519_FINGERPRINT: &str = "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p";
const X25519_DID: &str = "did:key:z6LShLeXRTzevtwcfehaGEzCMyL3bNsAeKCwcqwJxyCo63yE";
const X25519_FINGERPRINT: &str = "z6LShLeXRTzevtwcfehaGEzCMyL3bNsAeKCwcqwJxyCo63yE";
const P256_DID: &str = "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv";
const P256_FINGERPRINT: &str = "zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv";
const P384_DID: &str =
    "did:key:z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54";
const P384_FINGERPRINT: &str =
    "z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54";
const JWK_DID: &str = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
const JWK_FINGERPRINT: &str = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";

async fn resolve(
    did: &str,
    options: &DidKeyResolutionOptions,
) -> Result<DidResolutionOutput, GenericError> {
    DidKeyResolver::new()
        .resolve(&Did::parse(did.to_string()).unwrap(), options)
        .await
}

#[test]
fn experimental_public_key_types_are_disabled_by_default() {
    assert!(!DidKeyResolutionOptions::default().enable_experimental_public_key_types);
}

#[test]
fn deserializes_resolution_options_from_registry_shape() {
    let options: DidKeyResolutionOptions = serde_json::from_value(json!({
        "publicKeyFormat": "JsonWebKey2020",
        "enableEncryptionKeyDerivation": true,
        "enableExperimentalPublicKeyTypes": false,
        "defaultContext": ["https://example.com/context"]
    }))
    .unwrap();

    assert_eq!(
        options,
        DidKeyResolutionOptions {
            public_key_format: PublicKeyFormat::JsonWebKey2020,
            enable_encryption_key_derivation: true,
            enable_experimental_public_key_types: false,
            default_context: vec!["https://example.com/context".to_string()],
        }
    );
}

fn multikey_document(did: &str, fingerprint: &str, context: Value) -> Value {
    let method_id = format!("{did}#{fingerprint}");
    json!({
        "@context": context,
        "id": did,
        "verificationMethod": [{
            "id": method_id,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": fingerprint
        }],
        "authentication": [method_id],
        "assertionMethod": [method_id],
        "capabilityInvocation": [method_id],
        "capabilityDelegation": [method_id]
    })
}

fn did_from_bytes(bytes: &[u8]) -> String {
    format!(
        "did:key:{}",
        multibase::encode(multibase::Base::Base58Btc, bytes)
    )
}

#[tokio::test]
async fn resolves_key_as_multikey() {
    let context = json!([
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1"
    ]);
    for (did, fingerprint) in [
        (ED25519_DID, ED25519_FINGERPRINT),
        (P256_DID, P256_FINGERPRINT),
        (P384_DID, P384_FINGERPRINT),
    ] {
        let output = resolve(did, &Default::default()).await.unwrap();
        assert_eq!(
            serde_json::to_value(&output.did_document).unwrap(),
            multikey_document(did, fingerprint, context.clone()),
            "unexpected document for {did}"
        );
        assert_eq!(
            output
                .did_resolution_metadata
                .content_type()
                .map(String::as_str),
            Some("application/did+ld+json")
        );
    }
}

#[tokio::test]
async fn resolves_key_as_public_jwk_without_private_material() {
    let options = DidKeyResolutionOptions {
        public_key_format: PublicKeyFormat::JsonWebKey2020,
        ..Default::default()
    };
    let output = resolve(JWK_DID, &options).await.unwrap();
    let method_id = format!("{JWK_DID}#{JWK_FINGERPRINT}");

    assert_eq!(
        serde_json::to_value(output.did_document).unwrap(),
        json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
            "id": JWK_DID,
            "verificationMethod": [{
                "id": method_id,
                "type": "JsonWebKey2020",
                "controller": JWK_DID,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
                }
            }],
            "authentication": [method_id],
            "assertionMethod": [method_id],
            "capabilityInvocation": [method_id],
            "capabilityDelegation": [method_id]
        })
    );
}

#[tokio::test]
async fn resolves_key_as_ed25519_verification_key_2020() {
    let options = DidKeyResolutionOptions {
        public_key_format: PublicKeyFormat::Ed25519VerificationKey2020,
        ..Default::default()
    };
    let output = resolve(ED25519_DID, &options).await.unwrap();
    let mut expected = multikey_document(
        ED25519_DID,
        ED25519_FINGERPRINT,
        json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ]),
    );
    expected["verificationMethod"][0]["type"] = json!("Ed25519VerificationKey2020");

    assert_eq!(serde_json::to_value(output.did_document).unwrap(), expected);
}

#[tokio::test]
async fn derives_x25519_key_agreement_from_ed25519() {
    let options = DidKeyResolutionOptions {
        enable_encryption_key_derivation: true,
        ..Default::default()
    };
    let output = resolve(DERIVATION_DID, &options).await.unwrap();
    let signature_id = format!("{DERIVATION_DID}#{DERIVATION_FINGERPRINT}");
    let encryption_id = format!("{DERIVATION_DID}#{DERIVED_X25519_FINGERPRINT}");

    assert_eq!(
        serde_json::to_value(output.did_document).unwrap(),
        json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            "id": DERIVATION_DID,
            "verificationMethod": [
                {
                    "id": signature_id,
                    "type": "Multikey",
                    "controller": DERIVATION_DID,
                    "publicKeyMultibase": DERIVATION_FINGERPRINT
                },
                {
                    "id": encryption_id,
                    "type": "Multikey",
                    "controller": DERIVATION_DID,
                    "publicKeyMultibase": DERIVED_X25519_FINGERPRINT
                }
            ],
            "authentication": [signature_id],
            "assertionMethod": [signature_id],
            "capabilityInvocation": [signature_id],
            "capabilityDelegation": [signature_id],
            "keyAgreement": [encryption_id]
        })
    );
}

#[tokio::test]
async fn resolves_x25519_identifier_as_key_agreement() {
    let output = resolve(X25519_DID, &Default::default()).await.unwrap();
    let method_id = format!("{X25519_DID}#{X25519_FINGERPRINT}");

    assert_eq!(
        serde_json::to_value(output.did_document).unwrap(),
        json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            "id": X25519_DID,
            "verificationMethod": [{
                "id": method_id,
                "type": "Multikey",
                "controller": X25519_DID,
                "publicKeyMultibase": X25519_FINGERPRINT
            }],
            "keyAgreement": [method_id]
        })
    );
}

#[tokio::test]
async fn resolves_x25519_identifier_as_public_jwk() {
    let options = DidKeyResolutionOptions {
        public_key_format: PublicKeyFormat::JsonWebKey2020,
        ..Default::default()
    };
    let output = resolve(X25519_DID, &options).await.unwrap();
    let document = serde_json::to_value(output.did_document).unwrap();

    assert_eq!(
        document["@context"],
        json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ])
    );
    assert_eq!(document["verificationMethod"][0]["type"], "JsonWebKey2020");
    assert_eq!(
        document["verificationMethod"][0]["publicKeyJwk"]["crv"],
        "X25519"
    );
    assert!(document["verificationMethod"][0]["publicKeyJwk"]["d"].is_null());
    assert!(document.get("authentication").is_none());
    assert_eq!(document["keyAgreement"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn resolves_x25519_identifier_as_x25519_key_agreement_key_2020() {
    let options = DidKeyResolutionOptions {
        public_key_format: PublicKeyFormat::X25519KeyAgreementKey2020,
        ..Default::default()
    };
    let output = resolve(X25519_DID, &options).await.unwrap();
    let document = serde_json::to_value(output.did_document).unwrap();

    assert_eq!(
        document["@context"],
        json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/x25519-2020/v1"
        ])
    );
    assert_eq!(
        document["verificationMethod"][0]["type"],
        "X25519KeyAgreementKey2020"
    );
    assert_eq!(
        document["verificationMethod"][0]["publicKeyMultibase"],
        X25519_FINGERPRINT
    );
    assert!(document.get("authentication").is_none());
    assert_eq!(document["keyAgreement"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn preserves_custom_context_without_duplicating_method_context() {
    let options = DidKeyResolutionOptions {
        default_context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://example.com/context".to_string(),
            "https://w3id.org/security/multikey/v1".to_string(),
        ],
        ..Default::default()
    };
    let output = resolve(ED25519_DID, &options).await.unwrap();

    assert_eq!(
        serde_json::to_value(&output.did_document).unwrap(),
        multikey_document(
            ED25519_DID,
            ED25519_FINGERPRINT,
            json!([
                "https://www.w3.org/ns/did/v1",
                "https://example.com/context",
                "https://w3id.org/security/multikey/v1"
            ])
        )
    );
}

#[tokio::test]
async fn rejects_ed25519_format_for_x25519_identifier() {
    let options = DidKeyResolutionOptions {
        public_key_format: PublicKeyFormat::Ed25519VerificationKey2020,
        ..Default::default()
    };
    let error = resolve(X25519_DID, &options)
        .await
        .unwrap_err()
        .downcast::<DidKeyResolutionError>()
        .unwrap();

    assert!(matches!(
        *error,
        DidKeyResolutionError::InvalidPublicKeyType(ref value)
            if value == "Ed25519VerificationKey2020"
    ));
}

#[tokio::test]
async fn rejects_x25519_format_for_signing_identifier() {
    let options = DidKeyResolutionOptions {
        public_key_format: PublicKeyFormat::X25519KeyAgreementKey2020,
        ..Default::default()
    };
    let error = resolve(ED25519_DID, &options)
        .await
        .unwrap_err()
        .downcast::<DidKeyResolutionError>()
        .unwrap();

    assert!(matches!(
        *error,
        DidKeyResolutionError::InvalidPublicKeyType(ref value)
            if value == "X25519KeyAgreementKey2020"
    ));
}

#[tokio::test]
async fn rejects_non_key_method() {
    let error = resolve("did:example:123", &Default::default())
        .await
        .unwrap_err()
        .downcast::<DidKeyResolutionError>()
        .unwrap();
    assert!(
        matches!(*error, DidKeyResolutionError::MethodNotSupported(ref method) if method == "example")
    );
}

#[tokio::test]
async fn rejects_wrong_public_key_lengths() {
    for (prefix, length, key_type, expected) in [
        (&[0xed, 0x01][..], 31, KeyType::Ed25519, 32),
        (&[0xec, 0x01][..], 31, KeyType::X25519, 32),
        (&[0x80, 0x24][..], 32, KeyType::P256, 33),
        (&[0x81, 0x24][..], 48, KeyType::P384, 49),
    ] {
        let did = did_from_bytes(&[prefix, &vec![0; length]].concat());
        let error = resolve(&did, &Default::default())
            .await
            .unwrap_err()
            .downcast::<DidKeyResolutionError>()
            .unwrap();
        assert!(matches!(
            *error,
            DidKeyResolutionError::InvalidPublicKeyLength {
                key_type: actual_type,
                expected: actual_expected,
                actual
            } if actual_type == key_type && actual_expected == expected && actual == length
        ));
    }
}

#[tokio::test]
async fn rejects_invalid_ec_points_for_multikey_and_jwk() {
    for (prefix, length) in [(&[0x80, 0x24][..], 33), (&[0x81, 0x24][..], 49)] {
        let mut encoded_key = prefix.to_vec();
        encoded_key.push(0x02);
        encoded_key.extend(vec![0xff; length - 1]);
        let did = did_from_bytes(&encoded_key);

        for format in [PublicKeyFormat::Multikey, PublicKeyFormat::JsonWebKey2020] {
            let options = DidKeyResolutionOptions {
                public_key_format: format,
                ..Default::default()
            };
            let error = resolve(&did, &options)
                .await
                .unwrap_err()
                .downcast::<DidKeyResolutionError>()
                .unwrap();
            assert!(matches!(*error, DidKeyResolutionError::InvalidPublicKey(_)));
        }
    }
}

#[tokio::test]
async fn rejects_derivation_from_non_ed25519_keys() {
    let options = DidKeyResolutionOptions {
        enable_encryption_key_derivation: true,
        ..Default::default()
    };
    for (did, key_type) in [
        (X25519_DID, KeyType::X25519),
        (P256_DID, KeyType::P256),
        (P384_DID, KeyType::P384),
    ] {
        let error = resolve(did, &options)
            .await
            .unwrap_err()
            .downcast::<DidKeyResolutionError>()
            .unwrap();
        assert!(matches!(
            *error,
            DidKeyResolutionError::PublicKeyError(PublicKeyError::InvalidKeyType(
                actual,
                KeyType::Ed25519
            )) if actual == key_type
        ));
    }
}

#[tokio::test]
async fn rejects_ed25519_format_for_ec_keys() {
    let options = DidKeyResolutionOptions {
        public_key_format: PublicKeyFormat::Ed25519VerificationKey2020,
        ..Default::default()
    };
    for (did, key_type) in [(P256_DID, "P256"), (P384_DID, "P384")] {
        let error = resolve(did, &options)
            .await
            .unwrap_err()
            .downcast::<DidKeyResolutionError>()
            .unwrap();
        assert!(matches!(
            *error,
            DidKeyResolutionError::InvalidPublicKeyType(ref value)
                if value == &format!("Ed25519VerificationKey2020 for {key_type}")
        ));
    }
}

#[tokio::test]
async fn rejects_ed25519_verification_key_format_for_derived_x25519() {
    let options = DidKeyResolutionOptions {
        public_key_format: PublicKeyFormat::Ed25519VerificationKey2020,
        enable_encryption_key_derivation: true,
        ..Default::default()
    };
    let error = resolve(DERIVATION_DID, &options)
        .await
        .unwrap_err()
        .downcast::<DidKeyResolutionError>()
        .unwrap();
    assert!(matches!(
        *error,
        DidKeyResolutionError::InvalidPublicKeyType(ref value)
            if value == "Ed25519VerificationKey2020"
    ));
}
