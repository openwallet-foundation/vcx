use thiserror::Error;

#[derive(Debug, Error)]
pub enum DidKeyResolutionError {
    #[error("DID key error: {0}")]
    DidKeyError(#[from] did_key::error::DidKeyError),
    #[error("DID parser error: {0}")]
    DidParserError(#[from] did_parser_nom::ParseError),
    #[error("Invalid DID")]
    InvalidDid,
    #[error("Invalid {key_type} public key length: expected {expected}, got {actual}")]
    InvalidPublicKeyLength {
        key_type: public_key::KeyType,
        expected: usize,
        actual: usize,
    },
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(#[source] public_key::PublicKeyError),
    #[error("Invalid public key type: {0}")]
    InvalidPublicKeyType(String),
    #[error("JSON Web Key error: {0}")]
    JsonWebKeyError(#[from] did_doc::schema::types::jsonwebkey::JsonWebKeyError),
    #[error("DID method not supported: {0}")]
    MethodNotSupported(String),
    #[error("Public key error: {0}")]
    PublicKeyError(#[from] public_key::PublicKeyError),
    #[error("Unsupported did:key key type: {0}")]
    UnsupportedKeyType(public_key::KeyType),
}
