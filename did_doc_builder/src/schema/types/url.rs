use serde::{Deserialize, Serialize};
use url::Url as UrlDep;

use crate::error::DIDDocumentBuilderError;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Url(UrlDep);

impl Url {
    pub fn new(url: &str) -> Result<Self, DIDDocumentBuilderError> {
        Ok(Self(UrlDep::parse(url)?))
    }
}

impl TryFrom<&str> for Url {
    type Error = DIDDocumentBuilderError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self(UrlDep::parse(value)?))
    }
}

impl AsRef<str> for Url {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}
