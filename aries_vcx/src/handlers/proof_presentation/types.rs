use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct RetrievedCredentials {
    #[serde(rename = "attrs", skip_serializing_if = "HashMap::is_empty")]
    pub credentials_by_referent: HashMap<String, Vec<RetrievedCredentialForReferent>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct RetrievedCredentialForReferent {
    pub cred_info: CredentialInfo,
    #[serde(rename = "non_revoc_interval")]
    pub non_revoked_interval: NonRevokedInterval,
}

// NOTE: this could probably be moved to a more common location
// since anoncreds APIs will probably use it.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct CredentialInfo {
    pub referent: String,
    #[serde(rename = "attrs")]
    pub attributes: HashMap<String, String>,
    pub schema_id: String,
    pub cred_def_id: String,
    pub rev_reg_id: Option<String>,
    pub cred_rev_id: Option<String>,
}

// TODO: this could probably be moved to a more common location.
// It is currently defined in `proof_request_internal`, but it feels wrong
// to have a type from an `..._internal` file.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct NonRevokedInterval {
    pub from: Option<u64>,
    pub to: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SelectedCredentials {
    #[serde(rename = "attrs")]
    pub credential_for_referent: HashMap<String, Vec<SelectedCredentialForReferent>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SelectedCredentialForReferent {
    pub credential: SelectedCredentialForReferentCredential, // TODO - smelly struct name
    #[serde(rename = "tails_file")] // our APIs expect a tails_dir, but the legacy API calls it tails_file
    pub tails_dir: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SelectedCredentialForReferentCredential {
    pub cred_info: SelectedCredentialInfo,
}

// TODO - smelly.. this type is very similar to CredentialInfo above,
// with the exception of `revealed` field being added and `attrs` field being removed
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SelectedCredentialInfo {
    pub referent: String,
    pub schema_id: String,
    pub cred_def_id: String,
    pub rev_reg_id: Option<String>,
    pub cred_rev_id: Option<String>,
    pub revealed: Option<bool>,
}
