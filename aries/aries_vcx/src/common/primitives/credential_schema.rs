use std::sync::Arc;

use anoncreds_types::data_types::{
    identifiers::schema_id::SchemaId, ledger::schema::Schema as LedgerSchema,
};
use aries_vcx_core::{
    anoncreds::base_anoncreds::BaseAnonCreds,
    global::settings::DEFAULT_SERIALIZE_VERSION,
    ledger::base_ledger::{AnoncredsLedgerRead, AnoncredsLedgerWrite},
    wallet::base_wallet::BaseWallet,
};
use did_parser::Did;

use super::credential_definition::PublicEntityStateType;
use crate::{
    errors::error::{AriesVcxError, AriesVcxErrorKind, VcxResult},
    utils::serialization::ObjectWithVersion,
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SchemaData {
    pub name: String,
    pub version: String,
    #[serde(rename = "attrNames")]
    pub attr_names: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Schema {
    pub data: Vec<String>,
    pub version: String,
    pub schema_id: SchemaId,
    pub name: String,
    pub source_id: String,
    #[serde(default)]
    submitter_did: Did,
    #[serde(default)]
    pub state: PublicEntityStateType,
    pub schema_json: LedgerSchema,
}

impl Schema {
    pub async fn create(
        anoncreds: &impl BaseAnonCreds,
        source_id: &str,
        submitter_did: &Did,
        name: &str,
        version: &str,
        data: &Vec<String>,
    ) -> VcxResult<Self> {
        trace!(
            "Schema::create >>> submitter_did: {}, name: {}, version: {}, data: {:?}",
            submitter_did,
            name,
            version,
            data
        );

        let data_str = serde_json::to_string(data).map_err(|err| {
            AriesVcxError::from_msg(
                AriesVcxErrorKind::SerializationError,
                format!("Failed to serialize schema attributes, err: {}", err),
            )
        })?;

        let schema_json = anoncreds
            .issuer_create_schema(submitter_did, name, version, &data_str)
            .await?;

        Ok(Self {
            source_id: source_id.to_string(),
            name: name.to_string(),
            data: data.clone(),
            version: version.to_string(),
            schema_id: schema_json.id.clone(),
            submitter_did: submitter_did.to_owned(),
            schema_json,
            state: PublicEntityStateType::Built,
        })
    }

    pub async fn submitter_did(&self) -> String {
        self.submitter_did.to_string()
    }

    pub async fn publish(
        self,
        wallet: &impl BaseWallet,
        ledger: &impl AnoncredsLedgerWrite,
    ) -> VcxResult<Self> {
        trace!("Schema::publish >>>");

        ledger
            .publish_schema(wallet, self.schema_json.clone(), &self.submitter_did, None)
            .await?;

        Ok(Self {
            state: PublicEntityStateType::Published,
            ..self
        })
    }

    pub fn get_source_id(&self) -> String {
        self.source_id.clone()
    }

    pub fn get_schema_id(&self) -> String {
        self.schema_id.to_string()
    }

    pub fn to_string_versioned(&self) -> VcxResult<String> {
        ObjectWithVersion::new(DEFAULT_SERIALIZE_VERSION, self.to_owned())
            .serialize()
            .map_err(|err: AriesVcxError| err.extend("Cannot serialize Schema"))
    }

    pub fn from_string_versioned(data: &str) -> VcxResult<Schema> {
        ObjectWithVersion::deserialize(data)
            .map(|obj: ObjectWithVersion<Schema>| obj.data)
            .map_err(|err: AriesVcxError| err.extend("Cannot deserialize Schema"))
    }

    pub async fn update_state(&mut self, ledger: &impl AnoncredsLedgerRead) -> VcxResult<u32> {
        if ledger.get_schema(&self.schema_id, None).await.is_ok() {
            self.state = PublicEntityStateType::Published
        }
        Ok(self.state as u32)
    }

    pub async fn get_schema_json(
        &self,
        ledger: &Arc<dyn AnoncredsLedgerRead>,
    ) -> VcxResult<String> {
        // TODO: This has different behavior than the original code
        Ok(serde_json::to_string(&self.schema_json)?)
    }

    pub fn get_state(&self) -> u32 {
        self.state as u32
    }
}

#[cfg(test)]
mod tests {
    use test_utils::constants::{schema_id, DID, SCHEMA_ID, SCHEMA_JSON};

    use super::*;

    #[test]
    fn test_to_string_versioned() {
        let schema = Schema {
            data: vec!["name".to_string(), "age".to_string()],
            version: "1.0".to_string(),
            schema_id: schema_id(),
            name: "test".to_string(),
            source_id: "1".to_string(),
            submitter_did: DID.to_string().parse().unwrap(),
            state: PublicEntityStateType::Built,
            schema_json: serde_json::from_str(SCHEMA_JSON).unwrap(),
        };
        let serialized = schema.to_string_versioned().unwrap();
        assert!(serialized.contains(r#""version":"1.0""#));
        assert!(serialized.contains(r#""name":"test""#));
        assert!(serialized.contains(r#""schema_id":""#));
        assert!(serialized.contains(r#""source_id":"1""#));
        assert!(serialized.contains(r#""data":["name","age"]"#));
    }

    #[test]
    fn test_from_string_versioned() {
        let serialized = json!({
        "version": "1.0",
        "data": {
          "data": [
            "name",
            "age"
          ],
          "version": "1.0",
          "schema_id": "test_schema_id",
          "name": "test",
          "source_id": "1",
          "submitter_did": DID,
          "state": 1,
          "schema_json": serde_json::from_str::<LedgerSchema>(SCHEMA_JSON).unwrap()
        }})
        .to_string();
        let schema = Schema::from_string_versioned(&serialized).unwrap();
        assert_eq!(schema.version, "1.0");
        assert_eq!(schema.data, vec!["name".to_string(), "age".to_string()]);
        assert_eq!(schema.schema_id, SchemaId::new("test_schema_id").unwrap());
        assert_eq!(schema.name, "test");
        assert_eq!(schema.source_id, "1");
        assert_eq!(schema.state, PublicEntityStateType::Published);
    }

    #[test]
    fn test_get_schema_id() {
        let schema = Schema {
            data: vec!["name".to_string(), "age".to_string()],
            version: "1.0".to_string(),
            schema_id: schema_id(),
            name: "test".to_string(),
            source_id: "1".to_string(),
            submitter_did: DID.to_string().parse().unwrap(),
            state: PublicEntityStateType::Built,
            schema_json: serde_json::from_str(SCHEMA_JSON).unwrap(),
        };
        assert_eq!(schema.get_schema_id(), SCHEMA_ID);
    }
}
