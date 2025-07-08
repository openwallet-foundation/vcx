use display_json::DisplayAsJson;
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default, DisplayAsJson, TypedBuilder)]
#[serde(deny_unknown_fields)]
pub struct ExtraFieldsAIP1 {}
