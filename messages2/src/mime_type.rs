use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mime-type")]
pub enum MimeType {
    #[serde(rename = "application/json")]
    Json,
    #[serde(rename = "image/jpg")]
    Jpg,
    #[serde(rename = "image/jpeg")]
    Jpeg,
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "application/pdf")]
    Pdf,
    #[serde(rename = "text/plain")]
    Plain,
}