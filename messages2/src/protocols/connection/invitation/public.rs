use serde::{Deserialize, Serialize};

use crate::Message;

pub type PublicInvitation = Message<PublicInvitationContent>;

/// Represents a public invitation.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct PublicInvitationContent {
    pub label: String,
    pub did: String,
}

impl PublicInvitationContent {
    pub fn new(label: String, did: String) -> Self {
        Self { label, did }
    }
}
