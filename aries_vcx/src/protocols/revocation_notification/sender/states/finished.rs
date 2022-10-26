use messages::issuance::{revocation_notification::RevocationNotification, revocation_ack::RevocationAck};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct FinishedState {
    rev_msg: RevocationNotification,
    ack: Option<RevocationAck>
}

impl FinishedState {
    pub fn new(rev_msg: RevocationNotification, ack: Option<RevocationAck>) -> Self {
        Self { rev_msg, ack }
    }

    pub fn get_notification(&self) -> RevocationNotification {
        self.rev_msg.clone()
    }

    pub fn get_thread_id(&self) -> String {
        self.rev_msg.get_thread_id()
    }
}
