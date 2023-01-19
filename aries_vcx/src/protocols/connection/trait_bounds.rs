use messages::diddoc::aries::diddoc::AriesDidDoc;

/// Trait used for implementing common [`super::Connection`] behavior based
/// on states implementing it.
pub trait TheirDidDoc {
    fn their_did_doc(&self) -> &AriesDidDoc;
}