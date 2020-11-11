use mocking::AgencyMockDecrypted;
use utils::error::prelude::*;
use utils::libindy::crypto;

#[derive(Debug)]
pub struct EncryptionEnvelope(pub Vec<u8>);

impl EncryptionEnvelope {
    fn _unpack_a2a_message(payload: Vec<u8>) -> VcxResult<(String, Option<String>)> {
        trace!("EncryptionEnvelope::_unpack_a2a_message >>> processing payload of {} bytes", payload.len());

        let unpacked_msg = crypto::unpack_message(&payload)?;

        let msg_value: ::serde_json::Value = ::serde_json::from_slice(unpacked_msg.as_slice())
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize message: {}", err)))?;

        let sender_vk = msg_value["sender_verkey"].as_str().map(String::from);

        let msg_string = msg_value["message"].as_str()
            .ok_or(VcxError::from_msg(VcxErrorKind::InvalidJson, "Cannot find `message` field"))?.to_string();

        Ok((msg_string, sender_vk))
    }

    // todo: we should use auth_unpack wherever possible
    pub fn anon_unpack(payload: Vec<u8>) -> VcxResult<String> {
        trace!("EncryptionEnvelope::anon_unpack >>> processing payload of {} bytes", payload.len());
        let message = if AgencyMockDecrypted::has_decrypted_mock_messages() {
            trace!("EncryptionEnvelope::anon_unpack >>> returning decrypted mock message");
            AgencyMockDecrypted::get_next_decrypted_message()
        } else {
            let (a2a_message, _sender_vk) = Self::_unpack_a2a_message(payload)?;
            a2a_message
        };
        let a2a_message = ::serde_json::from_str(&message)
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize A2A message: {}", err)))?;
        Ok(json!(&a2a_message).to_string())
    }

    pub fn auth_unpack(payload: Vec<u8>, expected_vk: &str) -> VcxResult<String> {
        trace!("EncryptionEnvelope::auth_unpack >>> processing payload of {} bytes, expected_vk={}", payload.len(), expected_vk);

        let message = if AgencyMockDecrypted::has_decrypted_mock_messages() {
            trace!("EncryptionEnvelope::auth_unpack >>> returning decrypted mock message");
            AgencyMockDecrypted::get_next_decrypted_message()
        } else {
            let (a2a_message, sender_vk) = Self::_unpack_a2a_message(payload)?;

            match sender_vk {
                Some(sender_vk) => {
                    if sender_vk != expected_vk {
                        error!("auth_unpack :: sender_vk != expected_vk.... sender_vk={}, expected_vk={}", sender_vk, expected_vk);
                        return Err(VcxError::from_msg(VcxErrorKind::InvalidJson,
                                                      format!("Message did not pass authentication check. Expected sender verkey was {}, but actually was {}", expected_vk, sender_vk))
                        );
                    }
                }
                None => {
                    error!("auth_unpack :: message was authcrypted");
                    return Err(VcxError::from_msg(VcxErrorKind::InvalidJson, "Can't authenticate message because it was anoncrypted."));
                }
            }
            a2a_message
        };
        let a2a_message = ::serde_json::from_str(&message)
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize A2A message: {}", err)))?;
        Ok(json!(&a2a_message).to_string())
    }
}
