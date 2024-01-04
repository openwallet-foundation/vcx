use agency_client::testing::mocking::AgencyMockDecrypted;
use aries_vcx_core::{global::settings::VERKEY, wallet::base_wallet::BaseWallet};
use did_doc::schema::{did_doc::DidDocument, types::uri::Uri};
use diddoc_legacy::aries::diddoc::AriesDidDoc;
use messages::{
    msg_fields::protocols::routing::{Forward, ForwardContent},
    AriesMessage,
};
use uuid::Uuid;

use crate::{
    errors::error::prelude::*,
    utils::didcomm_utils::{get_routing_keys, resolve_base58_key_agreement},
};

#[derive(Debug)]
pub struct EncryptionEnvelope(pub Vec<u8>);

impl EncryptionEnvelope {
    pub async fn create_from_legacy(
        wallet: &impl BaseWallet,
        data: &[u8],
        sender_vk: Option<&str>,
        did_doc: &AriesDidDoc,
    ) -> VcxResult<EncryptionEnvelope> {
        trace!(
            "EncryptionEnvelope::create >>> data: {:?}, sender_vk: {:?}, did_doc: {:?}",
            data,
            sender_vk,
            did_doc
        );

        let recipient_key =
            did_doc
                .recipient_keys()?
                .first()
                .cloned()
                .ok_or(AriesVcxError::from_msg(
                    AriesVcxErrorKind::InvalidState,
                    format!("No recipient key found in DIDDoc: {:?}", did_doc),
                ))?;
        let routing_keys = did_doc.routing_keys();
        Self::create_from_keys(wallet, data, sender_vk, recipient_key, routing_keys).await
    }

    /// Create encrypted message based on key agreement keys of our did document, counterparties
    /// did document and their specific service, identified by id, which must be part of their
    /// did document
    ///
    /// # Arguments
    ///
    /// * `our_did_doc` - Our did_document, which the counterparty should already be in possession
    ///   of
    /// * `their_did_doc` - The did document of the counterparty, the recipient of the encrypted
    ///   message
    /// * `their_service_id` - Id of service where message will be sent. The counterparty did
    ///   document must contain Service object identified with such value.
    pub async fn create(
        wallet: &impl BaseWallet,
        data: &[u8],
        our_did_doc: &DidDocument,
        their_did_doc: &DidDocument,
        their_service_id: &Uri,
    ) -> VcxResult<EncryptionEnvelope> {
        let sender_vk = resolve_base58_key_agreement(our_did_doc)?;
        let recipient_key = resolve_base58_key_agreement(their_did_doc)?;
        let routing_keys = get_routing_keys(their_did_doc, their_service_id)?;

        EncryptionEnvelope::create_from_keys(
            wallet,
            data,
            Some(&sender_vk.to_string()),
            recipient_key.to_string(),
            routing_keys.iter().map(|k| k.to_string()).collect(),
        )
        .await
    }

    pub async fn create_from_keys(
        wallet: &impl BaseWallet,
        data: &[u8],
        sender_vk: Option<&str>,
        recipient_key: String,
        routing_keys: Vec<String>,
    ) -> VcxResult<EncryptionEnvelope> {
        let message = EncryptionEnvelope::encrypt_for_pairwise(
            wallet,
            data,
            sender_vk,
            recipient_key.clone(),
        )
        .await?;
        EncryptionEnvelope::wrap_into_forward_messages(wallet, message, recipient_key, routing_keys)
            .await
            .map(EncryptionEnvelope)
    }

    async fn encrypt_for_pairwise(
        wallet: &impl BaseWallet,
        data: &[u8],
        sender_vk: Option<&str>,
        recipient_key: String,
    ) -> VcxResult<Vec<u8>> {
        debug!(
            "Encrypting for pairwise; sender_vk: {:?}, recipient_key: {}",
            sender_vk, recipient_key
        );
        let recipient_keys = json!([recipient_key.clone()]).to_string();
        wallet
            .pack_message(sender_vk, &recipient_keys, data)
            .await
            .map_err(|err| err.into())
    }

    async fn wrap_into_forward_messages(
        wallet: &impl BaseWallet,
        mut data: Vec<u8>,
        recipient_key: String,
        routing_keys: Vec<String>,
    ) -> VcxResult<Vec<u8>> {
        let mut forward_to_key = recipient_key;

        for routing_key in routing_keys.iter() {
            debug!(
                "Wrapping message in forward message; forward_to_key: {}, routing_key: {}",
                forward_to_key, routing_key
            );
            data =
                EncryptionEnvelope::wrap_into_forward(wallet, data, &forward_to_key, routing_key)
                    .await?;
            forward_to_key = routing_key.clone();
        }
        Ok(data)
    }

    async fn wrap_into_forward(
        wallet: &impl BaseWallet,
        data: Vec<u8>,
        forward_to_key: &str,
        routing_key: &str,
    ) -> VcxResult<Vec<u8>> {
        let content = ForwardContent::builder()
            .to(forward_to_key.to_string())
            .msg(serde_json::from_slice(&data)?)
            .build();

        let message: Forward = Forward::builder()
            .id(Uuid::new_v4().to_string())
            .content(content)
            .build();

        let message = json!(AriesMessage::from(message)).to_string();
        let receiver_keys = json!(vec![routing_key]).to_string();

        wallet
            .pack_message(None, &receiver_keys, message.as_bytes())
            .await
            .map_err(|err| err.into())
    }

    async fn _unpack_a2a_message(
        wallet: &impl BaseWallet,
        encrypted_data: Vec<u8>,
    ) -> VcxResult<(String, Option<String>)> {
        trace!(
            "EncryptionEnvelope::_unpack_a2a_message >>> processing payload of {} bytes",
            encrypted_data.len()
        );
        let unpacked_msg = wallet.unpack_message(&encrypted_data).await?;
        Ok((unpacked_msg.message, unpacked_msg.sender_verkey))
    }

    pub async fn anon_unpack_aries_msg(
        wallet: &impl BaseWallet,
        encrypted_data: Vec<u8>,
    ) -> VcxResult<(AriesMessage, Option<String>)> {
        let (message, sender_vk) = Self::anon_unpack(wallet, encrypted_data).await?;
        let a2a_message = serde_json::from_str(&message).map_err(|err| {
            AriesVcxError::from_msg(
                AriesVcxErrorKind::InvalidJson,
                format!("Cannot deserialize A2A message: {}", err),
            )
        })?;
        Ok((a2a_message, sender_vk))
    }

    pub async fn anon_unpack(
        wallet: &impl BaseWallet,
        encrypted_data: Vec<u8>,
    ) -> VcxResult<(String, Option<String>)> {
        trace!(
            "EncryptionEnvelope::anon_unpack >>> processing payload of {} bytes",
            encrypted_data.len()
        );
        let (message, sender_vk) = if AgencyMockDecrypted::has_decrypted_mock_messages() {
            trace!("EncryptionEnvelope::anon_unpack >>> returning decrypted mock message");
            (
                AgencyMockDecrypted::get_next_decrypted_message(),
                Some(VERKEY.to_string()),
            )
        } else {
            Self::_unpack_a2a_message(wallet, encrypted_data).await?
        };

        Ok((message, sender_vk))
    }

    pub async fn auth_unpack_aries_msg(
        wallet: &impl BaseWallet,
        encrypted_data: Vec<u8>,
        expected_vk: &str,
    ) -> VcxResult<AriesMessage> {
        let message = Self::auth_unpack(wallet, encrypted_data, expected_vk).await?;
        let a2a_message = serde_json::from_str(&message).map_err(|err| {
            AriesVcxError::from_msg(
                AriesVcxErrorKind::InvalidJson,
                format!("Cannot deserialize A2A message: {}", err),
            )
        })?;
        Ok(a2a_message)
    }

    pub async fn auth_unpack(
        wallet: &impl BaseWallet,
        encrypted_data: Vec<u8>,
        expected_vk: &str,
    ) -> VcxResult<String> {
        trace!(
            "EncryptionEnvelope::auth_unpack >>> processing payload of {} bytes, expected_vk: {}",
            encrypted_data.len(),
            expected_vk
        );

        let message = if AgencyMockDecrypted::has_decrypted_mock_messages() {
            trace!("EncryptionEnvelope::auth_unpack >>> returning decrypted mock message");
            AgencyMockDecrypted::get_next_decrypted_message()
        } else {
            let (a2a_message, sender_vk) =
                Self::_unpack_a2a_message(wallet, encrypted_data).await?;
            trace!(
                "anon_unpack >> a2a_msg: {:?}, sender_vk: {:?}",
                a2a_message,
                sender_vk
            );

            match sender_vk {
                Some(sender_vk) => {
                    if sender_vk != expected_vk {
                        error!(
                            "auth_unpack  sender_vk != expected_vk.... sender_vk: {}, \
                             expected_vk: {}",
                            sender_vk, expected_vk
                        );
                        return Err(AriesVcxError::from_msg(
                            AriesVcxErrorKind::AuthenticationError,
                            format!(
                                "Message did not pass authentication check. Expected sender \
                                 verkey was {}, but actually was {}",
                                expected_vk, sender_vk
                            ),
                        ));
                    }
                }
                None => {
                    error!("auth_unpack  message was authcrypted");
                    return Err(AriesVcxError::from_msg(
                        AriesVcxErrorKind::AuthenticationError,
                        "Can't authenticate message because it was anoncrypted.",
                    ));
                }
            }
            a2a_message
        };
        Ok(message)
    }
}

#[cfg(test)]
pub mod unit_tests {
    use serde_json::Value;
    use test_utils::devsetup::build_setup_profile;

    use super::*;

    #[tokio::test]
    async fn test_pack_unpack_anon() {
        let setup = build_setup_profile().await;
        let (_, recipient_key) = setup
            .wallet
            .create_and_store_my_did(None, None)
            .await
            .unwrap();

        let data_original = "foobar";

        let envelope = EncryptionEnvelope::create_from_keys(
            &setup.wallet,
            data_original.as_bytes(),
            None,
            recipient_key,
            [].to_vec(),
        )
        .await
        .unwrap();

        let (data_unpacked, sender_verkey) =
            EncryptionEnvelope::anon_unpack(&setup.wallet, envelope.0)
                .await
                .unwrap();

        assert_eq!(data_original, data_unpacked);
        assert!(sender_verkey.is_none());
    }

    #[tokio::test]
    async fn test_pack_unpack_auth() {
        let setup = build_setup_profile().await;
        let (_, sender_key) = setup
            .wallet
            .create_and_store_my_did(None, None)
            .await
            .unwrap();
        let (_, recipient_key) = setup
            .wallet
            .create_and_store_my_did(None, None)
            .await
            .unwrap();

        let data_original = "foobar";

        let envelope = EncryptionEnvelope::create_from_keys(
            &setup.wallet,
            data_original.as_bytes(),
            Some(&sender_key),
            recipient_key,
            [].to_vec(),
        )
        .await
        .unwrap();

        let data_unpacked = EncryptionEnvelope::auth_unpack(&setup.wallet, envelope.0, &sender_key)
            .await
            .unwrap();

        assert_eq!(data_original, data_unpacked);
    }

    #[tokio::test]
    async fn test_pack_unpack_with_routing() {
        let setup = build_setup_profile().await;
        let (_, sender_key) = setup
            .wallet
            .create_and_store_my_did(None, None)
            .await
            .unwrap();
        let (_, recipient_key) = setup
            .wallet
            .create_and_store_my_did(None, None)
            .await
            .unwrap();
        let (_, routing_key1) = setup
            .wallet
            .create_and_store_my_did(None, None)
            .await
            .unwrap();

        let data_original = "foobar";

        let envelope = EncryptionEnvelope::create_from_keys(
            &setup.wallet,
            data_original.as_bytes(),
            Some(&sender_key),
            recipient_key,
            [routing_key1].to_vec(),
        )
        .await
        .unwrap();

        let (fwd_msg, _) = EncryptionEnvelope::anon_unpack(&setup.wallet, envelope.0)
            .await
            .unwrap();
        let fwd_payload = serde_json::from_str::<Value>(&fwd_msg)
            .unwrap()
            .get("msg")
            .unwrap()
            .to_string();
        let (core_payload, _) = EncryptionEnvelope::anon_unpack(&setup.wallet, fwd_payload.into())
            .await
            .unwrap();

        assert_eq!(data_original, core_payload);
    }

    #[tokio::test]
    async fn test_pack_unpack_unexpected_key_detection() {
        let setup = build_setup_profile().await;
        let (_, sender_key_alice) = setup
            .wallet
            .create_and_store_my_did(None, None)
            .await
            .unwrap();
        let (_, sender_key_bob) = setup
            .wallet
            .create_and_store_my_did(None, None)
            .await
            .unwrap();
        let (_, recipient_key) = setup
            .wallet
            .create_and_store_my_did(None, None)
            .await
            .unwrap();

        let data_original = "foobar";

        let envelope = EncryptionEnvelope::create_from_keys(
            &setup.wallet,
            data_original.as_bytes(),
            Some(&sender_key_bob), // bob trying to impersonate alice
            recipient_key,
            [].to_vec(),
        )
        .await
        .unwrap();

        let err =
            EncryptionEnvelope::auth_unpack(&setup.wallet, envelope.0, &sender_key_alice).await;
        assert!(err.is_err());
        assert_eq!(
            err.unwrap_err().kind(),
            AriesVcxErrorKind::AuthenticationError
        );
    }
}
