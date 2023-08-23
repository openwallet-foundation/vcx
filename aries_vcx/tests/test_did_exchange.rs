#[macro_use]
extern crate log;
mod fixtures;
mod utils;

use std::sync::Arc;

use aries_vcx::protocols::did_exchange::resolve_key_from_invitation;
use aries_vcx::protocols::did_exchange::state_machine::requester::{
    ConstructRequestConfig, DidExchangeRequester, PairwiseConstructRequestConfig,
};
use aries_vcx::protocols::did_exchange::state_machine::responder::{DidExchangeResponder, ReceiveRequestConfig};
use aries_vcx::protocols::did_exchange::states::requester::request_sent::RequestSent;
use aries_vcx::protocols::did_exchange::states::responder::response_sent::ResponseSent;
use aries_vcx::protocols::did_exchange::transition::transition_result::TransitionResult;
use aries_vcx::utils::devsetup::SetupPoolDirectory;
use did_doc::schema::verification_method::{PublicKeyField, VerificationMethodType};
use did_doc_sov::extra_fields::didcommv2::ExtraFieldsDidCommV2;
use did_doc_sov::service::didcommv2::ServiceDidCommV2;
use did_doc_sov::service::ServiceSov;
use did_peer::peer_did_resolver::resolver::PeerDidResolver;
use did_resolver_registry::ResolverRegistry;
use messages::msg_fields::protocols::out_of_band::invitation::Invitation;
use url::Url;

use crate::utils::devsetup_alice::create_alice;
use crate::utils::devsetup_faber::create_faber;

#[tokio::test]
async fn did_exchange_test() {
    SetupPoolDirectory::run(|setup| async move {
        let institution = create_faber(setup.genesis_file_path.clone()).await;
        let consumer = create_alice(setup.genesis_file_path).await;

        let did_peer_resolver = PeerDidResolver::new();
        let resolver_registry = Arc::new(
            ResolverRegistry::new().register_resolver::<PeerDidResolver>("peer".into(), did_peer_resolver.into()),
        );

        let url: Url = "http://dummyurl.org".parse().unwrap();
        // TODO: Create invite manually
        let invitation: Invitation = serde_json::from_str(fixtures::OOB_INVITE).unwrap();
        let invitation_id = invitation.id.clone();
        let invitation_key = resolve_key_from_invitation(&invitation, &resolver_registry)
            .await
            .unwrap();

        let TransitionResult {
            state: requester,
            output: request,
        } = DidExchangeRequester::<RequestSent>::construct_request(ConstructRequestConfig::Pairwise(
            PairwiseConstructRequestConfig {
                wallet: consumer.profile.inject_wallet(),
                invitation,
                service_endpoint: url.clone(),
                routing_keys: vec![],
                resolver_registry: resolver_registry.clone(),
            },
        ))
        .await
        .unwrap();

        let extra = ExtraFieldsDidCommV2::builder().build();
        let service =
            ServiceSov::DIDCommV2(ServiceDidCommV2::new(Default::default(), url.clone().into(), extra).unwrap());
        let TransitionResult {
            state: responder,
            output: response,
        } = DidExchangeResponder::<ResponseSent>::receive_request(ReceiveRequestConfig {
            wallet: institution.profile.inject_wallet(),
            resolver_registry,
            request,
            service_endpoint: url.clone(),
            routing_keys: vec![],
            invitation_id,
            invitation_key,
        })
        .await
        .unwrap();

        let TransitionResult {
            state: requester,
            output: complete,
        } = requester.receive_response(response).await.unwrap();

        let responder = responder.receive_complete(complete).unwrap();

        let responder_key = responder
            .our_did_doc()
            .verification_method()
            .first()
            .unwrap()
            .public_key()
            .unwrap()
            .base58();
        assert_eq!(
            requester
                .their_did_doc()
                .verification_method()
                .first()
                .unwrap()
                .public_key()
                .unwrap()
                .base58(),
            responder_key
        );

        let requester_key = requester
            .our_did_doc()
            .verification_method()
            .first()
            .unwrap()
            .public_key()
            .unwrap()
            .base58();
        assert_eq!(
            responder
                .their_did_doc()
                .verification_method()
                .first()
                .unwrap()
                .public_key()
                .unwrap()
                .base58(),
            requester_key
        );
    })
    .await;
}
