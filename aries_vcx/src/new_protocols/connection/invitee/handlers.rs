use std::sync::Arc;

use aries_vcx_core::{ledger::base_ledger::IndyLedgerRead, wallet::base_wallet::BaseWallet};
use chrono::Utc;
use diddoc_legacy::aries::diddoc::AriesDidDoc;
use messages::{
    decorators::{thread::Thread, timing::Timing},
    msg_fields::protocols::connection::{
        invitation::Invitation,
        request::{Request, RequestDecorators},
        ConnectionData,
    },
};
use url::Url;
use uuid::Uuid;

use crate::{
    common::ledger::transactions::get_service,
    errors::error::VcxResult,
    new_protocols::{connection::ConnectionSM, AriesSM, StateMachineStorage},
};

use super::{state::BootstrapInfo, InviteeConnection};

/// This is here as we only process a connection invitation.
/// An OOB invitation should be resolved to a connection invitation (or maybe both should get resolved
/// to some common type) instead of just being passed and processed here.
///
/// Nevertheless, this uses some pretty bad legacy API so the proper implementation
/// should rebuild this from the ground up.
//
// TODO: Make this prettier
async fn did_doc_from_invitation(ledger: &Arc<dyn IndyLedgerRead>, invitation: Invitation) -> VcxResult<BootstrapInfo> {
    let (service_endpoint, recipient_keys, routing_keys, did, service_endpoint_did) = match invitation {
        Invitation::Public(invitation) => {
            let service = match get_service(ledger, &invitation.content.did).await {
                Ok(s) => s,
                Err(err) => {
                    error!("Failed to obtain service definition from the ledger: {}", err);
                    return Err(err);
                }
            };

            (
                service.service_endpoint,
                service.recipient_keys,
                service.routing_keys,
                Some(invitation.content.did),
                None,
            )
        }
        Invitation::Pairwise(invitation) => (
            invitation.content.service_endpoint,
            invitation.content.recipient_keys,
            invitation.content.routing_keys,
            None,
            None,
        ),
        Invitation::PairwiseDID(mut invitation) => {
            let service = match get_service(ledger, &invitation.content.service_endpoint).await {
                Ok(s) => s,
                Err(err) => {
                    error!("Failed to obtain service definition from the ledger: {}", err);
                    return Err(err);
                }
            };

            // See https://github.com/hyperledger/aries-rfcs/blob/main/features/0160-connection-protocol/README.md#agency-endpoint
            invitation.content.routing_keys.extend(service.recipient_keys);

            (
                service.service_endpoint,
                invitation.content.recipient_keys,
                invitation.content.routing_keys,
                None,
                Some(invitation.content.service_endpoint),
            )
        }
    };

    let bootstrap_info = BootstrapInfo {
        service_endpoint,
        recipient_keys,
        routing_keys,
        did,
        service_endpoint_did,
    };

    Ok(bootstrap_info)
}

// TODO: This won't accept this many args in its final version
// and should process the invitation in a better way
pub async fn accept_invitation<S, W>(
    sm_storage: S,
    id_params: S::ResolveIdParams<'_>,
    invitation: Invitation,
    service_endpoint: Url,
    routing_keys: Vec<String>,
    label: String,
    ledger: &Arc<dyn IndyLedgerRead>,
    wallet: &W,
) -> VcxResult<Request>
where
    S: StateMachineStorage,
    W: BaseWallet,
{
    let sm_id = sm_storage.resolve_id(id_params).await?;
    let msg_id = Uuid::new_v4().to_string();

    let thread = match &invitation {
        Invitation::Public(i) => {
            let mut thread = Thread::new(msg_id.clone());
            thread.pthid = Some(i.id.clone());
            thread
        }
        Invitation::Pairwise(i) => Thread::new(i.id.clone()),
        Invitation::PairwiseDID(i) => Thread::new(i.id.clone()),
    };

    let bootstrap_info = did_doc_from_invitation(ledger, invitation).await?;
    let (did, verkey) = wallet.create_and_store_my_did(None, None).await?;

    let recipient_keys = vec![verkey.clone()];

    let mut did_doc = AriesDidDoc::default();
    did_doc.id = did.clone();
    did_doc.set_service_endpoint(service_endpoint);
    did_doc.set_routing_keys(routing_keys);
    did_doc.set_recipient_keys(recipient_keys);

    let con_data = ConnectionData::new(did.clone(), did_doc);

    let (sm, content) = InviteeConnection::new_invitee(did, verkey, label, bootstrap_info, con_data);

    let timing = Timing {
        out_time: Some(Utc::now()),
        ..Default::default()
    };

    let decorators = RequestDecorators {
        thread: Some(thread),
        timing: Some(timing),
    };

    let request = Request::with_decorators(msg_id, content, decorators);
    let sm = AriesSM::Connection(ConnectionSM::InviteeRequested(sm));
    sm_storage.put_different_state(sm_id, sm).await?;

    Ok(request)
}
