use std::sync::Arc;

use crate::errors::error::VcxResult;
use aries_vcx_core::wallet::base_wallet::BaseWallet;
use chrono::Utc;
use did_doc::schema::did_doc::DidDocument;
use did_resolver_sov::resolution::ExtraFieldsSov;
use messages::decorators::thread::Thread;
use messages::decorators::timing::Timing;
use messages::msg_fields::protocols::discover_features::disclose::{Disclose, DiscloseContent, DiscloseDecorators};
use messages::msg_fields::protocols::discover_features::query::{Query, QueryContent, QueryDecorators};
use messages::msg_fields::protocols::discover_features::ProtocolDescriptor;
use uuid::Uuid;

use crate::utils::send_message;

pub async fn send_discovery_query(
    wallet: &Arc<dyn BaseWallet>,
    query: Option<String>,
    comment: Option<String>,
    did_doc: &DidDocument<ExtraFieldsSov>,
    pw_vk: &str,
) -> VcxResult<()> {
    let query = query.unwrap_or("*".to_owned());
    let mut content = QueryContent::new(query);
    content.comment = comment;

    let mut decorators = QueryDecorators::default();
    let mut timing = Timing::default();
    timing.out_time = Some(Utc::now());
    decorators.timing = Some(timing);

    let query = Query::with_decorators(Uuid::new_v4().to_string(), content, decorators);

    send_message(
        Arc::clone(wallet),
        pw_vk.to_string(),
        did_doc.clone().into(),
        query.into(),
    )
    .await
}

pub async fn respond_discovery_query(
    wallet: &Arc<dyn BaseWallet>,
    query: Query,
    did_doc: &DidDocument<ExtraFieldsSov>,
    pw_vk: &str,
    _supported_protocols: Vec<ProtocolDescriptor>,
) -> VcxResult<()> {
    let content = DiscloseContent::default();

    let mut decorators = DiscloseDecorators::new(Thread::new(query.id));
    let mut timing = Timing::default();
    timing.out_time = Some(Utc::now());
    decorators.timing = Some(timing);

    let disclose = Disclose::with_decorators(Uuid::new_v4().to_string(), content, decorators);

    send_message(
        Arc::clone(wallet),
        pw_vk.to_string(),
        did_doc.clone().into(),
        disclose.into(),
    )
    .await
}
