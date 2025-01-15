mod action;
mod actor;
mod backend;

use raiko_core::interfaces::ProofRequestOpt;
use raiko_lib::consts::SupportedChainSpecs;
use tokio::sync::{mpsc, oneshot};

pub(crate) use backend::Backend;

// re-export
pub use action::Action;
pub use actor::Actor;
pub use raiko_reqpool::{
    AggregationRequestEntity, AggregationRequestKey, Pool, RequestEntity, RequestKey,
    SingleProofRequestEntity, SingleProofRequestKey, StatusWithContext,
};

/// Run the actor backend in background, and return the actor.
pub async fn start_actor(
    pool: Pool,
    chain_specs: SupportedChainSpecs,
    default_request_config: ProofRequestOpt,
    max_proving_concurrency: usize,
) -> Actor {
    let channel_size = 1024;
    let (action_tx, action_rx) =
        mpsc::channel::<(Action, oneshot::Sender<Result<StatusWithContext, String>>)>(channel_size);
    let (pause_tx, pause_rx) = mpsc::channel::<()>(1);

    Backend::serve_in_background(
        pool.clone(),
        chain_specs.clone(),
        pause_rx,
        action_rx,
        max_proving_concurrency,
    )
    .await;

    Actor::new(
        pool,
        default_request_config,
        chain_specs.clone(),
        action_tx,
        pause_tx,
    )
}
