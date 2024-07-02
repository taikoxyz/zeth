use axum::{debug_handler, extract::State, routing::post, Json, Router};
use raiko_core::interfaces::ProofRequest;
use raiko_core::provider::get_task_data;
use raiko_task_manager::{get_task_manager, EnqueueTaskParams, TaskManager, TaskStatus};
use serde_json::Value;
use tracing::info;
use utoipa::OpenApi;

use crate::{
    interfaces::HostResult,
    metrics::{inc_current_req, inc_guest_req_count, inc_host_req_count},
    server::api::v1::ProofResponse,
    ProverState,
};

#[utoipa::path(post, path = "/proof/cancel",
    tag = "Proving",
    request_body = ProofRequestOpt,
    responses (
        (status = 200, description = "Successfully cancelled proof task", body = Status)
    )
)]
#[debug_handler(state = ProverState)]
/// Cancel a proof task with requested config.
///
/// Accepts a proof request and cancels a proving task with the specified guest prover.
/// The guest provers currently available are:
/// - native - constructs a block and checks for equality
/// - sgx - uses the sgx environment to construct a block and produce proof of execution
/// - sp1 - uses the sp1 prover
/// - risc0 - uses the risc0 prover
async fn cancel_handler(
    State(prover_state): State<ProverState>,
    Json(req): Json<Value>,
) -> HostResult<Json<Value>> {
    // Override the existing proof request config from the config file and command line
    // options with the request from the client.
    let mut config = prover_state.opts.proof_request_opt.clone();
    config.merge(&req)?;

    // Construct the actual proof request from the available configs.
    let proof_request = ProofRequest::try_from(config)?;

    let (chain_id, block_hash) = get_task_data(
        &proof_request.network,
        proof_request.block_number,
        &prover_state.chain_specs,
    )
    .await?;

    let mut manager = get_task_manager(&(&prover_state.opts).into());

    manager
        .update_task_progress(
            chain_id,
            block_hash,
            proof_request.proof_type,
            proof_request.prover,
            TaskStatus::Cancelled,
            None,
        )
        .await?;

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

#[derive(OpenApi)]
#[openapi(paths(cancel_handler))]
struct Docs;

pub fn create_docs() -> utoipa::openapi::OpenApi {
    Docs::openapi()
}

pub fn create_router() -> Router<ProverState> {
    Router::new().route("/", post(cancel_handler))
}
