use axum::{debug_handler, extract::State, routing::post, Json, Router};
use raiko_core::{interfaces::ProofRequest, provider::get_task_data};
use raiko_tasks::{ProofTaskDescriptor, TaskManager, TaskStatus};
use serde_json::Value;
use utoipa::OpenApi;

use crate::{
    interfaces::HostResult,
    server::api::{
        util::{ensure_not_paused, ensure_proof_request_image_id},
        v2::CancelStatus,
    },
    Message, ProverState,
};

#[utoipa::path(post, path = "/proof/cancel",
    tag = "Proving",
    request_body = ProofRequestOpt,
    responses (
        (status = 200, description = "Successfully cancelled proof task", body = CancelStatus)
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
) -> HostResult<CancelStatus> {
    // Override the existing proof request config from the config file and command line
    // options with the request from the client.
    let mut config = prover_state.request_config();
    config.merge(&req)?;

    ensure_not_paused(&prover_state)?;
    ensure_proof_request_image_id(&mut config)?;

    // Construct the actual proof request from the available configs.
    let proof_request = ProofRequest::try_from(config)?;

    let (chain_id, block_hash) = get_task_data(
        &proof_request.network,
        proof_request.block_number,
        &prover_state.chain_specs,
    )
    .await?;

    let key = ProofTaskDescriptor::new(
        chain_id,
        proof_request.block_number,
        block_hash,
        proof_request.proof_type,
        proof_request.prover.to_string(),
        proof_request.image_id.clone(),
    );

    prover_state
        .task_channel
        .try_send(Message::Cancel(key.clone()))?;

    let mut manager = prover_state.task_manager();

    manager
        .update_task_progress(key, TaskStatus::Cancelled, None)
        .await?;

    Ok(CancelStatus::Ok)
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
