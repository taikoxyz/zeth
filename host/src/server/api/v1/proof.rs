use axum::{debug_handler, extract::State, routing::post, Json, Router};
use raiko_core::interfaces::ProofRequest;
use serde_json::Value;
use utoipa::OpenApi;

use crate::{
    interfaces::HostResult,
    metrics::{dec_current_req, inc_current_req, inc_guest_req_count, inc_host_req_count},
    proof::handle_proof,
    server::api::{
        util::{ensure_not_paused, ensure_proof_request_image_id},
        v1::Status,
    },
    ProverState,
};

use super::ProofResponse;

#[utoipa::path(post, path = "/proof",
    tag = "Proving",
    request_body = ProofRequestOpt,
    responses (
        (status = 200, description = "Successfully created proof for request", body = Status)
    )
)]
#[debug_handler(state = ProverState)]
/// Generate a proof for requested config.
///
/// Accepts a proof request and generates a proof with the specified guest prover.
/// The guest provers currently available are:
/// - native - constructs a block and checks for equality
/// - sgx - uses the sgx environment to construct a block and produce proof of execution
/// - sp1 - uses the sp1 prover
/// - risc0 - uses the risc0 prover
async fn proof_handler(
    State(prover_state): State<ProverState>,
    Json(req): Json<Value>,
) -> HostResult<Json<Status>> {
    inc_current_req();

    ensure_not_paused(&prover_state)?;

    // Override the existing proof request config from the config file and command line
    // options with the request from the client.
    let mut config = prover_state.request_config();
    config.merge(&req)?;

    ensure_proof_request_image_id(&mut config)?;

    // Construct the actual proof request from the available configs.
    let proof_request = ProofRequest::try_from(config)?;
    inc_host_req_count(proof_request.block_number);
    inc_guest_req_count(&proof_request.proof_type, proof_request.block_number);

    let mut manager = prover_state.task_manager();

    handle_proof(
        &proof_request,
        &prover_state.opts,
        &prover_state.chain_specs,
        Some(&mut manager),
    )
    .await
    .map_err(|e| {
        dec_current_req();
        e
    })
    .map(|proof| {
        dec_current_req();
        Json(Status::Ok {
            data: ProofResponse {
                output: None,
                proof: proof.proof,
                quote: proof.quote,
            },
        })
    })
}

#[derive(OpenApi)]
#[openapi(paths(proof_handler))]
struct Docs;

pub fn create_docs() -> utoipa::openapi::OpenApi {
    Docs::openapi()
}

pub fn create_router() -> Router<ProverState> {
    Router::new().route("/", post(proof_handler))
}
