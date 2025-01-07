use axum::{debug_handler, extract::State, routing::post, Json, Router};
use raiko_core::{interfaces::ProofRequest, provider::get_task_data};
use raiko_tasks::{ProofTaskDescriptor, TaskManager, TaskStatus};
use serde_json::Value;
use utoipa::OpenApi;

use crate::{
    interfaces::HostResult,
    metrics::{inc_current_req, inc_guest_req_count, inc_host_req_count},
    server::api::{
        util::{ensure_not_paused, ensure_proof_request_image_id},
        v2::Status,
    },
    Message, ProverState,
};

pub mod cancel;
pub mod list;
pub mod prune;
pub mod report;

#[utoipa::path(post, path = "/proof",
    tag = "Proving",
    request_body = ProofRequestOpt,
    responses (
        (status = 200, description = "Successfully submitted proof task, queried tasks in progress or retrieved proof.", body = Status)
    )
)]
#[debug_handler(state = ProverState)]
/// Submit a proof task with requested config, get task status or get proof value.
///
/// Accepts a proof request and creates a proving task with the specified guest prover.
/// The guest provers currently available are:
/// - native - constructs a block and checks for equality
/// - sgx - uses the sgx environment to construct a block and produce proof of execution
/// - sp1 - uses the sp1 prover
/// - risc0 - uses the risc0 prover
async fn proof_handler(
    State(prover_state): State<ProverState>,
    Json(req): Json<Value>,
) -> HostResult<Status> {
    inc_current_req();

    ensure_not_paused(&prover_state)?;

    // Override the existing proof request config from the config file and command line
    // options with the request from the client.
    let mut config = prover_state.request_config();
    config.merge(&req)?;

    // TODO: remove this assert after we support custom image_id for RISC0/SP1 proof type
    assert!(
        config.image_id.is_none(),
        "currently we don't support custom image_id for RISC0/SP1 proof type"
    );
    ensure_proof_request_image_id(&mut config)?;

    // Construct the actual proof request from the available configs.
    let proof_request = ProofRequest::try_from(config)?;
    inc_host_req_count(proof_request.block_number);
    inc_guest_req_count(&proof_request.proof_type, proof_request.block_number);

    let (chain_id, blockhash) = get_task_data(
        &proof_request.network,
        proof_request.block_number,
        &prover_state.chain_specs,
    )
    .await?;

    let key = ProofTaskDescriptor::new(
        chain_id,
        proof_request.block_number,
        blockhash,
        proof_request.proof_type,
        proof_request.prover.to_string(),
        proof_request.image_id.clone(),
    );

    let mut manager = prover_state.task_manager();
    let status = manager.get_task_proving_status(&key).await?;
    tracing::info!(
        "/v2/proof, request: {:?}, status: {:?}",
        proof_request,
        status
    );

    match status.0.last() {
        Some((latest_status, ..)) => {
            match latest_status {
                // If task has been cancelled
                TaskStatus::Cancelled
                | TaskStatus::Cancelled_Aborted
                | TaskStatus::Cancelled_NeverStarted
                | TaskStatus::CancellationInProgress
                // or if the task is failed, add it to the queue again
                | TaskStatus::GuestProverFailure(_)
                | TaskStatus::UnspecifiedFailureReason => {
                    manager
                        .update_task_progress(key, TaskStatus::Registered, None)
                        .await?;

                    prover_state
                        .task_channel
                        .try_send(Message::Task(proof_request))?;

                    Ok(TaskStatus::Registered.into())
                }
                // If the task has succeeded, return the proof.
                TaskStatus::Success => {
                    let proof = manager.get_task_proof(&key).await?;

                    Ok(proof.into())
                }
                // For all other statuses just return the status.
                status => Ok(status.clone().into()),
            }
        }
        None => {
            manager.enqueue_task(&key).await?;

            prover_state
                .task_channel
                .try_send(Message::Task(proof_request))?;

            Ok(TaskStatus::Registered.into())
        }
    }
}

#[derive(OpenApi)]
#[openapi(paths(proof_handler))]
struct Docs;

pub fn create_docs() -> utoipa::openapi::OpenApi {
    [
        cancel::create_docs(),
        report::create_docs(),
        list::create_docs(),
        prune::create_docs(),
    ]
    .into_iter()
    .fold(Docs::openapi(), |mut docs, curr| {
        docs.merge(curr);
        docs
    })
}

pub fn create_router() -> Router<ProverState> {
    Router::new()
        .route("/", post(proof_handler))
        .nest("/cancel", cancel::create_router())
        .nest("/report", report::create_router())
        .nest("/list", list::create_router())
        .nest("/prune", prune::create_router())
}
