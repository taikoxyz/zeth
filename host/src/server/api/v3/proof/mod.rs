use crate::{
    interfaces::HostResult,
    metrics::{inc_current_req, inc_guest_req_count, inc_host_req_count},
    server::api::{
        util::{ensure_aggregation_request_image_id, ensure_not_paused},
        v2,
        v3::Status,
    },
    Message, ProverState,
};
use axum::{debug_handler, extract::State, routing::post, Json, Router};
use raiko_core::{
    interfaces::{AggregationOnlyRequest, AggregationRequest, ProofRequest, ProofRequestOpt},
    provider::get_task_data,
};
use raiko_lib::prover::Proof;
use raiko_tasks::{ProofTaskDescriptor, TaskManager, TaskStatus};
use tracing::{debug, info};
use utoipa::OpenApi;

mod aggregate;
mod cancel;

#[utoipa::path(post, path = "/proof",
    tag = "Proving",
    request_body = AggregationRequest,
    responses (
        (status = 200, description = "Successfully submitted proof task, queried tasks in progress or retrieved proof.", body = Status)
    )
)]
#[debug_handler(state = ProverState)]
/// Submit a proof aggregation task with requested config, get task status or get proof value.
///
/// Accepts a proof request and creates a proving task with the specified guest prover.
/// The guest provers currently available are:
/// - native - constructs a block and checks for equality
/// - sgx - uses the sgx environment to construct a block and produce proof of execution
/// - sp1 - uses the sp1 prover
/// - risc0 - uses the risc0 prover
async fn proof_handler(
    State(prover_state): State<ProverState>,
    Json(mut aggregation_request): Json<AggregationRequest>,
) -> HostResult<Status> {
    inc_current_req();

    ensure_not_paused(&prover_state)?;

    // TODO: remove this assert after we support custom image_id for RISC0/SP1 proof type
    assert!(
        aggregation_request.image_id.is_none(),
        "currently we don't support custom image_id for RISC0/SP1 proof type"
    );
    ensure_aggregation_request_image_id(&mut aggregation_request)?;

    // Override the existing proof request config from the config file and command line
    // options with the request from the client.
    aggregation_request.merge(&prover_state.request_config())?;

    let mut tasks = Vec::with_capacity(aggregation_request.block_numbers.len());

    let proof_request_opts: Vec<ProofRequestOpt> = aggregation_request.clone().into();

    if proof_request_opts.is_empty() {
        return Err(anyhow::anyhow!("No blocks for proving provided").into());
    }

    // Construct the actual proof request from the available configs.
    for proof_request_opt in proof_request_opts {
        let proof_request = ProofRequest::try_from(proof_request_opt)?;

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

        tasks.push((key, proof_request));
    }

    let mut manager = prover_state.task_manager();

    let mut is_registered = false;
    let mut is_success = true;
    let mut statuses = Vec::with_capacity(tasks.len());

    for (key, req) in tasks.iter() {
        let status = manager.get_task_proving_status(key).await?;
        tracing::info!("/v3/proof, request: {:?}, status: {:?}", req, status);

        if let Some((latest_status, ..)) = status.0.last() {
            match latest_status {
                // If task has been cancelled
                TaskStatus::Cancelled
                | TaskStatus::Cancelled_Aborted
                | TaskStatus::Cancelled_NeverStarted
                | TaskStatus::CancellationInProgress
                // or if the task is failed, add it to the queue again
                | TaskStatus::GuestProverFailure(_)
                | TaskStatus::UnspecifiedFailureReason
                 => {
                    manager
                        .update_task_progress(key.clone(), TaskStatus::Registered, None)
                        .await?;
                    prover_state.task_channel.try_send(Message::Task(req.to_owned()))?;

                    is_registered = true;
                    is_success = false;
                }
                // If the task has succeeded, return the proof.
                TaskStatus::Success => {}
                // For all other statuses just return the status.
                status => {
                    statuses.push(status.clone());
                    is_registered = false;
                    is_success = false;
                }
            }
        } else {
            // If there are no tasks with provided config, create a new one.
            manager.enqueue_task(key).await?;

            prover_state
                .task_channel
                .try_send(Message::Task(req.to_owned()))?;
            is_registered = true;
            continue;
        };
    }

    if is_registered {
        Ok(TaskStatus::Registered.into())
    } else if is_success {
        info!("All tasks are successful, aggregating proofs");
        let mut proofs = Vec::with_capacity(tasks.len());
        let mut aggregation_ids = Vec::with_capacity(tasks.len());
        for (task, req) in tasks {
            let raw_proof: Vec<u8> = manager.get_task_proof(&task).await?;
            let proof: Proof = serde_json::from_slice(&raw_proof)?;
            debug!(
                "Aggregation sub-req: {req:?} gets proof {:?} with input {:?}.",
                proof.proof, proof.input
            );
            proofs.push(proof);
            aggregation_ids.push(req.block_number);
        }

        let aggregation_request = AggregationOnlyRequest {
            aggregation_ids,
            proofs,
            proof_type: aggregation_request.proof_type,
            prover_args: aggregation_request.prover_args,
            image_id: aggregation_request.image_id,
        };

        let status = manager
            .get_aggregation_task_proving_status(&aggregation_request)
            .await?;

        if let Some((latest_status, ..)) = status.0.last() {
            match latest_status {
                // If task has been cancelled add it to the queue again
                TaskStatus::Cancelled
                | TaskStatus::Cancelled_Aborted
                | TaskStatus::Cancelled_NeverStarted
                | TaskStatus::CancellationInProgress
                // or if the task is failed, add it to the queue again
                | TaskStatus::GuestProverFailure(_)
                | TaskStatus::UnspecifiedFailureReason
                => {
                    manager
                        .update_aggregation_task_progress(
                            &aggregation_request,
                            TaskStatus::Registered,
                            None,
                        )
                        .await?;
                    prover_state
                        .task_channel
                        .try_send(Message::Aggregate(aggregation_request))?;
                    Ok(Status::from(TaskStatus::Registered))
                }
                // If the task has succeeded, return the proof.
                TaskStatus::Success => {
                    let proof = manager
                        .get_aggregation_task_proof(&aggregation_request)
                        .await?;
                    Ok(proof.into())
                }
                // For all other statuses just return the status.
                status => Ok(status.clone().into()),
            }
        } else {
            // If there are no tasks with provided config, create a new one.
            manager
                .enqueue_aggregation_task(&aggregation_request)
                .await?;

            prover_state
                .task_channel
                .try_send(Message::Aggregate(aggregation_request))?;
            Ok(Status::from(TaskStatus::Registered))
        }
    } else {
        let status = statuses.into_iter().collect::<TaskStatus>();
        Ok(status.into())
    }
}

#[derive(OpenApi)]
#[openapi(paths(proof_handler))]
struct Docs;

pub fn create_docs() -> utoipa::openapi::OpenApi {
    [
        cancel::create_docs(),
        aggregate::create_docs(),
        v2::proof::report::create_docs(),
        v2::proof::list::create_docs(),
        v2::proof::prune::create_docs(),
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
        .nest("/aggregate", aggregate::create_router())
        .nest("/report", v2::proof::report::create_router())
        .nest("/list", v2::proof::list::create_router())
        .nest("/prune", v2::proof::prune::create_router())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use clap::Parser;
    use std::path::PathBuf;
    use tower::ServiceExt;

    #[serial_test::serial]
    #[test_log::test(tokio::test)]
    async fn test_proof_handler_when_paused() {
        let opts = {
            let mut opts = crate::Opts::parse();
            opts.config_path = PathBuf::from("../host/config/config.json");
            opts.merge_from_file().unwrap();
            opts
        };
        let state = ProverState::init_with_opts(opts).unwrap();
        let app = Router::new()
            .route("/", post(proof_handler))
            .with_state(state.clone());

        // Set pause flag
        state.set_pause(true).await.unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"block_numbers":[],"proof_type":"block","prover":"native"}"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("system_paused"),
            "{:?}",
            body
        );
    }
}
