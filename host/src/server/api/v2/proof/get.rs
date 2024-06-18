use axum::{
    debug_handler,
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use raiko_task_manager::TaskDb;
use utoipa::OpenApi;

use crate::{interfaces::HostResult, ProverState};

#[utoipa::path(get, path = "/proof/:task_id",
    tag = "Proving",
    request_body = ProofRequestOpt,
    responses (
        (status = 200, description = "Successfully retrieved a proof", body = Status)
    )
)]
#[debug_handler(state = ProverState)]
/// Get proof for given task id.
///
/// Accepts a proving task id.
async fn get_handler(
    State(prover_state): State<ProverState>,
    Path(task_id): Path<u64>,
) -> HostResult<Json<Vec<u8>>> {
    let db = TaskDb::open_or_create(&prover_state.opts.sqlite_file)?;
    let mut manager = db.manage()?;
    let status = manager.get_task_proof_by_id(task_id)?;
    Ok(Json(status))
}

#[derive(OpenApi)]
#[openapi(paths(get_handler))]
struct Docs;

pub fn create_docs() -> utoipa::openapi::OpenApi {
    Docs::openapi()
}

pub fn create_router() -> Router<ProverState> {
    Router::new().route("/:task_id", get(get_handler))
}
