use std::io::{Error as IOError, ErrorKind as IOErrorKind};

use chrono::{DateTime, Utc};
use raiko_core::interfaces::AggregationOnlyRequest;
use raiko_lib::{
    primitives::{ChainId, B256},
    proof_type::ProofType,
    prover::{IdStore, IdWrite, ProofKey, ProverResult},
};
use serde::{Deserialize, Serialize};
use tracing::debug;
use utoipa::ToSchema;

#[cfg(feature = "in-memory")]
use crate::mem_db::InMemoryTaskManager;
#[cfg(feature = "redis-db")]
use crate::redis_db::RedisTaskManager;

#[cfg(feature = "in-memory")]
mod mem_db;
#[cfg(feature = "redis-db")]
mod redis_db;

// Types
// ----------------------------------------------------------------
#[derive(Debug, thiserror::Error)]
pub enum TaskManagerError {
    #[error("IO Error {0}")]
    IOError(IOErrorKind),
    #[cfg(feature = "redis-db")]
    #[error("Redis Error {0}")]
    RedisError(#[from] crate::redis_db::RedisDbError),
    #[error("No data for query")]
    NoData,
    #[error("Anyhow error: {0}")]
    Anyhow(String),
}

pub type TaskManagerResult<T> = Result<T, TaskManagerError>;

impl From<IOError> for TaskManagerError {
    fn from(error: IOError) -> TaskManagerError {
        TaskManagerError::IOError(error.kind())
    }
}

impl From<anyhow::Error> for TaskManagerError {
    fn from(value: anyhow::Error) -> Self {
        TaskManagerError::Anyhow(value.to_string())
    }
}

#[allow(non_camel_case_types)]
#[rustfmt::skip]
#[derive(PartialEq, Debug, Clone, Deserialize, Serialize, ToSchema, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Success,
    Registered,
    WorkInProgress,
    ProofFailure_Generic,
    ProofFailure_OutOfMemory,
    NetworkFailure(String),
    Cancelled,
    Cancelled_NeverStarted,
    Cancelled_Aborted,
    CancellationInProgress,
    InvalidOrUnsupportedBlock,
    IoFailure(String),
    AnyhowError(String),
    GuestProverFailure(String),
    UnspecifiedFailureReason,
    TaskDbCorruption(String),
    SystemPaused,
}

impl From<TaskStatus> for i32 {
    fn from(status: TaskStatus) -> i32 {
        match status {
            TaskStatus::Success => 0,
            TaskStatus::Registered => 1000,
            TaskStatus::WorkInProgress => 2000,
            TaskStatus::ProofFailure_Generic => -1000,
            TaskStatus::ProofFailure_OutOfMemory => -1100,
            TaskStatus::NetworkFailure(_) => -2000,
            TaskStatus::Cancelled => -3000,
            TaskStatus::Cancelled_NeverStarted => -3100,
            TaskStatus::Cancelled_Aborted => -3200,
            TaskStatus::CancellationInProgress => -3210,
            TaskStatus::InvalidOrUnsupportedBlock => -4000,
            TaskStatus::IoFailure(_) => -5000,
            TaskStatus::AnyhowError(_) => -6000,
            TaskStatus::GuestProverFailure(_) => -7000,
            TaskStatus::UnspecifiedFailureReason => -8000,
            TaskStatus::TaskDbCorruption(_) => -9000,
            TaskStatus::SystemPaused => -10000,
        }
    }
}

impl From<i32> for TaskStatus {
    fn from(value: i32) -> TaskStatus {
        match value {
            0 => TaskStatus::Success,
            1000 => TaskStatus::Registered,
            2000 => TaskStatus::WorkInProgress,
            -1000 => TaskStatus::ProofFailure_Generic,
            -1100 => TaskStatus::ProofFailure_OutOfMemory,
            -2000 => TaskStatus::NetworkFailure("".to_string()),
            -3000 => TaskStatus::Cancelled,
            -3100 => TaskStatus::Cancelled_NeverStarted,
            -3200 => TaskStatus::Cancelled_Aborted,
            -3210 => TaskStatus::CancellationInProgress,
            -4000 => TaskStatus::InvalidOrUnsupportedBlock,
            -5000 => TaskStatus::IoFailure("".to_string()),
            -6000 => TaskStatus::AnyhowError("".to_string()),
            -7000 => TaskStatus::GuestProverFailure("".to_string()),
            -8000 => TaskStatus::UnspecifiedFailureReason,
            -9000 => TaskStatus::TaskDbCorruption("".to_string()),
            -10000 => TaskStatus::SystemPaused,
            _ => TaskStatus::UnspecifiedFailureReason,
        }
    }
}

impl FromIterator<TaskStatus> for TaskStatus {
    fn from_iter<T: IntoIterator<Item = TaskStatus>>(iter: T) -> Self {
        iter.into_iter()
            .min()
            .unwrap_or(TaskStatus::UnspecifiedFailureReason)
    }
}

impl<'a> FromIterator<&'a TaskStatus> for TaskStatus {
    fn from_iter<T: IntoIterator<Item = &'a TaskStatus>>(iter: T) -> Self {
        iter.into_iter()
            .min()
            .cloned()
            .unwrap_or(TaskStatus::UnspecifiedFailureReason)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct ProofTaskDescriptor {
    pub chain_id: ChainId,
    pub block_id: u64,
    pub blockhash: B256,
    pub proof_system: ProofType,
    pub prover: String,
}

impl From<(ChainId, u64, B256, ProofType, String)> for ProofTaskDescriptor {
    fn from(
        (chain_id, block_id, blockhash, proof_system, prover): (
            ChainId,
            u64,
            B256,
            ProofType,
            String,
        ),
    ) -> Self {
        ProofTaskDescriptor {
            chain_id,
            block_id,
            blockhash,
            proof_system,
            prover,
        }
    }
}

impl From<ProofTaskDescriptor> for (ChainId, B256) {
    fn from(
        ProofTaskDescriptor {
            chain_id,
            blockhash,
            ..
        }: ProofTaskDescriptor,
    ) -> Self {
        (chain_id, blockhash)
    }
}

#[derive(Default, Clone, Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
#[serde(default)]
/// A request for proof aggregation of multiple proofs.
pub struct AggregationTaskDescriptor {
    /// The block numbers and l1 inclusion block numbers for the blocks to aggregate proofs for.
    pub aggregation_ids: Vec<u64>,
    /// The proof type.
    pub proof_type: Option<String>,
}

impl From<&AggregationOnlyRequest> for AggregationTaskDescriptor {
    fn from(request: &AggregationOnlyRequest) -> Self {
        Self {
            aggregation_ids: request.aggregation_ids.clone(),
            proof_type: request.proof_type.clone().map(|p| p.to_string()),
        }
    }
}

/// Task status triplet (status, proof, timestamp).
pub type TaskProvingStatus = (TaskStatus, Option<String>, DateTime<Utc>);

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TaskProvingStatusRecords(pub Vec<TaskProvingStatus>);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskDescriptor {
    SingleProof(ProofTaskDescriptor),
    Aggregation(AggregationTaskDescriptor),
}

pub type TaskReport = (TaskDescriptor, TaskStatus);

pub type AggregationTaskReport = (AggregationOnlyRequest, TaskStatus);

#[derive(Debug, Clone, Default)]
pub struct TaskManagerOpts {
    pub max_db_size: usize,
    pub redis_url: String,
    pub redis_ttl: u64,
}

#[async_trait::async_trait]
pub trait TaskManager: IdStore + IdWrite + Send + Sync {
    /// Create a new task manager.
    fn new(opts: &TaskManagerOpts) -> Self;

    /// Enqueue a new task to the tasks database.
    async fn enqueue_task(
        &mut self,
        request: &ProofTaskDescriptor,
    ) -> TaskManagerResult<TaskProvingStatusRecords>;

    /// Update a specific tasks progress.
    async fn update_task_progress(
        &mut self,
        key: ProofTaskDescriptor,
        status: TaskStatus,
        proof: Option<&[u8]>,
    ) -> TaskManagerResult<()>;

    /// Returns the latest triplet (status, proof - if any, last update time).
    async fn get_task_proving_status(
        &mut self,
        key: &ProofTaskDescriptor,
    ) -> TaskManagerResult<TaskProvingStatusRecords>;

    /// Returns the proof for the given task.
    async fn get_task_proof(&mut self, key: &ProofTaskDescriptor) -> TaskManagerResult<Vec<u8>>;

    /// Returns the total and detailed database size.
    async fn get_db_size(&mut self) -> TaskManagerResult<(usize, Vec<(String, usize)>)>;

    /// Prune old tasks.
    async fn prune_db(&mut self) -> TaskManagerResult<()>;

    /// List all tasks in the db.
    async fn list_all_tasks(&mut self) -> TaskManagerResult<Vec<TaskReport>>;

    /// List all stored ids.
    async fn list_stored_ids(&mut self) -> TaskManagerResult<Vec<(ProofKey, String)>>;

    /// Enqueue a new aggregation task to the tasks database.
    async fn enqueue_aggregation_task(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<()>;

    /// Update a specific aggregation tasks progress.
    async fn update_aggregation_task_progress(
        &mut self,
        request: &AggregationOnlyRequest,
        status: TaskStatus,
        proof: Option<&[u8]>,
    ) -> TaskManagerResult<()>;

    /// Returns the latest triplet (status, proof - if any, last update time).
    async fn get_aggregation_task_proving_status(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<TaskProvingStatusRecords>;

    /// Returns the proof for the given aggregation task.
    async fn get_aggregation_task_proof(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<Vec<u8>>;

    /// Prune old tasks.
    async fn prune_aggregation_db(&mut self) -> TaskManagerResult<()>;

    /// List all tasks in the db.
    async fn list_all_aggregation_tasks(&mut self)
        -> TaskManagerResult<Vec<AggregationTaskReport>>;
}

pub fn ensure(expression: bool, message: &str) -> TaskManagerResult<()> {
    if !expression {
        return Err(TaskManagerError::Anyhow(message.to_string()));
    }
    Ok(())
}

pub struct TaskManagerWrapper<T: TaskManager> {
    manager: T,
}

#[async_trait::async_trait]
impl<T: TaskManager> IdWrite for TaskManagerWrapper<T> {
    async fn store_id(&mut self, key: ProofKey, id: String) -> ProverResult<()> {
        self.manager.store_id(key, id).await
    }

    async fn remove_id(&mut self, key: ProofKey) -> ProverResult<()> {
        self.manager.remove_id(key).await
    }
}

#[async_trait::async_trait]
impl<T: TaskManager> IdStore for TaskManagerWrapper<T> {
    async fn read_id(&mut self, key: ProofKey) -> ProverResult<String> {
        self.manager.read_id(key).await
    }
}

#[async_trait::async_trait]
impl<T: TaskManager> TaskManager for TaskManagerWrapper<T> {
    fn new(opts: &TaskManagerOpts) -> Self {
        let manager = T::new(opts);
        Self { manager }
    }

    async fn enqueue_task(
        &mut self,
        request: &ProofTaskDescriptor,
    ) -> TaskManagerResult<TaskProvingStatusRecords> {
        self.manager.enqueue_task(request).await
    }

    async fn update_task_progress(
        &mut self,
        key: ProofTaskDescriptor,
        status: TaskStatus,
        proof: Option<&[u8]>,
    ) -> TaskManagerResult<()> {
        self.manager.update_task_progress(key, status, proof).await
    }

    async fn get_task_proving_status(
        &mut self,
        key: &ProofTaskDescriptor,
    ) -> TaskManagerResult<TaskProvingStatusRecords> {
        self.manager.get_task_proving_status(key).await
    }

    async fn get_task_proof(&mut self, key: &ProofTaskDescriptor) -> TaskManagerResult<Vec<u8>> {
        self.manager.get_task_proof(key).await
    }

    async fn get_db_size(&mut self) -> TaskManagerResult<(usize, Vec<(String, usize)>)> {
        self.manager.get_db_size().await
    }

    async fn prune_db(&mut self) -> TaskManagerResult<()> {
        self.manager.prune_db().await
    }

    async fn list_all_tasks(&mut self) -> TaskManagerResult<Vec<TaskReport>> {
        self.manager.list_all_tasks().await
    }

    async fn list_stored_ids(&mut self) -> TaskManagerResult<Vec<(ProofKey, String)>> {
        self.manager.list_stored_ids().await
    }

    async fn enqueue_aggregation_task(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<()> {
        self.manager.enqueue_aggregation_task(request).await
    }

    async fn update_aggregation_task_progress(
        &mut self,
        request: &AggregationOnlyRequest,
        status: TaskStatus,
        proof: Option<&[u8]>,
    ) -> TaskManagerResult<()> {
        self.manager
            .update_aggregation_task_progress(request, status, proof)
            .await
    }

    async fn get_aggregation_task_proving_status(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<TaskProvingStatusRecords> {
        self.manager
            .get_aggregation_task_proving_status(request)
            .await
    }

    async fn get_aggregation_task_proof(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<Vec<u8>> {
        self.manager.get_aggregation_task_proof(request).await
    }

    async fn prune_aggregation_db(&mut self) -> TaskManagerResult<()> {
        self.manager.prune_aggregation_db().await
    }

    async fn list_all_aggregation_tasks(
        &mut self,
    ) -> TaskManagerResult<Vec<AggregationTaskReport>> {
        self.manager.list_all_aggregation_tasks().await
    }
}

#[cfg(feature = "in-memory")]
pub type TaskManagerWrapperImpl = TaskManagerWrapper<InMemoryTaskManager>;
#[cfg(feature = "redis-db")]
pub type TaskManagerWrapperImpl = TaskManagerWrapper<RedisTaskManager>;

pub fn get_task_manager(opts: &TaskManagerOpts) -> TaskManagerWrapperImpl {
    debug!("get task manager with options: {:?}", opts);
    TaskManagerWrapperImpl::new(opts)
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

    #[tokio::test]
    async fn test_new_taskmanager() {
        let opts = TaskManagerOpts {
            max_db_size: 1024 * 1024,
            redis_url: "redis://localhost:6379".to_string(),
            redis_ttl: 3600,
        };
        let mut task_manager = get_task_manager(&opts);

        let block_id = rand::thread_rng().gen_range(0..1000000);
        assert_eq!(
            task_manager
                .enqueue_task(&ProofTaskDescriptor {
                    chain_id: 1,
                    block_id,
                    blockhash: B256::default(),
                    proof_system: ProofType::Native,
                    prover: "test".to_string(),
                })
                .await
                .unwrap()
                .0
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn test_enqueue_twice() {
        let opts = TaskManagerOpts {
            max_db_size: 1024 * 1024,
            redis_url: "redis://localhost:6379".to_string(),
            redis_ttl: 3600,
        };
        let mut task_manager = get_task_manager(&opts);
        let block_id = rand::thread_rng().gen_range(0..1000000);
        let key = ProofTaskDescriptor {
            chain_id: 1,
            block_id,
            blockhash: B256::default(),
            proof_system: ProofType::Native,
            prover: "test".to_string(),
        };

        assert_eq!(task_manager.enqueue_task(&key).await.unwrap().0.len(), 1);
        // enqueue again
        assert_eq!(task_manager.enqueue_task(&key).await.unwrap().0.len(), 1);

        let status = task_manager.get_task_proving_status(&key).await.unwrap();
        assert_eq!(status.0.len(), 1);

        task_manager
            .update_task_progress(key.clone(), TaskStatus::InvalidOrUnsupportedBlock, None)
            .await
            .expect("update task failed");
        let status = task_manager.get_task_proving_status(&key).await.unwrap();
        assert_eq!(status.0.len(), 2);

        task_manager
            .update_task_progress(key.clone(), TaskStatus::Registered, None)
            .await
            .expect("update task failed");
        let status = task_manager.get_task_proving_status(&key).await.unwrap();
        assert_eq!(status.0.len(), 3);
        assert_eq!(status.0.first().unwrap().0, TaskStatus::Registered);
        assert_eq!(status.0.last().unwrap().0, TaskStatus::Registered);
    }
}
