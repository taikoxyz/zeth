use std::io::{Error as IOError, ErrorKind as IOErrorKind};
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use mem_db::InMemoryTaskManager;
use num_enum::{FromPrimitive, IntoPrimitive};
use raiko_core::interfaces::ProofType;
use raiko_lib::primitives::{ChainId, B256};
use rusqlite::Error as SqlError;
use serde::Serialize;

// mod adv_sqlite;
mod mem_db;

// Types
// ----------------------------------------------------------------
#[derive(PartialEq, Debug, thiserror::Error)]
pub enum TaskManagerError {
    #[error("IO Error {0}")]
    IOError(IOErrorKind),
    #[error("SQL Error {0}")]
    SqlError(String),
    #[error("Anyhow error: {0}")]
    Anyhow(String),
}

pub type TaskManagerResult<T> = Result<T, TaskManagerError>;

impl From<IOError> for TaskManagerError {
    fn from(error: IOError) -> TaskManagerError {
        TaskManagerError::IOError(error.kind())
    }
}

impl From<SqlError> for TaskManagerError {
    fn from(error: SqlError) -> TaskManagerError {
        TaskManagerError::SqlError(error.to_string())
    }
}

impl From<serde_json::Error> for TaskManagerError {
    fn from(error: serde_json::Error) -> TaskManagerError {
        TaskManagerError::SqlError(error.to_string())
    }
}

impl From<anyhow::Error> for TaskManagerError {
    fn from(value: anyhow::Error) -> Self {
        TaskManagerError::Anyhow(value.to_string())
    }
}

#[allow(non_camel_case_types)]
#[rustfmt::skip]
#[derive(PartialEq, Debug, Copy, Clone, IntoPrimitive, FromPrimitive, Serialize)]
#[repr(i32)]
pub enum TaskStatus {
    Success                   =     0,
    Registered                =  1000,
    WorkInProgress            =  2000,
    WorkReported              =  3000,
    ProofFailure_Generic      = -1000,
    ProofFailure_OutOfMemory  = -1100,
    NetworkFailure            = -2000,
    Cancelled                 = -3000,
    Cancelled_NeverStarted    = -3100,
    Cancelled_Aborted         = -3200,
    CancellationInProgress    = -3210,
    InvalidOrUnsupportedBlock = -4000,
    UnspecifiedFailureReason  = -9999,
    #[num_enum(default)]
    SqlDbCorruption           = -99999,
}

#[derive(Debug, Clone, Default)]
pub struct EnqueueTaskParams {
    pub chain_id: ChainId,
    pub blockhash: B256,
    pub proof_system: ProofType,
    pub prover: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskDescriptor {
    pub chain_id: ChainId,
    pub blockhash: B256,
    pub proof_system: ProofType,
    pub prover: String,
}

impl TaskDescriptor {
    pub fn to_vec(self) -> Vec<u8> {
        self.into()
    }
}

impl From<TaskDescriptor> for Vec<u8> {
    fn from(val: TaskDescriptor) -> Self {
        let mut v = Vec::new();
        v.extend_from_slice(&val.chain_id.to_be_bytes());
        v.extend_from_slice(val.blockhash.as_ref());
        v.extend_from_slice(&(val.proof_system as u8).to_be_bytes());
        v.extend_from_slice(val.prover.as_bytes());
        v
    }
}

// Taskkey from EnqueueTaskParams
impl From<&EnqueueTaskParams> for TaskDescriptor {
    fn from(params: &EnqueueTaskParams) -> TaskDescriptor {
        TaskDescriptor {
            chain_id: params.chain_id,
            blockhash: params.blockhash,
            proof_system: params.proof_system,
            prover: params.prover.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaskProvingStatus(pub TaskStatus, pub Option<String>, pub DateTime<Utc>);

pub type TaskProvingStatusRecords = Vec<TaskProvingStatus>;

#[derive(Debug, Clone)]
pub struct TaskManagerOpts {
    pub sqlite_file: PathBuf,
    pub max_db_size: usize,
}

pub trait TaskManager {
    /// new a task manager
    fn new(opts: &TaskManagerOpts) -> Self;

    /// enqueue_task
    fn enqueue_task(
        &mut self,
        request: &EnqueueTaskParams,
    ) -> TaskManagerResult<TaskProvingStatusRecords>;

    /// Update the task progress
    fn update_task_progress(
        &mut self,
        chain_id: ChainId,
        blockhash: B256,
        proof_system: ProofType,
        prover: Option<String>,
        status: TaskStatus,
        proof: Option<&[u8]>,
    ) -> TaskManagerResult<()>;

    /// Returns the latest triplet (submitter or fulfiller, status, last update time)
    fn get_task_proving_status(
        &mut self,
        chain_id: ChainId,
        blockhash: B256,
        proof_system: ProofType,
        prover: Option<String>,
    ) -> TaskManagerResult<TaskProvingStatusRecords>;

    /// Returns the latest triplet (submitter or fulfiller, status, last update time)
    fn get_task_proving_status_by_id(
        &mut self,
        task_id: u64,
    ) -> TaskManagerResult<TaskProvingStatusRecords>;

    /// Returns the proof for the given task
    fn get_task_proof(
        &mut self,
        chain_id: ChainId,
        blockhash: B256,
        proof_system: ProofType,
        prover: Option<String>,
    ) -> TaskManagerResult<Vec<u8>>;

    fn get_task_proof_by_id(&mut self, task_id: u64) -> TaskManagerResult<Vec<u8>>;

    /// Returns the total and detailed database size
    fn get_db_size(&mut self) -> TaskManagerResult<(usize, Vec<(String, usize)>)>;

    /// Prune old tasks
    fn prune_db(&mut self) -> TaskManagerResult<()>;
}

pub fn ensure(expression: bool, message: &str) -> TaskManagerResult<()> {
    if !expression {
        return Err(TaskManagerError::Anyhow(message.to_string()));
    }
    Ok(())
}

use std::sync::{Arc, Mutex, Once};

// todo: use feature to switch between sqlite and memory db
pub fn get_task_manager(opts: &TaskManagerOpts) -> Arc<Mutex<InMemoryTaskManager>> {
    static INIT: Once = Once::new();
    static mut SHARED_TASK_MANAGER: Option<Arc<Mutex<InMemoryTaskManager>>> = None;

    INIT.call_once(|| {
        let task_manager: Arc<Mutex<InMemoryTaskManager>> =
            Arc::new(Mutex::new(InMemoryTaskManager::new(opts)));
        unsafe {
            SHARED_TASK_MANAGER = Some(Arc::clone(&task_manager));
        }
    });

    unsafe { SHARED_TASK_MANAGER.as_ref().unwrap().clone() }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_taskmanager() {
        let opts = TaskManagerOpts {
            sqlite_file: "test.db".to_string().into(),
            max_db_size: 1024,
        };
        let binding = get_task_manager(&opts);
        let mut task_manager = binding.lock().unwrap();
        assert_eq!(task_manager.get_db_size().unwrap().0, 0);

        assert_eq!(
            task_manager
                .enqueue_task(&EnqueueTaskParams {
                    chain_id: 1,
                    blockhash: B256::default(),
                    proof_system: ProofType::Native,
                    prover: "test".to_string(),
                    block_number: 1
                })
                .unwrap()
                .len(),
            1
        );
    }
}
