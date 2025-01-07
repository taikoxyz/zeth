#![cfg(feature = "redis-db")]
// Raiko
// Copyright (c) 2024 Taiko Labs
// Licensed and distributed under either of
//   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
//   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
// at your option. This file may not be copied, modified, or distributed except according to those terms.

// Imports
// ----------------------------------------------------------------
use backoff::ExponentialBackoff;
use chrono::Utc;
use raiko_core::interfaces::AggregationOnlyRequest;
use raiko_lib::prover::{IdStore, IdWrite, ProofKey, ProverError, ProverResult};
use redis::{
    Client, Commands, ErrorKind, FromRedisValue, RedisError, RedisResult, RedisWrite, ToRedisArgs,
    Value,
};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::{
    AggregationTaskDescriptor, AggregationTaskReport, ProofTaskDescriptor, TaskDescriptor,
    TaskManager, TaskManagerError, TaskManagerOpts, TaskManagerResult, TaskProvingStatus,
    TaskProvingStatusRecords, TaskReport, TaskStatus,
};

pub struct RedisTaskDb {
    client: Client,
    config: RedisConfig,
}

#[derive(Clone)]
pub struct RedisTaskManager {
    arc_task_db: Arc<Mutex<RedisTaskDb>>,
}

impl std::fmt::Debug for RedisTaskManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RedisTaskManager")
    }
}

type RedisDbResult<T> = Result<T, RedisDbError>;

#[derive(Error, Debug)]
pub enum RedisDbError {
    #[error("Redis DB error: {0}")]
    RedisDb(#[from] RedisError),
    #[error("Redis Task Manager error: {0}")]
    TaskManager(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Redis key non-exist: {0}")]
    KeyNotFound(String),
}

impl ToRedisArgs for ProofTaskDescriptor {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        let serialized = serde_json::to_string(self).expect("Failed to serialize TaskDescriptor");
        out.write_arg(serialized.as_bytes());
    }
}

impl FromRedisValue for ProofTaskDescriptor {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        let serialized = String::from_redis_value(v)?;
        serde_json::from_str(&serialized).map_err(|_| {
            RedisError::from((
                ErrorKind::TypeError,
                "ProofTaskDescriptor type conversion fail",
            ))
        })
    }
}

impl ToRedisArgs for AggregationTaskDescriptor {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        let serialized =
            serde_json::to_string(self).expect("Failed to serialize AggregationTaskDescriptor");
        out.write_arg(serialized.as_bytes());
    }
}

impl FromRedisValue for AggregationTaskDescriptor {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        let serialized = String::from_redis_value(v)?;
        serde_json::from_str(&serialized).map_err(|_| {
            RedisError::from((
                ErrorKind::TypeError,
                "AggregationTaskDescriptor type conversion fail",
            ))
        })
    }
}

impl ToRedisArgs for TaskProvingStatusRecords {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        let serialized =
            serde_json::to_string(self).expect("Failed to serialize TaskProvingStatusRecords");
        out.write_arg(serialized.as_bytes());
    }
}

impl FromRedisValue for TaskProvingStatusRecords {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        let serialized = String::from_redis_value(v)?;
        serde_json::from_str(&serialized).map_err(|_| {
            RedisError::from((
                ErrorKind::TypeError,
                "TaskProvingStatusRecords type conversion fail",
            ))
        })
    }
}

struct TaskIdDescriptor(ProofKey);

impl ToRedisArgs for TaskIdDescriptor {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        let serialized =
            serde_json::to_string(&self.0).expect("Failed to serialize TaskIDDescriptor");
        out.write_arg(serialized.as_bytes());
    }
}

impl FromRedisValue for TaskIdDescriptor {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        let serialized = String::from_redis_value(v)?;
        let proof_key = serde_json::from_str(&serialized).map_err(|_| {
            RedisError::from((
                ErrorKind::TypeError,
                "TaskIdDescriptor type conversion fail",
            ))
        })?;
        Ok(TaskIdDescriptor(proof_key))
    }
}

#[derive(Debug, Clone, Default)]
pub struct RedisConfig {
    url: String,
    ttl: u64,
}

impl RedisTaskDb {
    fn new(config: RedisConfig) -> RedisDbResult<Self> {
        let url = config.url.clone();
        let client = Client::open(url).map_err(RedisDbError::RedisDb)?;
        Ok(RedisTaskDb { client, config })
    }

    fn get_conn(&mut self) -> Result<redis::Connection, redis::RedisError> {
        let backoff = ExponentialBackoff {
            initial_interval: Duration::from_secs(10),
            max_interval: Duration::from_secs(60),
            max_elapsed_time: Some(Duration::from_secs(300)),
            ..Default::default()
        };

        backoff::retry(backoff, || match self.client.get_connection() {
            Ok(conn) => Ok(conn),
            Err(e) => {
                error!("Failed to connect to redis: {e:?}, retrying...");
                self.client = redis::Client::open(self.config.url.clone())?;
                Err(backoff::Error::Transient {
                    err: e,
                    retry_after: None,
                })
            }
        })
        .map_err(|e| match e {
            backoff::Error::Transient {
                err,
                retry_after: _,
            }
            | backoff::Error::Permanent(err) => err,
        })
    }

    fn insert_proof_task(
        &mut self,
        key: &ProofTaskDescriptor,
        value: &TaskProvingStatusRecords,
    ) -> RedisDbResult<()> {
        self.insert_redis(key, value)
    }

    fn insert_aggregation_task(
        &mut self,
        key: &AggregationTaskDescriptor,
        value: &TaskProvingStatusRecords,
    ) -> RedisDbResult<()> {
        self.insert_redis(key, value)
    }

    fn insert_redis<K, V>(&mut self, key: &K, value: &V) -> RedisDbResult<()>
    where
        K: ToRedisArgs,
        V: ToRedisArgs,
    {
        self.get_conn()?
            .set_ex(key, value, self.config.ttl)
            .map_err(RedisDbError::RedisDb)?;
        Ok(())
    }

    fn query_proof_task(
        &mut self,
        key: &ProofTaskDescriptor,
    ) -> RedisDbResult<Option<TaskProvingStatusRecords>> {
        match self.query_redis(&key) {
            Ok(Some(v)) => {
                if let Some(records) = serde_json::from_str(&v)? {
                    Ok(Some(records))
                } else {
                    error!("Failed to deserialize TaskProvingStatusRecords");
                    Err(RedisDbError::TaskManager(
                        "Failed to deserialize TaskProvingStatusRecords".to_string(),
                    ))
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn query_proof_task_latest_status(
        &mut self,
        key: &ProofTaskDescriptor,
    ) -> RedisDbResult<Option<TaskProvingStatus>> {
        self.query_proof_task(key)
            .map(|v| v.map(|records| records.0.last().unwrap().clone()))
    }

    fn query_aggregation_task(
        &mut self,
        key: &AggregationTaskDescriptor,
    ) -> RedisDbResult<Option<TaskProvingStatusRecords>> {
        match self.query_redis(&key) {
            Ok(Some(v)) => Ok(Some(serde_json::from_str(&v)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn query_aggregation_task_latest_status(
        &mut self,
        key: &AggregationTaskDescriptor,
    ) -> RedisDbResult<Option<TaskProvingStatus>> {
        self.query_aggregation_task(key)
            .map(|v| v.map(|records| records.0.last().unwrap().clone()))
    }

    fn query_redis(&mut self, key: &impl ToRedisArgs) -> RedisDbResult<Option<String>> {
        match self.get_conn()?.get(key) {
            Ok(value) => Ok(Some(value)),
            Err(e) if e.kind() == redis::ErrorKind::TypeError => Ok(None),
            Err(e) => Err(RedisDbError::RedisDb(e)),
        }
    }

    fn delete_redis(&mut self, key: &impl ToRedisArgs) -> RedisDbResult<()> {
        let result: i32 = self.get_conn()?.del(key).map_err(RedisDbError::RedisDb)?;
        if result != 1 {
            return Err(RedisDbError::TaskManager("redis del".to_owned()));
        }
        Ok(())
    }

    fn update_proof_task_status(
        &mut self,
        key: &ProofTaskDescriptor,
        new_status: TaskProvingStatus,
    ) -> RedisDbResult<()> {
        let old_value = self.query_proof_task(key).unwrap_or_default();
        let mut records = match old_value {
            Some(v) => v,
            None => {
                warn!("Update a unknown task: {key:?} to {new_status:?}");
                TaskProvingStatusRecords(vec![])
            }
        };

        records.0.push(new_status);
        let k = serde_json::to_string(&key)?;
        let v = serde_json::to_string(&records)?;

        self.update_status_redis(&k, &v)
    }

    fn update_aggregation_status(
        &mut self,
        key: &AggregationTaskDescriptor,
        new_status: TaskProvingStatus,
    ) -> RedisDbResult<()> {
        let old_value = self.query_aggregation_task(key).unwrap_or_default();
        let mut records = match old_value {
            Some(v) => v,
            None => {
                warn!("Update a unknown task: {key:?} to {new_status:?}");
                TaskProvingStatusRecords(vec![])
            }
        };

        records.0.push(new_status);
        let k = serde_json::to_string(&key)?;
        let v = serde_json::to_string(&records)?;

        self.update_status_redis(&k, &v)
    }

    fn update_status_redis(&mut self, k: &String, v: &String) -> RedisDbResult<()> {
        self.get_conn()?.set_ex(k, v, self.config.ttl)?;
        Ok(())
    }
}

impl RedisTaskDb {
    fn enqueue_task(&mut self, key: &ProofTaskDescriptor) -> RedisDbResult<TaskProvingStatus> {
        let task_status = (TaskStatus::Registered, None, Utc::now());

        match self.query_proof_task(key) {
            Ok(Some(task_proving_records)) => {
                warn!(
                    "Task status exists: {:?}, register again",
                    task_proving_records.0.last()
                );
                self.insert_proof_task(key, &TaskProvingStatusRecords(vec![task_status.clone()]))?;
                Ok(task_status)
            } // do nothing
            Ok(None) => {
                info!("Enqueue new task: {key:?}");
                self.insert_proof_task(key, &TaskProvingStatusRecords(vec![task_status.clone()]))?;
                Ok(task_status)
            }
            Err(e) => {
                error!("Enqueue task failed: {e:?}");
                Err(e)
            }
        }
    }

    fn update_task_progress(
        &mut self,
        key: ProofTaskDescriptor,
        status: TaskStatus,
        proof: Option<&[u8]>,
    ) -> RedisDbResult<()> {
        match self.query_proof_task(&key) {
            Ok(Some(records)) => {
                if let Some(latest) = records.0.last() {
                    if latest.0 != status {
                        let new_statue = (status, proof.map(hex::encode), Utc::now());
                        self.update_proof_task_status(&key, new_statue)?;
                    }
                } else {
                    return Err(RedisDbError::TaskManager(
                        format!("task {key:?} not found").to_owned(),
                    ));
                }
                Ok(())
            }
            Ok(None) => Err(RedisDbError::TaskManager(
                format!("task {key:?} not found").to_owned(),
            )),
            Err(e) => Err(RedisDbError::TaskManager(
                format!("query {key:?} error: {e:?}").to_owned(),
            )),
        }
    }

    fn get_task_proving_status(
        &mut self,
        key: &ProofTaskDescriptor,
    ) -> RedisDbResult<TaskProvingStatusRecords> {
        match self.query_proof_task(key) {
            Ok(Some(records)) => Ok(records),
            Ok(None) => Err(RedisDbError::KeyNotFound(
                format!("task {key:?} not found").to_owned(),
            )),
            Err(e) => Err(RedisDbError::TaskManager(
                format!("query {key:?} error: {e:?}").to_owned(),
            )),
        }
    }

    fn get_task_proof(&mut self, key: &ProofTaskDescriptor) -> RedisDbResult<Vec<u8>> {
        let proving_status_records = self
            .query_proof_task(key)
            .map_err(|e| RedisDbError::TaskManager(format!("query error: {e:?}").to_owned()))?
            .unwrap_or_default();

        let (_, proof, ..) = proving_status_records
            .0
            .iter()
            .filter(|(status, ..)| (status == &TaskStatus::Success))
            .last()
            .ok_or_else(|| {
                RedisDbError::TaskManager(format!("task {key:?} not success.").to_owned())
            })?;

        if let Some(proof_str) = proof {
            hex::decode(proof_str).map_err(|e| {
                RedisDbError::TaskManager(
                    format!("task {key:?} hex decode failed for {e:?}").to_owned(),
                )
            })
        } else {
            Ok(vec![])
        }
    }

    fn prune(&mut self) -> RedisDbResult<()> {
        let keys: Vec<Value> = self.get_conn()?.keys("*").map_err(RedisDbError::RedisDb)?;
        for key in keys.iter() {
            match (
                ProofTaskDescriptor::from_redis_value(key),
                AggregationTaskDescriptor::from_redis_value(key),
            ) {
                (Ok(desc), _) => {
                    self.delete_redis(&desc)?;
                }
                (_, Ok(desc)) => {
                    self.delete_redis(&desc)?;
                }
                _ => (),
            }
        }

        self.prune_stored_ids()?;
        Ok(())
    }

    fn list_all_tasks(&mut self) -> RedisDbResult<Vec<TaskReport>> {
        let mut kvs = Vec::new();
        let keys: Vec<Value> = self.get_conn()?.keys("*").map_err(RedisDbError::RedisDb)?;
        for key in keys.iter() {
            match (
                ProofTaskDescriptor::from_redis_value(key),
                AggregationTaskDescriptor::from_redis_value(key),
            ) {
                (Ok(desc), _) => {
                    let status = self.query_proof_task_latest_status(&desc)?;
                    if let Some(s) = status {
                        kvs.push((TaskDescriptor::SingleProof(desc), s.0))
                    }
                }
                (_, Ok(desc)) => {
                    let status = self.query_aggregation_task_latest_status(&desc)?;
                    if let Some(s) = status {
                        kvs.push((TaskDescriptor::Aggregation(desc), s.0))
                    }
                }
                _ => (),
            }
        }

        Ok(kvs)
    }

    fn enqueue_aggregation_task(&mut self, request: &AggregationOnlyRequest) -> RedisDbResult<()> {
        let task_status = (TaskStatus::Registered, None, Utc::now());
        let agg_task_descriptor = request
            .try_into()
            .map_err(|e: String| RedisDbError::TaskManager(e))?;
        match self.query_aggregation_task(&agg_task_descriptor)? {
            Some(task_proving_records) => {
                info!(
                    "Task already exists: {:?}",
                    task_proving_records.0.last().unwrap().0
                );
            } // do nothing
            None => {
                info!("Enqueue new aggregation task: {request}");
                self.insert_aggregation_task(
                    &agg_task_descriptor,
                    &TaskProvingStatusRecords(vec![task_status]),
                )?;
            }
        }
        Ok(())
    }

    fn get_aggregation_task_proving_status(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> RedisDbResult<TaskProvingStatusRecords> {
        let agg_task_descriptor = request
            .try_into()
            .map_err(|e: String| RedisDbError::TaskManager(e))?;
        match self.query_aggregation_task(&agg_task_descriptor)? {
            Some(records) => Ok(records),
            None => Err(RedisDbError::KeyNotFound(
                format!("task {agg_task_descriptor:?} not found").to_owned(),
            )),
        }
    }

    fn update_aggregation_task_progress(
        &mut self,
        request: &AggregationOnlyRequest,
        status: TaskStatus,
        proof: Option<&[u8]>,
    ) -> RedisDbResult<()> {
        let agg_task_descriptor = request
            .try_into()
            .map_err(|e: String| RedisDbError::TaskManager(e))?;
        match self.query_aggregation_task(&agg_task_descriptor)? {
            Some(records) => {
                if let Some(latest) = records.0.last() {
                    if latest.0 != status {
                        let new_record = (status, proof.map(hex::encode), Utc::now());
                        self.update_aggregation_status(&agg_task_descriptor, new_record)?;
                    }
                } else {
                    return Err(RedisDbError::TaskManager(
                        format!("task {agg_task_descriptor:?} not found").to_owned(),
                    ));
                }
                Ok(())
            }
            None => Err(RedisDbError::TaskManager(
                format!("task {agg_task_descriptor:?} not found").to_owned(),
            )),
        }
    }

    fn get_aggregation_task_proof(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> RedisDbResult<Vec<u8>> {
        let agg_task_descriptor = request
            .try_into()
            .map_err(|e: String| RedisDbError::TaskManager(e))?;
        let proving_status_records = self
            .query_aggregation_task(&agg_task_descriptor)?
            .unwrap_or_default();

        let (_, proof, ..) = proving_status_records
            .0
            .iter()
            .filter(|(status, ..)| (status == &TaskStatus::Success))
            .last()
            .ok_or_else(|| {
                RedisDbError::TaskManager(
                    format!("task {agg_task_descriptor:?} not found").to_owned(),
                )
            })?;

        if let Some(proof) = proof {
            hex::decode(proof).map_err(|e| {
                RedisDbError::TaskManager(
                    format!("task {agg_task_descriptor:?} hex decode failed for {e:?}").to_owned(),
                )
            })
        } else {
            Ok(vec![])
        }
    }

    fn get_db_size(&self) -> TaskManagerResult<(usize, Vec<(String, usize)>)> {
        // todo
        Ok((0, vec![]))
    }

    fn prune_aggregation(&mut self) -> RedisDbResult<()> {
        let keys: Vec<Value> = self.get_conn()?.keys("*").map_err(RedisDbError::RedisDb)?;
        for key in keys.iter() {
            if let Ok(desc) = AggregationTaskDescriptor::from_redis_value(key) {
                self.delete_redis(&desc)?;
            }
        }
        Ok(())
    }

    fn list_all_aggregation_tasks(&mut self) -> RedisDbResult<Vec<AggregationTaskReport>> {
        let mut kvs: Vec<AggregationTaskReport> = Vec::new();
        let keys: Vec<Value> = self.get_conn()?.keys("*").map_err(RedisDbError::RedisDb)?;
        for key in keys.iter() {
            if let Ok(desc) = AggregationTaskDescriptor::from_redis_value(key) {
                let status = self.query_aggregation_task_latest_status(&desc)?;
                if let Some(s) = status {
                    kvs.push((
                        AggregationOnlyRequest {
                            aggregation_ids: desc.aggregation_ids,
                            proof_type: desc.proof_type,
                            ..Default::default()
                        },
                        s.0,
                    ));
                }
            }
        }
        Ok(kvs)
    }
}

impl RedisTaskDb {
    fn store_id(&mut self, key: ProofKey, id: String) -> RedisDbResult<()> {
        self.insert_redis(&TaskIdDescriptor(key), &id)
    }

    fn remove_id(&mut self, key: ProofKey) -> RedisDbResult<()> {
        self.delete_redis(&TaskIdDescriptor(key))
    }

    fn read_id(&mut self, key: ProofKey) -> RedisDbResult<String> {
        match self.query_redis(&TaskIdDescriptor(key)) {
            Ok(Some(v)) => Ok(v),
            Ok(None) => Err(RedisDbError::TaskManager(
                format!("id {key:?} not found").to_owned(),
            )),
            Err(e) => Err(RedisDbError::TaskManager(
                format!("id {key:?} query error: {e:?}").to_owned(),
            )),
        }
    }

    fn list_stored_ids(&mut self) -> RedisDbResult<Vec<(ProofKey, String)>> {
        let mut kvs = Vec::new();
        let keys: Vec<Value> = self.get_conn()?.keys("*").map_err(RedisDbError::RedisDb)?;
        for key in keys.iter() {
            if let Ok(desc) = TaskIdDescriptor::from_redis_value(key) {
                let status = self.query_redis(&desc)?;
                if let Some(s) = status {
                    kvs.push((desc.0, s));
                }
            }
        }
        Ok(kvs)
    }

    fn prune_stored_ids(&mut self) -> RedisDbResult<()> {
        let keys: Vec<Value> = self.get_conn()?.keys("*").map_err(RedisDbError::RedisDb)?;
        for key in keys.iter() {
            if let Ok(desc) = TaskIdDescriptor::from_redis_value(key) {
                self.delete_redis(&desc)?;
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl IdStore for RedisTaskManager {
    async fn read_id(&self, key: ProofKey) -> ProverResult<String> {
        let mut db = self.arc_task_db.lock().await;
        db.read_id(key)
            .map_err(|e| ProverError::StoreError(e.to_string()))
    }
}

#[async_trait::async_trait]
impl IdWrite for RedisTaskManager {
    async fn store_id(&mut self, key: ProofKey, id: String) -> ProverResult<()> {
        let mut db = self.arc_task_db.lock().await;
        db.store_id(key, id)
            .map_err(|e| ProverError::StoreError(e.to_string()))
    }

    async fn remove_id(&mut self, key: ProofKey) -> ProverResult<()> {
        let mut db = self.arc_task_db.lock().await;
        db.remove_id(key)
            .map_err(|e| ProverError::StoreError(e.to_string()))
    }
}

#[async_trait::async_trait]
impl TaskManager for RedisTaskManager {
    #[cfg(not(test))]
    fn new(opts: &TaskManagerOpts) -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        static mut REDIS_DB: Option<Arc<Mutex<RedisTaskDb>>> = None;
        INIT.call_once(|| {
            unsafe {
                REDIS_DB = Some(Arc::new(Mutex::new(
                    RedisTaskDb::new(RedisConfig {
                        url: opts.redis_url.clone(),
                        ttl: opts.redis_ttl,
                    })
                    .unwrap(),
                )))
            };
        });
        Self {
            arc_task_db: unsafe { REDIS_DB.clone().unwrap() },
        }
    }
    #[cfg(test)]
    fn new(opts: &TaskManagerOpts) -> Self {
        Self {
            arc_task_db: Arc::new(Mutex::new(
                RedisTaskDb::new(RedisConfig {
                    url: opts.redis_url.clone(),
                    ttl: opts.redis_ttl.clone(),
                })
                .unwrap(),
            )),
        }
    }

    async fn enqueue_task(
        &mut self,
        params: &ProofTaskDescriptor,
    ) -> Result<TaskProvingStatusRecords, TaskManagerError> {
        let mut task_db = self.arc_task_db.lock().await;
        let enq_status = task_db.enqueue_task(params)?;
        Ok(TaskProvingStatusRecords(vec![enq_status]))
    }

    async fn update_task_progress(
        &mut self,
        key: ProofTaskDescriptor,
        status: TaskStatus,
        proof: Option<&[u8]>,
    ) -> TaskManagerResult<()> {
        let mut task_db = self.arc_task_db.lock().await;
        task_db.update_task_progress(key, status, proof)?;
        Ok(())
    }

    /// Returns the latest triplet (submitter or fulfiller, status, last update time)
    async fn get_task_proving_status(
        &mut self,
        key: &ProofTaskDescriptor,
    ) -> TaskManagerResult<TaskProvingStatusRecords> {
        let mut task_db = self.arc_task_db.lock().await;
        match task_db.get_task_proving_status(key) {
            Ok(records) => Ok(records),
            Err(RedisDbError::KeyNotFound(_)) => Ok(TaskProvingStatusRecords(vec![])),
            Err(e) => Err(TaskManagerError::RedisError(e)),
        }
    }

    async fn get_task_proof(&mut self, key: &ProofTaskDescriptor) -> TaskManagerResult<Vec<u8>> {
        let mut task_db = self.arc_task_db.lock().await;
        let proof = task_db.get_task_proof(key)?;
        Ok(proof)
    }

    /// Returns the total and detailed database size
    async fn get_db_size(&mut self) -> TaskManagerResult<(usize, Vec<(String, usize)>)> {
        let task_db = self.arc_task_db.lock().await;
        let res = task_db.get_db_size()?;
        Ok(res)
    }

    async fn prune_db(&mut self) -> TaskManagerResult<()> {
        let mut task_db = self.arc_task_db.lock().await;
        task_db.prune().map_err(TaskManagerError::RedisError)
    }

    async fn list_all_tasks(&mut self) -> TaskManagerResult<Vec<TaskReport>> {
        let mut task_db = self.arc_task_db.lock().await;
        task_db
            .list_all_tasks()
            .map_err(TaskManagerError::RedisError)
    }

    async fn list_stored_ids(&mut self) -> TaskManagerResult<Vec<(ProofKey, String)>> {
        let mut task_db = self.arc_task_db.lock().await;
        task_db
            .list_stored_ids()
            .map_err(TaskManagerError::RedisError)
    }

    async fn enqueue_aggregation_task(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<()> {
        let mut task_db = self.arc_task_db.lock().await;
        task_db
            .enqueue_aggregation_task(request)
            .map_err(TaskManagerError::RedisError)
    }

    async fn get_aggregation_task_proving_status(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<TaskProvingStatusRecords> {
        let mut task_db = self.arc_task_db.lock().await;
        match task_db.get_aggregation_task_proving_status(request) {
            Ok(records) => Ok(records),
            Err(RedisDbError::KeyNotFound(_)) => Ok(TaskProvingStatusRecords(vec![])),
            Err(e) => Err(TaskManagerError::RedisError(e)),
        }
    }

    async fn update_aggregation_task_progress(
        &mut self,
        request: &AggregationOnlyRequest,
        status: TaskStatus,
        proof: Option<&[u8]>,
    ) -> TaskManagerResult<()> {
        let mut task_db = self.arc_task_db.lock().await;
        task_db
            .update_aggregation_task_progress(request, status, proof)
            .map_err(TaskManagerError::RedisError)
    }

    async fn get_aggregation_task_proof(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<Vec<u8>> {
        let mut task_db = self.arc_task_db.lock().await;
        task_db
            .get_aggregation_task_proof(request)
            .map_err(TaskManagerError::RedisError)
    }

    async fn prune_aggregation_db(&mut self) -> TaskManagerResult<()> {
        let mut task_db = self.arc_task_db.lock().await;
        task_db
            .prune_aggregation()
            .map_err(TaskManagerError::RedisError)
    }

    async fn list_all_aggregation_tasks(
        &mut self,
    ) -> TaskManagerResult<Vec<AggregationTaskReport>> {
        let mut task_db = self.arc_task_db.lock().await;
        task_db
            .list_all_aggregation_tasks()
            .map_err(TaskManagerError::RedisError)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;

    use super::*;
    use crate::ProofType;

    #[test]
    fn test_db_enqueue() {
        let mut db = RedisTaskDb::new(RedisConfig {
            url: "redis://localhost:6379".to_owned(),
            ttl: 3600,
        })
        .unwrap();
        let params = ProofTaskDescriptor {
            chain_id: 1,
            block_id: 1,
            blockhash: B256::default(),
            proof_system: ProofType::Native,
            prover: "0x1234".to_owned(),
            image_id: None,
        };
        db.enqueue_task(&params).expect("enqueue task failed");
        let status = db.get_task_proving_status(&params);
        assert!(status.is_ok());
    }

    #[test]
    fn test_db_enqueue_and_prune() {
        let mut db = RedisTaskDb::new(RedisConfig {
            url: "redis://localhost:6379".to_owned(),
            ttl: 3600,
        })
        .unwrap();
        let params = ProofTaskDescriptor {
            chain_id: 1,
            block_id: 1,
            blockhash: B256::default(),
            proof_system: ProofType::Native,
            prover: "0x1234".to_owned(),
            image_id: None,
        };
        db.enqueue_task(&params).expect("enqueue task failed");
        let status = db.get_task_proving_status(&params);
        assert!(status.is_ok());

        db.prune().expect("prune failed");
        let status = db.get_task_proving_status(&params);
        assert!(status.is_err());
    }

    #[test]
    fn test_db_id_operatioins() {
        let mut db = RedisTaskDb::new(RedisConfig {
            url: "redis://localhost:6379".to_owned(),
            ttl: 3600,
        })
        .unwrap();
        db.prune_stored_ids().expect("prune ids failed");
        let store_ids = db.list_stored_ids().expect("list ids failed");
        assert_eq!(store_ids.len(), 0);

        let params = (1, 1, B256::random(), 1);
        db.store_id(params, "1-2-3-4".to_owned())
            .expect("store id failed");
        let store_ids = db.list_stored_ids().expect("list ids failed");
        assert_eq!(store_ids.len(), 1);

        db.remove_id(params).expect("remove id failed");
        let store_ids = db.list_stored_ids().expect("list ids failed");
        assert_eq!(store_ids.len(), 0);
    }
}
