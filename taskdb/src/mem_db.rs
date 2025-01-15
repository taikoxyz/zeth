// Raiko
// Copyright (c) 2024 Taiko Labs
// Licensed and distributed under either of
//   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
//   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
// at your option. This file may not be copied, modified, or distributed except according to those terms.

// Imports
// ----------------------------------------------------------------
use std::{
    collections::HashMap,
    sync::{Arc, Once},
};

use chrono::Utc;
use raiko_core::interfaces::AggregationOnlyRequest;
use raiko_lib::prover::{IdStore, IdWrite, ProofKey, ProverError, ProverResult};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::{
    ensure, AggregationTaskDescriptor, AggregationTaskReport, ProofTaskDescriptor, TaskDescriptor,
    TaskManager, TaskManagerError, TaskManagerOpts, TaskManagerResult, TaskProvingStatusRecords,
    TaskReport, TaskStatus,
};

#[derive(Debug)]
pub struct InMemoryTaskManager {
    db: Arc<Mutex<InMemoryTaskDb>>,
}

#[derive(Debug)]
pub struct InMemoryTaskDb {
    tasks_queue: HashMap<ProofTaskDescriptor, TaskProvingStatusRecords>,
    aggregation_tasks_queue: HashMap<AggregationOnlyRequest, TaskProvingStatusRecords>,
    store: HashMap<ProofKey, String>,
}

impl InMemoryTaskDb {
    fn new() -> InMemoryTaskDb {
        InMemoryTaskDb {
            tasks_queue: HashMap::new(),
            aggregation_tasks_queue: HashMap::new(),
            store: HashMap::new(),
        }
    }

    fn enqueue_task(&mut self, key: &ProofTaskDescriptor) -> TaskManagerResult<()> {
        let task_status = (TaskStatus::Registered, None, Utc::now());

        match self.tasks_queue.get(key) {
            Some(task_proving_records) => {
                let previous_status = &task_proving_records.0.last().unwrap().0;
                warn!("Task already exists: {key:?} with previous statuw {previous_status:?}");
                if previous_status != &TaskStatus::Success {
                    self.update_task_progress(key.clone(), TaskStatus::Registered, None)?;
                }
            } // do nothing
            None => {
                info!("Enqueue new task: {key:?}");
                self.tasks_queue
                    .insert(key.clone(), TaskProvingStatusRecords(vec![task_status]));
            }
        }

        Ok(())
    }

    fn update_task_progress(
        &mut self,
        key: ProofTaskDescriptor,
        status: TaskStatus,
        proof: Option<&[u8]>,
    ) -> TaskManagerResult<()> {
        ensure(self.tasks_queue.contains_key(&key), "no task found")?;

        self.tasks_queue.entry(key).and_modify(|entry| {
            if let Some(latest) = entry.0.last() {
                if latest.0 != status {
                    entry.0.push((status, proof.map(hex::encode), Utc::now()));
                }
            }
        });

        Ok(())
    }

    fn get_task_proving_status(
        &mut self,
        key: &ProofTaskDescriptor,
    ) -> TaskManagerResult<TaskProvingStatusRecords> {
        Ok(self.tasks_queue.get(key).cloned().unwrap_or_default())
    }

    fn get_task_proof(&mut self, key: &ProofTaskDescriptor) -> TaskManagerResult<Vec<u8>> {
        ensure(self.tasks_queue.contains_key(key), "no task found")?;

        let proving_status_records = self
            .tasks_queue
            .get(key)
            .ok_or_else(|| TaskManagerError::Anyhow("no task in db".to_owned()))?;

        let (_, proof, ..) = proving_status_records
            .0
            .iter()
            .filter(|(status, ..)| (status == &TaskStatus::Success))
            .last()
            .ok_or_else(|| TaskManagerError::Anyhow("no successful task in db".to_owned()))?;

        let Some(proof) = proof else {
            return Ok(vec![]);
        };

        hex::decode(proof)
            .map_err(|_| TaskManagerError::Anyhow("couldn't decode from hex".to_owned()))
    }

    fn size(&mut self) -> TaskManagerResult<(usize, Vec<(String, usize)>)> {
        Ok((self.tasks_queue.len(), vec![]))
    }

    fn prune(&mut self) -> TaskManagerResult<()> {
        self.tasks_queue.clear();
        Ok(())
    }

    fn list_all_tasks(&mut self) -> TaskManagerResult<Vec<TaskReport>> {
        let single_proofs = self.tasks_queue.iter().filter_map(|(desc, statuses)| {
            statuses
                .0
                .last()
                .map(|s| (TaskDescriptor::SingleProof(desc.clone()), s.0.clone()))
        });

        let aggregations = self
            .aggregation_tasks_queue
            .iter()
            .filter_map(|(desc, statuses)| {
                statuses.0.last().map(|s| {
                    (
                        TaskDescriptor::Aggregation(AggregationTaskDescriptor::from(desc)),
                        s.0.clone(),
                    )
                })
            });

        Ok(single_proofs.chain(aggregations).collect())
    }

    fn list_stored_ids(&mut self) -> TaskManagerResult<Vec<(ProofKey, String)>> {
        Ok(self.store.iter().map(|(k, v)| (*k, v.clone())).collect())
    }

    fn store_id(&mut self, key: ProofKey, id: String) -> TaskManagerResult<()> {
        self.store.insert(key, id);
        Ok(())
    }

    fn remove_id(&mut self, key: ProofKey) -> TaskManagerResult<()> {
        self.store.remove(&key);
        Ok(())
    }

    fn read_id(&mut self, key: ProofKey) -> TaskManagerResult<String> {
        self.store
            .get(&key)
            .cloned()
            .ok_or(TaskManagerError::NoData)
    }

    fn enqueue_aggregation_task(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<()> {
        let task_status = (TaskStatus::Registered, None, Utc::now());

        match self.aggregation_tasks_queue.get(request) {
            Some(task_proving_records) => {
                let previous_status = &task_proving_records.0.last().unwrap().0;
                warn!("Task already exists: {request} with previous status {previous_status:?}");
                if previous_status != &TaskStatus::Success {
                    self.update_aggregation_task_progress(request, TaskStatus::Registered, None)?;
                }
            } // do nothing
            None => {
                info!("Enqueue new task: {request}");
                self.aggregation_tasks_queue
                    .insert(request.clone(), TaskProvingStatusRecords(vec![task_status]));
            }
        }
        Ok(())
    }

    fn get_aggregation_task_proving_status(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<TaskProvingStatusRecords> {
        Ok(self
            .aggregation_tasks_queue
            .get(request)
            .cloned()
            .unwrap_or_default())
    }

    fn update_aggregation_task_progress(
        &mut self,
        request: &AggregationOnlyRequest,
        status: TaskStatus,
        proof: Option<&[u8]>,
    ) -> TaskManagerResult<()> {
        ensure(
            self.aggregation_tasks_queue.contains_key(request),
            "no task found",
        )?;

        self.aggregation_tasks_queue
            .entry(request.clone())
            .and_modify(|entry| {
                if let Some(latest) = entry.0.last() {
                    if latest.0 != status {
                        entry.0.push((status, proof.map(hex::encode), Utc::now()));
                    }
                }
            });

        Ok(())
    }

    fn get_aggregation_task_proof(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<Vec<u8>> {
        ensure(
            self.aggregation_tasks_queue.contains_key(request),
            "no task found",
        )?;

        let proving_status_records = self
            .aggregation_tasks_queue
            .get(request)
            .ok_or_else(|| TaskManagerError::Anyhow("no task in db".to_owned()))?;

        let (_, proof, ..) = proving_status_records
            .0
            .iter()
            .filter(|(status, ..)| (status == &TaskStatus::Success))
            .last()
            .ok_or_else(|| TaskManagerError::Anyhow("no successful task in db".to_owned()))?;

        let Some(proof) = proof else {
            return Ok(vec![]);
        };

        hex::decode(proof)
            .map_err(|_| TaskManagerError::Anyhow("couldn't decode from hex".to_owned()))
    }

    fn prune_aggregation(&mut self) -> TaskManagerResult<()> {
        self.aggregation_tasks_queue.clear();
        Ok(())
    }

    fn list_all_aggregation_tasks(&mut self) -> TaskManagerResult<Vec<AggregationTaskReport>> {
        Ok(self
            .aggregation_tasks_queue
            .iter()
            .flat_map(|(request, statuses)| {
                statuses
                    .0
                    .last()
                    .map(|status| (request.clone(), status.0.clone()))
            })
            .collect())
    }
}

#[async_trait::async_trait]
impl IdWrite for InMemoryTaskManager {
    async fn store_id(&mut self, key: ProofKey, id: String) -> ProverResult<()> {
        let mut db = self.db.lock().await;
        db.store_id(key, id)
            .map_err(|e| ProverError::StoreError(e.to_string()))
    }

    async fn remove_id(&mut self, key: ProofKey) -> ProverResult<()> {
        let mut db = self.db.lock().await;
        db.remove_id(key)
            .map_err(|e| ProverError::StoreError(e.to_string()))
    }
}

#[async_trait::async_trait]
impl IdStore for InMemoryTaskManager {
    async fn read_id(&mut self, key: ProofKey) -> ProverResult<String> {
        let mut db = self.db.lock().await;
        db.read_id(key)
            .map_err(|e| ProverError::StoreError(e.to_string()))
    }
}

#[async_trait::async_trait]
impl TaskManager for InMemoryTaskManager {
    fn new(_opts: &TaskManagerOpts) -> Self {
        static INIT: Once = Once::new();
        static mut SHARED_TASK_MANAGER: Option<Arc<Mutex<InMemoryTaskDb>>> = None;

        INIT.call_once(|| {
            let task_manager: Arc<Mutex<InMemoryTaskDb>> =
                Arc::new(Mutex::new(InMemoryTaskDb::new()));
            unsafe {
                SHARED_TASK_MANAGER = Some(Arc::clone(&task_manager));
            }
        });

        InMemoryTaskManager {
            db: unsafe { SHARED_TASK_MANAGER.clone().unwrap() },
        }
    }

    async fn enqueue_task(
        &mut self,
        params: &ProofTaskDescriptor,
    ) -> TaskManagerResult<TaskProvingStatusRecords> {
        let mut db = self.db.lock().await;
        let status = db.get_task_proving_status(params)?;
        if !status.0.is_empty() {
            return Ok(status);
        }

        db.enqueue_task(params)?;
        db.get_task_proving_status(params)
    }

    async fn update_task_progress(
        &mut self,
        key: ProofTaskDescriptor,
        status: TaskStatus,
        proof: Option<&[u8]>,
    ) -> TaskManagerResult<()> {
        let mut db = self.db.lock().await;
        db.update_task_progress(key, status, proof)
    }

    /// Returns the latest triplet (submitter or fulfiller, status, last update time)
    async fn get_task_proving_status(
        &mut self,
        key: &ProofTaskDescriptor,
    ) -> TaskManagerResult<TaskProvingStatusRecords> {
        let mut db = self.db.lock().await;
        db.get_task_proving_status(key)
    }

    async fn get_task_proof(&mut self, key: &ProofTaskDescriptor) -> TaskManagerResult<Vec<u8>> {
        let mut db = self.db.lock().await;
        db.get_task_proof(key)
    }

    /// Returns the total and detailed database size
    async fn get_db_size(&mut self) -> TaskManagerResult<(usize, Vec<(String, usize)>)> {
        let mut db = self.db.lock().await;
        db.size()
    }

    async fn prune_db(&mut self) -> TaskManagerResult<()> {
        let mut db = self.db.lock().await;
        db.prune()
    }

    async fn list_all_tasks(&mut self) -> TaskManagerResult<Vec<TaskReport>> {
        let mut db = self.db.lock().await;
        db.list_all_tasks()
    }

    async fn list_stored_ids(&mut self) -> TaskManagerResult<Vec<(ProofKey, String)>> {
        let mut db = self.db.lock().await;
        db.list_stored_ids()
    }

    async fn enqueue_aggregation_task(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<()> {
        let mut db = self.db.lock().await;
        db.enqueue_aggregation_task(request)
    }

    async fn get_aggregation_task_proving_status(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<TaskProvingStatusRecords> {
        let mut db = self.db.lock().await;
        db.get_aggregation_task_proving_status(request)
    }

    async fn update_aggregation_task_progress(
        &mut self,
        request: &AggregationOnlyRequest,
        status: TaskStatus,
        proof: Option<&[u8]>,
    ) -> TaskManagerResult<()> {
        let mut db = self.db.lock().await;
        db.update_aggregation_task_progress(request, status, proof)
    }

    async fn get_aggregation_task_proof(
        &mut self,
        request: &AggregationOnlyRequest,
    ) -> TaskManagerResult<Vec<u8>> {
        let mut db = self.db.lock().await;
        db.get_aggregation_task_proof(request)
    }

    async fn prune_aggregation_db(&mut self) -> TaskManagerResult<()> {
        let mut db = self.db.lock().await;
        db.prune_aggregation()
    }

    async fn list_all_aggregation_tasks(
        &mut self,
    ) -> TaskManagerResult<Vec<AggregationTaskReport>> {
        let mut db = self.db.lock().await;
        db.list_all_aggregation_tasks()
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;

    use super::*;
    use crate::ProofType;

    #[test]
    fn test_db_open() {
        assert!(InMemoryTaskDb::new().size().is_ok());
    }

    #[test]
    fn test_db_enqueue() {
        let mut db = InMemoryTaskDb::new();
        let params = ProofTaskDescriptor {
            chain_id: 1,
            block_id: 1,
            blockhash: B256::default(),
            proof_system: ProofType::Native,
            prover: "0x1234".to_owned(),
        };
        db.enqueue_task(&params).expect("enqueue task");
        let status = db.get_task_proving_status(&params);
        assert!(status.is_ok());
    }
}
