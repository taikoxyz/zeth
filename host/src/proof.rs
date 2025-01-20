use std::{
    collections::{HashMap, VecDeque},
    str::FromStr,
    sync::Arc,
};

use raiko_core::{
    interfaces::{
        aggregate_proofs, cancel_proof, AggregationOnlyRequest, ProofRequest, RaikoError,
    },
    provider::{get_task_data, rpc::RpcBlockDataProvider},
    Raiko,
};
use raiko_lib::{
    consts::SupportedChainSpecs,
    input::{AggregationGuestInput, AggregationGuestOutput},
    proof_type::ProofType,
    prover::{IdWrite, Proof},
    Measurement,
};
use raiko_tasks::{
    get_task_manager, ProofTaskDescriptor, TaskManager, TaskManagerWrapperImpl, TaskStatus,
};
use reth_primitives::B256;
use tokio::{
    select,
    sync::{
        mpsc::{Receiver, Sender},
        Mutex, OwnedSemaphorePermit, Semaphore,
    },
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{
    cache,
    interfaces::{HostError, HostResult},
    memory,
    metrics::{
        inc_guest_error, inc_guest_success, inc_host_error, observe_guest_time,
        observe_prepare_input_time, observe_total_time,
    },
    Message, Opts,
};

pub struct ProofActor {
    opts: Opts,
    chain_specs: SupportedChainSpecs,
    aggregate_tasks: Arc<Mutex<HashMap<AggregationOnlyRequest, CancellationToken>>>,
    running_tasks: Arc<Mutex<HashMap<ProofTaskDescriptor, CancellationToken>>>,
    pending_tasks: Arc<Mutex<VecDeque<ProofRequest>>>,
    receiver: Receiver<Message>,
    sender: Sender<Message>,
}

impl ProofActor {
    pub fn new(
        sender: Sender<Message>,
        receiver: Receiver<Message>,
        opts: Opts,
        chain_specs: SupportedChainSpecs,
    ) -> Self {
        let running_tasks = Arc::new(Mutex::new(
            HashMap::<ProofTaskDescriptor, CancellationToken>::new(),
        ));
        let aggregate_tasks = Arc::new(Mutex::new(HashMap::<
            AggregationOnlyRequest,
            CancellationToken,
        >::new()));
        let pending_tasks = Arc::new(Mutex::new(VecDeque::<ProofRequest>::new()));

        Self {
            opts,
            chain_specs,
            aggregate_tasks,
            running_tasks,
            pending_tasks,
            receiver,
            sender,
        }
    }

    pub async fn cancel_task(&mut self, key: ProofTaskDescriptor) -> HostResult<()> {
        let task = {
            let tasks_map = self.running_tasks.lock().await;
            match tasks_map.get(&key) {
                Some(task) => task.to_owned(),
                None => {
                    warn!("No task with those keys to cancel");
                    return Ok(());
                }
            }
        };

        let mut manager = get_task_manager(&self.opts.clone().into());
        cancel_proof(
            key.proof_system,
            (
                key.chain_id,
                key.block_id,
                key.blockhash,
                key.proof_system as u8,
            ),
            Box::new(&mut manager),
        )
        .await
        .or_else(|e| {
            if e.to_string().contains("No data for query") {
                warn!("Task already cancelled or not yet started!");
                Ok(())
            } else {
                Err::<(), HostError>(e.into())
            }
        })?;
        task.cancel();
        Ok(())
    }

    pub async fn run_task(&mut self, proof_request: ProofRequest) {
        let cancel_token = CancellationToken::new();

        let (chain_id, blockhash) = match get_task_data(
            &proof_request.network,
            proof_request.block_number,
            &self.chain_specs,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                error!("Could not get task data for {proof_request:?}, error: {e}");
                return;
            }
        };

        let key = ProofTaskDescriptor::from((
            chain_id,
            proof_request.block_number,
            blockhash,
            proof_request.proof_type,
            proof_request.prover.clone().to_string(),
        ));

        {
            let mut tasks = self.running_tasks.lock().await;
            tasks.insert(key.clone(), cancel_token.clone());
        }

        let sender = self.sender.clone();
        let tasks = self.running_tasks.clone();
        let opts = self.opts.clone();
        let chain_specs = self.chain_specs.clone();

        tokio::spawn(async move {
            select! {
                _ = cancel_token.cancelled() => {
                    info!("Task cancelled");
                }
                result = Self::handle_message(proof_request.clone(), key.clone(), &opts, &chain_specs) => {
                    match result {
                        Ok(status) => {
                            info!("Host handling message: {status:?}");
                        }
                        Err(error) => {
                            error!("Worker failed due to: {error:?}");
                        }
                    };
                }
            }
            let mut tasks = tasks.lock().await;
            tasks.remove(&key);
            // notify complete task to let next pending task run
            sender
                .send(Message::TaskComplete(proof_request))
                .await
                .expect("Couldn't send message");
        });
    }

    pub async fn cancel_aggregation_task(
        &mut self,
        request: AggregationOnlyRequest,
    ) -> HostResult<()> {
        let tasks_map = self.aggregate_tasks.lock().await;
        let Some(task) = tasks_map.get(&request) else {
            warn!("No task with those keys to cancel");
            return Ok(());
        };

        // TODO:(petar) implement cancel_proof_aggregation
        // let mut manager = get_task_manager(&self.opts.clone().into());
        // let proof_type = ProofType::from_str(
        //     request
        //         .proof_type
        //         .as_ref()
        //         .ok_or_else(|| anyhow!("No proof type"))?,
        // )?;
        // proof_type
        //     .cancel_proof_aggregation(request, Box::new(&mut manager))
        //     .await
        //     .or_else(|e| {
        //         if e.to_string().contains("No data for query") {
        //             warn!("Task already cancelled or not yet started!");
        //             Ok(())
        //         } else {
        //             Err::<(), HostError>(e.into())
        //         }
        //     })?;
        task.cancel();
        Ok(())
    }

    pub async fn run_aggregate(
        &mut self,
        request: AggregationOnlyRequest,
        _permit: OwnedSemaphorePermit,
    ) {
        let cancel_token = CancellationToken::new();

        let mut tasks = self.aggregate_tasks.lock().await;
        tasks.insert(request.clone(), cancel_token.clone());

        let request_clone = request.clone();
        let tasks = self.aggregate_tasks.clone();
        let opts = self.opts.clone();

        tokio::spawn(async move {
            select! {
                _ = cancel_token.cancelled() => {
                    info!("Task cancelled");
                }
                result = Self::handle_aggregate(request_clone, &opts) => {
                    match result {
                        Ok(status) => {
                            info!("Host handling message: {status:?}");
                        }
                        Err(error) => {
                            error!("Worker failed due to: {error:?}");
                        }
                    };
                }
            }
            let mut tasks = tasks.lock().await;
            tasks.remove(&request);
        });
    }

    pub async fn run(&mut self) {
        // recv() is protected by outside mpsc, no lock needed here
        let semaphore = Arc::new(Semaphore::new(self.opts.concurrency_limit));
        while let Some(message) = self.receiver.recv().await {
            match message {
                Message::Cancel(key) => {
                    debug!("Message::Cancel({key:?})");
                    if let Err(error) = self.cancel_task(key).await {
                        error!("Failed to cancel task: {error}")
                    }
                }
                Message::Task(proof_request) => {
                    debug!("Message::Task({proof_request:?})");
                    let running_task_count = self.running_tasks.lock().await.len();
                    if running_task_count < self.opts.concurrency_limit {
                        info!("Running task {proof_request:?}");
                        self.run_task(proof_request).await;
                    } else {
                        info!(
                            "Task concurrency status: running:{running_task_count:?}, add {proof_request:?} to pending list[{:?}]",
                            self.pending_tasks.lock().await.len()
                        );
                        let mut pending_tasks = self.pending_tasks.lock().await;
                        pending_tasks.push_back(proof_request);
                    }
                }
                Message::TaskComplete(req) => {
                    // pop up pending task if any task complete
                    debug!("Message::TaskComplete({req:?})");
                    info!(
                        "task {req:?} completed, current running {:?}, pending: {:?}",
                        self.running_tasks.lock().await.len(),
                        self.pending_tasks.lock().await.len()
                    );
                    let mut pending_tasks = self.pending_tasks.lock().await;
                    if let Some(proof_request) = pending_tasks.pop_front() {
                        info!("Pop out pending task {proof_request:?}");
                        self.sender
                            .send(Message::Task(proof_request))
                            .await
                            .expect("Couldn't send message");
                    }
                }
                Message::CancelAggregate(request) => {
                    debug!("Message::CancelAggregate({request:?})");
                    if let Err(error) = self.cancel_aggregation_task(request).await {
                        error!("Failed to cancel task: {error}")
                    }
                }
                Message::Aggregate(request) => {
                    debug!("Message::Aggregate({request:?})");
                    let permit = Arc::clone(&semaphore)
                        .acquire_owned()
                        .await
                        .expect("Couldn't acquire permit");
                    self.run_aggregate(request, permit).await;
                }
                Message::SystemPause(notifier) => {
                    let result = self.handle_system_pause().await;
                    let _ = notifier.send(result);
                }
            }
        }
    }

    pub async fn handle_message(
        proof_request: ProofRequest,
        key: ProofTaskDescriptor,
        opts: &Opts,
        chain_specs: &SupportedChainSpecs,
    ) -> HostResult<TaskStatus> {
        let mut manager = get_task_manager(&opts.clone().into());

        let status = manager.get_task_proving_status(&key).await?;

        if let Some(latest_status) = status.0.iter().last() {
            if !matches!(latest_status.0, TaskStatus::Registered) {
                return Ok(latest_status.0.clone());
            }
        }

        manager
            .update_task_progress(key.clone(), TaskStatus::WorkInProgress, None)
            .await?;

        let (status, proof) =
            match handle_proof(&proof_request, opts, chain_specs, Some(&mut manager)).await {
                Err(error) => {
                    error!("{error}");
                    (error.into(), None)
                }
                Ok(proof) => (TaskStatus::Success, Some(serde_json::to_vec(&proof)?)),
            };

        manager
            .update_task_progress(key, status.clone(), proof.as_deref())
            .await
            .map_err(HostError::from)?;
        Ok(status)
    }

    pub async fn handle_aggregate(request: AggregationOnlyRequest, opts: &Opts) -> HostResult<()> {
        let proof_type_str = request.proof_type.to_owned().unwrap_or_default();
        let proof_type = ProofType::from_str(&proof_type_str).map_err(HostError::Conversion)?;

        let mut manager = get_task_manager(&opts.clone().into());

        let status = manager
            .get_aggregation_task_proving_status(&request)
            .await?;

        if let Some(latest_status) = status.0.iter().last() {
            if !matches!(latest_status.0, TaskStatus::Registered) {
                return Ok(());
            }
        }

        manager
            .update_aggregation_task_progress(&request, TaskStatus::WorkInProgress, None)
            .await?;

        let input = AggregationGuestInput {
            proofs: request.clone().proofs,
        };
        let output = AggregationGuestOutput { hash: B256::ZERO };
        let config = serde_json::to_value(request.clone().prover_args)?;
        let mut manager = get_task_manager(&opts.clone().into());

        let (status, proof) =
            match aggregate_proofs(proof_type, input, &output, &config, Some(&mut manager)).await {
                Err(error) => {
                    error!("{error}");
                    (HostError::from(error).into(), None)
                }
                Ok(proof) => (TaskStatus::Success, Some(serde_json::to_vec(&proof)?)),
            };

        manager
            .update_aggregation_task_progress(&request, status, proof.as_deref())
            .await?;

        Ok(())
    }

    async fn cancel_all_running_tasks(&mut self) -> HostResult<()> {
        info!("Cancelling all running tasks");

        // Clone all tasks to avoid holding locks to avoid deadlock, they will be locked by other
        // internal functions.
        let running_tasks = {
            let running_tasks = self.running_tasks.lock().await;
            (*running_tasks).clone()
        };

        // Cancel all running tasks, don't stop even if any task fails.
        let mut final_result = Ok(());
        for proof_task_descriptor in running_tasks.keys() {
            match self.cancel_task(proof_task_descriptor.clone()).await {
                Ok(()) => {
                    info!(
                        "Cancel task during system pause, task: {:?}",
                        proof_task_descriptor
                    );
                }
                Err(e) => {
                    error!(
                        "Failed to cancel task during system pause: {}, task: {:?}",
                        e, proof_task_descriptor
                    );
                    final_result = final_result.and(Err(e));
                }
            }
        }
        final_result
    }

    async fn cancel_all_aggregation_tasks(&mut self) -> HostResult<()> {
        info!("Cancelling all aggregation tasks");

        // Clone all tasks to avoid holding locks to avoid deadlock, they will be locked by other
        // internal functions.
        let aggregate_tasks = {
            let aggregate_tasks = self.aggregate_tasks.lock().await;
            (*aggregate_tasks).clone()
        };

        // Cancel all aggregation tasks, don't stop even if any task fails.
        let mut final_result = Ok(());
        for request in aggregate_tasks.keys() {
            match self.cancel_aggregation_task(request.clone()).await {
                Ok(()) => {
                    info!(
                        "Cancel aggregation task during system pause, task: {}",
                        request
                    );
                }
                Err(e) => {
                    error!(
                        "Failed to cancel aggregation task during system pause: {}, task: {}",
                        e, request
                    );
                    final_result = final_result.and(Err(e));
                }
            }
        }
        final_result
    }

    async fn handle_system_pause(&mut self) -> HostResult<()> {
        info!("System pausing");

        let mut final_result = Ok(());

        self.pending_tasks.lock().await.clear();

        if let Err(e) = self.cancel_all_running_tasks().await {
            final_result = final_result.and(Err(e));
        }

        if let Err(e) = self.cancel_all_aggregation_tasks().await {
            final_result = final_result.and(Err(e));
        }

        // TODO(Kero): make sure all tasks are saved to database, including pending tasks.

        final_result
    }
}

pub async fn handle_proof(
    proof_request: &ProofRequest,
    opts: &Opts,
    chain_specs: &SupportedChainSpecs,
    store: Option<&mut TaskManagerWrapperImpl>,
) -> HostResult<Proof> {
    info!(
        "Generating proof for block {} on {}",
        proof_request.block_number, proof_request.network
    );

    // Check for a cached input for the given request config.
    let cached_input = cache::get_input(
        &opts.cache_path,
        proof_request.block_number,
        &proof_request.network.to_string(),
    );

    let l1_chain_spec = chain_specs
        .get_chain_spec(&proof_request.l1_network.to_string())
        .ok_or_else(|| HostError::InvalidRequestConfig("Unsupported l1 network".to_string()))?;

    let taiko_chain_spec = chain_specs
        .get_chain_spec(&proof_request.network.to_string())
        .ok_or_else(|| HostError::InvalidRequestConfig("Unsupported raiko network".to_string()))?;

    // Execute the proof generation.
    let total_time = Measurement::start("", false);

    let batch_mode = proof_request.l2_l1_block_pairs.is_some();
    let raiko = Raiko::new(
        l1_chain_spec.clone(),
        taiko_chain_spec.clone(),
        proof_request.clone(),
    );
    let provider = RpcBlockDataProvider::new(
        &taiko_chain_spec.rpc.clone(),
        proof_request.block_number - 1,
    )?;
    let input = match cache::validate_input(cached_input, &provider).await {
        Ok(cache_input) => cache_input,
        Err(_) => {
            // no valid cache
            memory::reset_stats();
            let measurement = Measurement::start("Generating input...", false);
            let input = raiko.generate_input(provider).await?;
            let input_time = measurement.stop_with("=> Input generated");
            observe_prepare_input_time(proof_request.block_number, input_time, true);
            memory::print_stats("Input generation peak memory used: ");
            input
        }
    };
    memory::reset_stats();
    let output = raiko.get_output(&input)?;
    memory::print_stats("Guest program peak memory used: ");

    memory::reset_stats();
    let measurement = Measurement::start("Generating proof...", false);
    let proof = raiko
        .prove(input.clone(), &output, store.map(|s| s as &mut dyn IdWrite))
        .await
        .map_err(|e| {
            let total_time = total_time.stop_with("====> Proof generation failed");
            observe_total_time(proof_request.block_number, total_time, false);
            match e {
                RaikoError::Guest(e) => {
                    inc_guest_error(&proof_request.proof_type, proof_request.block_number);
                    HostError::Core(e.into())
                }
                e => {
                    inc_host_error(proof_request.block_number);
                    e.into()
                }
            }
        })?;
    let guest_time = measurement.stop_with("=> Proof generated");
    observe_guest_time(
        &proof_request.proof_type,
        proof_request.block_number,
        guest_time,
        true,
    );
    memory::print_stats("Prover peak memory used: ");

    inc_guest_success(&proof_request.proof_type, proof_request.block_number);
    let total_time = total_time.stop_with("====> Complete proof generated");
    observe_total_time(proof_request.block_number, total_time, true);

    // Cache the input for future use.
    cache::set_input(
        &opts.cache_path,
        proof_request.block_number,
        &proof_request.network.to_string(),
        &input,
    )?;

    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_handle_system_pause_happy_path() {
        let (tx, rx) = mpsc::channel(100);
        let mut actor = setup_actor_with_tasks(tx, rx);

        let result = actor.handle_system_pause().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_system_pause_with_pending_tasks() {
        let (tx, rx) = mpsc::channel(100);
        let mut actor = setup_actor_with_tasks(tx, rx);

        // Add some pending tasks
        actor.pending_tasks.lock().await.push_back(ProofRequest {
            block_number: 1,
            l1_inclusion_block_number: 1,
            l2_l1_block_pairs: None,
            network: "test".to_string(),
            l1_network: "test".to_string(),
            graffiti: B256::ZERO,
            prover: Default::default(),
            proof_type: Default::default(),
            blob_proof_type: Default::default(),
            prover_args: HashMap::new(),
        });

        let result = actor.handle_system_pause().await;
        assert!(result.is_ok());

        // Verify pending tasks were cleared
        assert_eq!(actor.pending_tasks.lock().await.len(), 0);
    }

    #[tokio::test]
    async fn test_handle_system_pause_with_running_tasks() {
        let (tx, rx) = mpsc::channel(100);
        let mut actor = setup_actor_with_tasks(tx, rx);

        // Add some running tasks
        let task_descriptor = ProofTaskDescriptor::default();
        let cancellation_token = CancellationToken::new();
        actor
            .running_tasks
            .lock()
            .await
            .insert(task_descriptor.clone(), cancellation_token.clone());

        let result = actor.handle_system_pause().await;
        assert!(result.is_ok());

        // Verify running tasks were cancelled
        assert!(cancellation_token.is_cancelled());

        // TODO(Kero): Cancelled tasks should be removed from running_tasks
        // assert_eq!(actor.running_tasks.lock().await.len(), 0);
    }

    #[tokio::test]
    async fn test_handle_system_pause_with_aggregation_tasks() {
        let (tx, rx) = mpsc::channel(100);
        let mut actor = setup_actor_with_tasks(tx, rx);

        // Add some aggregation tasks
        let request = AggregationOnlyRequest::default();
        let cancellation_token = CancellationToken::new();
        actor
            .aggregate_tasks
            .lock()
            .await
            .insert(request.clone(), cancellation_token.clone());

        let result = actor.handle_system_pause().await;
        assert!(result.is_ok());

        // Verify aggregation tasks were cancelled
        assert!(cancellation_token.is_cancelled());
        // TODO(Kero): Cancelled tasks should be removed from aggregate_tasks
        // assert_eq!(actor.aggregate_tasks.lock().await.len(), 0);
    }

    #[tokio::test]
    async fn test_handle_system_pause_with_failures() {
        let (tx, rx) = mpsc::channel(100);
        let mut actor = setup_actor_with_tasks(tx, rx);

        // Add some pending tasks
        {
            actor.pending_tasks.lock().await.push_back(ProofRequest {
                block_number: 1,
                l1_inclusion_block_number: 1,
                l2_l1_block_pairs: None,
                network: "test".to_string(),
                l1_network: "test".to_string(),
                graffiti: B256::ZERO,
                prover: Default::default(),
                proof_type: Default::default(),
                blob_proof_type: Default::default(),
                prover_args: HashMap::new(),
            });
        }

        let good_running_task_token = {
            // Add some running tasks
            let task_descriptor = ProofTaskDescriptor::default();
            let cancellation_token = CancellationToken::new();
            actor
                .running_tasks
                .lock()
                .await
                .insert(task_descriptor.clone(), cancellation_token.clone());
            cancellation_token
        };

        let good_aggregation_task_token = {
            // Add some aggregation tasks
            let request = AggregationOnlyRequest::default();
            let cancellation_token = CancellationToken::new();
            actor
                .aggregate_tasks
                .lock()
                .await
                .insert(request.clone(), cancellation_token.clone());
            cancellation_token
        };

        // Setup tasks that will fail to cancel
        {
            let task_descriptor_should_fail_cause_not_supported_error = ProofTaskDescriptor {
                proof_system: ProofType::Risc0,
                ..Default::default()
            };
            actor.running_tasks.lock().await.insert(
                task_descriptor_should_fail_cause_not_supported_error.clone(),
                CancellationToken::new(),
            );
        }

        let result = actor.handle_system_pause().await;

        // Verify error contains all accumulated errors
        #[cfg(not(feature = "risc0"))]
        assert!(
            matches!(
                result,
                Err(HostError::Core(RaikoError::FeatureNotSupportedError(..)))
            ),
            "Unexpected result: {result:?}",
        );
        assert!(good_running_task_token.is_cancelled());
        assert!(good_aggregation_task_token.is_cancelled());
        assert!(actor.pending_tasks.lock().await.is_empty());
    }

    // Helper function to setup actor with common test configuration
    fn setup_actor_with_tasks(tx: Sender<Message>, rx: Receiver<Message>) -> ProofActor {
        let opts = Opts {
            concurrency_limit: 4,
            ..Default::default()
        };

        ProofActor::new(tx, rx, opts, SupportedChainSpecs::default())
    }
}
