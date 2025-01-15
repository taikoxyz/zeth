use std::sync::Arc;
use std::time::Duration;

use raiko_core::{
    interfaces::{aggregate_proofs, ProofRequest},
    provider::rpc::RpcBlockDataProvider,
    Raiko,
};
use raiko_lib::{
    consts::SupportedChainSpecs,
    input::{AggregationGuestInput, AggregationGuestOutput},
    prover::{IdWrite, Proof},
};
use raiko_reqpool::{
    AggregationRequestEntity, RequestEntity, RequestKey, SingleProofRequestEntity, Status,
    StatusWithContext,
};
use reth_primitives::B256;
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    oneshot, Semaphore,
};

use crate::{Action, Pool};

/// Backend runs in the background, and handles the actions from the actor.
#[derive(Clone)]
pub(crate) struct Backend {
    pool: Pool,
    chain_specs: SupportedChainSpecs,
    internal_tx: Sender<RequestKey>,
    proving_semaphore: Arc<Semaphore>,
}

// TODO: load pool and notify internal channel
impl Backend {
    /// Run the backend in background.
    ///
    /// The returned channel sender is used to send actions to the actor, and the actor will
    /// act on the actions and send responses back.
    pub async fn serve_in_background(
        pool: Pool,
        chain_specs: SupportedChainSpecs,
        pause_rx: Receiver<()>,
        action_rx: Receiver<(Action, oneshot::Sender<Result<StatusWithContext, String>>)>,
        max_proving_concurrency: usize,
    ) {
        let channel_size = 1024;
        let (internal_tx, internal_rx) = mpsc::channel::<RequestKey>(channel_size);
        tokio::spawn(async move {
            Backend {
                pool,
                chain_specs,
                internal_tx,
                proving_semaphore: Arc::new(Semaphore::new(max_proving_concurrency)),
            }
            .serve(action_rx, internal_rx, pause_rx)
            .await;
        });
    }

    // There are three incoming channels:
    // 1. action_rx: actions from the external Actor
    // 2. internal_rx: internal signals from the backend itself
    // 3. pause_rx: pause signal from the external Actor
    async fn serve(
        mut self,
        mut action_rx: Receiver<(Action, oneshot::Sender<Result<StatusWithContext, String>>)>,
        mut internal_rx: Receiver<RequestKey>,
        mut pause_rx: Receiver<()>,
    ) {
        loop {
            tokio::select! {
                Some((action, resp_tx)) = action_rx.recv() => {
                    let request_key = action.request_key().clone();
                    let response = self.handle_external_action(action.clone()).await;

                    // Signal the request key to the internal channel, to move on to the next step, whatever the result is
                    //
                    // NOTE: Why signal whatever the result is? It's for fault tolerance, to ensure the request will be
                    // handled even when something unexpected happens.
                    self.ensure_internal_signal(request_key).await;

                    if let Err(err) = resp_tx.send(response.clone()) {
                        tracing::error!(
                            "Actor Backend failed to send response {response:?} to action {action}: {err:?}"
                        );
                    }
                }
                Some(request_key) = internal_rx.recv() => {
                    self.handle_internal_signal(request_key.clone()).await;
                }
                Some(()) = pause_rx.recv() => {
                    tracing::info!("Actor Backend received pause-signal, halting");
                    if let Err(err) = self.halt().await {
                        tracing::error!("Actor Backend failed to halt: {err:?}");
                    }
                }
                else => {
                    // All channels are closed, exit the loop
                    tracing::info!("Actor Backend exited");
                    break;
                }
            }
        }
    }

    async fn handle_external_action(
        &mut self,
        action: Action,
    ) -> Result<StatusWithContext, String> {
        match action {
            Action::Prove {
                request_key,
                request_entity,
            } => match self.pool.get_status(&request_key) {
                Ok(None) => {
                    tracing::info!("Actor Backend received prove-action {request_key}, and it is not in pool, registering");
                    self.register(request_key.clone(), request_entity).await
                }
                Ok(Some(status)) => match status.status() {
                    Status::Registered | Status::WorkInProgress | Status::Success { .. } => {
                        tracing::info!("Actor Backend received prove-action {request_key}, but it is already {status}, skipping");
                        Ok(status)
                    }
                    Status::Cancelled { .. } => {
                        tracing::warn!("Actor Backend received prove-action {request_key}, and it is cancelled, re-registering");
                        self.register(request_key, request_entity).await
                    }
                    Status::Failed { .. } => {
                        tracing::warn!("Actor Backend received prove-action {request_key}, and it is failed, re-registering");
                        self.register(request_key, request_entity).await
                    }
                },
                Err(err) => {
                    tracing::error!(
                        "Actor Backend failed to get status of prove-action {request_key}: {err:?}"
                    );
                    Err(err)
                }
            },
            Action::Cancel { request_key } => match self.pool.get_status(&request_key) {
                Ok(None) => {
                    tracing::warn!("Actor Backend received cancel-action {request_key}, but it is not in pool, skipping");
                    Err("request is not in pool".to_string())
                }
                Ok(Some(status)) => match status.status() {
                    Status::Registered | Status::WorkInProgress => {
                        tracing::info!("Actor Backend received cancel-action {request_key}, and it is {status}, cancelling");
                        self.cancel(request_key, status).await
                    }

                    Status::Failed { .. } | Status::Cancelled { .. } | Status::Success { .. } => {
                        tracing::info!("Actor Backend received cancel-action {request_key}, but it is already {status}, skipping");
                        Ok(status)
                    }
                },
                Err(err) => {
                    tracing::error!(
                        "Actor Backend failed to get status of cancel-action {request_key}: {err:?}"
                    );
                    Err(err)
                }
            },
        }
    }

    // Check the request status and then move on to the next step accordingly.
    async fn handle_internal_signal(&mut self, request_key: RequestKey) {
        match self.pool.get(&request_key) {
            Ok(Some((request_entity, status))) => match status.status() {
                Status::Registered => match request_entity {
                    RequestEntity::SingleProof(entity) => {
                        tracing::info!("Actor Backend received internal signal {request_key}, status: {status}, proving single proof");
                        self.prove_single(request_key.clone(), entity).await;
                        self.ensure_internal_signal(request_key).await;
                    }
                    RequestEntity::Aggregation(entity) => {
                        tracing::info!("Actor Backend received internal signal {request_key}, status: {status}, proving aggregation proof");
                        self.prove_aggregation(request_key.clone(), entity).await;
                        self.ensure_internal_signal(request_key).await;
                    }
                },
                Status::WorkInProgress => {
                    // Wait for proving completion
                    tracing::info!(
                        "Actor Backend checks a work-in-progress request {request_key}, elapsed: {elapsed:?}",
                        elapsed = chrono::Utc::now() - status.timestamp(),
                    );
                    self.ensure_internal_signal_after(request_key, Duration::from_secs(3))
                        .await;
                }
                Status::Success { .. } | Status::Cancelled { .. } | Status::Failed { .. } => {
                    tracing::info!("Actor Backend received internal signal {request_key}, status: {status}, done");
                }
            },
            Ok(None) => {
                tracing::warn!(
                    "Actor Backend received internal signal {request_key}, but it is not in pool, skipping"
                );
            }
            Err(err) => {
                // Fault tolerance: re-enqueue the internal signal after 3 seconds
                tracing::warn!(
                    "Actor Backend failed to get status of internal signal {request_key}: {err:?}, performing fault tolerance and retrying later"
                );
                self.ensure_internal_signal_after(request_key, Duration::from_secs(3))
                    .await;
            }
        }
    }

    // Ensure signal the request key to the internal channel.
    //
    // Note that this function will retry sending the signal until success.
    async fn ensure_internal_signal(&mut self, request_key: RequestKey) {
        let mut ticker = tokio::time::interval(Duration::from_secs(3));
        let internal_tx = self.internal_tx.clone();
        tokio::spawn(async move {
            loop {
                if let Err(err) = internal_tx.send(request_key.clone()).await {
                    tracing::error!("Actor Backend failed to send internal signal {request_key}: {err:?}, retrying. It should not happen, please issue a bug report");
                }
                ticker.tick().await;
            }
        });
    }

    async fn ensure_internal_signal_after(&mut self, request_key: RequestKey, after: Duration) {
        let mut timer = tokio::time::interval(after);
        timer.tick().await;
        self.ensure_internal_signal(request_key).await
    }

    // Register a new request to the pool and notify the actor.
    async fn register(
        &mut self,
        request_key: RequestKey,
        request_entity: RequestEntity,
    ) -> Result<StatusWithContext, String> {
        // 1. Register to the pool
        let status = StatusWithContext::new_registered();
        if let Err(err) = self
            .pool
            .add(request_key.clone(), request_entity, status.clone())
        {
            return Err(err);
        }

        Ok(status)
    }

    async fn cancel(
        &mut self,
        request_key: RequestKey,
        old_status: StatusWithContext,
    ) -> Result<StatusWithContext, String> {
        debug_assert!(
            old_status.status() == &Status::WorkInProgress
                || old_status.status() == &Status::Registered
        );

        // Case: old_status is registered: mark the request as cancelled in the pool and return directly
        if old_status.status() == &Status::Registered {
            let status = StatusWithContext::new_cancelled();
            self.pool.update_status(request_key, status.clone())?;
            return Ok(status);
        }

        // Case: old_status is work-in-progress:
        // 1. Cancel the proving work by the cancel token // TODO: cancel token
        // 2. Remove the proof id from the pool
        // 3. Mark the request as cancelled in the pool
        match &request_key {
            RequestKey::SingleProof(key) => {
                raiko_core::interfaces::cancel_proof(
                    key.proof_type().clone(),
                    (
                        key.chain_id().clone(),
                        key.block_number().clone(),
                        key.block_hash().clone(),
                        *key.proof_type() as u8,
                    ),
                    Box::new(&mut self.pool),
                )
                .await
                .or_else(|e| {
                    if e.to_string().contains("No data for query") {
                        tracing::warn!("Actor Backend received cancel-action {request_key}, but it is already cancelled or not yet started, skipping");
                        Ok(())
                    } else {
                        tracing::error!(
                            "Actor Backend received cancel-action {request_key}, but failed to cancel proof: {e:?}"
                        );
                        Err(format!("failed to cancel proof: {e:?}"))
                    }
                })?;

                // 3. Mark the request as cancelled in the pool
                let status = StatusWithContext::new_cancelled();
                self.pool.update_status(request_key, status.clone())?;
                Ok(status)
            }
            RequestKey::Aggregation(..) => {
                let status = StatusWithContext::new_cancelled();
                self.pool.update_status(request_key, status.clone())?;
                Ok(status)
            }
        }
    }

    async fn prove_single(
        &mut self,
        request_key: RequestKey,
        request_entity: SingleProofRequestEntity,
    ) {
        // 1. Update the request status in pool to WorkInProgress
        if let Err(err) = self
            .pool
            .update_status(request_key.clone(), Status::WorkInProgress.into())
        {
            tracing::error!(
                "Actor Backend failed to update status of prove-action {request_key}: {err:?}, status: {status}",
                status = Status::WorkInProgress,
            );
            return;
        }

        // 2. Start the proving work in a separate thread
        let mut actor = self.clone();
        let proving_semaphore = self.proving_semaphore.clone();
        tokio::spawn(async move {
            // Acquire a permit from the semaphore before starting the proving work
            let _permit = proving_semaphore
                .acquire()
                .await
                .expect("semaphore should not be closed");

            // 2.1. Start the proving work
            let proven_status = do_prove_single(
                &mut actor.pool,
                &actor.chain_specs,
                request_key.clone(),
                request_entity,
            )
            .await
            .map(|proof| Status::Success { proof })
            .unwrap_or_else(|error| Status::Failed { error });

            // 2.2. Update the request status in pool to the resulted status
            if let Err(err) = actor
                .pool
                .update_status(request_key.clone(), proven_status.clone().into())
            {
                tracing::error!(
                    "Actor Backend failed to update status of prove-action {request_key}: {err:?}, status: {proven_status}"
                );
                return;
            }
            // The permit is automatically dropped here, releasing the semaphore
        });
    }

    async fn prove_aggregation(
        &mut self,
        request_key: RequestKey,
        request_entity: AggregationRequestEntity,
    ) {
        // 1. Update the request status in pool to WorkInProgress
        if let Err(err) = self
            .pool
            .update_status(request_key.clone(), Status::WorkInProgress.into())
        {
            tracing::error!(
                "Actor Backend failed to update status of prove-action {request_key}: {err:?}, status: {status}",
                status = Status::WorkInProgress,
            );
            return;
        }

        // 2. Start the proving work in a separate thread
        let mut actor = self.clone();
        let proving_semaphore = self.proving_semaphore.clone();
        tokio::spawn(async move {
            // Acquire a permit from the semaphore before starting the proving work
            let _permit = proving_semaphore
                .acquire()
                .await
                .expect("semaphore should not be closed");

            // 2.1. Start the proving work
            let proven_status =
                do_prove_aggregation(&mut actor.pool, request_key.clone(), request_entity)
                    .await
                    .map(|proof| Status::Success { proof })
                    .unwrap_or_else(|error| Status::Failed { error });

            // 2.2. Update the request status in pool to the resulted status
            if let Err(err) = actor
                .pool
                .update_status(request_key.clone(), proven_status.clone().into())
            {
                tracing::error!(
                    "Actor Backend failed to update status of prove-action {request_key}: {err:?}, status: {proven_status}"
                );
                return;
            }
            // The permit is automatically dropped here, releasing the semaphore
        });
    }

    async fn halt(&mut self) -> Result<(), String> {
        todo!("halt")
    }
}

// TODO: cache input, reference to raiko_host::cache
// TODO: memory tracking
// TODO: metrics
// TODO: measurement
pub async fn do_prove_single(
    pool: &mut dyn IdWrite,
    chain_specs: &SupportedChainSpecs,
    request_key: RequestKey,
    request_entity: SingleProofRequestEntity,
) -> Result<Proof, String> {
    tracing::info!("Generating proof for {request_key}");

    let l1_chain_spec = chain_specs
        .get_chain_spec(&request_entity.l1_network())
        .ok_or_else(|| {
            format!(
                "unsupported l1 network: {}, it should not happen, please issue a bug report",
                request_entity.l1_network()
            )
        })?;
    let taiko_chain_spec = chain_specs
        .get_chain_spec(&request_entity.network())
        .ok_or_else(|| {
            format!(
                "unsupported raiko network: {}, it should not happen, please issue a bug report",
                request_entity.network()
            )
        })?;
    let proof_request = ProofRequest {
        block_number: *request_entity.block_number(),
        l1_inclusion_block_number: *request_entity.l1_inclusion_block_number(),
        network: request_entity.network().clone(),
        l1_network: request_entity.l1_network().clone(),
        graffiti: request_entity.graffiti().clone(),
        prover: request_entity.prover().clone(),
        proof_type: request_entity.proof_type().clone(),
        blob_proof_type: request_entity.blob_proof_type().clone(),
        prover_args: request_entity.prover_args().clone(),
    };
    let raiko = Raiko::new(l1_chain_spec, taiko_chain_spec.clone(), proof_request);
    let provider = RpcBlockDataProvider::new(
        &taiko_chain_spec.rpc.clone(),
        request_entity.block_number() - 1,
    )
    .map_err(|err| format!("failed to create rpc block data provider: {err:?}"))?;

    // 1. Generate the proof input
    let input = raiko
        .generate_input(provider)
        .await
        .map_err(|e| format!("failed to generate input: {e:?}"))?;

    // 2. Generate the proof output
    let output = raiko
        .get_output(&input)
        .map_err(|e| format!("failed to get output: {e:?}"))?;

    // 3. Generate the proof
    let proof = raiko
        .prove(input, &output, Some(pool))
        .await
        .map_err(|err| format!("failed to generate single proof: {err:?}"))?;

    Ok(proof)
}

async fn do_prove_aggregation(
    pool: &mut dyn IdWrite,
    request_key: RequestKey,
    request_entity: AggregationRequestEntity,
) -> Result<Proof, String> {
    let proof_type = request_key.proof_type().clone();
    let proofs = request_entity.proofs().clone();

    let input = AggregationGuestInput { proofs };
    let output = AggregationGuestOutput { hash: B256::ZERO };
    let config = serde_json::to_value(request_entity.prover_args())
        .map_err(|err| format!("failed to serialize prover args: {err:?}"))?;

    let proof = aggregate_proofs(proof_type, input, &output, &config, Some(pool))
        .await
        .map_err(|err| format!("failed to generate aggregation proof: {err:?}"))?;

    Ok(proof)
}
