use crate::{
    impl_display_using_json_pretty, proof_key_to_hack_request_key, RedisPoolConfig, RequestEntity,
    RequestKey, StatusWithContext,
};
use backoff::{exponential::ExponentialBackoff, SystemClock};
use raiko_lib::prover::{IdStore, IdWrite, ProofKey, ProverError, ProverResult};
use raiko_redis_derive::RedisValue;
#[allow(unused_imports)]
use redis::{Client, Commands, RedisResult};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Pool {
    client: Client,
    config: RedisPoolConfig,
}

impl Pool {
    pub fn add(
        &mut self,
        request_key: RequestKey,
        request_entity: RequestEntity,
        status: StatusWithContext,
    ) -> Result<(), String> {
        tracing::info!("RedisPool.add: {request_key}, {status}");
        let request_entity_and_status = RequestEntityAndStatus {
            entity: request_entity,
            status,
        };
        self.conn()
            .map_err(|e| e.to_string())?
            .set_ex(
                request_key,
                request_entity_and_status,
                self.config.redis_ttl,
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn remove(&mut self, request_key: &RequestKey) -> Result<usize, String> {
        tracing::info!("RedisPool.remove: {request_key}");
        let result: usize = self
            .conn()
            .map_err(|e| e.to_string())?
            .del(request_key)
            .map_err(|e| e.to_string())?;
        Ok(result)
    }

    pub fn get(
        &mut self,
        request_key: &RequestKey,
    ) -> Result<Option<(RequestEntity, StatusWithContext)>, String> {
        let result: RedisResult<RequestEntityAndStatus> =
            self.conn().map_err(|e| e.to_string())?.get(request_key);
        match result {
            Ok(value) => Ok(Some(value.into())),
            Err(e) if e.kind() == redis::ErrorKind::TypeError => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn get_status(
        &mut self,
        request_key: &RequestKey,
    ) -> Result<Option<StatusWithContext>, String> {
        self.get(request_key).map(|v| v.map(|v| v.1))
    }

    pub fn update_status(
        &mut self,
        request_key: RequestKey,
        status: StatusWithContext,
    ) -> Result<StatusWithContext, String> {
        tracing::info!("RedisPool.update_status: {request_key}, {status}");
        match self.get(&request_key)? {
            Some((entity, old_status)) => {
                self.add(request_key, entity, status)?;
                Ok(old_status)
            }
            None => Err("Request not found".to_string()),
        }
    }
}

#[async_trait::async_trait]
impl IdStore for Pool {
    async fn read_id(&mut self, proof_key: ProofKey) -> ProverResult<String> {
        let hack_request_key = proof_key_to_hack_request_key(proof_key);

        tracing::info!("RedisPool.read_id: {hack_request_key}");

        let result: RedisResult<String> = self
            .conn()
            .map_err(|e| e.to_string())?
            .get(&hack_request_key);
        match result {
            Ok(value) => Ok(value.into()),
            Err(e) => Err(ProverError::StoreError(e.to_string())),
        }
    }
}

#[async_trait::async_trait]
impl IdWrite for Pool {
    async fn store_id(&mut self, proof_key: ProofKey, id: String) -> ProverResult<()> {
        let hack_request_key = proof_key_to_hack_request_key(proof_key);

        tracing::info!("RedisPool.store_id: {hack_request_key}, {id}");

        self.conn()
            .map_err(|e| e.to_string())?
            .set_ex(hack_request_key, id, self.config.redis_ttl)
            .map_err(|e| ProverError::StoreError(e.to_string()))?;
        Ok(())
    }

    async fn remove_id(&mut self, proof_key: ProofKey) -> ProverResult<()> {
        let hack_request_key = proof_key_to_hack_request_key(proof_key);

        tracing::info!("RedisPool.remove_id: {hack_request_key}");

        self.conn()
            .map_err(|e| e.to_string())?
            .del(hack_request_key)
            .map_err(|e| ProverError::StoreError(e.to_string()))?;
        Ok(())
    }
}

impl Pool {
    pub fn open(config: RedisPoolConfig) -> Result<Self, redis::RedisError> {
        tracing::info!("RedisPool.open: connecting to redis: {}", config.redis_url);

        let client = Client::open(config.redis_url.clone())?;
        Ok(Self { client, config })
    }

    #[cfg(any(test, feature = "enable-mock"))]
    pub(crate) fn conn(&mut self) -> Result<crate::mock::MockRedisConnection, redis::RedisError> {
        Ok(crate::mock::MockRedisConnection::new(
            self.config.redis_url.clone(),
        ))
    }

    #[cfg(not(any(test, feature = "enable-mock")))]
    fn conn(&mut self) -> Result<redis::Connection, redis::RedisError> {
        self.redis_conn()
    }

    #[allow(dead_code)]
    fn redis_conn(&mut self) -> Result<redis::Connection, redis::RedisError> {
        let backoff: ExponentialBackoff<SystemClock> = ExponentialBackoff {
            initial_interval: Duration::from_secs(10),
            max_interval: Duration::from_secs(60),
            max_elapsed_time: Some(Duration::from_secs(300)),
            ..Default::default()
        };

        backoff::retry(backoff, || match self.client.get_connection() {
            Ok(conn) => Ok(conn),
            Err(e) => {
                tracing::error!(
                    "RedisPool.get_connection: failed to connect to redis: {e:?}, retrying..."
                );

                self.client = redis::Client::open(self.config.redis_url.clone())?;
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
}

/// A internal wrapper for request entity and status, used for redis serialization
#[derive(PartialEq, Debug, Clone, Deserialize, Serialize, RedisValue)]
struct RequestEntityAndStatus {
    entity: RequestEntity,
    status: StatusWithContext,
}

impl From<(RequestEntity, StatusWithContext)> for RequestEntityAndStatus {
    fn from(value: (RequestEntity, StatusWithContext)) -> Self {
        Self {
            entity: value.0,
            status: value.1,
        }
    }
}

impl From<RequestEntityAndStatus> for (RequestEntity, StatusWithContext) {
    fn from(value: RequestEntityAndStatus) -> Self {
        (value.entity, value.status)
    }
}

impl_display_using_json_pretty!(RequestEntityAndStatus);
