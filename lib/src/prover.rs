use reth_primitives::{ChainId, B256};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::input::{AggregationGuestInput, AggregationGuestOutput, GuestInput, GuestOutput};

#[derive(thiserror::Error, Debug)]
pub enum ProverError {
    #[error("ProverError::GuestError `{0}`")]
    GuestError(String),
    #[error("ProverError::FileIo `{0}`")]
    FileIo(#[from] std::io::Error),
    #[error("ProverError::Param `{0}`")]
    Param(#[from] serde_json::Error),
    #[error("Store error `{0}`")]
    StoreError(String),
}

impl From<String> for ProverError {
    fn from(e: String) -> Self {
        ProverError::GuestError(e)
    }
}

pub type ProverResult<T, E = ProverError> = core::result::Result<T, E>;
pub type ProverConfig = serde_json::Value;
pub type ProofKey = (ChainId, u64, B256, u8);

#[derive(
    Clone, Debug, Serialize, ToSchema, Deserialize, Default, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
/// The response body of a proof request.
pub struct Proof {
    /// The proof either TEE or ZK.
    pub proof: Option<String>,
    /// The public input
    pub input: Option<B256>,
    /// The TEE quote.
    pub quote: Option<String>,
    /// The assumption UUID.
    pub uuid: Option<String>,
    /// The kzg proof.
    pub kzg_proof: Option<String>,
}

#[async_trait::async_trait]
pub trait IdWrite: Send {
    async fn store_id(&mut self, key: ProofKey, id: String) -> ProverResult<()>;

    async fn remove_id(&mut self, key: ProofKey) -> ProverResult<()>;
}

#[async_trait::async_trait]
pub trait IdStore: IdWrite {
    async fn read_id(&mut self, key: ProofKey) -> ProverResult<String>;
}

#[allow(async_fn_in_trait)]
pub trait Prover {
    async fn run(
        input: GuestInput,
        output: &GuestOutput,
        config: &ProverConfig,
        store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof>;

    async fn aggregate(
        input: AggregationGuestInput,
        output: &AggregationGuestOutput,
        config: &ProverConfig,
        store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof>;

    async fn cancel(proof_key: ProofKey, read: Box<&mut dyn IdStore>) -> ProverResult<()>;
}
