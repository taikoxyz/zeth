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

#[derive(Clone, Debug, Serialize, ToSchema, Deserialize, Default, PartialEq, Eq, Hash)]
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
    async fn read_id(&self, key: ProofKey) -> ProverResult<String>;
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

    /// The image id and ELF of current proving guest program.
    fn current_proving_image() -> (&'static [u8], &'static [u32; 8]) {
        (&[], &[0; 8])
    }

    /// The image id and ELF of current aggregation guest program.
    fn current_aggregation_image() -> (&'static [u8], &'static [u32; 8]) {
        (&[], &[0; 8])
    }
}

/// A helper function to encode image id to hex string.
pub fn encode_image_id(image_id: &[u32; 8]) -> String {
    let bytes = bytemuck::cast_slice(image_id);
    hex::encode(bytes)
}

/// A helper function to decode image id from hex string.
pub fn decode_image_id(hex_image_id: &str) -> Result<[u32; 8], hex::FromHexError> {
    let bytes: Vec<u8> = if let Some(stripped) = hex_image_id.strip_prefix("0x") {
        hex::decode(stripped)?
    } else {
        hex::decode(hex_image_id)?
    };
    let array: &[u32] = bytemuck::cast_slice::<u8, u32>(&bytes);
    let result: [u32; 8] = array.try_into().expect("invalid hex image id");
    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_image_id() {
        let image_id: [u32; 8] = [
            1848002361, 3447634449, 2932177819, 2827220601, 4284138344, 2572487667, 1602600202,
            3769687346,
        ];
        let encoded = encode_image_id(&image_id);
        assert_eq!(
            encoded,
            "3947266e11ba7ecd9b7bc5ae79f683a868c35afff30b55990abd855f32ddb0e0"
        );
        let decoded = decode_image_id(&encoded).unwrap();
        assert_eq!(decoded, image_id);

        let decoded = decode_image_id(&format!("0x{encoded}")).unwrap();
        assert_eq!(decoded, image_id);
    }
}
