use std::path::{Path, PathBuf};

use raiko_lib::{
    input::{GuestInput, GuestOutput},
    proof_type::ProofType,
    protocol_instance::ProtocolInstance,
    prover::{IdStore, IdWrite, Proof, ProofKey, Prover, ProverConfig, ProverError, ProverResult},
};
use serde::{de::Error, Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;
use tokio::fs;
use tracing::trace;

#[derive(Error, Debug)]
pub enum NativeProverError {
    #[error("Native param not provided")]
    ParamNotProvided,
    #[error("Failed to serialize input to JSON")]
    SerializeError(#[from] serde_json::Error),
    #[error("Failed to write JSON to file")]
    FileWriteError(#[from] std::io::Error),
    #[error("Protocol Instance hash not matched")]
    HashMismatch,
    #[error("Guest Error: {0}")]
    GuestError(String),
}

pub struct NativeProver;

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeParam {
    pub json_guest_input: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeResponse {
    pub output: GuestOutput,
}

impl NativeProver {
    async fn save_input_to_file(path: &Path, input: &GuestInput) -> Result<(), NativeProverError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let json = serde_json::to_string(input)?;
        fs::write(path, json).await?;
        Ok(())
    }
}

impl Prover for NativeProver {
    async fn run(
        input: GuestInput,
        output: &GuestOutput,
        config: &ProverConfig,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        let param = config
            .get("native")
            .ok_or(NativeProverError::ParamNotProvided)
            .and_then(|p| NativeParam::deserialize(p).map_err(NativeProverError::SerializeError))?;

        if let Some(path_str) = param.json_guest_input {
            let path = PathBuf::from(path_str);
            Self::save_input_to_file(&path, &input).await?;
        }

        trace!("Running the native prover for input {:?}", input);

        let pi = ProtocolInstance::new(&input, &output.header, ProofType::Native)
            .map_err(|e| ProverError::GuestError(e.to_string()))?;
        if pi.instance_hash() != output.hash {
            return Err(ProverError::GuestError(NativeProverError::HashMismatch.to_string()));
        }

        Ok(Proof {
            input: None,
            proof: None,
            quote: None,
            uuid: None,
            kzg_proof: None,
        })
    }

    async fn cancel(_proof_key: ProofKey, _read: Box<&mut dyn IdStore>) -> ProverResult<()> {
        Ok(())
    }

    async fn aggregate(
        _input: raiko_lib::input::AggregationGuestInput,
        _output: &raiko_lib::input::AggregationGuestOutput,
        _config: &ProverConfig,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        Ok(Proof {
            ..Default::default()
        })
    }
}

#[ignore = "Only used to test serialized data"]
#[tokio::test(flavor = "multi_thread")]
async fn test_native_prover() {
    use serde_json::json;

    // Get the current working directory
    let current_dir = std::env::current_dir().expect("Failed to get current directory");

    // Adjust as needed based on your tests
    let file_name = "ethereum-20612846.json";
    let path = current_dir.join("../data").join(file_name);

    // Check if the path exists
    if !path.exists() {
        panic!("File does not exist: {}", path.display());
    }
    let json = std::fs::read_to_string(path).unwrap();

    // Deserialize the input.
    let input: GuestInput = serde_json::from_str(&json).unwrap();
    let output = GuestOutput {
        header: reth_primitives::Header::default(),
        hash: reth_primitives::B256::default(),
    };

    let param = json!({
        "native": {
            "json_guest_input": null
        }
    });
    NativeProver::run(input, &output, &param, None)
        .await
        .expect_err("Default output should not match input.");
}
