use std::path::Path;

use raiko_lib::{
    input::{GuestInput, GuestOutput},
    proof_type::ProofType,
    protocol_instance::ProtocolInstance,
    prover::{IdStore, IdWrite, Proof, ProofKey, Prover, ProverConfig, ProverError, ProverResult},
};
use serde::{de::Error, Deserialize, Serialize};
use serde_with::serde_as;
use tracing::trace;

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

impl Prover for NativeProver {
    async fn run(
        input: GuestInput,
        output: &GuestOutput,
        config: &ProverConfig,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        let param =
            config
                .get("native")
                .map(NativeParam::deserialize)
                .ok_or(ProverError::Param(serde_json::Error::custom(
                    "native param not provided",
                )))??;

        if let Some(path) = param.json_guest_input {
            let path = Path::new(&path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let json = serde_json::to_string(&input)?;
            std::fs::write(path, json)?;
        }

        trace!("Running the native prover for input {input:?}");

        let pi = ProtocolInstance::new(&input, &output.header, ProofType::Native)
            .map_err(|e| ProverError::GuestError(e.to_string()))?;
        if pi.instance_hash() != output.hash {
            return Err(ProverError::GuestError(
                "Protocol Instance hash not matched".to_string(),
            ));
        }

        Ok(Proof {
            input: None,
            proof: None,
            quote: None,
            uuid: None,
            kzg_proof: None,
        })
    }

    async fn batch_run(
        input: raiko_lib::input::GuestBatchInput,
        output: &GuestOutput,
        config: &ProverConfig,
        store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        let param =
            config
                .get("native")
                .map(NativeParam::deserialize)
                .ok_or(ProverError::Param(serde_json::Error::custom(
                    "native param not provided",
                )))??;

        if let Some(path) = param.json_guest_input {
            let path = Path::new(&path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let json = serde_json::to_string(&input)?;
            std::fs::write(path, json)?;
        }

        trace!("Running the native prover for input {input:?}");

        let pi = ProtocolInstance::new_batch(&input, &output.header, ProofType::Native)
            .map_err(|e| ProverError::GuestError(e.to_string()))?;
        if pi.instance_hash() != output.hash {
            return Err(ProverError::GuestError(
                "Protocol Instance hash not matched".to_string(),
            ));
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
