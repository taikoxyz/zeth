#![cfg(feature = "enable")]

#[cfg(feature = "bonsai-auto-scaling")]
use crate::bonsai::auto_scaling::shutdown_bonsai;
use alloy_primitives::{hex::ToHexExt, B256};
use bonsai::{cancel_proof, maybe_prove};
use log::{info, warn};
use raiko_lib::{
    input::{
        AggregationGuestInput, AggregationGuestOutput, GuestInput, GuestOutput,
        ZkAggregationGuestInput,
    },
    proof_type::ProofType,
    prover::{
        encode_image_id, IdStore, IdWrite, Proof, ProofKey, Prover, ProverConfig, ProverError,
        ProverResult,
    },
};
use risc0_zkvm::{
    compute_image_id, default_prover, serde::to_vec, sha::Digestible, ExecutorEnv, ProverOpts,
    Receipt,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fmt::Debug;

pub mod bonsai;
pub mod methods;
pub mod snarks;

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Risc0Param {
    pub bonsai: bool,
    pub snark: bool,
    pub profile: bool,
    pub execution_po2: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Risc0Response {
    pub proof: String,
    pub receipt: String,
    pub uuid: String,
    pub input: B256,
}

impl From<Risc0Response> for Proof {
    fn from(value: Risc0Response) -> Self {
        Self {
            proof: Some(value.proof),
            quote: Some(value.receipt),
            input: Some(value.input),
            uuid: Some(value.uuid),
            kzg_proof: None,
        }
    }
}

pub struct Risc0Prover;

impl Prover for Risc0Prover {
    async fn run(
        input: GuestInput,
        output: &GuestOutput,
        config: &ProverConfig,
        id_store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        let mut id_store = id_store;
        let config = Risc0Param::deserialize(config.get("risc0").unwrap()).unwrap();
        let proof_key = (
            input.chain_spec.chain_id,
            input.block.header.number,
            output.hash,
            ProofType::Risc0 as u8,
        );

        let (elf, image_id) = Risc0Prover::current_proving_image();

        info!(
            "Using risc0 image id: {}, elf.length: {}",
            encode_image_id(image_id),
            elf.len()
        );

        let encoded_input = to_vec(&input).expect("Could not serialize proving input!");

        let (uuid, receipt) = maybe_prove::<GuestInput, B256>(
            &config,
            encoded_input,
            elf,
            &output.hash,
            (Vec::<Receipt>::new(), Vec::new()),
            proof_key,
            &mut id_store,
        )
        .await?;

        let proof_gen_result = if config.snark && config.bonsai {
            bonsai::bonsai_stark_to_snark(uuid, receipt, output.hash)
                .await
                .map(|r0_response| r0_response.into())
                .map_err(|e| ProverError::GuestError(e.to_string()))
        } else {
            if !config.snark {
                warn!("proof is not in snark mode, please check.");
            }
            Ok(Risc0Response {
                proof: receipt.journal.encode_hex_with_prefix(),
                receipt: serde_json::to_string(&receipt).unwrap(),
                uuid,
                input: output.hash,
            }
            .into())
        };

        #[cfg(feature = "bonsai-auto-scaling")]
        if config.bonsai {
            // shutdown bonsai
            shutdown_bonsai()
                .await
                .map_err(|e| ProverError::GuestError(e.to_string()))?;
        }

        proof_gen_result
    }

    async fn aggregate(
        input: AggregationGuestInput,
        _output: &AggregationGuestOutput,
        config: &ProverConfig,
        _id_store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        let config = Risc0Param::deserialize(config.get("risc0").unwrap()).unwrap();
        assert!(
            config.snark && config.bonsai,
            "Aggregation must be in bonsai snark mode"
        );

        let (proving_elf, proving_image_id) = Risc0Prover::current_proving_image();
        let (aggregation_elf, aggregation_image_id) = Risc0Prover::current_aggregation_image();

        info!(
            "Using risc0 proving image id: {}, elf.length: {}",
            encode_image_id(proving_image_id),
            proving_elf.len()
        );
        info!(
            "Using risc0 aggregation image id: {}, elf.length: {}",
            encode_image_id(aggregation_image_id),
            aggregation_elf.len()
        );

        // Extract the block proof receipts
        let assumptions: Vec<Receipt> = input
            .proofs
            .iter()
            .map(|proof| {
                let receipt: Receipt = serde_json::from_str(&proof.quote.clone().unwrap())
                    .expect("Failed to deserialize");
                receipt
            })
            .collect::<Vec<_>>();
        let block_inputs: Vec<B256> = input
            .proofs
            .iter()
            .map(|proof| proof.input.unwrap())
            .collect::<Vec<_>>();
        let input = ZkAggregationGuestInput {
            // TODO(Kero): use input.image_id
            image_id: *proving_image_id,
            block_inputs,
        };
        info!("Start aggregate proofs");
        // add_assumption makes the receipt to be verified available to the prover.
        let env = {
            let mut env = ExecutorEnv::builder();
            for assumption in assumptions {
                env.add_assumption(assumption);
            }
            env.write(&input).unwrap().build().unwrap()
        };

        let opts = ProverOpts::groth16();
        let receipt = default_prover()
            .prove_with_opts(env, aggregation_elf, &opts)
            .unwrap()
            .receipt;

        info!(
            "Generate aggregation receipt journal: {:?}",
            alloy_primitives::hex::encode_prefixed(receipt.journal.bytes.clone())
        );
        let block_proof_image_id = compute_image_id(proving_elf).unwrap();
        let aggregation_image_id = compute_image_id(aggregation_elf).unwrap();
        let proof_data = snarks::verify_aggregation_groth16_proof(
            block_proof_image_id,
            aggregation_image_id,
            receipt.clone(),
        )
        .await
        .map_err(|err| format!("Failed to verify SNARK: {err:?}"))?;
        let snark_proof = alloy_primitives::hex::encode_prefixed(proof_data);

        info!("Aggregation proof: {snark_proof:?}");
        let proof_gen_result = Ok(Risc0Response {
            proof: snark_proof,
            receipt: serde_json::to_string(&receipt).unwrap(),
            uuid: "".to_owned(),
            input: B256::from_slice(receipt.journal.digest().as_bytes()),
        }
        .into());

        #[cfg(feature = "bonsai-auto-scaling")]
        if config.bonsai {
            // shutdown bonsai
            shutdown_bonsai()
                .await
                .map_err(|e| ProverError::GuestError(e.to_string()))?;
        }

        proof_gen_result
    }

    async fn cancel(key: ProofKey, id_store: Box<&mut dyn IdStore>) -> ProverResult<()> {
        let uuid = match id_store.read_id(key).await {
            Ok(uuid) => uuid,
            Err(e) => {
                if e.to_string().contains("No data for query") {
                    return Ok(());
                } else {
                    return Err(ProverError::GuestError(e.to_string()));
                }
            }
        };
        cancel_proof(uuid)
            .await
            .map_err(|e| ProverError::GuestError(e.to_string()))?;
        id_store.remove_id(key).await
    }

    fn current_proving_image() -> (&'static [u8], &'static [u32; 8]) {
        use crate::methods::risc0_guest::{RISC0_GUEST_ELF, RISC0_GUEST_ID};
        (RISC0_GUEST_ELF, &RISC0_GUEST_ID)
    }

    fn current_aggregation_image() -> (&'static [u8], &'static [u32; 8]) {
        use crate::methods::risc0_aggregation::{RISC0_AGGREGATION_ELF, RISC0_AGGREGATION_ID};
        (RISC0_AGGREGATION_ELF, &RISC0_AGGREGATION_ID)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use methods::test_risc0_guest::{TEST_RISC0_GUEST_ELF, TEST_RISC0_GUEST_ID};
    use risc0_zkvm::{default_prover, ExecutorEnv};

    #[test]
    fn run_unittest_elf() {
        std::env::set_var("RISC0_PROVER", "local");
        let env = ExecutorEnv::builder().build().unwrap();
        let prover = default_prover();
        let receipt = prover.prove(env, TEST_RISC0_GUEST_ELF).unwrap();
        receipt.receipt.verify(TEST_RISC0_GUEST_ID).unwrap();
    }

    #[ignore = "only to print image id for docker image build"]
    #[test]
    fn test_show_risc0_image_id() {
        let (_, proving_image_id) = Risc0Prover::current_proving_image();
        let (_, aggregation_image_id) = Risc0Prover::current_aggregation_image();
        println!(
            "RISC0 PROVING IMAGE_ID: {}",
            encode_image_id(proving_image_id)
        );
        println!(
            "RISC0 AGGREGATION IMAGE_ID: {}",
            encode_image_id(aggregation_image_id)
        );
    }
}
