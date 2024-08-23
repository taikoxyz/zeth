#![cfg(feature = "enable")]

#[cfg(feature = "bonsai-auto-scaling")]
use crate::bonsai::auto_scaling::shutdown_bonsai;
use crate::{
    methods::risc0_guest::{RISC0_GUEST_ELF, RISC0_GUEST_ID},
    methods::risc0_aggregation::{RISC0_AGGREGATION_ELF, RISC0_AGGREGATION_ID},
    snarks::verify_groth16_snark,
};
use alloy_primitives::B256;
use hex::ToHex;
use log::warn;
use raiko_lib::{
    input::{AggregationGuestInput, AggregationGuestOutput, GuestInput, GuestOutput, ZkAggregationGuestInput},
    prover::{IdStore, IdWrite, Proof, ProofKey, Prover, ProverConfig, ProverError, ProverResult},
};
use risc0_zkvm::{serde::to_vec, sha::Digest, AssumptionReceipt, Receipt};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fmt::Debug;
use tracing::{debug, info as traicing_info};

pub use bonsai::*;

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
            input: Some(value.input),
            quote: Some(value.receipt),
            uuid: Some(value.uuid),
            kzg_proof: None,
        }
    }
}

pub struct Risc0Prover;

const RISC0_PROVER_CODE: u8 = 3;

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
            output.hash.clone(),
            RISC0_PROVER_CODE,
        );

        debug!("elf code length: {}", RISC0_GUEST_ELF.len());
        let encoded_input = to_vec(&input).expect("Could not serialize proving input!");

        let result = maybe_prove::<GuestInput, B256>(
            &config,
            encoded_input,
            RISC0_GUEST_ELF,
            &output.hash,
            (Vec::<Receipt>::new(), Vec::new()),
            proof_key,
            &mut id_store,
        )
        .await;

        let receipt = result.clone().unwrap().1.clone();
        let uuid = result.clone().unwrap().0;
        let journal: String = receipt.journal.encode_hex();

        // Create/verify Groth16 SNARK in bonsai
        let snark_proof = if config.snark && config.bonsai {
            let Some((stark_uuid, stark_receipt)) = result else {
                return Err(ProverError::GuestError(
                    "No STARK data to snarkify!".to_owned(),
                ));
            };
            let image_id = Digest::from(RISC0_GUEST_ID);
            let (snark_uuid, snark_receipt) =
                snarks::stark2snark(image_id, stark_uuid, stark_receipt)
                    .await
                    .map_err(|err| format!("Failed to convert STARK to SNARK: {err:?}"))?;

            traicing_info!("Validating SNARK uuid: {snark_uuid}");

            let enc_proof = verify_groth16_snark(image_id, snark_receipt)
                .await
                .map_err(|err| format!("Failed to verify SNARK: {err:?}"))?;

            format!("0x{}", hex::encode(enc_proof))
        } else {
            warn!("proof is not in snark mode, please check.");
            journal.clone()
        };

        #[cfg(feature = "bonsai-auto-scaling")]
        if config.bonsai {
            // shutdown bonsai
            shutdown_bonsai()
                .await
                .map_err(|e| ProverError::GuestError(e.to_string()))?;
        }

        Ok(Risc0Response { proof: snark_proof, receipt: serde_json::to_string(&receipt).unwrap(), uuid, input: output.hash }.into())
    }

    async fn aggregate(
        input: AggregationGuestInput,
        output: &AggregationGuestOutput,
        config: &ProverConfig,
        id_store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        let mut id_store = id_store;
        let config = Risc0Param::deserialize(config.get("risc0").unwrap()).unwrap();
        let proof_key = (
            0,
            output.hash.clone(),
            RISC0_PROVER_CODE,
        );

        // Extract the block proof receipts
        let assumptions: Vec<Receipt> = input.proofs
            .iter()
            .map(|proof| {
                let receipt: Receipt = serde_json::from_str(&proof.quote.clone().unwrap()).expect("Failed to deserialize");
                receipt
            })
            .collect::<Vec<_>>();
        let block_inputs: Vec<B256> = input.proofs
            .iter()
            .map(|proof| {
                proof.input.unwrap()
            })
            .collect::<Vec<_>>();
        // For bonsai
        let assumptions_uuids: Vec<String> = input.proofs
            .iter()
            .map(|proof| proof.uuid.clone().unwrap())
            .collect::<Vec<_>>();

        let input = ZkAggregationGuestInput {
            image_id: RISC0_GUEST_ID,
            block_inputs,
        };

        debug!("elf code length: {}", RISC0_AGGREGATION_ELF.len());
        let encoded_input = to_vec(&input).expect("Could not serialize proving input!");

        let result = maybe_prove::<AggregationGuestInput, B256>(
            &config,
            encoded_input,
            RISC0_AGGREGATION_ELF,
            &output.hash,
            (assumptions, assumptions_uuids),
            proof_key,
            &mut id_store,
        )
        .await;

        let receipt = result.clone().unwrap().1.clone();
        let uuid = result.clone().unwrap().0;
        let journal: String = receipt.journal.encode_hex();

        // Create/verify Groth16 SNARK in bonsai
        let snark_proof = if config.snark && config.bonsai {
            let Some((stark_uuid, stark_receipt)) = result else {
                return Err(ProverError::GuestError(
                    "No STARK data to snarkify!".to_owned(),
                ));
            };
            let image_id = Digest::from(RISC0_AGGREGATION_ID);
            let (snark_uuid, snark_receipt) =
                snarks::stark2snark(image_id, stark_uuid, stark_receipt)
                    .await
                    .map_err(|err| format!("Failed to convert STARK to SNARK: {err:?}"))?;

            traicing_info!("Validating SNARK uuid: {snark_uuid}");

            let enc_proof = verify_groth16_snark(image_id, snark_receipt)
                .await
                .map_err(|err| format!("Failed to verify SNARK: {err:?}"))?;

            format!("0x{}", hex::encode(enc_proof))
        } else {
            warn!("proof is not in snark mode, please check.");
            journal.clone()
        };

        #[cfg(feature = "bonsai-auto-scaling")]
        if config.bonsai {
            // shutdown bonsai
            shutdown_bonsai()
                .await
                .map_err(|e| ProverError::GuestError(e.to_string()))?;
        }

        Ok(Risc0Response { proof: snark_proof, receipt: serde_json::to_string(&receipt).unwrap(), uuid, input: output.hash }.into())
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
}
