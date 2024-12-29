use std::{collections::HashMap, hint::black_box};

use alloy_primitives::Address;
use alloy_rpc_types::EIP1186AccountProofResponse;
use interfaces::{cancel_proof, run_prover};
use raiko_lib::{
    builder::{create_mem_db, RethBlockBuilder},
    consts::ChainSpec,
    input::{GuestInput, GuestOutput, TaikoProverData},
    protocol_instance::ProtocolInstance,
    prover::{IdStore, IdWrite, Proof, ProofKey},
};
use reth_primitives::Header;
use serde_json::Value;
use tracing::{debug, error, info, warn};

use crate::{
    interfaces::{ProofRequest, RaikoError, RaikoResult},
    preflight::{preflight, preflight_v2, PreflightData},
    provider::BlockDataProvider,
};

pub mod interfaces;
pub mod preflight;
pub mod prover;
pub mod provider;

pub type MerkleProof = HashMap<Address, EIP1186AccountProofResponse>;

pub struct Raiko {
    l1_chain_spec: ChainSpec,
    taiko_chain_spec: ChainSpec,
    request: ProofRequest,
    v2_preflight: bool,
}

impl Raiko {
    pub fn new(
        l1_chain_spec: ChainSpec,
        taiko_chain_spec: ChainSpec,
        request: ProofRequest,
        v2_preflight: bool,
    ) -> Self {
        Self {
            l1_chain_spec,
            taiko_chain_spec,
            request,
            v2_preflight,
        }
    }

    fn get_preflight_data(&self) -> PreflightData {
        PreflightData::new(
            self.request.block_number,
            self.request.l1_inclusion_block_number,
            self.l1_chain_spec.to_owned(),
            self.taiko_chain_spec.to_owned(),
            TaikoProverData {
                graffiti: self.request.graffiti,
                prover: self.request.prover,
            },
            self.request.blob_proof_type.clone(),
        )
    }

    pub async fn generate_input<BDP: BlockDataProvider>(
        &self,
        provider: BDP,
    ) -> RaikoResult<GuestInput> {
        if self.v2_preflight {
            self.generate_input_v2(provider).await
        } else {
            self.generate_input_v1(provider).await
        }
    }

    // v1 uses the geth node & batched rpc calls
    pub async fn generate_input_v1<BDP: BlockDataProvider>(
        &self,
        provider: BDP,
    ) -> RaikoResult<GuestInput> {
        //TODO: read fork from config
        let preflight_data = self.get_preflight_data();
        info!(
            "Generating v1(common-batch) input for block {}",
            self.request.block_number
        );
        preflight(provider, preflight_data)
            .await
            .map_err(Into::<RaikoError>::into)
    }

    // v2 uses the taiko node & single preflight rpc call together with the block rpc calls
    pub async fn generate_input_v2<BDP: BlockDataProvider>(
        &self,
        provider: BDP,
    ) -> RaikoResult<GuestInput> {
        //TODO: read fork from config
        let preflight_data = self.get_preflight_data();
        info!(
            "Generating v2(reth-preflight) input for block {}",
            self.request.block_number
        );
        preflight_v2(provider, preflight_data)
            .await
            .map_err(Into::<RaikoError>::into)
    }

    pub fn get_output(&self, input: &GuestInput) -> RaikoResult<GuestOutput> {
        let db = create_mem_db(&mut input.clone()).unwrap();
        let mut builder = RethBlockBuilder::new(input, db);
        builder.execute_transactions(false).expect("execute");
        let result = builder.finalize();

        match result {
            Ok(header) => {
                info!("Verifying final state using provider data ...");
                info!(
                    "Final block hash derived successfully. {}",
                    header.hash_slow()
                );
                debug!("Final block header derived successfully. {header:?}");
                // Check if the header is the expected one
                check_header(&input.block.header, &header)?;

                Ok(GuestOutput {
                    header: header.clone(),
                    hash: ProtocolInstance::new(input, &header, self.request.proof_type)?
                        .instance_hash(),
                })
            }
            Err(e) => {
                warn!("Proving bad block construction!");
                Err(RaikoError::Guest(
                    raiko_lib::prover::ProverError::GuestError(e.to_string()),
                ))
            }
        }
    }

    pub async fn prove(
        &self,
        input: GuestInput,
        output: &GuestOutput,
        store: Option<&mut dyn IdWrite>,
    ) -> RaikoResult<Proof> {
        let config = serde_json::to_value(&self.request)?;
        run_prover(self.request.proof_type, input, output, &config, store).await
    }

    pub async fn cancel(
        &self,
        proof_key: ProofKey,
        read: Box<&mut dyn IdStore>,
    ) -> RaikoResult<()> {
        cancel_proof(self.request.proof_type, proof_key, read).await
    }
}

fn check_header(exp: &Header, header: &Header) -> Result<(), RaikoError> {
    // Check against the expected value of all fields for easy debugability
    check_eq(&exp.parent_hash, &header.parent_hash, "parent_hash");
    check_eq(&exp.ommers_hash, &header.ommers_hash, "ommers_hash");
    check_eq(&exp.beneficiary, &header.beneficiary, "beneficiary");
    check_eq(&exp.state_root, &header.state_root, "state_root");
    check_eq(
        &exp.transactions_root,
        &header.transactions_root,
        "transactions_root",
    );
    check_eq(&exp.receipts_root, &header.receipts_root, "receipts_root");
    check_eq(
        &exp.withdrawals_root,
        &header.withdrawals_root,
        "withdrawals_root",
    );
    check_eq(&exp.logs_bloom, &header.logs_bloom, "logs_bloom");
    check_eq(&exp.difficulty, &header.difficulty, "difficulty");
    check_eq(&exp.number, &header.number, "number");
    check_eq(&exp.gas_limit, &header.gas_limit, "gas_limit");
    check_eq(&exp.gas_used, &header.gas_used, "gas_used");
    check_eq(&exp.timestamp, &header.timestamp, "timestamp");
    check_eq(&exp.mix_hash, &header.mix_hash, "mix_hash");
    check_eq(&exp.nonce, &header.nonce, "nonce");
    check_eq(
        &exp.base_fee_per_gas,
        &header.base_fee_per_gas,
        "base_fee_per_gas",
    );
    check_eq(&exp.blob_gas_used, &header.blob_gas_used, "blob_gas_used");
    check_eq(
        &exp.excess_blob_gas,
        &header.excess_blob_gas,
        "excess_blob_gas",
    );
    check_eq(
        &exp.parent_beacon_block_root,
        &header.parent_beacon_block_root,
        "parent_beacon_block_root",
    );
    check_eq(&exp.extra_data, &header.extra_data, "extra_data");

    // Make sure the blockhash from the node matches the one from the builder
    require_eq(
        &exp.hash_slow(),
        &header.hash_slow(),
        &format!("block hash unexpected for block {}", exp.number),
    )
}

fn check_eq<T: std::cmp::PartialEq + std::fmt::Debug>(expected: &T, actual: &T, message: &str) {
    // printing out error, if any, but ignoring the result
    // making sure it's not optimized out
    let _ = black_box(require_eq(expected, actual, message));
}

fn require(expression: bool, message: &str) -> RaikoResult<()> {
    if !expression {
        let msg = format!("Assertion failed: {message}");
        error!("{msg}");
        return Err(anyhow::Error::msg(msg).into());
    }
    Ok(())
}

fn require_eq<T: std::cmp::PartialEq + std::fmt::Debug>(
    expected: &T,
    actual: &T,
    message: &str,
) -> RaikoResult<()> {
    let msg = format!("{message} - Expected: {expected:?}, Found: {actual:?}");
    require(expected == actual, &msg)
}

/// Merges two json's together, overwriting `a` with the values of `b`
pub fn merge(a: &mut Value, b: &Value) {
    match (a, b) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, v) in b {
                merge(a.entry(k).or_insert(Value::Null), v);
            }
        }
        (a, b) if !b.is_null() => b.clone_into(a),
        // If b is null, just keep a (which means do nothing).
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use crate::interfaces::aggregate_proofs;
    use crate::{
        interfaces::ProofRequest,
        provider::{BlockDataProviderType, RethPreflightBlockDataProvider, RpcBlockDataProvider},
        ChainSpec, Raiko,
    };
    use alloy_primitives::Address;
    use alloy_provider::Provider;
    use env_logger;
    use raiko_lib::{
        consts::{Network, SupportedChainSpecs},
        input::{AggregationGuestInput, AggregationGuestOutput, BlobProofType},
        primitives::B256,
        proof_type::ProofType,
        prover::Proof,
    };
    use serde_json::{json, Value};
    use std::{collections::HashMap, env, str::FromStr};

    fn get_proof_type_from_env() -> ProofType {
        let proof_type = env::var("TARGET").unwrap_or("native".to_string());
        ProofType::from_str(&proof_type).unwrap()
    }

    fn is_ci() -> bool {
        let ci = env::var("CI").unwrap_or("0".to_string());
        ci == "1"
    }

    fn test_proof_params(enable_aggregation: bool) -> HashMap<String, Value> {
        let mut prover_args = HashMap::new();
        prover_args.insert(
            "native".to_string(),
            json! {
                {
                    "json_guest_input": null
                }
            },
        );
        prover_args.insert(
            "sp1".to_string(),
            json! {
                {
                    "recursion": if enable_aggregation { "compressed" } else { "plonk" },
                    "prover": "mock",
                    "verify": true
                }
            },
        );
        prover_args.insert(
            "risc0".to_string(),
            json! {
                {
                    "bonsai": false,
                    "snark": false,
                    "profile": true,
                    "execution_po2": 18
                }
            },
        );
        prover_args.insert(
            "sgx".to_string(),
            json! {
                {
                    "instance_id": 121,
                    "setup": enable_aggregation,
                    "bootstrap": enable_aggregation,
                    "prove": true,
                }
            },
        );
        prover_args
    }

    async fn prove_block(
        l1_chain_spec: ChainSpec,
        taiko_chain_spec: ChainSpec,
        proof_request: ProofRequest,
    ) -> Proof {
        let v2_preflight = std::env::var("V2_PREFLIGHT")
            .unwrap_or("false".to_string())
            .parse()
            .unwrap();
        let provider = if v2_preflight {
            let provider: RethPreflightBlockDataProvider = RethPreflightBlockDataProvider::new(
                &taiko_chain_spec.rpc.clone(),
                proof_request.block_number - 1,
            )
            .await
            .expect("new RethPreflightBlockDataProvider should be ok");
            BlockDataProviderType::PreflightRpc(provider)
        } else {
            let provider = RpcBlockDataProvider::new(
                &taiko_chain_spec.rpc.clone(),
                proof_request.block_number - 1,
            )
            .expect("new RpcBlockDataProvider should be ok");
            BlockDataProviderType::CommonRpc(provider)
        };

        let raiko = Raiko::new(
            l1_chain_spec,
            taiko_chain_spec,
            proof_request.clone(),
            v2_preflight,
        );

        let input = raiko
            .generate_input(provider)
            .await
            .expect("input generation failed");
        let output = raiko.get_output(&input).expect("output generation failed");
        raiko
            .prove(input, &output, None)
            .await
            .expect("proof generation failed")
    }

    #[ignore]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_prove_block_taiko_dev() {
        let proof_type = get_proof_type_from_env();
        let l1_network = "taiko_dev_l1".to_owned();
        let network = "taiko_dev".to_owned();
        // Give the CI an simpler block to test because it doesn't have enough memory.
        // Unfortunately that also means that kzg is not getting fully verified by CI.
        let block_number = 20;
        let chain_specs = SupportedChainSpecs::merge_from_file(
            "../host/config/chain_spec_list_devnet.json".into(),
        )
        .unwrap();
        let taiko_chain_spec = chain_specs.get_chain_spec(&network).unwrap();
        let l1_chain_spec = chain_specs.get_chain_spec(&l1_network).unwrap();

        let proof_request = ProofRequest {
            block_number,
            l1_inclusion_block_number: 80,
            network,
            graffiti: B256::ZERO,
            prover: Address::ZERO,
            l1_network,
            proof_type,
            blob_proof_type: BlobProofType::ProofOfEquivalence,
            prover_args: test_proof_params(false),
        };
        prove_block(l1_chain_spec, taiko_chain_spec, proof_request).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_prove_block_taiko_a7() {
        let _ = env_logger::builder().is_test(true).try_init();

        let proof_type = get_proof_type_from_env();
        let l1_network = Network::Holesky.to_string();
        let network = Network::TaikoA7.to_string();
        // Give the CI an simpler block to test because it doesn't have enough memory.
        // Unfortunately that also means that kzg is not getting fully verified by CI.
        let block_number = if is_ci() { 105987 } else { 101368 };
        let taiko_chain_spec = SupportedChainSpecs::default()
            .get_chain_spec(&network)
            .unwrap();
        let l1_chain_spec = SupportedChainSpecs::default()
            .get_chain_spec(&l1_network)
            .unwrap();

        let proof_request = ProofRequest {
            block_number,
            l1_inclusion_block_number: 0,
            network,
            graffiti: B256::ZERO,
            prover: Address::ZERO,
            l1_network,
            proof_type,
            blob_proof_type: BlobProofType::ProofOfEquivalence,
            prover_args: test_proof_params(false),
        };
        prove_block(l1_chain_spec, taiko_chain_spec, proof_request).await;
    }

    async fn get_recent_block_num(chain_spec: &ChainSpec) -> u64 {
        let provider = RpcBlockDataProvider::new(&chain_spec.rpc, 0).unwrap();
        let height = provider.provider.get_block_number().await.unwrap();
        height - 100
    }

    #[ignore = "public node does not support long distance MPT proof query."]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_prove_block_ethereum() {
        let proof_type = get_proof_type_from_env();
        // Skip test on SP1 for now because it's too slow on CI
        if !(is_ci() && proof_type == ProofType::Sp1) {
            let network = Network::Ethereum.to_string();
            let l1_network = Network::Ethereum.to_string();
            let taiko_chain_spec = SupportedChainSpecs::default()
                .get_chain_spec(&network)
                .unwrap();
            let l1_chain_spec = SupportedChainSpecs::default()
                .get_chain_spec(&l1_network)
                .unwrap();
            let block_number = get_recent_block_num(&taiko_chain_spec).await;
            println!(
                "test_prove_block_ethereum in block_number: {}",
                block_number
            );
            let proof_request = ProofRequest {
                block_number,
                l1_inclusion_block_number: 0,
                network,
                graffiti: B256::ZERO,
                prover: Address::ZERO,
                l1_network,
                proof_type,
                blob_proof_type: BlobProofType::ProofOfEquivalence,
                prover_args: test_proof_params(false),
            };
            prove_block(l1_chain_spec, taiko_chain_spec, proof_request).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_prove_block_taiko_mainnet() {
        let proof_type = get_proof_type_from_env();
        // Skip test on SP1 for now because it's too slow on CI
        if !(is_ci() && proof_type == ProofType::Sp1) {
            let network = Network::TaikoMainnet.to_string();
            let l1_network = Network::Ethereum.to_string();
            let taiko_chain_spec = SupportedChainSpecs::default()
                .get_chain_spec(&network)
                .unwrap();
            let l1_chain_spec = SupportedChainSpecs::default()
                .get_chain_spec(&l1_network)
                .unwrap();
            let block_number = get_recent_block_num(&taiko_chain_spec).await;
            println!(
                "test_prove_block_taiko_mainnet in block_number: {}",
                block_number
            );
            let proof_request = ProofRequest {
                block_number,
                l1_inclusion_block_number: 0,
                network,
                graffiti: B256::ZERO,
                prover: Address::ZERO,
                l1_network,
                proof_type,
                blob_proof_type: BlobProofType::ProofOfEquivalence,
                prover_args: test_proof_params(false),
            };
            prove_block(l1_chain_spec, taiko_chain_spec, proof_request).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_prove_block_taiko_a7_aggregated() {
        let proof_type = get_proof_type_from_env();
        let l1_network = Network::Holesky.to_string();
        let network = Network::TaikoA7.to_string();
        // Give the CI an simpler block to test because it doesn't have enough memory.
        // Unfortunately that also means that kzg is not getting fully verified by CI.
        let block_number = if is_ci() { 105987 } else { 101368 };
        let taiko_chain_spec = SupportedChainSpecs::default()
            .get_chain_spec(&network)
            .unwrap();
        let l1_chain_spec = SupportedChainSpecs::default()
            .get_chain_spec(&l1_network)
            .unwrap();

        let proof_request = ProofRequest {
            block_number,
            l1_inclusion_block_number: 0,
            network,
            graffiti: B256::ZERO,
            prover: Address::ZERO,
            l1_network,
            proof_type,
            blob_proof_type: BlobProofType::ProofOfEquivalence,
            prover_args: test_proof_params(true),
        };
        let proof = prove_block(l1_chain_spec, taiko_chain_spec, proof_request).await;

        let input = AggregationGuestInput {
            proofs: vec![proof.clone(), proof],
        };

        let output = AggregationGuestOutput { hash: B256::ZERO };

        let aggregated_proof = aggregate_proofs(
            proof_type,
            input,
            &output,
            &serde_json::to_value(&test_proof_params(false)).unwrap(),
            None,
        )
        .await
        .expect("proof aggregation failed");
        println!("aggregated proof: {aggregated_proof:?}");
    }
}
