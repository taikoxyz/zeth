use crate::common::{complete_proof_request, v2_assert_report, Client};
use raiko_core::interfaces::{get_aggregation_image, ProofRequestOpt, ProverSpecificOpts};
use raiko_host::server::api;
use raiko_lib::{proof_type::ProofType, prover::encode_image_id};
use raiko_tasks::TaskStatus;
use serde_json::json;
use std::str::FromStr;

/// This test is used to manually test the proof process. Operator can use this to test case to
/// simplly test online service.
///
/// To run this test, you need to set the `RAIKO_TEST_MANUAL_PROVE_ENABLED` environment variable to `true`, and
/// specify the parameters via environment variables.
///
/// ```bash
/// RAIKO_TEST_MANUAL_PROVE_ENABLED=true \
/// RAIKO_TEST_MANUAL_PROVE_API_VERSION=v2 \
/// RAIKO_TEST_MANUAL_PROVE_NETWORK=taiko_mainnet \
/// RAIKO_TEST_MANUAL_PROVE_PROOF_TYPE=native \
/// RAIKO_TEST_MANUAL_PROVE_BLOCK_NUMBER=656443 \
/// RAIKO_TEST_MANUAL_PROVE_RAIKO_RPC_URL=https://rpc.raiko.xyz \
/// cargo test --test test_manual_prove -- --ignored
/// ```
#[test_log::test(tokio::test)]
#[ignore]
pub async fn test_manual_prove() {
    let enabled = std::env::var("RAIKO_TEST_MANUAL_PROVE_ENABLED").unwrap_or_default() == "false";
    if !enabled {
        return;
    }

    // Manual test enabled, we require all parameters to be set.
    // Currently, we don't validate the parameters, so operator should ensure the parameters are intended.
    let api_version = std::env::var("RAIKO_TEST_MANUAL_PROVE_API_VERSION").unwrap_or_default();
    let network = std::env::var("RAIKO_TEST_MANUAL_PROVE_NETWORK").unwrap_or_default();
    let proof_type = std::env::var("RAIKO_TEST_MANUAL_PROVE_PROOF_TYPE").unwrap_or_default();
    let proof_type = ProofType::from_str(&proof_type).unwrap();
    let block_number = std::env::var("RAIKO_TEST_MANUAL_PROVE_BLOCK_NUMBER")
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap();
    let raiko_rpc_url = std::env::var("RAIKO_TEST_MANUAL_PROVE_RAIKO_RPC_URL").unwrap_or_default();

    let image_id = match proof_type {
        ProofType::Sp1 | ProofType::Risc0 => {
            let (_, image_id) = get_aggregation_image(proof_type).unwrap();
            Some(encode_image_id(image_id))
        }
        ProofType::Native | ProofType::Sgx => None,
    };

    let client = Client::new(raiko_rpc_url.clone());
    let request = ProofRequestOpt {
        block_number: Some(block_number),
        network: Some(network.clone()),
        proof_type: Some(proof_type.to_string()),
        image_id,

        // Untesting parameters
        l1_inclusion_block_number: None,
        l1_network: Some("ethereum".to_string()),
        graffiti: Some(
            "8008500000000000000000000000000000000000000000000000000000000000".to_owned(),
        ),
        prover: Some("0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_owned()),
        blob_proof_type: Some("proof_of_equivalence".to_string()),
        prover_args: ProverSpecificOpts {
            native: None,
            sgx: None,
            sp1: None,
            risc0: None,
        },
    };

    println!(
        "test_manual_prove parameters {}",
        json!({
            "request": request,
            "api_version": api_version,
            "network": network,
            "proof_type": proof_type,
            "block_number": block_number,
            "raiko_rpc_url": raiko_rpc_url,
        })
    );

    let status: api::v2::Status = client
        .post("/v2/proof", &request)
        .await
        .expect("failed to send request");
    assert!(
        matches!(
            status,
            api::v2::Status::Ok {
                data: api::v2::ProofResponse::Status {
                    status: TaskStatus::Registered,
                    ..
                }
            }
        ),
        "status: {status:?}"
    );

    complete_proof_request(&api_version, &client, &request).await;
    v2_assert_report(&client).await;
}
