use crate::common::{
    complete_aggregate_proof_request, complete_proof_request, make_aggregate_proof_request,
    make_proof_request, randomly_select_blocks, setup, v2_assert_report,
};
use raiko_host::server::api;
use raiko_lib::consts::Network;
use raiko_lib::proof_type::ProofType;
use raiko_tasks::TaskStatus;

#[serial_test::serial]
#[test_log::test(tokio::test)]
async fn test_v2_mainnet_aggregate_native() {
    test_v2_mainnet_aggregate(Network::TaikoMainnet, ProofType::Native).await;
}

#[ignore]
#[serial_test::serial]
#[cfg(feature = "risc0")]
#[test_log::test(tokio::test)]
async fn test_v2_mainnet_aggregate_risc0() {
    test_v2_mainnet_aggregate(Network::TaikoMainnet, ProofType::Risc0).await;
}

async fn test_v2_mainnet_aggregate(network: Network, proof_type: ProofType) {
    setup_mock_zkvm_elf();

    let api_version = "v2";
    let aggregate_block_count = 1;

    let block_numbers = randomly_select_blocks(network, aggregate_block_count)
        .await
        .expect("randomly select blocks failed");
    println!(
        "[test_aggregate_v2_mainnet] network: {network}, proof_type: {proof_type}, block_numbers: {block_numbers:?}"
    );

    let (_server, client) = setup().await;
    let requests: Vec<_> = block_numbers
        .iter()
        .map(|block_number| make_proof_request(&network, &proof_type, *block_number))
        .collect();
    let mut proofs = Vec::with_capacity(block_numbers.len());

    for request in requests {
        let status: api::v2::Status = client
            .post("/v2/proof", &request)
            .await
            .expect("failed to send request");
        assert!(
            matches!(
                status,
                api::v2::Status::Ok {
                    data: api::v2::ProofResponse::Status {
                        status: TaskStatus::Registered
                            | TaskStatus::WorkInProgress
                            | TaskStatus::Success,
                        ..
                    }
                }
            ),
            "status: {status:?}"
        );

        let proof = complete_proof_request(api_version, &client, &request).await;
        proofs.push(proof);
    }

    let aggregate_request =
        make_aggregate_proof_request(&network, &proof_type, block_numbers, proofs).await;

    // NOTE: Only v3 supports aggregate proof
    let status: api::v3::Status = client
        .post("/v3/proof/aggregate", &aggregate_request)
        .await
        .expect("failed to send aggregate proof request");
    assert!(
        matches!(
            status,
            api::v3::Status::Ok {
                data: api::v3::ProofResponse::Status {
                    status: TaskStatus::Registered
                        | TaskStatus::WorkInProgress
                        | TaskStatus::Success,
                    ..
                }
            }
        ),
        "status: {status:?}"
    );

    // NOTE: Only v3 supports aggregate proof
    complete_aggregate_proof_request("v3", &client, &aggregate_request).await;

    // santy check for report format
    v2_assert_report(&client).await;
}

// Use mock zkvm elf for testing
fn setup_mock_zkvm_elf() {
    std::env::set_var("RAIKO_MOCK_ZKVM_ELF", "true");
}
