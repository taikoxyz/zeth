use std::collections::HashSet;

use alloy_primitives::Bytes;
// use alloy_rpc_types::Block;
use raiko_lib::{
    builder::RethBlockBuilder,
    consts::ChainSpec,
    input::{BlobProofType, GuestBatchInput, GuestInput, TaikoGuestInput, TaikoProverData},
    primitives::mpt::proofs_to_tries,
    Measurement,
};

use crate::{
    interfaces::{RaikoError, RaikoResult},
    provider::{db::ProviderDb, BlockDataProvider},
};

use util::{
    execute_txs, get_batch_blocks_and_parent_data, get_block_and_parent_data,
    prepare_taiko_chain_batch_input, prepare_taiko_chain_input,
};

mod util;

pub struct PreflightData {
    pub block_number: u64,
    pub l1_chain_spec: ChainSpec,
    pub l1_inclusion_block_number: u64,
    pub taiko_chain_spec: ChainSpec,
    pub prover_data: TaikoProverData,
    pub blob_proof_type: BlobProofType,
}

pub struct BatchPreflightData {
    pub block_numbers: Vec<u64>,
    // in real batch, we will have only 1 inclusion block number
    // here use vec for back compatbiility
    pub l1_inclusion_block_numbers: Option<Vec<u64>>,
    pub l1_chain_spec: ChainSpec,
    pub taiko_chain_spec: ChainSpec,
    pub prover_data: TaikoProverData,
    pub blob_proof_type: BlobProofType,
}

impl PreflightData {
    pub fn new(
        block_number: u64,
        l1_inclusion_block_number: u64,
        l1_chain_spec: ChainSpec,
        taiko_chain_spec: ChainSpec,
        prover_data: TaikoProverData,
        blob_proof_type: BlobProofType,
    ) -> Self {
        Self {
            block_number,
            l1_chain_spec,
            l1_inclusion_block_number,
            taiko_chain_spec,
            prover_data,
            blob_proof_type,
        }
    }
}

pub async fn preflight<BDP: BlockDataProvider>(
    provider: BDP,
    PreflightData {
        block_number,
        l1_chain_spec,
        taiko_chain_spec,
        prover_data,
        blob_proof_type,
        l1_inclusion_block_number,
    }: PreflightData,
) -> RaikoResult<GuestInput> {
    let measurement = Measurement::start("Fetching block data...", false);

    let (block, parent_block) = get_block_and_parent_data(&provider, block_number).await?;

    let taiko_guest_input = if taiko_chain_spec.is_taiko() {
        prepare_taiko_chain_input(
            &l1_chain_spec,
            &taiko_chain_spec,
            block_number,
            (l1_inclusion_block_number != 0).then_some(l1_inclusion_block_number),
            &block,
            prover_data,
            &blob_proof_type,
        )
        .await?
    } else {
        // For Ethereum blocks we just convert the block transactions in a tx_list
        // so that we don't have to supports separate paths.
        TaikoGuestInput::try_from(block.body.clone()).map_err(|e| RaikoError::Conversion(e.0))?
    };
    measurement.stop();

    let parent_header: reth_primitives::Header =
        parent_block.header.clone().try_into().map_err(|e| {
            RaikoError::Conversion(format!("Failed converting to reth header: {e}"))
        })?;
    let parent_block_number = parent_header.number;

    // Create the guest input
    let input = GuestInput {
        block,
        parent_header,
        chain_spec: taiko_chain_spec.clone(),
        taiko: taiko_guest_input,
        ..Default::default()
    };

    // Create the block builder, run the transactions and extract the DB
    let provider_db = ProviderDb::new(&provider, taiko_chain_spec, parent_block_number).await?;

    // Now re-execute the transactions in the block to collect all required data
    let mut builder = RethBlockBuilder::new(&input, provider_db);

    // Optimize data gathering by executing the transactions multiple times so data can be requested in batches
    execute_txs(&mut builder).await?;

    let Some(db) = builder.db.as_mut() else {
        return Err(RaikoError::Preflight("No db in builder".to_owned()));
    };

    // Gather inclusion proofs for the initial and final state
    let measurement = Measurement::start("Fetching storage proofs...", true);
    let (parent_proofs, proofs, num_storage_proofs) = db.get_proofs().await?;
    measurement.stop_with_count(&format!(
        "[{} Account/{num_storage_proofs} Storage]",
        parent_proofs.len() + proofs.len(),
    ));

    // Construct the state trie and storage from the storage proofs.
    let measurement = Measurement::start("Constructing MPT...", true);
    let (parent_state_trie, parent_storage) =
        proofs_to_tries(input.parent_header.state_root, parent_proofs, proofs)?;
    measurement.stop();

    // Gather proofs for block history
    let measurement = Measurement::start("Fetching historical block headers...", true);
    let ancestor_headers = db.get_ancestor_headers().await?;
    measurement.stop();

    // Get the contracts from the initial db.
    let measurement = Measurement::start("Fetching contract code...", true);
    let contracts =
        HashSet::<Bytes>::from_iter(db.initial_db.accounts.values().filter_map(|account| {
            account
                .info
                .code
                .clone()
                .map(|code| Bytes(code.bytecode().0.clone()))
        }))
        .into_iter()
        .collect::<Vec<Bytes>>();
    measurement.stop();

    // Fill in remaining generated guest input data
    let input = GuestInput {
        parent_state_trie,
        parent_storage,
        contracts,
        ancestor_headers,
        ..input
    };

    Ok(input)
}

pub async fn batch_preflight<BDP: BlockDataProvider>(
    provider: BDP,
    BatchPreflightData {
        block_numbers,
        l1_chain_spec,
        taiko_chain_spec,
        prover_data,
        blob_proof_type,
        l1_inclusion_block_numbers,
    }: BatchPreflightData,
) -> RaikoResult<GuestBatchInput> {
    let measurement = Measurement::start("Fetching block data...", false);

    let block_parent_pairs = get_batch_blocks_and_parent_data(&provider, &block_numbers).await?;

    let l2_l1_block_pairs: Vec<(u64, Option<u64>)> = block_numbers
        .iter()
        .zip(l1_inclusion_block_numbers.iter())
        .map(|(block_number, _)| (*block_number, None))
        .collect::<Vec<(u64, Option<u64>)>>();

    let all_prove_blocks = block_parent_pairs
        .iter()
        .map(|(block, _)| block.clone())
        .collect::<Vec<_>>();
    let taiko_guest_inputs = if taiko_chain_spec.is_taiko() {
        prepare_taiko_chain_batch_input(
            &l1_chain_spec,
            &taiko_chain_spec,
            l2_l1_block_pairs,
            &all_prove_blocks,
            prover_data,
            &blob_proof_type,
        )
        .await?
    } else {
        // For Ethereum blocks we just convert the block transactions in a tx_list
        // so that we don't have to supports separate paths.
        all_prove_blocks
            .iter()
            .map(|block| {
                TaikoGuestInput::try_from(block.body.clone())
                    .map_err(|e| RaikoError::Conversion(e.0))
            })
            .collect::<RaikoResult<Vec<_>>>()?
    };
    measurement.stop();

    let mut batch_guest_input = Vec::new();
    for ((prove_block, parent_block), taiko_input) in
        block_parent_pairs.iter().zip(taiko_guest_inputs.iter())
    {
        let parent_header: reth_primitives::Header =
            parent_block.header.clone().try_into().map_err(|e| {
                RaikoError::Conversion(format!("Failed converting to reth header: {e}"))
            })?;
        let parent_block_number = parent_header.number;

        // Create the guest input
        let input = GuestInput {
            block: prove_block.clone(),
            parent_header,
            chain_spec: taiko_chain_spec.clone(),
            taiko: taiko_input.clone(),
            ..Default::default()
        };

        // Create the block builder, run the transactions and extract the DB
        let provider_db =
            ProviderDb::new(&provider, taiko_chain_spec.clone(), parent_block_number).await?;

        // Now re-execute the transactions in the block to collect all required data
        let mut builder = RethBlockBuilder::new(&input, provider_db);

        // Optimize data gathering by executing the transactions multiple times so data can be requested in batches
        execute_txs(&mut builder).await?;

        let Some(db) = builder.db.as_mut() else {
            return Err(RaikoError::Preflight("No db in builder".to_owned()));
        };

        // Gather inclusion proofs for the initial and final state
        let measurement = Measurement::start("Fetching storage proofs...", true);
        let (parent_proofs, proofs, num_storage_proofs) = db.get_proofs().await?;
        measurement.stop_with_count(&format!(
            "[{} Account/{num_storage_proofs} Storage]",
            parent_proofs.len() + proofs.len(),
        ));

        // Construct the state trie and storage from the storage proofs.
        let measurement = Measurement::start("Constructing MPT...", true);
        let (parent_state_trie, parent_storage) =
            proofs_to_tries(input.parent_header.state_root, parent_proofs, proofs)?;
        measurement.stop();

        // Gather proofs for block history
        let measurement = Measurement::start("Fetching historical block headers...", true);
        let ancestor_headers = db.get_ancestor_headers().await?;
        measurement.stop();

        // Get the contracts from the initial db.
        let measurement = Measurement::start("Fetching contract code...", true);
        let contracts =
            HashSet::<Bytes>::from_iter(db.initial_db.accounts.values().filter_map(|account| {
                account
                    .info
                    .code
                    .clone()
                    .map(|code| Bytes(code.bytecode().0.clone()))
            }))
            .into_iter()
            .collect::<Vec<Bytes>>();
        measurement.stop();

        // Fill in remaining generated guest input data
        let input = GuestInput {
            parent_state_trie,
            parent_storage,
            contracts,
            ancestor_headers,
            ..input
        };
        batch_guest_input.push(input);
    }

    Ok(GuestBatchInput {
        inputs: batch_guest_input,
    })
}

#[cfg(test)]
mod test {
    use ethers_core::types::Transaction;
    use raiko_lib::{
        consts::{Network, SupportedChainSpecs},
        utils::decode_transactions,
    };

    use crate::preflight::util::{blob_to_bytes, block_time_to_block_slot};

    #[test]
    fn test_new_blob_decode() {
        let valid_blob_str = "\
            01000004b0f904adb8b502f8b283028c59188459682f008459682f028286b394\
            006700100000000000000000000000000001009980b844a9059cbb0000000000\
            0000000000000001670010000000000000000000000000000100990000000000\
            000000000000000000000000000000000000000000000000000001c080a0af40\
            093afa19e4b7256a209c71a902d33985c5655e580d5fbf36815e290b623177a0\
            19d4b4ccaa5497a47845016680c128b63e74e9d6a9756ebdeb2f78a65e0fa120\
            0001f802f901f483028c592e8459682f008459682f02832625a0941670010000\
            0b000000000000000000000000000280b90184fa233d0c000000000000000000\
            0000000000000000000000000000000000000000000000200000000000000000\
            000000000000000000000000000000000000000000007e7e0000000000000000\
            0000000014dc79964da2c08b23698b3d3cc7ca32193d99550000000000000000\
            0000000014dc79964da2c08b23698b3d3cc7ca32193d99550000000000000000\
            0000000000016700100000000000000000000000000001009900000000000000\
            0000000000000000000000000000000000000000000000000100000000000000\
            000000000000000000000000000000000000000000002625a000000000000000\
            0000000000000000000000000000000000000000000000000000000000000000\
            000000000000976ea74026e726554db657fa54763abd0c3a0aa9000000000000\
            0000000000000000000000000000000000000000000000000120000000000000\
            220000000000000000000000000000000000000000000000001243726f6e4a6f\
            102053656e64546f6b656e730000000000000000000000000000c080a0a99edd\
            2b13d5436cb0fe71b2ea4e69c2292fdc682ae54fe702cc36d6634dd0ba85a057\
            119f9297ca5ebd5402bd886405fe3aa8f8182438a9e56c1ef2a1ec0ae4a0acb9\
            00f802f901f483028c592f8459682f008459682f02832625a094167001000000\
            000000000000000000000000000280b90184fa233d0c00000000000000000000\
            0000000000000000000000000000000000000000000020000000000000000000\
            0000000000000000000000000000000000000000007e7e000000000000000000\
            00000014dc79964da2c08b23698b3d3cc7ca32193d9955000000000000000000\
            00000014dc79964da2c08b23698b3d3cc7ca32193d9955000000000000000000\
            0000000001670010000000000000000000000000000100990000000000000000\
            0000000000000000000000000000000000000000000000010000000000000000\
            0000000000000000000000000000000000000000002625a00000000000000000\
            0000000000000000000000000000000000000000000000000000000000000000\
            0000000000976ea74026e726554db657fa54763abd0c3a0aa900000000000000\
            0000000000000000000000000000000000000000000000012000000000000000\
            2000000000000000000000000000000000000000000000001243726f6e4a6f62\
            0053656e64546f6b656e730000000000000000000000000000c080a08f0a9757\
            35d78526f1339c69c2ed02df7a6d7cded10c74fb57398c11c1420526c2a0047f\
            003054d3d75d33120020872b6d5e0a4a05e47c50179bb9a8b866b7fb71b30000\
            0000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000";
        let blob_str = format!("{:0<262144}", valid_blob_str);
        let dec_blob = blob_to_bytes(&blob_str);
        println!("dec blob tx len: {:?}", dec_blob.len());
        let txs = decode_transactions(&dec_blob);
        println!("dec blob tx: {txs:?}");
    }

    #[ignore]
    #[test]
    fn test_slot_block_num_mapping() {
        let chain_spec = SupportedChainSpecs::default()
            .get_chain_spec(&Network::TaikoA7.to_string())
            .unwrap();
        let expected_slot = 1000u64;
        let second_per_slot = 12u64;
        let block_time = chain_spec.genesis_time + expected_slot * second_per_slot;
        let block_num =
            block_time_to_block_slot(block_time, chain_spec.genesis_time, second_per_slot)
                .expect("block time to slot failed");
        assert_eq!(block_num, expected_slot);

        assert!(block_time_to_block_slot(
            chain_spec.genesis_time - 10,
            chain_spec.genesis_time,
            second_per_slot
        )
        .is_err());
    }

    #[ignore]
    #[test]
    fn json_to_ethers_blob_tx() {
        let response = "{
            \"blockHash\":\"0xa61eea0256aa361dfd436be11b0e276470413fbbc34b3642fbbf3b5d8d72f612\",
		    \"blockNumber\":\"0x4\",
		    \"from\":\"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266\",
		    \"gas\":\"0xf4240\",
		    \"gasPrice\":\"0x5e92e74e\",
		    \"maxFeePerGas\":\"0x8b772ea6\",
		    \"maxPriorityFeePerGas\":\"0x3b9aca00\",
		    \"maxFeePerBlobGas\":\"0x2\",
		    \"hash\":\"0xdb3b11250a2332cc4944fa8022836bd32da43c34d4f2e9e1b246cfdbc5b4c60e\",
		    \"input\":\"0x11762da2\",
		    \"nonce\":\"0x1\",
		    \"to\":\"0x5fbdb2315678afecb367f032d93f642f64180aa3\",
		    \"transactionIndex\":\"0x0\",
		    \"value\":\"0x0\",
		    \"type\":\"0x3\",
            \"accessList\":[],
		    \"chainId\":\"0x7e7e\",
            \"blobVersionedHashes\":[\"0x012d46373b7d1f53793cd6872e40e801f9af6860ecbdbaa2e28df25937618c6f\",\"0x0126d296b606f85b775b12b8b4abeb3bdb88f5a50502754d598537ae9b7fb947\"],
            \"v\":\"0x0\",
		    \"r\":\"0xaba289efba8ef610a5b3b70b72a42fe1916640f64d7112ec0b89087bbc8fff5f\",
		    \"s\":\"0x1de067d69b79d28d0a3bd179e332c85b93cedbd299d9e205398c073a59633dcf\",
		    \"yParity\":\"0x0\"
        }";
        let tx: Transaction = serde_json::from_str(response).unwrap();
        println!("tx: {tx:?}");
    }
}
