use std::{fs::File, path::PathBuf};

use raiko_core::{
    interfaces::RaikoError,
    provider::{BlockDataProvider, BlockDataProviderType},
};
use raiko_lib::input::{get_input_path, GuestInput};
use tracing::{debug, info};

use crate::interfaces::{HostError, HostResult};

pub fn get_input(
    cache_path: &Option<PathBuf>,
    block_number: u64,
    network: &str,
) -> Option<GuestInput> {
    let dir = cache_path.as_ref()?;

    let path = get_input_path(dir, block_number, network);

    let file = File::open(path).ok()?;

    bincode::deserialize_from(file).ok()
}

pub fn set_input(
    cache_path: &Option<PathBuf>,
    block_number: u64,
    network: &str,
    input: &GuestInput,
) -> HostResult<()> {
    let Some(dir) = cache_path.as_ref() else {
        return Ok(());
    };

    let path = get_input_path(dir, block_number, network);
    info!("caching input for {path:?}");

    let file = File::create(&path).map_err(<std::io::Error as Into<HostError>>::into)?;
    bincode::serialize_into(file, input).map_err(|e| HostError::Anyhow(e.into()))
}

pub async fn validate_input(
    cached_input: Option<GuestInput>,
    provider: &BlockDataProviderType,
) -> HostResult<GuestInput> {
    if let Some(cache_input) = cached_input {
        debug!("Using cached input");
        let blocks = provider
            .get_blocks(&[(cache_input.block.number, false)])
            .await?;
        let block = blocks
            .first()
            .ok_or_else(|| RaikoError::RPC("No block data for the requested block".to_owned()))?;

        let cached_block_hash = cache_input.block.header.hash_slow();
        let real_block_hash = block.header.hash.unwrap();
        debug!("cache_block_hash={cached_block_hash:?}, real_block_hash={real_block_hash:?}");

        // double check if cache is valid
        if cached_block_hash == real_block_hash {
            Ok(cache_input)
        } else {
            Err(HostError::InvalidRequestConfig(
                "Cached input is not valid".to_owned(),
            ))
        }
    } else {
        Err(HostError::InvalidRequestConfig(
            "Cached input is not enabled".to_owned(),
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::cache;

    use alloy_primitives::{Address, B256};
    use alloy_provider::Provider;

    use raiko_core::{interfaces::ProofRequest, provider::rpc::RpcBlockDataProvider, Raiko};
    use raiko_lib::input::BlobProofType;
    use raiko_lib::{
        consts::{ChainSpec, Network, SupportedChainSpecs},
        input::GuestInput,
        proof_type::ProofType,
    };

    async fn create_cache_input(
        l1_network: &String,
        network: &String,
        block_number: u64,
    ) -> (GuestInput, RpcBlockDataProvider) {
        let l1_chain_spec = SupportedChainSpecs::default()
            .get_chain_spec(l1_network)
            .unwrap();
        let taiko_chain_spec = SupportedChainSpecs::default()
            .get_chain_spec(network)
            .unwrap();
        let proof_request = ProofRequest {
            block_number,
            network: network.to_string(),
            l1_network: l1_network.to_string(),
            graffiti: B256::ZERO,
            prover: Address::ZERO,
            proof_type: ProofType::Native,
            blob_proof_type: BlobProofType::KzgVersionedHash,
            prover_args: Default::default(),
            l1_inclusion_block_number: 0,
        };
        let raiko = Raiko::new(
            l1_chain_spec.clone(),
            taiko_chain_spec.clone(),
            proof_request.clone(),
            false,
        );
        let provider = RpcBlockDataProvider::new(
            &taiko_chain_spec.rpc.clone(),
            proof_request.block_number - 1,
        )
        .expect("provider init ok");

        let input = raiko
            .generate_input(provider.clone())
            .await
            .expect("input generation failed");
        (input, provider.clone())
    }

    async fn get_a_testable_block_num(chain_spec: &ChainSpec) -> u64 {
        get_latest_block_num(chain_spec).await - 299582u64 // a hardcode helka & mainnet height diff for the test
    }

    async fn get_latest_block_num(chain_spec: &ChainSpec) -> u64 {
        let provider = RpcBlockDataProvider::new(&chain_spec.rpc, 0).unwrap();

        provider.provider.get_block_number().await.unwrap()
    }

    #[tokio::test]
    async fn test_generate_input_from_cache() {
        let l1 = &Network::Holesky.to_string();
        let l2 = &Network::TaikoA7.to_string();
        let taiko_chain_spec = SupportedChainSpecs::default().get_chain_spec(l2).unwrap();
        let block_number: u64 = get_a_testable_block_num(&taiko_chain_spec).await;
        let (input, provider) = create_cache_input(l1, l2, block_number).await;
        let cache_path = Some("./".into());
        assert!(cache::set_input(&cache_path, block_number, l2, &input).is_ok());
        let cached_input = cache::get_input(&cache_path, block_number, l2).expect("load cache");
        assert!(cache::validate_input(Some(cached_input), &provider)
            .await
            .is_ok());

        let new_l1 = &Network::Ethereum.to_string();
        let new_l2 = &Network::TaikoMainnet.to_string();
        let taiko_chain_spec = SupportedChainSpecs::default()
            .get_chain_spec(new_l2)
            .unwrap();
        let block_number: u64 = get_latest_block_num(&taiko_chain_spec).await;
        let (new_input, _) = create_cache_input(new_l1, new_l2, block_number).await;
        // save to old l2 cache slot
        assert!(cache::set_input(&cache_path, block_number, l2, &new_input).is_ok());
        let inv_cached_input = cache::get_input(&cache_path, block_number, l2).expect("load cache");

        // should fail with old provider
        assert!(cache::validate_input(Some(inv_cached_input), &provider)
            .await
            .is_err());
    }
}
