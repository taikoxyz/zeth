use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types::Block;
use raiko_lib::consts::SupportedChainSpecs;
use reth_primitives::revm_primitives::AccountInfo;
use std::collections::HashMap;

use crate::{
    interfaces::{RaikoError, RaikoResult},
    provider::rpc::RpcBlockDataProvider,
    MerkleProof,
};

pub mod db;
pub mod rpc;

#[allow(async_fn_in_trait)]
pub trait BlockDataProvider {
    async fn get_blocks(&self, blocks_to_fetch: &[(u64, bool)]) -> RaikoResult<Vec<Block>>;

    async fn get_accounts(
        &self,
        block_number: u64,
        accounts: &[Address],
    ) -> RaikoResult<Vec<AccountInfo>>;

    async fn get_storage_values(
        &self,
        block_number: u64,
        accounts: &[(Address, U256)],
    ) -> RaikoResult<Vec<U256>>;

    async fn get_merkle_proofs(
        &self,
        block_number: u64,
        accounts: HashMap<Address, Vec<U256>>,
        offset: usize,
        num_storage_proofs: usize,
    ) -> RaikoResult<MerkleProof>;
}

pub async fn get_task_data(
    network: &str,
    block_number: u64,
    chain_specs: &SupportedChainSpecs,
) -> RaikoResult<(u64, B256)> {
    let taiko_chain_spec = chain_specs
        .get_chain_spec(network)
        .ok_or_else(|| RaikoError::InvalidRequestConfig("Unsupported raiko network".to_string()))?;
    let provider = RpcBlockDataProvider::new(&taiko_chain_spec.rpc.clone(), block_number - 1)?;
    let blocks = provider.get_blocks(&[(block_number, true)]).await?;
    let block = blocks
        .first()
        .ok_or_else(|| RaikoError::RPC("No block for requested block number".to_string()))?;
    let blockhash = block
        .header
        .hash
        .ok_or_else(|| RaikoError::RPC("No block hash for requested block".to_string()))?;
    Ok((taiko_chain_spec.chain_id, blockhash))
}

pub async fn get_batch_task_data(
    network: &str,
    block_numbers: &[u64],
    chain_specs: &SupportedChainSpecs,
) -> RaikoResult<(u64, B256)> {
    let taiko_chain_spec = chain_specs
        .get_chain_spec(network)
        .ok_or_else(|| RaikoError::InvalidRequestConfig("Unsupported raiko network".to_string()))?;
    let block_number = block_numbers.last().expect("No block numbers provided");
    let provider = RpcBlockDataProvider::new(&taiko_chain_spec.rpc.clone(), block_number - 1)?;
    let blocks = provider.get_blocks(&[(*block_number, false)]).await?;
    let block = blocks
        .first()
        .ok_or_else(|| RaikoError::RPC("No block for requested block number".to_string()))?;
    let blockhash = block
        .header
        .hash
        .ok_or_else(|| RaikoError::RPC("No block hash for requested block".to_string()))?;
    Ok((taiko_chain_spec.chain_id, blockhash))
}
