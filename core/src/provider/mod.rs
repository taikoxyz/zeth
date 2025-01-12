use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types::Block;
use raiko_lib::consts::SupportedChainSpecs;
use reth_primitives::revm_primitives::AccountInfo;
use std::collections::HashMap;

use crate::{
    interfaces::{RaikoError, RaikoResult},
    MerkleProof,
};

pub mod db;
pub mod preflight_rpc;
pub mod rpc;

pub use crate::provider::{
    preflight_rpc::RethPreflightBlockDataProvider, rpc::RpcBlockDataProvider,
};

#[allow(async_fn_in_trait)]
pub trait BlockDataProvider {
    async fn get_blocks(&self, blocks_to_fetch: &[(u64, bool)]) -> RaikoResult<Vec<Block>>;

    async fn get_accounts(&self, accounts: &[Address]) -> RaikoResult<Vec<AccountInfo>>;

    async fn get_storage_values(&self, accounts: &[(Address, U256)]) -> RaikoResult<Vec<U256>>;

    async fn get_merkle_proofs(
        &self,
        block_number: u64,
        accounts: HashMap<Address, Vec<U256>>,
        offset: usize,
        num_storage_proofs: usize,
    ) -> RaikoResult<MerkleProof>;
}

pub enum BlockDataProviderType {
    CommonRpc(RpcBlockDataProvider),
    PreflightRpc(RethPreflightBlockDataProvider),
}

impl BlockDataProvider for BlockDataProviderType {
    async fn get_blocks(&self, blocks_to_fetch: &[(u64, bool)]) -> RaikoResult<Vec<Block>> {
        match self {
            BlockDataProviderType::CommonRpc(provider) => {
                provider.get_blocks(blocks_to_fetch).await
            }
            BlockDataProviderType::PreflightRpc(provider) => {
                provider.get_blocks(blocks_to_fetch).await
            }
        }
    }

    async fn get_accounts(&self, accounts: &[Address]) -> RaikoResult<Vec<AccountInfo>> {
        match self {
            BlockDataProviderType::CommonRpc(provider) => provider.get_accounts(accounts).await,
            BlockDataProviderType::PreflightRpc(provider) => provider.get_accounts(accounts).await,
        }
    }

    async fn get_storage_values(&self, accounts: &[(Address, U256)]) -> RaikoResult<Vec<U256>> {
        match self {
            BlockDataProviderType::CommonRpc(provider) => {
                provider.get_storage_values(accounts).await
            }
            BlockDataProviderType::PreflightRpc(provider) => {
                provider.get_storage_values(accounts).await
            }
        }
    }

    async fn get_merkle_proofs(
        &self,
        block_number: u64,
        accounts: HashMap<Address, Vec<U256>>,
        offset: usize,
        num_storage_proofs: usize,
    ) -> RaikoResult<MerkleProof> {
        match self {
            BlockDataProviderType::CommonRpc(provider) => {
                provider
                    .get_merkle_proofs(block_number, accounts, offset, num_storage_proofs)
                    .await
            }
            BlockDataProviderType::PreflightRpc(provider) => {
                provider
                    .get_merkle_proofs(block_number, accounts, offset, num_storage_proofs)
                    .await
            }
        }
    }
}

pub async fn get_task_data(
    network: &str,
    block_number: u64,
    chain_specs: &SupportedChainSpecs,
) -> RaikoResult<(u64, B256)> {
    let taiko_chain_spec = chain_specs
        .get_chain_spec(network)
        .ok_or_else(|| RaikoError::InvalidRequestConfig("Unsupported raiko network".to_string()))?;
    let provider =
        RpcBlockDataProvider::new(&taiko_chain_spec.rpc.clone(), None, block_number - 1).await?;
    let blocks = provider.get_blocks(&[(block_number, false)]).await?;
    let block = blocks
        .first()
        .ok_or_else(|| RaikoError::RPC("No block for requested block number".to_string()))?;
    let blockhash = block
        .header
        .hash
        .ok_or_else(|| RaikoError::RPC("No block hash for requested block".to_string()))?;
    Ok((taiko_chain_spec.chain_id, blockhash))
}
