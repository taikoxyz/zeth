use alloy_primitives::{Address, FixedBytes, U256};
use alloy_provider::{ProviderBuilder, ReqwestProvider, RootProvider};
use alloy_rpc_client::{ClientBuilder, RpcClient};
use alloy_rpc_types::{Block, BlockId, BlockNumberOrTag};
use alloy_transport_http::Http;
use reqwest_alloy::Client;
use reth_primitives::revm_primitives::{AccountInfo, Bytecode};
use std::collections::HashMap;
use tracing::error;

use crate::{
    interfaces::{RaikoError, RaikoResult},
    preflight::PreFlightRpcData,
    provider::BlockDataProvider,
    MerkleProof,
};

#[derive(Clone)]
pub struct RethPreflightBlockDataProvider {
    pub provider: ReqwestProvider,
    pub client: RpcClient<Http<Client>>,
    // use parent because it's the base of tx execution
    parent_block_num: u64,
    preflight_data: Option<PreFlightRpcData>,
}

impl RethPreflightBlockDataProvider {
    pub async fn new(url: &str, parent_block_num: u64) -> RaikoResult<Self> {
        let url =
            reqwest::Url::parse(url).map_err(|_| RaikoError::RPC("Invalid RPC URL".to_owned()))?;

        let client = ClientBuilder::default().http(url.clone());
        let preflight_data = client
            .request(
                "taiko_provingPreflight",
                &(BlockId::from(parent_block_num + 1)),
            )
            .await
            .map_err(|e| RaikoError::RPC(format!("Error getting preflight data: {e}")))?;

        Ok(Self {
            provider: ProviderBuilder::new().on_provider(RootProvider::new_http(url.clone())),
            client,
            parent_block_num,
            preflight_data,
        })
    }

    fn preflight_data_is_available(&self) -> RaikoResult<()> {
        if self.preflight_data.is_none() {
            Err(RaikoError::RPC("Preflight data not available".to_owned()))
        } else {
            Ok(())
        }
    }

    pub fn provider(&self) -> &ReqwestProvider {
        &self.provider
    }
}

impl BlockDataProvider for RethPreflightBlockDataProvider {
    async fn get_blocks(&self, blocks_to_fetch: &[(u64, bool)]) -> RaikoResult<Vec<Block>> {
        let mut all_blocks = Vec::with_capacity(blocks_to_fetch.len());

        let max_batch_size = 32;
        for blocks_to_fetch in blocks_to_fetch.chunks(max_batch_size) {
            let mut batch = self.client.new_batch();
            let mut requests = Vec::with_capacity(max_batch_size);

            for (block_number, full) in blocks_to_fetch {
                requests.push(Box::pin(
                    batch
                        .add_call(
                            "eth_getBlockByNumber",
                            &(BlockNumberOrTag::from(*block_number), full),
                        )
                        .map_err(|_| {
                            RaikoError::RPC(
                                "Failed adding eth_getBlockByNumber call to batch".to_owned(),
                            )
                        })?,
                ));
            }

            batch.send().await.map_err(|e| {
                RaikoError::RPC(format!(
                    "Error sending batch request for block {blocks_to_fetch:?}: {e}"
                ))
            })?;

            let mut blocks = Vec::with_capacity(max_batch_size);
            // Collect the data from the batch
            for request in requests {
                blocks.push(
                    request.await.map_err(|e| {
                        RaikoError::RPC(format!("Error collecting request data: {e}"))
                    })?,
                );
            }

            all_blocks.append(&mut blocks);
        }

        Ok(all_blocks)
    }

    async fn get_accounts(&self, accounts: &[Address]) -> RaikoResult<Vec<AccountInfo>> {
        self.preflight_data_is_available()?;

        let preflight_data = self.preflight_data.as_ref().unwrap();
        let mut all_accounts: Vec<AccountInfo> = Vec::with_capacity(accounts.len());
        preflight_data
            .parent_account_proofs
            .iter()
            .for_each(|account_proof| {
                let balance = account_proof.balance;
                let nonce = account_proof.nonce;
                let code_hash = account_proof.code_hash;
                let code = preflight_data
                    .contracts
                    .get(&account_proof.code_hash)
                    .map(|code| Bytecode::new_raw(code.clone()))
                    .unwrap();
                assert_eq!(code_hash, code.hash_slow());
                all_accounts.push(AccountInfo::new(
                    balance,
                    nonce.as_limbs()[0],
                    code_hash,
                    code,
                ))
            });
        Ok(all_accounts)
    }

    async fn get_storage_values(&self, accounts: &[(Address, U256)]) -> RaikoResult<Vec<U256>> {
        self.preflight_data_is_available()?;

        let preflight_data = self.preflight_data.as_ref().unwrap();
        let mut all_values = Vec::with_capacity(accounts.len());

        for (address, key) in accounts {
            let storage_proof = preflight_data
                .parent_account_proofs
                .iter()
                .find(|account_proof| account_proof.address == *address)
                .and_then(|account_proof| {
                    account_proof
                        .storage_proof
                        .iter()
                        .find(|storage_proof| storage_proof.key.0 == FixedBytes::<32>::from(*key))
                });

            if let Some(storage_proof) = storage_proof {
                all_values.push(storage_proof.value);
            } else {
                error!("Unable to find storage proof for address {address} and key {key}");
                return Err(RaikoError::RPC(format!(
                    "Unable to find storage proof for address {address} and key {key}"
                )));
            }
        }
        Ok(all_values)
    }

    async fn get_merkle_proofs(
        &self,
        block_number: u64,
        accounts: HashMap<Address, Vec<U256>>,
        _offset: usize,
        num_storage_proofs: usize,
    ) -> RaikoResult<MerkleProof> {
        if block_number != self.parent_block_num || block_number != self.parent_block_num + 1 {
            return Err(RaikoError::RPC(format!(
                "Block number {block_number} does not match preflight block number {:?} or its parent", self.parent_block_num
            )));
        }

        self.preflight_data_is_available()?;

        let preflight_data = self.preflight_data.as_ref().unwrap();
        let account_proofs = if block_number == self.parent_block_num {
            &preflight_data.parent_account_proofs
        } else {
            &preflight_data.account_proofs
        };
        let mut storage_proofs: MerkleProof = HashMap::new();

        for (address, keys) in accounts.iter() {
            let account_proof = account_proofs
                .iter()
                .find(|account_proof| account_proof.address == *address)
                .ok_or(RaikoError::RPC(format!(
                    "Unable to find account proof for address {address}"
                )))?;

            for key in keys.iter().take(num_storage_proofs) {
                account_proof
                    .storage_proof
                    .iter()
                    .find(|storage_proof| storage_proof.key.0 == FixedBytes::<32>::from(*key))
                    .ok_or(RaikoError::RPC(format!(
                        "Unable to find storage proof for key {key}"
                    )))?;
            }

            storage_proofs.insert(*address, account_proof.clone());
        }
        Ok(storage_proofs)
    }
}

#[cfg(test)]
mod test {
    use crate::provider::BlockDataProvider;

    use super::RethPreflightBlockDataProvider;

    #[tokio::test]
    async fn test_preflight_rpc() {
        let preflight_rpc_provider =
            RethPreflightBlockDataProvider::new("http://localhost:8545", 0)
                .await
                .unwrap();

        let blocks: Vec<alloy_rpc_types::Block> = preflight_rpc_provider
            .get_blocks(&[(0, true)])
            .await
            .unwrap();
        assert_eq!(blocks.len(), 1);
    }
}
