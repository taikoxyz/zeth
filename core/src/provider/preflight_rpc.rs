use alloy_primitives::{Address, FixedBytes, U256};
use alloy_provider::{ProviderBuilder, ReqwestProvider, RootProvider};
use alloy_rpc_client::{ClientBuilder, RpcClient};
use alloy_rpc_types::{Block, BlockNumberOrTag};
use alloy_transport_http::Http;
use reqwest_alloy::Client;
use reth_primitives::{
    revm_primitives::{AccountInfo, Bytecode},
    U64,
};
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
    pub fn new(url: &str, parent_block_num: u64) -> RaikoResult<Self> {
        let url =
            reqwest::Url::parse(url).map_err(|_| RaikoError::RPC("Invalid RPC URL".to_owned()))?;

        let client = ClientBuilder::default().http(url.clone());

        Ok(Self {
            provider: ProviderBuilder::new().on_provider(RootProvider::new_http(url.clone())),
            client,
            parent_block_num,
            preflight_data: None,
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

    pub async fn fetch_preflight_data(&mut self) -> RaikoResult<()> {
        let curr_block_num_hex = format!("0x{:x}", self.parent_block_num + 1);
        let preflight_data = self
            .client
            .request("taiko_provingPreflight", vec![curr_block_num_hex])
            .await
            .map_err(|e| RaikoError::RPC(format!("Error getting preflight data: {e}")))?;
        self.preflight_data = Some(preflight_data);
        Ok(())
    }

    // temporary functions to get account/storage/mkl and mark missing ones as None
    // which will be further processed by fall back to legacy rpc.
    // to be removed after the preflight data is all available

    pub async fn try_get_accounts(
        &self,
        accounts: &[Address],
    ) -> RaikoResult<Vec<Option<AccountInfo>>> {
        let account_infos = self.get_accounts(accounts).await?;
        let account_opt_infos: Vec<Option<AccountInfo>> = account_infos
            .iter()
            .zip(accounts.iter())
            .map(|(info, addr)| {
                if empty_account_info(info) {
                    error!("Empty account info for address {}", addr);
                    None
                } else {
                    Some(info.clone())
                }
            })
            .collect();
        Ok(account_opt_infos)
    }

    pub async fn try_get_storage_values(
        &self,
        account_keys: &[(Address, U256)],
    ) -> RaikoResult<Vec<Option<U256>>> {
        let storage_values = self.get_storage_values(account_keys).await?;
        assert_eq!(storage_values.len(), account_keys.len());
        let storage_values: Vec<Option<U256>> = storage_values
            .iter()
            .zip(account_keys.iter())
            .map(|(value, (addr, _))| {
                if value.is_zero() {
                    error!("Empty storage value for address {}", addr);
                    None
                } else {
                    Some(value.clone())
                }
            })
            .collect();
        Ok(storage_values)
    }

    pub async fn try_get_merkle_proofs(
        &self,
        block_number: u64,
        accounts: HashMap<Address, Vec<U256>>,
        offset: usize,
        num_storage_proofs: usize,
    ) -> RaikoResult<(MerkleProof, HashMap<Address, Vec<U256>>)> {
        let merkle_proof: HashMap<Address, alloy_rpc_types::EIP1186AccountProofResponse> = self
            .get_merkle_proofs(block_number, accounts.clone(), offset, num_storage_proofs)
            .await?;
        let mut missed_accounts: HashMap<Address, Vec<U256>> = HashMap::new();
        for (address, keys) in accounts.iter() {
            assert!(
                merkle_proof.contains_key(address),
                "{}",
                format!(
                    "address {} is missing in mkl proofs {:?}",
                    address,
                    merkle_proof.keys()
                )
                .as_str()
            );
            let account_proof = merkle_proof.get(address).unwrap();
            let mut missed_keys = Vec::new();

            assert_eq!(account_proof.storage_proof.len(), keys.len());
            keys.iter()
                .zip(account_proof.storage_proof.iter())
                .for_each(|(key, proof)| {
                    if proof.value.is_zero() && proof.proof.is_empty() {
                        missed_keys.push(*key);
                    }
                });
            if !missed_keys.is_empty() {
                missed_accounts.insert(*address, missed_keys);
            }
        }

        Ok((merkle_proof, missed_accounts))
    }
}

fn empty_account_info(account_info: &AccountInfo) -> bool {
    account_info.balance.is_zero()
        && account_info.nonce == 0
        && account_info
            .code
            .clone()
            .is_some_and(|code| code.is_empty())
        && account_info.code_hash.is_zero()
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
        let none_place_holder = alloy_rpc_types::EIP1186AccountProofResponse::default();
        let none_byte_holder = reth_primitives::Bytes::default();
        accounts.iter().for_each(|address| {
            let account_proof: &alloy_rpc_types::EIP1186AccountProofResponse = match preflight_data
                .parent_account_proofs
                .iter()
                .find(|account_proof| {
                    account_proof.address.to_checksum(None) == address.to_checksum(None)
                }) {
                Some(account_proof) => account_proof,
                None => {
                    println!(
                        "Unable to find account proof for address {} in {:?} parent account proofs",
                        address.to_checksum(None),
                        &preflight_data
                            .parent_account_proofs
                            .iter()
                            .map(|a| a.address.to_checksum(None))
                            .collect::<Vec<_>>()
                    );
                    &none_place_holder
                }
            };

            all_accounts.push(AccountInfo::new(
                account_proof.balance,
                account_proof.nonce.as_limbs()[0],
                account_proof.code_hash,
                Bytecode::new_raw(
                    preflight_data
                        .contracts
                        .get(&account_proof.code_hash)
                        .or_else(|| Some(&none_byte_holder))
                        .unwrap()
                        .clone(),
                ),
            ));
        });
        Ok(all_accounts)
    }

    async fn get_storage_values(&self, accounts: &[(Address, U256)]) -> RaikoResult<Vec<U256>> {
        self.preflight_data_is_available()?;

        let preflight_data = self.preflight_data.as_ref().unwrap();
        let mut all_values = Vec::with_capacity(accounts.len());
        let empty_storage_value = U256::ZERO;
        for (address, key) in accounts {
            let storage_proof = preflight_data
                .parent_account_proofs
                .iter()
                .find(|account_proof| {
                    account_proof.address.to_checksum(None) == address.to_checksum(None)
                })
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
                all_values.push(empty_storage_value);
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
        if block_number != self.parent_block_num && block_number != self.parent_block_num + 1 {
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
            if let Some(account_proof) = account_proofs
                .iter()
                .find(|account_proof| account_proof.address == *address)
            {
                let mut account_proof_holder = account_proof.clone();
                account_proof_holder.storage_proof = Vec::with_capacity(num_storage_proofs);
                for key in keys.iter().take(num_storage_proofs) {
                    if let Some(proof) = account_proof
                        .storage_proof
                        .iter()
                        .find(|storage_proof| storage_proof.key.0 == FixedBytes::<32>::from(*key))
                    {
                        account_proof_holder.storage_proof.push(proof.clone());
                    } else {
                        account_proof_holder.storage_proof.push(
                            alloy_rpc_types::EIP1186StorageProof {
                                key: alloy_rpc_types::serde_helpers::JsonStorageKey::from(*key),
                                value: U256::ZERO,
                                proof: Vec::new(),
                            },
                        );
                    }
                }
                storage_proofs.insert(*address, account_proof_holder.clone());
            } else {
                let mut all_missed_key_proofs = Vec::new();
                for key in keys.iter().take(num_storage_proofs) {
                    all_missed_key_proofs.push(alloy_rpc_types::EIP1186StorageProof {
                        key: alloy_rpc_types::serde_helpers::JsonStorageKey::from(*key),
                        value: U256::ZERO,
                        proof: Vec::new(),
                    });
                }
                storage_proofs.insert(
                    *address,
                    alloy_rpc_types::EIP1186AccountProofResponse {
                        address: *address,
                        balance: U256::ZERO,
                        nonce: U64::ZERO,
                        code_hash: FixedBytes::<32>::default(),
                        storage_proof: all_missed_key_proofs,
                        storage_hash: FixedBytes::<32>::default(),
                        account_proof: Vec::new(),
                    },
                );
            }
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
            RethPreflightBlockDataProvider::new("http://localhost:8545", 0).unwrap();

        let blocks: Vec<alloy_rpc_types::Block> = preflight_rpc_provider
            .get_blocks(&[(0, true)])
            .await
            .unwrap();
        assert_eq!(blocks.len(), 1);
    }
}
