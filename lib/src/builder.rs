use core::mem;
use std::sync::Arc;

use crate::primitives::keccak::keccak;
use crate::primitives::mpt::StateAccount;
use crate::{
    consts::{ChainSpec, MAX_BLOCK_HASH_AGE},
    guest_mem_forget,
    input::GuestInput,
    mem_db::{AccountState, DbAccount, MemDb},
    CycleTracker,
};
use anyhow::{bail, ensure, Result};
use reth_chainspec::{
    ChainSpecBuilder, Hardfork, HOLESKY, MAINNET, TAIKO_A7, TAIKO_DEV, TAIKO_MAINNET,
};
use reth_evm::execute::{BlockExecutionOutput, BlockValidationError, Executor, ProviderError};
use reth_evm_ethereum::execute::{
    validate_block_post_execution, Consensus, EthBeaconConsensus, EthExecutorProvider,
};
use reth_evm_ethereum::taiko::TaikoData;
use reth_primitives::revm_primitives::db::{Database, DatabaseCommit};
use reth_primitives::revm_primitives::{
    Account, AccountInfo, AccountStatus, Bytecode, Bytes, HashMap, SpecId,
};
use reth_primitives::{
    Address, BlockWithSenders, Header, TransactionSigned, B256, KECCAK_EMPTY, U256,
};
use tracing::{debug, error};

pub fn calculate_block_header(input: &GuestInput) -> Header {
    let cycle_tracker = CycleTracker::start("initialize_database");
    let db = create_mem_db(&mut input.clone()).unwrap();
    cycle_tracker.end();

    let mut builder = RethBlockBuilder::new(input, db);

    let cycle_tracker = CycleTracker::start("execute_transactions");
    builder.execute_transactions(false).expect("execute");
    cycle_tracker.end();

    let cycle_tracker = CycleTracker::start("finalize");
    let header = builder.finalize().expect("execute");
    cycle_tracker.end();

    header
}

/// Optimistic database
#[allow(async_fn_in_trait)]
pub trait OptimisticDatabase {
    /// Handle post execution work
    async fn fetch_data(&mut self) -> bool;

    /// If the current database is optimistic
    fn is_optimistic(&self) -> bool;
}
/// A generic builder for building a block.
#[derive(Clone, Debug)]
pub struct RethBlockBuilder<DB> {
    pub chain_spec: ChainSpec,
    pub input: GuestInput,
    pub db: Option<DB>,
    pub original_txs: Vec<TransactionSigned>,
}

impl<DB: Database<Error = ProviderError> + DatabaseCommit + OptimisticDatabase>
    RethBlockBuilder<DB>
{
    /// Creates a new block builder.
    pub fn new(input: &GuestInput, db: DB) -> RethBlockBuilder<DB> {
        // original tx comes from guest input L1 event, which should be a super set of input.block.body
        let original_txs = input
            .get_original_txs()
            .expect("get_original_txs should success");
        RethBlockBuilder {
            chain_spec: input.chain_spec.clone(),
            input: input.clone(),
            db: Some(db),
            original_txs,
        }
    }

    /// Executes all input transactions.
    pub fn execute_transactions(&mut self, optimistic: bool) -> Result<()> {
        // Get the chain spec
        let chain_spec = &self.input.chain_spec;
        let total_difficulty = U256::ZERO;
        let reth_chain_spec = match chain_spec.name.as_str() {
            "taiko_a7" => TAIKO_A7.clone(),
            "taiko_mainnet" => TAIKO_MAINNET.clone(),
            "ethereum" => {
                //MAINNET.clone()
                // TODO(Brecht): for some reason using the spec directly doesn't work
                Arc::new(
                    ChainSpecBuilder::default()
                        .chain(MAINNET.chain)
                        .genesis(MAINNET.genesis.clone())
                        .cancun_activated()
                        .build(),
                )
            }
            "holesky" => HOLESKY.clone(),
            "taiko_dev" => TAIKO_DEV.clone(),
            _ => unimplemented!(),
        };

        if reth_chain_spec.is_taiko() {
            let block_num = self.input.taiko.block_proposed.block_number();
            let block_timestamp = 0u64; // self.input.taiko.block_proposed.block_timestamp();
            let taiko_fork = self
                .input
                .chain_spec
                .spec_id(block_num, block_timestamp)
                .unwrap();
            match taiko_fork {
                SpecId::HEKLA => {
                    assert!(
                        reth_chain_spec
                            .fork(Hardfork::Hekla)
                            .active_at_block(block_num),
                        "evm fork is not active, please update the chain spec"
                    );
                }
                SpecId::ONTAKE => {
                    assert!(
                        reth_chain_spec
                            .fork(Hardfork::Ontake)
                            .active_at_block(block_num),
                        "evm fork is not active, please update the chain spec"
                    );
                }
                _ => unimplemented!(),
            }
        }

        // Generate the transactions from the tx list
        let mut block = self.input.block.clone();
        block.body = self.original_txs.clone();
        // Recover senders
        let mut block = block
            .with_recovered_senders()
            .ok_or(BlockValidationError::SenderRecoveryError)?;

        // Execute transactions
        let executor = EthExecutorProvider::ethereum(reth_chain_spec.clone())
            .eth_executor(self.db.take().unwrap())
            .taiko_data(TaikoData {
                l1_header: self.input.taiko.l1_header.clone(),
                parent_header: self.input.parent_header.clone(),
                l2_contract: self.input.chain_spec.l2_contract.unwrap_or_default(),
                base_fee_config: self.input.taiko.block_proposed.base_fee_config(),
            })
            .optimistic(optimistic);
        let BlockExecutionOutput {
            state,
            receipts,
            requests,
            gas_used: _,
            db: full_state,
            valid_transaction_indices,
        } = executor
            .execute((&block, total_difficulty).into())
            .map_err(|e| {
                error!("Error executing block: {e:?}");
                e
            })?;
        // Filter out the valid transactions so that the header checks only take these into account
        block.body = valid_transaction_indices
            .iter()
            .map(|&i| block.body[i].clone())
            .collect();

        // Header validation
        let block = block.seal_slow();
        if !optimistic {
            let consensus = EthBeaconConsensus::new(reth_chain_spec.clone());
            // Validates extra data
            consensus.validate_header_with_total_difficulty(&block.header, total_difficulty)?;
            // Validates if some values are set that should not be set for the current HF
            consensus.validate_header(&block.header)?;
            // Validates parent block hash, block number and timestamp
            consensus.validate_header_against_parent(
                &block.header,
                &self.input.parent_header.clone().seal_slow(),
            )?;
            // Validates ommers hash, transaction root, withdrawals root
            consensus.validate_block_pre_execution(&block)?;
            // Validates the gas used, the receipts root and the logs bloom
            validate_block_post_execution(
                &BlockWithSenders {
                    block: block.block.unseal(),
                    senders: block.senders,
                },
                &reth_chain_spec.clone(),
                &receipts,
                &requests,
            )?;
        }

        // Apply DB changes
        self.db = Some(full_state.database);
        let changes: HashMap<Address, Account> = state
            .state
            .into_iter()
            .map(|(address, bundle_account)| {
                let mut account = Account {
                    info: bundle_account.account_info().unwrap_or_default(),
                    storage: bundle_account.storage,
                    status: AccountStatus::default(),
                };
                account.mark_touch();
                if bundle_account.info.is_none() {
                    account.mark_selfdestruct();
                }
                if bundle_account.original_info.is_none() {
                    account.mark_created();
                }
                (address, account)
            })
            .collect();
        self.db.as_mut().unwrap().commit(changes);

        Ok(())
    }
}

impl RethBlockBuilder<MemDb> {
    /// Finalizes the block building and returns the header
    pub fn finalize(&mut self) -> Result<Header> {
        let state_root = self.calculate_state_root()?;
        ensure!(self.input.block.state_root == state_root);
        Ok(self.input.block.header.clone())
    }

    /// Calculates the state root of the block
    pub fn calculate_state_root(&mut self) -> Result<B256> {
        let mut account_touched = 0;
        let mut storage_touched = 0;

        // apply state updates
        let mut state_trie = mem::take(&mut self.input.parent_state_trie);
        for (address, account) in &self.db.as_ref().unwrap().accounts {
            // if the account has not been touched, it can be ignored
            if account.state == AccountState::None {
                continue;
            }

            // compute the index of the current account in the state trie
            let state_trie_index = keccak(address);

            // remove deleted accounts from the state trie
            if account.state == AccountState::Deleted {
                state_trie.delete(&state_trie_index)?;
                continue;
            }

            account_touched += 1;

            // otherwise, compute the updated storage root for that account
            let state_storage = &account.storage;
            let storage_root = {
                // getting a mutable reference is more efficient than calling remove
                // every account must have an entry, even newly created accounts
                let (storage_trie, _) = self
                    .input
                    .parent_storage
                    .get_mut(address)
                    .expect("Address not found in storage");
                // for cleared accounts always start from the empty trie
                if account.state == AccountState::StorageCleared {
                    storage_trie.clear();
                }

                // apply all new storage entries for the current account (address)
                for (key, value) in state_storage {
                    let storage_trie_index = keccak(key.to_be_bytes::<32>());
                    if value.is_zero() {
                        storage_trie.delete(&storage_trie_index)?;
                    } else {
                        storage_trie.insert_rlp(&storage_trie_index, *value)?;
                    }
                }

                storage_touched += 1;

                storage_trie.hash()
            };

            let state_account = StateAccount {
                nonce: account.info.nonce,
                balance: account.info.balance,
                storage_root,
                code_hash: account.info.code_hash,
            };
            state_trie.insert_rlp(&state_trie_index, state_account)?;
        }

        debug!("Accounts touched {account_touched:?}");
        debug!("Storages touched {storage_touched:?}");

        Ok(state_trie.hash())
    }
}

pub fn create_mem_db(input: &mut GuestInput) -> Result<MemDb> {
    // Verify state trie root
    if input.parent_state_trie.hash() != input.parent_header.state_root {
        bail!(
            "Invalid state trie: expected {}, got {}",
            input.parent_header.state_root,
            input.parent_state_trie.hash()
        );
    }

    // hash all the contract code
    let contracts: HashMap<B256, Bytes> = mem::take(&mut input.contracts)
        .into_iter()
        .map(|bytes| (keccak(&bytes).into(), bytes))
        .collect();

    let mut account_touched = 0;
    let mut storage_touched = 0;

    // Load account data into db
    let mut accounts = HashMap::with_capacity(input.parent_storage.len());
    for (address, (storage_trie, slots)) in &mut input.parent_storage {
        // consume the slots, as they are no longer needed afterwards
        let slots = mem::take(slots);

        account_touched += 1;

        // load the account from the state trie or empty if it does not exist
        let state_account = input
            .parent_state_trie
            .get_rlp::<StateAccount>(&keccak(address))?
            .unwrap_or_default();
        // Verify storage trie root
        if storage_trie.hash() != state_account.storage_root {
            bail!(
                "Invalid storage trie for {address:?}: expected {}, got {}",
                state_account.storage_root,
                storage_trie.hash()
            );
        }

        // load the corresponding code
        let code_hash = state_account.code_hash;
        let bytecode = if code_hash.0 == KECCAK_EMPTY.0 {
            Bytecode::new()
        } else {
            let bytes = contracts
                .get(&code_hash)
                .expect("Contract not found")
                .clone();
            Bytecode::new_raw(bytes)
        };

        // load storage reads
        let mut storage = HashMap::with_capacity(slots.len());
        for slot in slots {
            let value: U256 = storage_trie
                .get_rlp(&keccak(slot.to_be_bytes::<32>()))?
                .unwrap_or_default();
            storage.insert(slot, value);

            storage_touched += 1;
        }

        let mem_account = DbAccount {
            info: AccountInfo {
                balance: state_account.balance,
                nonce: state_account.nonce,
                code_hash: state_account.code_hash,
                code: Some(bytecode),
            },
            state: AccountState::None,
            storage,
        };

        accounts.insert(*address, mem_account);
    }
    guest_mem_forget(contracts);

    debug!("Accounts touched: {account_touched:?}");
    debug!("Storages touched: {storage_touched:?}");

    // prepare block hash history
    let mut block_hashes = HashMap::with_capacity(input.ancestor_headers.len() + 1);
    block_hashes.insert(input.parent_header.number, input.parent_header.hash_slow());
    let mut prev = &input.parent_header;
    for current in &input.ancestor_headers {
        let current_hash = current.hash_slow();
        if prev.parent_hash != current_hash {
            bail!(
                "Invalid chain: {} is not the parent of {}",
                current.number,
                prev.number
            );
        }
        if input.parent_header.number < current.number
            || input.parent_header.number - current.number >= MAX_BLOCK_HASH_AGE
        {
            bail!(
                "Invalid chain: {} is not one of the {MAX_BLOCK_HASH_AGE} most recent blocks",
                current.number,
            );
        }
        block_hashes.insert(current.number, current_hash);
        prev = current;
    }

    // Store database
    Ok(MemDb {
        accounts,
        block_hashes,
    })
}
