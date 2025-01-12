//! Constants for the Ethereum protocol.
extern crate alloc;

use crate::primitives::{uint, BlockNumber, ChainId, U256};
use crate::proof_type::ProofType;
use alloc::collections::BTreeMap;
use alloy_primitives::Address;
use anyhow::{anyhow, bail, Result};
use once_cell::sync::Lazy;
use reth_primitives::revm_primitives::SpecId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::{collections::HashMap, env::var};

#[cfg(not(feature = "std"))]
use crate::no_std::*;

/// U256 representation of 0.
pub const ZERO: U256 = U256::ZERO;
/// U256 representation of 1.
pub const ONE: U256 = uint!(1_U256);

/// Maximum size of extra data.
pub const MAX_EXTRA_DATA_BYTES: usize = 32;

/// Maximum allowed block number difference for the `block_hash` call.
pub const MAX_BLOCK_HASH_AGE: u64 = 256;

/// Multiplier for converting gwei to wei.
pub const GWEI_TO_WEI: U256 = uint!(1_000_000_000_U256);

const DEFAULT_CHAIN_SPECS: &str = include_str!("../../host/config/chain_spec_list_default.json");

pub static IN_CONTAINER: Lazy<Option<()>> = Lazy::new(|| var("IN_CONTAINER").ok().map(|_| ()));

#[derive(Clone, Debug)]
pub struct SupportedChainSpecs(HashMap<String, ChainSpec>);

impl Default for SupportedChainSpecs {
    fn default() -> Self {
        let deserialized: Vec<ChainSpec> =
            serde_json::from_str(DEFAULT_CHAIN_SPECS).unwrap_or_default();
        let chain_spec_list = deserialized
            .into_iter()
            .map(|cs| (cs.name.clone(), cs))
            .collect::<HashMap<String, ChainSpec>>();
        SupportedChainSpecs(chain_spec_list)
    }
}

impl SupportedChainSpecs {
    #[cfg(feature = "std")]
    pub fn merge_from_file(file_path: PathBuf) -> Result<SupportedChainSpecs> {
        let mut known_chain_specs = SupportedChainSpecs::default();
        let file = std::fs::File::open(file_path)?;
        let reader = std::io::BufReader::new(file);
        let config: Value = serde_json::from_reader(reader)?;
        let chain_spec_list: Vec<ChainSpec> = serde_json::from_value(config)?;
        let new_chain_specs = chain_spec_list
            .into_iter()
            .map(|cs| (cs.name.clone(), cs))
            .collect::<HashMap<String, ChainSpec>>();

        // override known specs
        known_chain_specs.0.extend(new_chain_specs);
        Ok(known_chain_specs)
    }

    pub fn supported_networks(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }

    pub fn get_chain_spec(&self, network: &str) -> Option<ChainSpec> {
        self.0.get(network).cloned()
    }

    pub fn get_chain_spec_with_chain_id(&self, chain_id: u64) -> Option<ChainSpec> {
        self.0
            .values()
            .find(|spec| spec.chain_id == chain_id)
            .cloned()
    }
}

/// The condition at which a fork is activated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ForkCondition {
    /// The fork is activated with a certain block.
    Block(BlockNumber),
    /// The fork is activated with a specific timestamp.
    Timestamp(u64),
    /// The fork is not yet active.
    TBD,
}

impl ForkCondition {
    /// Returns whether the condition has been met.
    pub fn active(&self, block_no: BlockNumber, timestamp: u64) -> bool {
        match self {
            ForkCondition::Block(block) => *block <= block_no,
            ForkCondition::Timestamp(ts) => *ts <= timestamp,
            ForkCondition::TBD => false,
        }
    }
}

/// [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) parameters.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct Eip1559Constants {
    pub base_fee_change_denominator: U256,
    pub base_fee_max_increase_denominator: U256,
    pub base_fee_max_decrease_denominator: U256,
    pub elasticity_multiplier: U256,
}

impl Default for Eip1559Constants {
    /// Defaults to Ethereum network values
    fn default() -> Self {
        Self {
            base_fee_change_denominator: uint!(8_U256),
            base_fee_max_increase_denominator: uint!(8_U256),
            base_fee_max_decrease_denominator: uint!(8_U256),
            elasticity_multiplier: uint!(2_U256),
        }
    }
}

/// Specification of a specific chain.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ChainSpec {
    pub name: String,
    pub chain_id: ChainId,
    pub max_spec_id: SpecId,
    pub hard_forks: BTreeMap<SpecId, ForkCondition>,
    pub eip_1559_constants: Eip1559Constants,
    pub l1_contract: Option<Address>,
    pub l2_contract: Option<Address>,
    pub rpc: String,
    pub preflight_rpc: Option<String>,
    pub beacon_rpc: Option<String>,
    pub verifier_address_forks: BTreeMap<SpecId, BTreeMap<ProofType, Option<Address>>>,
    pub genesis_time: u64,
    pub seconds_per_slot: u64,
    pub is_taiko: bool,
}

impl ChainSpec {
    /// Creates a new configuration consisting of only one specification ID.
    pub fn new_single(
        name: String,
        chain_id: ChainId,
        spec_id: SpecId,
        eip_1559_constants: Eip1559Constants,
        is_taiko: bool,
    ) -> Self {
        ChainSpec {
            name,
            chain_id,
            max_spec_id: spec_id,
            hard_forks: BTreeMap::from([(spec_id, ForkCondition::Block(0))]),
            eip_1559_constants,
            l1_contract: None,
            l2_contract: None,
            rpc: "".to_string(),
            preflight_rpc: None,
            beacon_rpc: None,
            verifier_address_forks: BTreeMap::new(),
            genesis_time: 0u64,
            seconds_per_slot: 1u64,
            is_taiko,
        }
    }

    /// Returns the network chain ID.
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Returns the [SpecId] for a given block number and timestamp or an error if not
    /// supported.
    pub fn active_fork(&self, block_no: BlockNumber, timestamp: u64) -> Result<SpecId> {
        match self.spec_id(block_no, timestamp) {
            Some(spec_id) => {
                if spec_id > self.max_spec_id {
                    bail!("expected <= {:?}, got {spec_id:?}", self.max_spec_id);
                }
                Ok(spec_id)
            }
            None => Err(anyhow!("no supported fork for block {block_no}")),
        }
    }

    /// Returns the Eip1559 constants
    pub fn gas_constants(&self) -> &Eip1559Constants {
        &self.eip_1559_constants
    }

    pub fn spec_id(&self, block_no: BlockNumber, timestamp: u64) -> Option<SpecId> {
        for (spec_id, fork) in self.hard_forks.iter().rev() {
            if fork.active(block_no, timestamp) {
                return Some(*spec_id);
            }
        }
        None
    }

    pub fn get_fork_verifier_address(
        &self,
        block_num: u64,
        proof_type: ProofType,
    ) -> Result<Address> {
        // fall down to the first fork that is active as default
        for (spec_id, fork) in self.hard_forks.iter().rev() {
            if fork.active(block_num, 0u64) {
                if let Some(fork_verifier) = self.verifier_address_forks.get(spec_id) {
                    return fork_verifier
                        .get(&proof_type)
                        .ok_or_else(|| anyhow!("Verifier type not found"))
                        .and_then(|address| {
                            address.ok_or_else(|| anyhow!("Verifier address not found"))
                        });
                }
            }
        }

        Err(anyhow!("fork verifier is not active"))
    }

    pub fn is_taiko(&self) -> bool {
        self.is_taiko
    }

    pub fn network(&self) -> String {
        self.name.clone()
    }
}

// network enum here either has fixed setting or need known patch fix
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum Network {
    /// The Ethereum Mainnet
    #[default]
    Ethereum,
    /// Ethereum testnet holesky
    Holesky,
    /// Taiko A7 tesnet
    TaikoA7,
    /// Taiko Mainnet
    TaikoMainnet,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Network::Ethereum => "ethereum",
            Network::Holesky => "holesky",
            Network::TaikoA7 => "taiko_a7",
            Network::TaikoMainnet => "taiko_mainnet",
        })
    }
}

#[cfg(test)]
mod tests {
    use reth_primitives::address;

    use super::*;

    #[test]
    fn revm_spec_id() {
        let eth_mainnet_spec = SupportedChainSpecs::default()
            .get_chain_spec(&Network::Ethereum.to_string())
            .unwrap();
        assert!(eth_mainnet_spec.spec_id(15_537_393, 0) < Some(SpecId::MERGE));
        assert_eq!(eth_mainnet_spec.spec_id(15_537_394, 0), Some(SpecId::MERGE));
        assert_eq!(eth_mainnet_spec.spec_id(17_034_869, 0), Some(SpecId::MERGE));
        assert_eq!(
            eth_mainnet_spec.spec_id(17_034_870, 0),
            Some(SpecId::SHANGHAI)
        );
    }

    #[test]
    fn raiko_active_fork() {
        let eth_mainnet_spec = SupportedChainSpecs::default()
            .get_chain_spec(&Network::Ethereum.to_string())
            .unwrap();
        assert_eq!(
            eth_mainnet_spec.active_fork(0, 0).unwrap(),
            SpecId::FRONTIER
        );
        assert_eq!(
            eth_mainnet_spec.active_fork(15_537_394, 0).unwrap(),
            SpecId::MERGE
        );
        assert_eq!(
            eth_mainnet_spec.active_fork(17_034_869, 0).unwrap(),
            SpecId::MERGE
        );
        assert_eq!(
            eth_mainnet_spec.active_fork(17_034_870, 0).unwrap(),
            SpecId::SHANGHAI
        );

        let taiko_mainnet_spec = SupportedChainSpecs::default()
            .get_chain_spec(&Network::TaikoMainnet.to_string())
            .unwrap();
        assert_eq!(taiko_mainnet_spec.active_fork(0, 0).unwrap(), SpecId::HEKLA);
        assert_eq!(
            taiko_mainnet_spec.active_fork(538303, 0).unwrap(),
            SpecId::HEKLA
        );
        assert_eq!(
            taiko_mainnet_spec.active_fork(538304, 0).unwrap(),
            SpecId::ONTAKE
        );
    }

    #[test]
    fn forked_verifier_address() {
        let eth_mainnet_spec = SupportedChainSpecs::default()
            .get_chain_spec(&Network::Ethereum.to_string())
            .unwrap();
        let verifier_address = eth_mainnet_spec
            .get_fork_verifier_address(15_537_394, ProofType::Sgx)
            .unwrap();
        assert_eq!(
            verifier_address,
            address!("532efbf6d62720d0b2a2bb9d11066e8588cae6d9")
        );

        let hekla_mainnet_spec = SupportedChainSpecs::default()
            .get_chain_spec(&Network::TaikoA7.to_string())
            .unwrap();
        let verifier_address = hekla_mainnet_spec
            .get_fork_verifier_address(12345, ProofType::Sgx)
            .unwrap();
        assert_eq!(
            verifier_address,
            address!("532efbf6d62720d0b2a2bb9d11066e8588cae6d9")
        );
        let verifier_address = hekla_mainnet_spec
            .get_fork_verifier_address(15_537_394, ProofType::Sgx)
            .unwrap();
        assert_eq!(
            verifier_address,
            address!("532efbf6d62720d0b2a2bb9d11066e8588cae6d9")
        );
    }

    #[test]
    fn forked_native_verifier_address() {
        let eth_mainnet_spec = SupportedChainSpecs::default()
            .get_chain_spec(&Network::Ethereum.to_string())
            .unwrap();
        let verifier_address = eth_mainnet_spec
            .get_fork_verifier_address(15_537_394, ProofType::Native)
            .unwrap_or_default();
        assert_eq!(verifier_address, Address::ZERO);
    }

    #[ignore]
    #[test]
    fn serde_chain_spec() {
        let spec = ChainSpec {
            name: "test".to_string(),
            chain_id: 1,
            max_spec_id: SpecId::CANCUN,
            hard_forks: BTreeMap::from([
                (SpecId::FRONTIER, ForkCondition::Block(0)),
                (SpecId::MERGE, ForkCondition::Block(15537394)),
                (SpecId::SHANGHAI, ForkCondition::Block(17034870)),
                (SpecId::CANCUN, ForkCondition::Timestamp(1710338135)),
            ]),
            eip_1559_constants: Eip1559Constants {
                base_fee_change_denominator: uint!(8_U256),
                base_fee_max_increase_denominator: uint!(8_U256),
                base_fee_max_decrease_denominator: uint!(8_U256),
                elasticity_multiplier: uint!(2_U256),
            },
            l1_contract: None,
            l2_contract: None,
            rpc: "".to_string(),
            preflight_rpc: None,
            beacon_rpc: None,
            verifier_address_forks: BTreeMap::from([(
                SpecId::FRONTIER,
                BTreeMap::from([
                    (ProofType::Sgx, Some(Address::default())),
                    (ProofType::Sp1, None),
                    (ProofType::Risc0, Some(Address::default())),
                ]),
            )]),
            genesis_time: 0u64,
            seconds_per_slot: 1u64,
            is_taiko: false,
        };

        let json = serde_json::to_string(&spec).unwrap();
        // write to a file called chain_specs.json
        std::fs::write("chain_spec.json", json).unwrap();

        // read back from the file
        let json = std::fs::read_to_string("chain_spec.json").unwrap();
        let deserialized: ChainSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, deserialized);
    }
}
