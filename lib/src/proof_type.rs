use serde::{Deserialize, Serialize};

#[derive(
    PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Default, Deserialize, Serialize, Hash, Copy,
)]
#[repr(u8)]
pub enum ProofType {
    #[default]
    /// # Native
    ///
    /// This builds the block the same way the node does and then runs the result.
    #[serde(alias = "NATIVE")]
    Native = 0u8,
    /// # Sp1
    ///
    /// Uses the SP1 prover to build the block.
    #[serde(alias = "SP1")]
    Sp1 = 1u8,
    /// # Sgx
    ///
    /// Builds the block on a SGX supported CPU to create a proof.
    #[serde(alias = "SGX")]
    Sgx = 2u8,
    /// # Risc0
    ///
    /// Uses the RISC0 prover to build the block.
    #[serde(alias = "RISC0")]
    Risc0 = 3u8,
}

impl std::fmt::Display for ProofType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ProofType::Native => "native",
            ProofType::Sp1 => "sp1",
            ProofType::Sgx => "sgx",
            ProofType::Risc0 => "risc0",
        })
    }
}

impl std::str::FromStr for ProofType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "native" => Ok(ProofType::Native),
            "sp1" => Ok(ProofType::Sp1),
            "sgx" => Ok(ProofType::Sgx),
            "risc0" => Ok(ProofType::Risc0),
            _ => Err(format!("Unknown proof type: {}", s)),
        }
    }
}

impl TryFrom<u8> for ProofType {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Native),
            1 => Ok(Self::Sp1),
            2 => Ok(Self::Sgx),
            3 => Ok(Self::Risc0),
            _ => Err(format!("Unknown proof type {}", value)),
        }
    }
}
