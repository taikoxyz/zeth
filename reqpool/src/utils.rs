use raiko_lib::{proof_type::ProofType, prover::ProofKey};

use crate::{RequestKey, SingleProofRequestKey};

/// Returns the proof key corresponding to the request key.
///
/// During proving, the prover will store the network proof id into pool, which is identified by **proof key**. This
/// function is used to generate a unique proof key corresponding to the request key, so that we can store the
/// proof key into the pool.
///
/// Note that this is a hack, and it should be removed in the future.
pub fn proof_key_to_hack_request_key(proof_key: ProofKey) -> RequestKey {
    let (chain_id, block_number, block_hash, proof_type) = proof_key;

    // HACK: Use a special prover address as a mask, to distinguish from real
    // RequestKeys
    let hack_prover_address = String::from("0x1231231231231231231231231231231231231231");

    SingleProofRequestKey::new(
        chain_id,
        block_number,
        block_hash,
        ProofType::try_from(proof_type).expect("unsupported proof type, it should not happen at proof_key_to_hack_request_key, please issue a bug report"),
        hack_prover_address,
    )
    .into()
}
