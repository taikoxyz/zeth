use raiko_core::interfaces::{
    get_aggregation_image, get_proving_image, AggregationRequest, ProofRequestOpt,
};
use raiko_lib::{proof_type::ProofType, prover::encode_image_id};

use crate::{
    interfaces::{HostError, HostResult},
    ProverState,
};

/// Ensure that the system is not paused, otherwise return an error.
pub fn ensure_not_paused(prover_state: &ProverState) -> HostResult<()> {
    if prover_state.is_paused() {
        return Err(HostError::SystemPaused);
    }
    Ok(())
}

/// Ensure the image_id is filled for RISC0/SP1, and not filled for Native/SGX.
/// And fill it with the default value for RISC0/SP1 proof type.
pub fn ensure_proof_request_image_id(proof_request_opt: &mut ProofRequestOpt) -> HostResult<()> {
    // Parse the proof type string
    let proof_type = proof_request_opt
        .proof_type
        .as_ref()
        .ok_or(HostError::InvalidRequestConfig(
            "Missing proof_type".to_string(),
        ))?
        .parse()
        .map_err(|_| HostError::InvalidRequestConfig("Invalid proof_type".to_string()))?;
    match proof_type {
        // For Native/SGX, ensure image_id is None
        ProofType::Native | ProofType::Sgx => {
            if proof_request_opt.image_id.is_some() {
                return Err(HostError::InvalidRequestConfig(
                    "Native/SGX provers must not have image_id".to_string(),
                ));
            }
        }
        // For RISC0/SP1, fill default image_id if None
        ProofType::Risc0 | ProofType::Sp1 => {
            match &proof_request_opt.image_id {
                Some(image_id) => {
                    // Temporarily workaround for RISC0/SP1 proof type: assert that the image_id is the same with `get_aggregation_image_id()`,
                    // that means we don't support custom image_id for RISC0/SP1 proof type.
                    let (_, supported_image_id) = get_proving_image(proof_type)?;
                    let supported_image_id = encode_image_id(supported_image_id);
                    if *image_id != supported_image_id {
                        return Err(HostError::InvalidRequestConfig(
                                format!(
                                    "Custom image_id is not supported for RISC0/SP1 proof type: actual=({}) != supported=({})",
                                    image_id, supported_image_id
                                ),
                            ));
                    }
                }
                None => {
                    // If image_id is None, fill it with the default value
                    let (_, supported_image_id) = get_proving_image(proof_type)?;
                    let supported_image_id = encode_image_id(supported_image_id);
                    proof_request_opt.image_id = Some(supported_image_id);
                }
            }
        }
    }
    Ok(())
}

/// Ensure the image_id is filled for RISC0/SP1, and not filled for Native/SGX.
/// And fill it with the default value for RISC0/SP1 proof type.
pub fn ensure_aggregation_request_image_id(
    aggregation_request: &mut AggregationRequest,
) -> HostResult<()> {
    // Parse the proof type string
    let proof_type = aggregation_request
        .proof_type
        .as_ref()
        .ok_or(HostError::InvalidRequestConfig(
            "Missing proof_type".to_string(),
        ))?
        .parse()
        .map_err(|_| HostError::InvalidRequestConfig("Invalid proof_type".to_string()))?;

    match proof_type {
        // For Native/SGX, ensure image_id is None
        ProofType::Native | ProofType::Sgx => {
            if aggregation_request.image_id.is_some() {
                return Err(HostError::InvalidRequestConfig(
                    "Native/SGX provers must not have image_id".to_string(),
                ));
            }
        }
        // For RISC0/SP1, fill default image_id if None
        ProofType::Risc0 | ProofType::Sp1 => {
            match &aggregation_request.image_id {
                Some(image_id) => {
                    // Temporarily workaround for RISC0/SP1 proof type: assert that the image_id is the same with `get_aggregation_image_id()`,
                    // that means we don't support custom image_id for RISC0/SP1 proof type.
                    let (_, supported_image_id) = get_aggregation_image(proof_type)?;
                    let supported_image_id = encode_image_id(supported_image_id);
                    if *image_id != supported_image_id {
                        return Err(HostError::InvalidRequestConfig(
                                format!(
                                    "Custom image_id is not supported for RISC0/SP1 proof type: actual=({}) != supported=({})",
                                    image_id, supported_image_id
                                ),
                            ));
                    }
                }
                None => {
                    // If image_id is None, fill it with the default value
                    let (_, supported_image_id) = get_aggregation_image(proof_type)?;
                    let supported_image_id = encode_image_id(supported_image_id);
                    aggregation_request.image_id = Some(supported_image_id);
                }
            }
        }
    }
    Ok(())
}
