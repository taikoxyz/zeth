use crate::protocol_helper::*;
use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use raiko_lib::{
    builder::{BlockBuilderStrategy, TaikoStrategy},
    input::{GuestInput, GuestOutput},
    protocol_instance::ProtocolInstance,
    prover::{to_proof, Proof, Prover, ProverConfig, ProverError, ProverResult},
    signature::{generate_key, sign_message},
};
use serde_bytes::ByteBuf;
use tracing::{debug, info, warn};
use vsock::{VsockAddr, VsockStream};

pub mod protocol_helper;

pub const CID: u32 = 16;
pub const PORT: u32 = 26000;
pub const BUF_MAX_LEN: usize = 8192;

pub struct NitroProver;

impl NitroProver {
    pub fn prove(input: GuestInput) -> ProverResult<Proof> {
        debug!("Starting VSock for nitro proof enclave communication");
        let mut stream = VsockStream::connect(&VsockAddr::new(CID, PORT)).map_err(|e| {
            ProverError::GuestError(format!("Connection to VSoc failed with details {}", e))
        })?;

        let input_bytes = serde_json::to_string(&input)?;
        // send proof request
        debug!("Sending input to enclave");
        send_message(&mut stream, input_bytes).map_err(|e| {
            ProverError::GuestError(format!(
                "Failed to send proof request to enclave with details {}",
                e
            ))
        })?;
        // read proof response
        debug!("Reading proof from enclave");
        let proof = recv_message(&mut stream).map_err(|e| {
            ProverError::GuestError(format!(
                "Failed to read proof from enclave with details {}",
                e
            ))
        })?;
        debug!("Proof aquired. Returning it.");
        Ok(proof.into())
    }
}

impl Prover for NitroProver {
    async fn run(
        input: GuestInput,
        _output: &GuestOutput,
        _config: &ProverConfig,
    ) -> ProverResult<Proof> {
        // read and validate inputs
        info!("Starting Nitro guest and proof generation");
        // read and validate inputs
        if input.taiko.skip_verify_blob {
            warn!("blob verification skip. terminating");
            return Err(ProverError::GuestError(
                "Skip verify blob present. Doing nothing.".into(),
            ));
        }
        // process the block
        let (header, _mpt_node) = TaikoStrategy::build_from(&input)
            .map_err(|e| ProverError::GuestError(e.to_string()))?;
        // calculate the public input hash
        let pi = ProtocolInstance::new(&input, &header, raiko_lib::consts::VerifierType::Nitro)
            .map_err(|e| ProverError::GuestError(e.to_string()))?;
        let pi_hash = pi.instance_hash();
        info!(
            "Block {}. PI data to be signed {}",
            input.block_number, pi_hash
        );

        // Nitro prove of processed block
        let nsm_fd = nsm_init();

        let signing_key = generate_key();
        let public = signing_key.public_key();
        let signature = sign_message(&signing_key.secret_key(), pi_hash)
            .map_err(|e| ProverError::GuestError(e.to_string()))?;
        let user_data = ByteBuf::from(signature.to_vec());

        let request = Request::Attestation {
            user_data: Some(user_data),
            nonce: None, // FIXME: shold this be some?
            public_key: Some(ByteBuf::from(public.serialize_uncompressed())), // use this provided key in doc to verify
        };
        let Response::Attestation { document: result } = nsm_process_request(nsm_fd, request)
        else {
            return Err(ProverError::GuestError(
                "Failed to collect attestation document".to_string(),
            ));
        };

        nsm_exit(nsm_fd);
        info!("Successfully generated proof for PI {}", pi_hash);
        to_proof(Ok(result))
    }
}