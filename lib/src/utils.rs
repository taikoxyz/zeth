use core::str::FromStr;
use std::io::Read;
use std::io::Write;

use alloy_consensus::{Signed, TxEip1559, TxEnvelope};
use alloy_primitives::{uint, Address, Signature, TxKind, U256};
use alloy_rlp::Decodable;
use alloy_rpc_types::Transaction as AlloyTransaction;
use anyhow::{anyhow, bail, ensure, Context, Result};
use lazy_static::lazy_static;
use libflate::zlib::Decoder as zlibDecoder;
use libflate::zlib::Encoder as zlibEncoder;

#[cfg(not(feature = "std"))]
use crate::no_std::*;
use crate::{
    consts::{ChainSpec, Network},
    input::{decode_anchor, GuestInput},
    primitives::{keccak256, B256},
};

pub const ANCHOR_GAS_LIMIT: u64 = 250_000;

lazy_static! {
    pub static ref GOLDEN_TOUCH_ACCOUNT: Address = {
        Address::from_str("0x0000777735367b36bC9B61C50022d9D0700dB4Ec")
            .expect("invalid golden touch account")
    };
    static ref GX1: U256 =
        uint!(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798_U256);
    static ref N: U256 =
        uint!(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141_U256);
    static ref GX1_MUL_PRIVATEKEY: U256 =
        uint!(0x4341adf5a780b4a87939938fd7a032f6e6664c7da553c121d3b4947429639122_U256);
    static ref GX2: U256 =
        uint!(0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5_U256);
}

pub fn decode_transactions(tx_list: &[u8]) -> Vec<TxEnvelope> {
    Vec::<TxEnvelope>::decode(&mut &tx_list.to_owned()[..]).unwrap_or_else(|e| {
        // If decoding fails we need to make an empty block
        println!("decode_transactions not successful: {e:?}, use empty tx_list");
        vec![]
    })
}

// pub fn decode_transactions2(tx_list: &[u8]) -> Vec<AlloyTransaction> {
//     let txs = decode_transactions(tx_list);
//     txs.iter().map(|l| l.try_into().unwrap()).collect::<Vec<_>>()
// }

// leave a simply fn in case of more checks in future
fn validate_calldata_tx_list(tx_list: &[u8]) -> bool {
    tx_list.len() <= CALL_DATA_CAPACITY
}

fn get_tx_list(chain_spec: &ChainSpec, is_blob_data: bool, tx_list: &[u8]) -> Vec<u8> {
    if chain_spec.is_taiko() {
        // taiko has some limitations to be aligned with taiko-client
        if is_blob_data {
            let compressed_tx_list = decode_blob_data(tx_list);
            return zlib_decompress_data(&compressed_tx_list).unwrap_or_default();
        }

        if Network::TaikoA7.to_string() == chain_spec.network() {
            let de_tx_list: Vec<u8> = zlib_decompress_data(tx_list).unwrap_or_default();

            if validate_calldata_tx_list(&de_tx_list) {
                return de_tx_list;
            }

            println!("validate_calldata_tx_list failed, use empty tx_list");
            return vec![];
        }

        if validate_calldata_tx_list(tx_list) {
            zlib_decompress_data(tx_list).unwrap_or_default()
        } else {
            println!("validate_calldata_tx_list failed, use empty tx_list");
            vec![]
        }
    } else {
        // no limitation on non-taiko chains
        zlib_decompress_data(tx_list).unwrap_or_default()
    }
}

pub fn generate_transactions(
    chain_spec: &ChainSpec,
    is_blob_data: bool,
    tx_list: &[u8],
    anchor_tx: Option<AlloyTransaction>,
) -> Vec<TxEnvelope> {
    // Decode the tx list from the raw data posted onchain
    let tx_list = get_tx_list(chain_spec, is_blob_data, tx_list);

    // Decode the transactions from the tx list
    let mut transactions = decode_transactions(&tx_list);
    if let Some(anchor_tx) = anchor_tx {
        // Create a tx from the anchor tx that has the same type as the transactions encoded from
        // the tx list
        let signed_eip1559_tx = Signed::<TxEip1559>::new_unchecked(
            TxEip1559 {
                chain_id: anchor_tx.chain_id.unwrap(),
                nonce: anchor_tx.nonce,
                gas_limit: anchor_tx.gas,
                max_fee_per_gas: anchor_tx.max_fee_per_gas.unwrap(),
                max_priority_fee_per_gas: anchor_tx.max_priority_fee_per_gas.unwrap(),
                to: TxKind::Call(anchor_tx.to.unwrap()),
                value: anchor_tx.value,
                access_list: Default::default(),
                input: anchor_tx.input,
            },
            Signature::from_rs_and_parity(
                anchor_tx.signature.unwrap().r,
                anchor_tx.signature.unwrap().s,
                anchor_tx.signature.unwrap().y_parity.unwrap().0,
            )
            .unwrap(),
            anchor_tx.hash,
        );
        // Insert the anchor transactions generated by the node (which needs to be verified!)
        transactions.insert(0, TxEnvelope::from(signed_eip1559_tx));
    }
    transactions
}

const BLOB_FIELD_ELEMENT_NUM: usize = 4096;
const BLOB_FIELD_ELEMENT_BYTES: usize = 32;
const BLOB_DATA_CAPACITY: usize = BLOB_FIELD_ELEMENT_NUM * BLOB_FIELD_ELEMENT_BYTES;
// max call data bytes
const CALL_DATA_CAPACITY: usize = BLOB_FIELD_ELEMENT_NUM * (BLOB_FIELD_ELEMENT_BYTES - 1);
const BLOB_VERSION_OFFSET: usize = 1;
const BLOB_ENCODING_VERSION: u8 = 0;
const MAX_BLOB_DATA_SIZE: usize = (4 * 31 + 3) * 1024 - 4;

// decoding https://github.com/ethereum-optimism/optimism/blob/develop/op-service/eth/blob.go
fn decode_blob_data(blob_buf: &[u8]) -> Vec<u8> {
    // check the version
    if blob_buf[BLOB_VERSION_OFFSET] != BLOB_ENCODING_VERSION {
        return Vec::new();
    }

    // decode the 3-byte big-endian length value into a 4-byte integer
    let output_len = (u32::from(blob_buf[2]) << 16
        | u32::from(blob_buf[3]) << 8
        | u32::from(blob_buf[4])) as usize;

    if output_len > MAX_BLOB_DATA_SIZE {
        return Vec::new();
    }

    // round 0 is special cased to copy only the remaining 27 bytes of the first field element
    // into the output due to version/length encoding already occupying its first 5 bytes.
    let mut output = [0; MAX_BLOB_DATA_SIZE];
    output[0..27].copy_from_slice(&blob_buf[5..32]);

    // now process remaining 3 field elements to complete round 0
    let mut opos: usize = 28; // current position into output buffer
    let mut ipos: usize = 32; // current position into the input blob
    let mut encoded_byte: [u8; 4] = [0; 4]; // buffer for the 4 6-bit chunks
    encoded_byte[0] = blob_buf[0];
    for encoded_byte_i in encoded_byte.iter_mut().skip(1) {
        let Ok(res) = decode_field_element(blob_buf, opos, ipos, &mut output) else {
            return Vec::new();
        };

        (*encoded_byte_i, opos, ipos) = res;
    }
    opos = reassemble_bytes(opos, encoded_byte, &mut output);

    // in each remaining round we decode 4 field elements (128 bytes) of the input into 127
    // bytes of output
    for _ in 1..1024 {
        if opos < output_len {
            for encoded_byte_j in &mut encoded_byte {
                // save the first byte of each field element for later re-assembly
                let Ok(res) = decode_field_element(blob_buf, opos, ipos, &mut output) else {
                    return Vec::new();
                };

                (*encoded_byte_j, opos, ipos) = res;
            }
            opos = reassemble_bytes(opos, encoded_byte, &mut output);
        }
    }
    for otailing in output.iter().skip(output_len) {
        if *otailing != 0 {
            return Vec::new();
        }
    }
    for itailing in blob_buf.iter().take(BLOB_DATA_CAPACITY).skip(ipos) {
        if *itailing != 0 {
            return Vec::new();
        }
    }
    output[0..output_len].to_vec()
}

fn decode_field_element(
    b: &[u8],
    opos: usize,
    ipos: usize,
    output: &mut [u8],
) -> Result<(u8, usize, usize)> {
    // two highest order bits of the first byte of each field element should always be 0
    if b[ipos] & 0b1100_0000 != 0 {
        return Err(anyhow::anyhow!(
            "ErrBlobInvalidFieldElement: field element: {ipos}",
        ));
    }
    // copy(output[opos:], b[ipos+1:ipos+32])
    output[opos..opos + 31].copy_from_slice(&b[ipos + 1..ipos + 32]);
    Ok((b[ipos], opos + 32, ipos + 32))
}

fn reassemble_bytes(
    opos: usize,
    encoded_byte: [u8; 4],
    output: &mut [u8; MAX_BLOB_DATA_SIZE],
) -> usize {
    // account for fact that we don't output a 128th byte
    let opos = opos - 1;
    let x = (encoded_byte[0] & 0b0011_1111) | ((encoded_byte[1] & 0b0011_0000) << 2);
    let y = (encoded_byte[1] & 0b0000_1111) | ((encoded_byte[3] & 0b0000_1111) << 4);
    let z = (encoded_byte[2] & 0b0011_1111) | ((encoded_byte[3] & 0b0011_0000) << 2);
    // put the re-assembled bytes in their appropriate output locations
    output[opos - 32] = z;
    output[opos - (32 * 2)] = y;
    output[opos - (32 * 3)] = x;
    opos
}

pub fn zlib_decompress_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = zlibDecoder::new(data)?;
    let mut decoded_buf = Vec::new();
    decoder.read_to_end(&mut decoded_buf)?;
    Ok(decoded_buf)
}

pub fn zlib_compress_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = zlibEncoder::new(Vec::new())?;
    encoder.write_all(data).unwrap();
    let res = encoder.finish().into_result()?;
    Ok(res.clone())
}

/// check the anchor signature with fixed K value
fn check_anchor_signature(anchor: &Signed<TxEip1559>) -> Result<()> {
    let sign = anchor.signature();
    if sign.r() == *GX1 {
        return Ok(());
    }
    let msg_hash = anchor.signature_hash();
    let msg_hash: U256 = msg_hash.into();
    if sign.r() == *GX2 {
        // when r == GX2 require s == 0 if k == 1
        // alias: when r == GX2 require N == msg_hash + *GX1_MUL_PRIVATEKEY
        if *N != msg_hash + *GX1_MUL_PRIVATEKEY {
            bail!(
                "r == GX2, but N != msg_hash + *GX1_MUL_PRIVATEKEY, N: {}, msg_hash: {msg_hash}, *GX1_MUL_PRIVATEKEY: {}",
                *N, *GX1_MUL_PRIVATEKEY
            );
        }
        return Ok(());
    }
    Err(anyhow!(
        "r != *GX1 && r != GX2, r: {}, *GX1: {}, GX2: {}",
        sign.r(),
        *GX1,
        *GX2
    ))
}

pub fn check_anchor_tx(input: &GuestInput, anchor: &TxEnvelope, from: &Address) -> Result<()> {
    match anchor {
        TxEnvelope::Eip1559(tx) => {
            // Check the signature
            check_anchor_signature(tx).context(anyhow!("failed to check anchor signature"))?;

            let tx = tx.tx();

            // Extract the `to` address
            let TxKind::Call(to) = tx.to else {
                panic!("anchor tx not a smart contract call")
            };
            // Check that it's from the golden touch address
            ensure!(
                *from == *GOLDEN_TOUCH_ACCOUNT,
                "anchor transaction from mismatch"
            );
            // Check that the L2 contract is being called
            ensure!(
                to == input.chain_spec.l2_contract.unwrap(),
                "anchor transaction to mismatch"
            );
            // Tx can't have any ETH attached
            ensure!(
                tx.value == U256::from(0),
                "anchor transaction value mismatch"
            );
            // Tx needs to have the expected gas limit
            ensure!(
                tx.gas_limit == ANCHOR_GAS_LIMIT.into(),
                "anchor transaction gas price mismatch"
            );
            // Check needs to have the base fee set to the block base fee
            ensure!(
                tx.max_fee_per_gas == input.base_fee_per_gas.into(),
                "anchor transaction gas mismatch"
            );

            // Okay now let's decode the anchor tx to verify the inputs
            let anchor_call = decode_anchor(&tx.input)?;
            // The L1 blockhash needs to match the expected value
            ensure!(
                anchor_call.l1Hash == input.taiko.l1_header.hash_slow(),
                "L1 hash mismatch"
            );
            if input.chain_spec.network() == Network::TaikoA7.to_string() {
                ensure!(
                    anchor_call.l1StateRoot == input.taiko.l1_header.state_root,
                    "L1 state root mismatch"
                );
            }
            ensure!(
                anchor_call.l1BlockId == input.taiko.l1_header.number,
                "L1 block number mismatch"
            );
            // The parent gas used input needs to match the gas used value of the parent block
            ensure!(
                anchor_call.parentGasUsed == input.parent_header.gas_used as u32,
                "parentGasUsed mismatch"
            );
        }
        _ => {
            panic!("invalid anchor tx type");
        }
    }

    Ok(())
}
