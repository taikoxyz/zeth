#![no_main]
harness::entrypoint!(main);
use risc0_zkvm::guest::env;
use std::hint::black_box;

use revm_precompile::zk_op::ZkvmOperator;
use zk_op::Risc0Operator;

fn main() {
    let input: [u8; 32] = black_box([
        0x6b, 0x6f, 0x6f, 0x74, 0x68, 0x65, 0x6e, 0x65, 0x76, 0x65, 0x72, 0x67, 0x6f, 0x6e, 0x6e,
        0x61, 0x67, 0x69, 0x76, 0x65, 0x79, 0x6f, 0x75, 0x72, 0x6d, 0x69, 0x6e, 0x64, 0x6f, 0x6e,
        0x6e, 0x61,
    ]);

    let op = Risc0Operator {};
    let res = op.sha256_run(&input).unwrap();

    env::commit::<[u8; 32]>(&res);
}
