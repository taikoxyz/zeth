#!/usr/bin/env bash

# Any error will result in failure
set -e

TOOLCHAIN_RISC0=+nightly-2024-04-18
TOOLCHAIN_SP1=+nightly-2024-04-18
TOOLCHAIN_SGX=+nightly-2024-04-18

check_toolchain() {
    local TOOLCHAIN=$1

    # Remove the plus sign from the toolchain name
    TOOLCHAIN=${TOOLCHAIN#+}

    # Function to check if the toolchain is installed
    exist() {
        rustup toolchain list | grep "$TOOLCHAIN" >/dev/null
    }

    # Main script logic
    if exist; then
        echo "Toolchain $TOOLCHAIN exists"
    else
        echo "Installing Rust toolchain: $TOOLCHAIN"
        rustup install "$TOOLCHAIN"
    fi
}

if [ -z "${DEBUG}" ]; then
    FLAGS=--release
else
    echo "Warning: in debug mode"
fi

TASKDB=${TASKDB:-raiko-tasks/in-memory}

if [ -z "${RUN}" ]; then
    COMMAND=build
else
    COMMAND=run
fi

if [ "$CPU_OPT" = "1" ]; then
    export RUSTFLAGS='-C target-cpu=native'
    echo "Enable cpu optimization with host RUSTFLAGS"
fi

# install cargo-nextest if not installed
if ! cargo nextest --version >/dev/null 2>&1; then
    cargo install cargo-nextest@0.9.85 --locked
fi

# NATIVE
if [ -z "$1" ] || [ "$1" == "native" ]; then
    if [ -n "${CLIPPY}" ]; then
        cargo clippy -F ${TASKDB} -- -D warnings
    elif [ -z "${RUN}" ]; then
        if [ -z "${TEST}" ]; then
            echo "Building native prover"
            cargo build ${FLAGS} -F $TASKDB
        else
            echo "Building native tests"
            cargo test ${FLAGS} --no-run -F $TASKDB
        fi
    else
        if [ -z "${TEST}" ]; then
            echo "Running native prover"
            cargo run ${FLAGS} -F $TASKDB
        else
            echo "Running native tests"
            cargo test ${FLAGS} -F $TASKDB
        fi
    fi
fi

# SGX
if [ "$1" == "sgx" ]; then
    check_toolchain $TOOLCHAIN_SGX
    if [ "$MOCK" = "1" ]; then
        export SGX_DIRECT=1
        echo "SGX_DIRECT is set to $SGX_DIRECT"
    fi
    if [ -n "${CLIPPY}" ]; then
        cargo ${TOOLCHAIN_SGX} clippy -p raiko-host -p sgx-prover -F "sgx enable" -F $TASKDB -- -D warnings
    elif [ -z "${RUN}" ]; then
        if [ -z "${TEST}" ]; then
            echo "Building SGX prover"
            cargo ${TOOLCHAIN_SGX} build ${FLAGS} --features sgx -F $TASKDB
        else
            echo "Building SGX tests"
            cargo ${TOOLCHAIN_SGX} test ${FLAGS} -p raiko-host -p sgx-prover --features "sgx enable" -F $TASKDB --no-run
        fi
    else
        if [ -z "${TEST}" ]; then
            echo "Running SGX prover"
            cargo ${TOOLCHAIN_SGX} run ${FLAGS} --features sgx -F $TASKDB
        else
            echo "Running SGX tests"
            cargo ${TOOLCHAIN_SGX} test ${FLAGS} -p raiko-host -p sgx-prover --features "sgx enable" -F $TASKDB
        fi
    fi
fi

# RISC0
if [ "$1" == "risc0" ]; then
    check_toolchain $TOOLCHAIN_RISC0
    ./script/setup-bonsai.sh
    if [ "$MOCK" = "1" ]; then
        export RISC0_DEV_MODE=1
        echo "RISC0_DEV_MODE is set to $RISC0_DEV_MODE"
    fi
    if [ -n "${CLIPPY}" ]; then
        MOCK=1
        RISC0_DEV_MODE=1
        CI=1
        cargo ${TOOLCHAIN_RISC0} run --bin risc0-builder -F $TASKDB
        cargo ${TOOLCHAIN_RISC0} clippy -F risc0 -F $TASKDB
    elif [ -z "${RUN}" ]; then
        if [ -z "${TEST}" ]; then
            echo "Building Risc0 prover"
            cargo ${TOOLCHAIN_RISC0} run --bin risc0-builder -F $TASKDB
        else
            echo "Building test elfs for Risc0 prover"
            cargo ${TOOLCHAIN_RISC0} run --bin risc0-builder --features test,bench -F $TASKDB
        fi
        if [ -z "${GUEST}" ]; then
            cargo ${TOOLCHAIN_RISC0} build ${FLAGS} --features risc0 -F $TASKDB
        fi
    else
        if [ -z "${TEST}" ]; then
            echo "Running Risc0 prover"
            cargo ${TOOLCHAIN_RISC0} run ${FLAGS} --features risc0 -F $TASKDB
        else
            echo "Running Risc0 tests"
            cargo ${TOOLCHAIN_RISC0} test ${FLAGS} --lib risc0-driver --features risc0  -F $TASKDB -- run_unittest_elf
            cargo ${TOOLCHAIN_RISC0} test ${FLAGS} -p raiko-host -p risc0-driver --features "risc0 enable" -F $TASKDB
        fi
    fi
fi

# SP1
if [ "$1" == "sp1" ]; then
    check_toolchain $TOOLCHAIN_SP1
    if [ "$MOCK" = "1" ]; then
        export SP1_PROVER=mock
        echo "SP1_PROVER is set to $SP1_PROVER"
    fi
    if [ -n "${CLIPPY}" ]; then
        cargo ${TOOLCHAIN_SP1} clippy -p raiko-host -p sp1-builder -p sp1-driver -F "sp1,enable" -F $TASKDB
    elif [ -z "${RUN}" ]; then
        if [ -z "${TEST}" ]; then
            echo "Building Sp1 prover"
            cargo ${TOOLCHAIN_SP1} run --bin sp1-builder -F $TASKDB
        else
            echo "Building test elfs for Sp1 prover"
            cargo ${TOOLCHAIN_SP1} run --bin sp1-builder --features test,bench -F $TASKDB
        fi
        if [ -z "${GUEST}" ]; then
            cargo ${TOOLCHAIN_SP1} build ${FLAGS} --features sp1 -F $TASKDB
        fi
    else
        if [ -z "${TEST}" ]; then
            echo "Running Sp1 prover"
            cargo ${TOOLCHAIN_SP1} run ${FLAGS} --features sp1 -F $TASKDB
        else
            echo "Running Sp1 unit tests"
            cargo ${TOOLCHAIN_SP1} test ${FLAGS} --lib sp1-driver --features sp1 -F $TASKDB -- run_unittest_elf
            cargo ${TOOLCHAIN_SP1} test ${FLAGS} -p raiko-host -p sp1-driver --features "sp1 enable" -F $TASKDB

            # Don't wannt to span Succinct Network and wait 2 hours in CI
            # echo "Running Sp1 verification"
            # cargo ${TOOLCHAIN_SP1} run ${FLAGS} --bin sp1-verifier --features enable,sp1-verifier -F $TASKDB
        fi
    fi
fi
