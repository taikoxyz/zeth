#!/usr/bin/env bash

# toolchain necessary to compile c-kzg in SP1/risc0
if [ -z "$1" ] || [ "$1" == "sp1" ] || [ "$1" == "risc0" ]; then
	# Check if the RISC-V GCC prebuilt binary archive already exists
	if [ -f /tmp/riscv32-unknown-elf.gcc-13.2.0.tar.gz ]; then
		echo "riscv-gcc-prebuilt existed, please check the file manually"
	else
		# Download the file using wget
		wget -O /tmp/riscv32-unknown-elf.gcc-13.2.0.tar.gz https://github.com/stnolting/riscv-gcc-prebuilt/releases/download/rv32i-131023/riscv32-unknown-elf.gcc-13.2.0.tar.gz
		# Check if wget succeeded
		if [ $? -ne 0 ]; then
			echo "Failed to download riscv-gcc-prebuilt"
			exit 1
		fi
		# Create the directory if it doesn't exist
		if [ ! -d /opt/riscv ]; then
			mkdir /opt/riscv
		fi
		# Extract the downloaded archive
		tar -xzf /tmp/riscv32-unknown-elf.gcc-13.2.0.tar.gz -C /opt/riscv/
		# Check if tar succeeded
		if [ $? -ne 0 ]; then
			echo "Failed to extract riscv-gcc-prebuilt"
			exit 1
		fi
	fi

	# unzip to dest folder
	mkdir -p /tmp/riscv
	tar -xzvf /tmp/riscv32-unknown-elf.gcc-13.2.0.tar.gz -C /tmp/riscv
	if [ $? -ne 0 ]; then
		echo "failed to unzip riscv-gcc-prebuilt"
		exit 1
	fi
fi

# SGX
if [ -z "$1" ] || [ "$1" == "sgx" ]; then
	wget -O /tmp/gramine.deb https://packages.gramineproject.io/pool/main/g/gramine/gramine_1.6.2_amd64.deb
	sudo apt install /tmp/gramine.deb
fi
# RISC0
if [ -z "$1" ] || [ "$1" == "risc0" ]; then
	cargo install cargo-risczero
	cargo risczero install --version v2024-02-08.1
fi
# SP1
if [ -z "$1" ] || [ "$1" == "sp1" ]; then
	curl -L https://sp1.succinct.xyz | bash
	# Need to add sp1up to the path here
	PROFILE=$HOME/.bashrc
	echo ${PROFILE}
	source ${PROFILE}
	$HOME/.profile/sp1up
fi