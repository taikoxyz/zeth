import requests
import time
from datetime import datetime
import json
import logging
from typing import Optional, Dict, Any, Tuple
import asyncio
import argparse
from dataclasses import dataclass
from random import random


@dataclass
class RaikoResponse:
    status: str
    data: Optional[Dict[str, Any]] = None
    message: Optional[str] = None


class BlockMonitor:
    def __init__(
        self,
        eth_rpc: str,
        raiko_rpc: str,
        log_file: str = "block_monitor.log",
        polling_interval: int = 3,
        max_retries: int = 3,
        block_running_ratio: float = 0.1,
        block_range: Optional[Tuple[int, int]] = None,
        timeout: int = 3600,  # 1 hour
        prove_type: str = "native",
    ):
        self.eth_rpc = eth_rpc
        self.raiko_rpc = raiko_rpc
        self.log_file = log_file
        self.block_polling_interval = polling_interval
        self.task_polling_interval = polling_interval * 5
        self.max_retries = max_retries
        self.timeout = timeout
        self.last_block = None
        self.block_running_ratio = block_running_ratio
        self.block_range = block_range
        self.ts_offset: Optional(int) = None
        self.running_count = 0
        self.prove_type = prove_type

        # logger
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
        )
        self.logger = logging.getLogger(__name__)

    async def get_next_block(self) -> Optional[int]:
        """get latest block number"""
        if self.block_range is not None:
            return await self.get_in_range_next_block()
        else:
            return await self.get_latest_block()

    async def get_block(self, block_number) -> Optional[Dict[str, Any]]:
        """get block by number"""
        try:
            response = requests.post(
                self.eth_rpc,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_getBlockByNumber",
                    "params": [hex(block_number), False],
                    "id": 1,
                },
                timeout=10,
            )
            result = response.json()
            return result.get("result")
        except Exception as e:
            self.logger.error(f"Failed to get block {block_number}: {e}")

    async def align_ts_offset(self, first_block: int) -> bool:
        # query block timestamp
        try:
            block = await self.get_block(first_block)
            timestamp = int(block["timestamp"], 16)
            current_timestamp = int(time.time())
            self.ts_offset = current_timestamp - timestamp
            self.logger.info(
                f"Begin timestamp: {timestamp}, timestamp offset: {self.ts_offset}"
            )
            return True
        except Exception as e:
            self.logger.error(f"align_ts_offset from {first_block} failed: {e}")
            return False

    async def get_in_range_next_block(self) -> Optional[int]:
        """get latest block number"""
        start_block, end_block = self.block_range
        # align block timestamp offset
        if self.ts_offset is None:
            if not await self.align_ts_offset(start_block):
                return None

        if self.last_block is None:
            return start_block
        else:
            # check if next block timestamp is overdue
            next_block = self.last_block + 1
            if next_block >= end_block:
                self.logger.info(f"Block range {self.block_range} finished")
                if self.running_count == 0:
                    self.logger.info("All blocks finished, exiting")
                    exit(0)
                return None
            else:
                block = await self.get_block(next_block)
                timestamp = int(block["timestamp"], 16) + self.ts_offset
                current_timestamp = int(time.time())
                if current_timestamp > timestamp:
                    return next_block
                else:
                    self.logger.info(
                        f"Block {next_block} timestamp:{timestamp} is not reached, current:{current_timestamp}"
                    )
                    await asyncio.sleep(timestamp - current_timestamp)
                    return None

    async def get_latest_block(self) -> Optional[int]:
        """get latest block number"""
        try:
            response = requests.post(
                self.eth_rpc,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_blockNumber",
                    "params": [],
                    "id": 1,
                },
                timeout=10,
            )
            result = response.json()
            return int(result["result"], 16)
        except Exception as e:
            self.logger.error(f"Failed to get latest block: {e}")
            return None

    def generate_post_data(self, block_number: int) -> Dict[str, Any]:
        """generate post data"""
        return {
            "block_numbers": [[block_number, None]],
            "block_number": block_number,
            "prover": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "graffiti": "8008500000000000000000000000000000000000000000000000000000000000",
            "proof_type": self.prove_type,
            "blob_proof_type": "proof_of_equivalence",
            "native": {},
            "risc0": {
                "bonsai": True,
                "snark": True,
                "profile": False,
                "execution_po2": 20,
            },
            "sp1": {"recursion": "plonk", "prover": "network", "verify": True},
        }

    async def submit_to_raiko(self, block_number: int) -> Optional[str]:
        """submit block to Raiko"""
        try:
            headers = {"x-api-key": "1", "Content-Type": "application/json"}

            payload = self.generate_post_data(block_number)

            response = requests.post(
                f"{self.raiko_rpc}/v2/proof",
                headers=headers,
                json=payload,
                timeout=10,
            )
            result = response.json()

            if result.get("status") == "ok":
                self.logger.info(
                    f"Block {block_number} submitted to Raiko with response: {result}"
                )
                return None
            else:
                self.logger.error(
                    f"Failed to submit block: {result.get('message', 'Unknown error')}"
                )
                return None
        except Exception as e:
            self.logger.error(f"Failed to submit to Raiko: {e}")
            return None

    async def query_raiko_status(self, block_number: int) -> RaikoResponse:
        """query Raiko status"""
        try:
            headers = {"x-api-key": "1", "Content-Type": "application/json"}
            payload = self.generate_post_data(block_number)
            response = requests.post(
                f"{self.raiko_rpc}/v2/proof",
                headers=headers,
                json=payload,
                timeout=10,
            )
            result = response.json()
            if result.get("status") == "error":
                return RaikoResponse(
                    status="error", message=result.get("message", "Unknown error")
                )
            elif result.get("status") == "ok":
                return RaikoResponse(status="ok", data=result.get("data", {}))
            else:
                return RaikoResponse(status="error", message="Invalid response format")
        except Exception as e:
            self.logger.error(f"Failed to query Raiko status: {e}")
            return RaikoResponse(status="error", message=str(e))

    async def process_block(self, block_number: int):
        """handle new block"""
        try:
            start_time = datetime.now()
            self.logger.info(
                f"Starting to process block {block_number} at {start_time}"
            )

            with open(self.log_file, "a") as f:
                f.write(f"\nBlock {block_number} processing started at {start_time}\n")

            # request Raiko
            await self.submit_to_raiko(block_number)

            # polling
            retry_count = 0
            start_polling_time = time.time()

            while True:
                if time.time() - start_polling_time > self.timeout:
                    self.logger.error(f"Timeout waiting for block {block_number}")
                    break

                response = await self.query_raiko_status(block_number)

                if response.status == "error":
                    self.logger.error(
                        f"Error processing block {block_number}: {response.message}"
                    )
                    retry_count += 1
                    if retry_count >= self.max_retries:
                        self.logger.error(
                            f"Max retries reached for block {block_number}"
                        )
                        break

                if response.data:
                    retry_count = 0  # reset retry count
                    if response.data.get("status") == "registered":
                        self.logger.info(f"Block {block_number} registered")
                    elif response.data.get("status") == "work_in_progress":
                        self.logger.info(f"Block {block_number} in progress")
                    elif response.data.get("proof"):
                        self.logger.info(
                            f"Block {block_number} completed with proof {response.data['proof']['proof']}"
                        )
                        break
                    else:
                        self.logger.warning(
                            f"Block {block_number} unhandled status: {response}"
                        )

                await asyncio.sleep(self.task_polling_interval)

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            # log ending status
            with open(self.log_file, "a") as f:
                f.write(f"Block {block_number} processing ended at {end_time}\n")
                f.write(f"Duration: {duration} seconds\n")
                f.write(f"Final status: {response.status}\n")
                if response.message:
                    f.write(f"Message: {response.message}\n")
                if response.data and response.data.get("proof"):
                    f.write(f"Proof: {response.data['proof']['proofG']}\n")
        finally:
            self.running_count -= 1
            self.logger.info(
                f"Block {block_number} processed, remaining running: {self.running_count}"
            )

    async def run(self):
        """main loop"""
        self.logger.info("Starting block monitor")
        # print start config
        self.logger.info(f"Config:\n{json.dumps(self.__dict__, indent=2, default=str)}")
        while True:
            try:
                current_block = await self.get_next_block()

                if current_block and (
                    not self.last_block or current_block > self.last_block
                ):
                    self.logger.info(f"New block detected: {current_block}")
                    if random() < self.block_running_ratio:
                        self.logger.info(
                            f"To run block: {current_block}, current running: {self.running_count}"
                        )
                        self.running_count += 1
                        # await self.process_block(current_block)
                        asyncio.create_task(self.process_block(current_block))
                    else:
                        self.logger.info(
                            f"Block {current_block} skipped due to block_running_ratio:{self.block_running_ratio}"
                        )
                    self.last_block = current_block
                await asyncio.sleep(self.block_polling_interval)

            except Exception as e:
                self.logger.error(f"Error in main loop: {e}")
                await asyncio.sleep(self.block_polling_interval)


def parse_none_value(value):
    """support none value"""
    if value and value.lower() in ["none", "null"]:
        return None
    return value


def parse_block_range(value):
    """support block range in format start,end or none"""
    if value and value.lower() in ["none", "null"]:
        return None
    try:
        start_block, end_block = map(int, value.split(","))
        return (start_block, end_block)
    except (ValueError, AttributeError):
        raise argparse.ArgumentTypeError(
            'Block range must be in format "start,end" or "none"'
        )


async def main():
    parser = argparse.ArgumentParser(description="Block Monitor CLI")

    parser.add_argument(
        "-e",
        "--eth-rpc",
        type=parse_none_value,
        default="https://rpc.mainnet.taiko.xyz",
        help='Ethereum RPC endpoint (use "none" for None value)',
    )

    parser.add_argument(
        "-a",
        "--raiko-rpc",
        type=parse_none_value,
        default="http://localhost:8088",
        help='Raiko RPC endpoint (use "none" for None value)',
    )

    parser.add_argument(
        "-o",
        "--log-file",
        type=parse_none_value,
        default="block_monitor.log",
        help='Log file path (use "none" for None value)',
    )

    parser.add_argument(
        "-p",
        "--polling-interval",
        type=lambda x: int(x) if x.lower() not in ["none", "null"] else None,
        default=3,
        help='Polling interval in seconds (use "none" for None value)',
    )

    parser.add_argument(
        "-r",
        "--block-running-ratio",
        type=lambda x: float(x) if x.lower() not in ["none", "null"] else None,
        default=1.0,
        help='Block running ratio (use "none" for None value)',
    )

    parser.add_argument(
        "-g",
        "--block-range",
        type=parse_block_range,
        default="None",
        help='Block range in format "start,end" or "none" for None value',
    )

    parser.add_argument(
        "-t",
        "--prove-type",
        type=parse_none_value,
        default="native",
        help='Prove type (use "none" for None value)',
    )

    args = parser.parse_args()

    # 创建 BlockMonitor 实例
    monitor = BlockMonitor(
        eth_rpc=args.eth_rpc,
        raiko_rpc=args.raiko_rpc,
        log_file=args.log_file,
        polling_interval=args.polling_interval,
        block_running_ratio=args.block_running_ratio,
        block_range=args.block_range,
        prove_type=args.prove_type,
    )

    await monitor.run()


if __name__ == "__main__":
    asyncio.run(main())
