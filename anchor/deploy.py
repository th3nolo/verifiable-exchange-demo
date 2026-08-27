#!/usr/bin/env python3
"""Deploys an anchor contract to an EVM chain and records where it landed.

The private key is read from a file and never printed, logged, or written
anywhere by this script. What it writes is a deployment record: the address,
the transaction, the chain and the block, all of which are public and all of
which an auditor needs to check the anchor without asking the
operator for anything.

    python3 deploy.py --rpc https://sepolia.base.org --key ../.anchor/anchor.key

The defaults deploy `ExchangeRootAnchor` and write `root-deployment.json`. The
chain-hash `ExchangeAnchor` is closed and its `deployment.json` is a record of
what was deployed, so nothing here writes to it by default: deploying that one
again takes both `--artefact` and `--out` on purpose.
"""

import argparse
import json
import pathlib
import sys
import time

from eth_account import Account
from eth_utils import keccak
from web3 import Web3

HERE = pathlib.Path(__file__).resolve().parent

# What to call a chain and where to look things up on it. The same three the
# matcher knows in `chain_labels`; an id that is not here still deploys, and
# the record simply carries no explorer link.
EXPLORERS = {
    1: "https://etherscan.io",
    8453: "https://basescan.org",
    84532: "https://sepolia.basescan.org",
    11155111: "https://sepolia.etherscan.io",
}

# Endpoints to try when the one in --rpc does not answer, written into the
# record so that everything reading it gets the same list: the browser, which
# reads the anchor from the chain itself, and the sender, which writes it.
#
# They are here because a public testnet endpoint goes down and takes the
# anchor with it. On 18 August 2026 https://sepolia.base.org answered 503 to
# ten requests out of ten while both of these answered all ten, and the sender
# knew about one endpoint, so it wrote nothing for the length of the outage.
FALLBACKS = {
    84532: [
        "https://base-sepolia-rpc.publicnode.com",
        "https://base-sepolia.drpc.org",
    ],
    11155111: [
        "https://ethereum-sepolia-rpc.publicnode.com",
    ],
}


def event_topics(abi: list) -> dict:
    """The `keccak256` topic of every event in the ABI.

    The Rust auditor filters `eth_getLogs` on one of these and has no Keccak of
    its own, so the value it holds has to come from somewhere an auditor can
    reproduce. This record is that place, and `anchor_test.go` checks the Rust
    constant against a real Keccak of the same signature.
    """
    topics = {}
    for item in abi:
        if item.get("type") != "event":
            continue
        signature = "{}({})".format(
            item["name"], ",".join(i["type"] for i in item["inputs"])
        )
        topics[signature] = "0x" + keccak(text=signature).hex()
    return topics


def as_int(value) -> int:
    """A receipt field that may arrive as an int or as a hex string."""
    if isinstance(value, str):
        return int(value, 16)
    return int(value or 0)


def load_key(path: pathlib.Path) -> Account:
    """Reads a 64-hex-character private key. Nothing here echoes it."""
    text = path.read_text().strip()
    if text.startswith("0x"):
        text = text[2:]
    if len(text) != 64 or any(c not in "0123456789abcdefABCDEF" for c in text):
        raise SystemExit(f"{path} does not hold a 64-character hex private key")
    return Account.from_key(bytes.fromhex(text))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", default="https://sepolia.base.org")
    parser.add_argument(
        "--rpc-fallback",
        action="append",
        default=[],
        metavar="URL",
        help="an endpoint to try when --rpc does not answer; repeatable. "
        "Defaults to the known public endpoints for the chain deployed to",
    )
    parser.add_argument("--key", type=pathlib.Path, default=HERE.parent / ".anchor" / "anchor.key")
    parser.add_argument(
        "--artefact", type=pathlib.Path, default=HERE / "ExchangeRootAnchor.json"
    )
    parser.add_argument(
        "--out", type=pathlib.Path, default=HERE / "root-deployment.json"
    )
    args = parser.parse_args()

    artefact = json.loads(args.artefact.read_text())
    account = load_key(args.key)
    w3 = Web3(Web3.HTTPProvider(args.rpc, request_kwargs={"timeout": 60}))
    chain_id = w3.eth.chain_id
    balance = w3.eth.get_balance(account.address)
    print(f"deploying from {account.address}")
    print(f"  chain id {chain_id} at {args.rpc}")
    print(f"  balance  {w3.from_wei(balance, 'ether')} ETH")

    contract = w3.eth.contract(abi=artefact["abi"], bytecode=artefact["bytecode"])
    tx = contract.constructor().build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "chainId": chain_id,
        }
    )
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"  sent {tx_hash.hex()}, waiting for the receipt...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    if receipt["status"] != 1:
        raise SystemExit(f"deployment reverted: {dict(receipt)}")

    address = receipt["contractAddress"]
    # Base returns the L1 data fee as a hex string on some nodes and an int on
    # others, and it is the half of the cost an L2-only estimate misses.
    l1_fee = as_int(receipt.get("l1Fee", 0))
    spent = receipt["gasUsed"] * receipt["effectiveGasPrice"] + l1_fee
    explorer = EXPLORERS.get(chain_id)
    # The primary is never repeated among the fallbacks: a reader that tried
    # the same dead host twice would wait twice as long to reach a live one.
    fallbacks = [
        endpoint
        for endpoint in dict.fromkeys(args.rpc_fallback or FALLBACKS.get(chain_id, []))
        if endpoint != args.rpc
    ]
    record = {
        "contract": artefact.get("contract", args.artefact.stem),
        "address": address,
        "chain_id": chain_id,
        "rpc": args.rpc,
        "rpc_fallbacks": fallbacks,
        "tx_hash": "0x" + tx_hash.hex().removeprefix("0x"),
        "block_number": receipt["blockNumber"],
        "writer": account.address,
        "solc": artefact["solc"],
        "optimizer": artefact["optimizer"],
        "selectors": artefact["selectors"],
        "events": event_topics(artefact["abi"]),
        "deployed_at": int(time.time()),
    }
    if explorer:
        record["explorer"] = explorer
        record["explorer_address_url"] = f"{explorer}/address/{address}"
    args.out.write_text(json.dumps(record, indent=2) + "\n")

    print(f"\ndeployed at {address}")
    print(f"  block   {receipt['blockNumber']}")
    print(f"  L2 gas  {receipt['gasUsed']} at {receipt['effectiveGasPrice']} wei")
    print(f"  L1 fee  {l1_fee} wei")
    print(f"  total   {w3.from_wei(spent, 'ether')} ETH")
    print(f"  wrote   {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
