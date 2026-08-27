#!/usr/bin/env python3
"""Compiles an anchor contract and writes the artefact deploy.py reads.

Kept separate from deployment so the bytecode that goes on chain is a file
anyone can rebuild from the source beside it and compare, rather than
something produced inside the transaction that sent it.

    python3 compile.py                      # ExchangeRootAnchor.sol, the one in use
    python3 compile.py ExchangeAnchor.sol   # the closed chain-hash contract

The contract name is taken from the file name, because both files hold one
contract each and naming them apart is the only thing keeping their artefacts
from overwriting one another.
"""

import argparse
import json
import pathlib
import sys

import solcx

HERE = pathlib.Path(__file__).resolve().parent
SOLC = "0.8.26"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "source",
        nargs="?",
        default="ExchangeRootAnchor.sol",
        help="the .sol file to compile, relative to this directory",
    )
    args = parser.parse_args()

    source = HERE / args.source
    if not source.is_file():
        raise SystemExit(f"{source} does not exist")
    name = source.stem
    out = HERE / f"{name}.json"

    if SOLC not in {str(v) for v in solcx.get_installed_solc_versions()}:
        solcx.install_solc(SOLC)

    compiled = solcx.compile_standard(
        {
            "language": "Solidity",
            "sources": {source.name: {"content": source.read_text()}},
            "settings": {
                "optimizer": {"enabled": True, "runs": 200},
                "outputSelection": {
                    "*": {"*": ["abi", "evm.bytecode.object", "evm.methodIdentifiers"]}
                },
            },
        },
        solc_version=SOLC,
    )
    contract = compiled["contracts"][source.name][name]
    artefact = {
        "contract": name,
        "solc": SOLC,
        "optimizer": {"enabled": True, "runs": 200},
        "abi": contract["abi"],
        "bytecode": "0x" + contract["evm"]["bytecode"]["object"],
        "selectors": contract["evm"]["methodIdentifiers"],
    }
    out.write_text(json.dumps(artefact, indent=2) + "\n")
    print(f"wrote {out}")
    print(f"  runtime deploy bytecode: {len(artefact['bytecode']) // 2 - 1} bytes")
    for signature, selector in artefact["selectors"].items():
        print(f"  0x{selector}  {signature}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
