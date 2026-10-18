"""Tool wrapper so an AI agent can call the risk engine (function-calling schema + CLI)."""
import argparse
import json
import sys

from .engine import analyze
from .proofs import LocalLedger, canonical_hash

TOOL_SCHEMA = {
    "name": "assess_platform",
    "description": "Analyze a smart contract's source code and/or a project whitepaper and "
                   "return a risk report with an anchored cryptographic proof.",
    "parameters": {
        "type": "object",
        "properties": {
            "source_code": {"type": "string", "description": "Smart contract source code"},
            "whitepaper": {"type": "string", "description": "Whitepaper text"},
        },
    },
}

_default_ledger = LocalLedger()


def assess_platform(source_code="", whitepaper="", anchor=None):
    anchor = anchor or _default_ledger
    report = analyze(source_code, whitepaper)
    digest = canonical_hash(report)
    return {"report": report, "proof": {"sha256": digest, "anchor": anchor.anchor(digest)}}


def main(argv=None):
    p = argparse.ArgumentParser(description="Risk assessment tool (also usable by AI agents)")
    p.add_argument("--code", help="path to contract source")
    p.add_argument("--whitepaper", help="path to whitepaper text")
    p.add_argument("--schema", action="store_true", help="print tool schema")
    a = p.parse_args(argv)
    if a.schema:
        print(json.dumps(TOOL_SCHEMA, indent=2))
        return 0
    read = lambda f: open(f, encoding="utf-8").read() if f else ""
    print(json.dumps(assess_platform(read(a.code), read(a.whitepaper)), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
