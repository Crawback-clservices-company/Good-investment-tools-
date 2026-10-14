"""Cryptographic proofs: hash a report and anchor the hash on a blockchain."""
import hashlib
import json
import time
import urllib.request


def canonical_hash(report):
    data = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class LocalLedger:
    """Tamper-evident hash-chained ledger (offline stand-in for a blockchain)."""

    def __init__(self):
        self.blocks = []

    def anchor(self, digest):
        prev = self.blocks[-1]["block_hash"] if self.blocks else "0" * 64
        block = {"index": len(self.blocks), "timestamp": time.time(), "data": digest, "prev_hash": prev}
        block["block_hash"] = hashlib.sha256(
            json.dumps(block, sort_keys=True).encode()).hexdigest()
        self.blocks.append(block)
        return {"chain": "local", "tx": block["block_hash"], "index": block["index"]}

    def contains(self, digest, tx):
        prev = "0" * 64
        for b in self.blocks:
            body = {k: v for k, v in b.items() if k != "block_hash"}
            if b["prev_hash"] != prev or hashlib.sha256(
                    json.dumps(body, sort_keys=True).encode()).hexdigest() != b["block_hash"]:
                return False
            prev = b["block_hash"]
        return any(b["block_hash"] == tx and b["data"] == digest for b in self.blocks)


class EvmRpcAnchor:
    """Anchors the hash as calldata of a self-transaction on an EVM chain via JSON-RPC.

    The node must manage the `account` (eth_sendTransaction).
    """

    def __init__(self, rpc_url, account):
        self.rpc_url, self.account = rpc_url, account

    def _call(self, method, params):
        req = urllib.request.Request(
            self.rpc_url,
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
            {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            out = json.load(r)
        if "error" in out:
            raise RuntimeError(out["error"])
        return out["result"]

    def anchor(self, digest):
        tx = self._call("eth_sendTransaction", [{"from": self.account, "to": self.account,
                                                  "value": "0x0", "data": "0x" + digest}])
        return {"chain": "evm", "tx": tx}

    def contains(self, digest, tx):
        t = self._call("eth_getTransactionByHash", [tx])
        return bool(t) and t.get("input", "").lower() == "0x" + digest


def verify_report(report, proof, anchor):
    """True only if the report still matches its hash and the hash is on-chain."""
    digest = canonical_hash(report)
    return digest == proof["sha256"] and anchor.contains(digest, proof["anchor"]["tx"])
