"""Stdlib-unittest tests for the Ethereum anchoring primitives.

Run with::

    python -m unittest tests.test_anchor -v

Two surfaces are tested:

  1. Merkle math — pure stdlib, no network. Asserted against the
     shared cross-implementation fixture ``tests/fixtures/anchor_inclusion.json``
     so the backend's web3-bearing implementation is byte-identical
     to this verifier's stdlib one. Drift between the two = silent
     integrity loss; the assertion below catches it on every run.

  2. On-chain verification — network-gated. Loads
     ``tests/fixtures/sepolia_anchor.json`` (a real Sepolia tx hash
     produced once by step 5 of 4.5c.7 and committed forever as a
     CI regression fixture) and runs verify_anchor_on_chain against
     a live RPC. SKIPs if ``ETH_SEPOLIA_RPC_URL`` is not set so the
     suite stays green on machines without RPC access.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import hashlib  # noqa: E402

from audit_chain_verifier.anchor import (  # noqa: E402
    LEAF_PREFIX,
    compute_inclusion_proof,
    compute_merkle_root,
    verify_anchor_on_chain,
    verify_inclusion_proof,
)

FIXTURES = REPO_ROOT / "tests" / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class MerkleRootTests(unittest.TestCase):
    def test_merkle_root_empty(self) -> None:
        # CT convention: empty input → SHA-256(b"").
        self.assertEqual(
            compute_merkle_root([]),
            hashlib.sha256(b"").hexdigest(),
        )

    def test_merkle_root_single_leaf(self) -> None:
        # Single leaf → root = SHA-256(LEAF_PREFIX || raw_hash_bytes).
        h = "d3c450a58ecd8103eb364ad34b62c32da61507e6ab0125d0b25e9115500efe78"
        expected = hashlib.sha256(LEAF_PREFIX + bytes.fromhex(h)).hexdigest()
        self.assertEqual(compute_merkle_root([h]), expected)

    def test_merkle_root_two_leaves(self) -> None:
        h0 = "aa" * 32
        h1 = "bb" * 32
        root = compute_merkle_root([h0, h1])
        # Independent recomputation: leaf hashes, then inner.
        from audit_chain_verifier.anchor import INNER_PREFIX

        leaf0 = hashlib.sha256(LEAF_PREFIX + bytes.fromhex(h0)).digest()
        leaf1 = hashlib.sha256(LEAF_PREFIX + bytes.fromhex(h1)).digest()
        expected = hashlib.sha256(INNER_PREFIX + leaf0 + leaf1).hexdigest()
        self.assertEqual(root, expected)

    def test_merkle_root_odd_count_duplicates_last(self) -> None:
        # 3 leaves: the third gets paired with itself at level 0; that
        # pair is then paired with the (leaf0||leaf1) pair at level 1.
        h0 = "aa" * 32
        h1 = "bb" * 32
        h2 = "cc" * 32
        root3 = compute_merkle_root([h0, h1, h2])
        # Independent recomputation of the same logic.
        from audit_chain_verifier.anchor import INNER_PREFIX

        leaf0 = hashlib.sha256(LEAF_PREFIX + bytes.fromhex(h0)).digest()
        leaf1 = hashlib.sha256(LEAF_PREFIX + bytes.fromhex(h1)).digest()
        leaf2 = hashlib.sha256(LEAF_PREFIX + bytes.fromhex(h2)).digest()
        pair01 = hashlib.sha256(INNER_PREFIX + leaf0 + leaf1).digest()
        pair22 = hashlib.sha256(INNER_PREFIX + leaf2 + leaf2).digest()
        expected = hashlib.sha256(INNER_PREFIX + pair01 + pair22).hexdigest()
        self.assertEqual(root3, expected)

    def test_merkle_root_matches_shared_fixture(self) -> None:
        """Cross-implementation contract: backend test asserts the same
        value. Both sides MUST produce this hex from the row_hashes."""
        fixture = _load("anchor_inclusion.json")
        self.assertEqual(
            compute_merkle_root(fixture["row_hashes_hex"]),
            fixture["expected_merkle_root_hex"],
        )


class InclusionProofTests(unittest.TestCase):
    def test_inclusion_proof_roundtrip_every_index(self) -> None:
        fixture = _load("anchor_inclusion.json")
        hashes = fixture["row_hashes_hex"]
        root = fixture["expected_merkle_root_hex"]
        for idx in range(len(hashes)):
            proof = compute_inclusion_proof(hashes, idx)
            self.assertTrue(
                verify_inclusion_proof(hashes[idx], proof, root),
                f"verify_inclusion_proof failed at idx={idx}",
            )

    def test_inclusion_proof_matches_shared_fixture(self) -> None:
        fixture = _load("anchor_inclusion.json")
        for idx_str, expected_proof in fixture["expected_inclusion_proofs"].items():
            idx = int(idx_str)
            computed = compute_inclusion_proof(fixture["row_hashes_hex"], idx)
            # JSON loads each proof element as ``[hex, side]``; our
            # helper returns tuples — compare element-wise.
            self.assertEqual(
                [list(t) for t in computed],
                expected_proof,
                f"proof shape mismatch at idx={idx}",
            )

    def test_inclusion_proof_rejects_tampered_root(self) -> None:
        fixture = _load("anchor_inclusion.json")
        hashes = fixture["row_hashes_hex"]
        proof = compute_inclusion_proof(hashes, 0)
        tampered_root = "0" * 64
        self.assertFalse(verify_inclusion_proof(hashes[0], proof, tampered_root))

    def test_inclusion_proof_rejects_wrong_leaf(self) -> None:
        fixture = _load("anchor_inclusion.json")
        hashes = fixture["row_hashes_hex"]
        proof = compute_inclusion_proof(hashes, 3)
        # Use proof for idx 3 but pass leaf at idx 5 — verification fails.
        self.assertFalse(
            verify_inclusion_proof(hashes[5], proof, fixture["expected_merkle_root_hex"])
        )

    def test_inclusion_proof_single_leaf_returns_empty(self) -> None:
        h = "aa" * 32
        proof = compute_inclusion_proof([h], 0)
        self.assertEqual(proof, [])
        # The root in this case is the leaf hash itself.
        root = compute_merkle_root([h])
        self.assertTrue(verify_inclusion_proof(h, proof, root))


class OnChainAnchorTests(unittest.TestCase):
    """Network-gated. SKIPs unless ETH_SEPOLIA_RPC_URL is set AND
    tests/fixtures/sepolia_anchor.json contains a real tx hash."""

    @unittest.skipUnless(
        os.environ.get("ETH_SEPOLIA_RPC_URL"),
        "ETH_SEPOLIA_RPC_URL not set — skipping live RPC test.",
    )
    def test_verify_anchor_on_chain_sepolia(self) -> None:
        fixture_path = FIXTURES / "sepolia_anchor.json"
        if not fixture_path.is_file():
            self.skipTest("sepolia_anchor.json fixture not yet produced")
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        tx_hash = fixture.get("tx_hash")
        expected_root = fixture.get("expected_root_hex")
        if not tx_hash or not expected_root:
            self.skipTest("sepolia_anchor.json fixture incomplete")
        rpc_url = os.environ["ETH_SEPOLIA_RPC_URL"]
        result = verify_anchor_on_chain(rpc_url, tx_hash, expected_root)
        self.assertTrue(result["calldata_matches"])
        self.assertEqual(result["network_inferred"], "sepolia")
        self.assertEqual(
            result["block_number"], fixture.get("expected_block_number")
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
