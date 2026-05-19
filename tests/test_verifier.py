"""Stdlib-unittest tests for the audit-chain verifier.

Run with::

    python -m unittest discover tests -v

No third-party dependencies. Fixtures under ``tests/fixtures/`` are
handcrafted JSON committed to the repo so the unit tests don't
depend on a live FidesChain instance.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

# Allow the test to import the package without installing.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from audit_chain_verifier import (  # noqa: E402
    SCHEMA_VERSION,
    canonical_form,
    row_hash_hex,
    verify_export,
)

FIXTURES = REPO_ROOT / "tests" / "fixtures"
SAMPLE_KEY_HEX = "0123456789abcdef" * 4


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class CanonicalFormTests(unittest.TestCase):
    def test_schema_version_pinned(self) -> None:
        self.assertEqual(SCHEMA_VERSION, "v1")

    def test_canonical_form_byte_for_byte_stable(self) -> None:
        bytes_a = canonical_form(
            "00000000-0000-0000-0000-000000000001",
            "2026-05-19T07:00:00.000000Z",
            "screen.person",
            {"name_hash": "abc123"},
        )
        bytes_b = canonical_form(
            "00000000-0000-0000-0000-000000000001",
            "2026-05-19T07:00:00.000000Z",
            "screen.person",
            {"name_hash": "abc123"},
        )
        self.assertEqual(bytes_a, bytes_b)
        self.assertIsInstance(bytes_a, bytes)
        # Newline-separated form per the contract.
        self.assertEqual(bytes_a.count(b"\n"), 3)

    def test_payload_key_ordering_independent(self) -> None:
        # Same payload, different key ordering at construction → same hash.
        a = row_hash_hex(
            "00000000-0000-0000-0000-000000000001",
            "2026-05-19T07:00:00.000000Z",
            "screen.person",
            {"name_hash": "abc", "context": "onboarding"},
        )
        b = row_hash_hex(
            "00000000-0000-0000-0000-000000000001",
            "2026-05-19T07:00:00.000000Z",
            "screen.person",
            {"context": "onboarding", "name_hash": "abc"},
        )
        self.assertEqual(a, b)

    def test_customer_id_case_insensitive(self) -> None:
        a = row_hash_hex(
            "00000000-0000-0000-0000-000000000001",
            "2026-05-19T07:00:00.000000Z",
            "x",
            {},
        )
        b = row_hash_hex(
            "00000000-0000-0000-0000-000000000001".upper(),
            "2026-05-19T07:00:00.000000Z",
            "x",
            {},
        )
        self.assertEqual(a, b)

    def test_timestamp_normalisation_offset_form(self) -> None:
        # Both timestamp forms must hash identically; the verifier
        # consumes whatever the backend exports and normalises.
        a = row_hash_hex(
            "00000000-0000-0000-0000-000000000001",
            "2026-05-19T07:00:00.000000Z",
            "x",
            {},
        )
        b = row_hash_hex(
            "00000000-0000-0000-0000-000000000001",
            "2026-05-19T07:00:00.000000+00:00",
            "x",
            {},
        )
        self.assertEqual(a, b)


class VerifyExportTests(unittest.TestCase):
    def test_clean_chain_passes(self) -> None:
        export = _load("clean.json")
        result = verify_export(export)
        self.assertTrue(result.passed, f"unexpected failures: {result.failures}")
        self.assertEqual(result.rows_verified, 3)
        self.assertTrue(result.chain_intact)
        self.assertFalse(result.hmac_checked)

    def test_clean_chain_passes_with_correct_hmac_key(self) -> None:
        export = _load("clean.json")
        result = verify_export(export, hmac_key_hex=SAMPLE_KEY_HEX)
        self.assertTrue(result.passed, f"unexpected failures: {result.failures}")
        self.assertTrue(result.hmac_checked)
        self.assertTrue(result.hmac_ok)

    def test_clean_chain_fails_with_wrong_hmac_key(self) -> None:
        export = _load("clean.json")
        wrong_key = "deadbeef" * 8  # 64 hex chars, but the wrong value
        result = verify_export(export, hmac_key_hex=wrong_key)
        self.assertFalse(result.passed)
        self.assertTrue(result.hmac_checked)
        self.assertFalse(result.hmac_ok)
        self.assertTrue(
            any("HMAC signature" in f for f in result.failures),
            f"expected HMAC failure, got {result.failures}",
        )

    def test_tampered_row_detected(self) -> None:
        export = _load("tampered.json")
        result = verify_export(export)
        self.assertFalse(result.passed)
        # Row 2 was tampered; failure points at id=2.
        self.assertTrue(
            any("row_hash mismatch at id=2" in f for f in result.failures),
            f"expected row_hash mismatch at id=2, got {result.failures}",
        )

    def test_gapped_chain_detected(self) -> None:
        export = _load("gapped.json")
        result = verify_export(export)
        self.assertFalse(result.passed)
        self.assertFalse(result.chain_intact)
        self.assertTrue(
            any("gap in chain" in f for f in result.failures),
            f"expected gap in chain, got {result.failures}",
        )

    def test_malformed_export_envelope(self) -> None:
        result = verify_export({"data": []})
        self.assertFalse(result.passed)
        self.assertTrue(
            any("malformed" in f.lower() for f in result.failures)
        )

    def test_passes_without_hmac_key_when_key_is_optional(self) -> None:
        """A chain whose envelope lacks an HMAC signature still passes
        per-row + chain checks when --hmac-key is not supplied."""
        export = _load("clean.json")
        # Drop the signature to simulate a no-HMAC envelope.
        export["envelope"].pop("signature", None)
        result = verify_export(export)
        self.assertTrue(result.passed)
        self.assertFalse(result.hmac_checked)

    def test_rejects_missing_hmac_when_key_supplied(self) -> None:
        export = _load("clean.json")
        export["envelope"].pop("signature", None)
        result = verify_export(export, hmac_key_hex=SAMPLE_KEY_HEX)
        self.assertFalse(result.passed)
        self.assertTrue(result.hmac_checked)
        self.assertFalse(result.hmac_ok)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
