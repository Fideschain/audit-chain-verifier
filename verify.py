#!/usr/bin/env python3
"""Audit-chain verifier — CLI entry point.

Usage:
    verify.py <export.json> [--hmac-key HEX]

Exit codes:
    0   PASS — all enabled checks succeeded.
    2   chain-integrity violation — at least one row failed
        re-hashing, the id sequence had a gap, or the envelope
        HMAC did not validate. Regulator's escalation signal.
    3   malformed input — file unreadable / not JSON / missing
        envelope or data fields. Caller's problem, not the
        customer's.
    64  usage error — argument parsing failed.

Zero non-stdlib dependencies. Tested against handcrafted fixtures
in ``tests/fixtures/`` (no FidesChain monorepo required).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow ``python verify.py`` from the package root without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit_chain_verifier import SCHEMA_VERSION, verify_export

EXIT_PASS = 0
EXIT_INTEGRITY = 2
EXIT_MALFORMED = 3
EXIT_USAGE = 64


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verify.py",
        description=(
            "Verify a FidesChain audit-chain export. Reports PASS only "
            "when every row's row_hash recomputes, the id sequence has "
            "no gaps, and (with --hmac-key) the envelope signature "
            "validates."
        ),
    )
    parser.add_argument(
        "export_path",
        type=Path,
        help="Path to the export JSON file (envelope + data).",
    )
    parser.add_argument(
        "--hmac-key",
        dest="hmac_key",
        default=None,
        help=(
            "Optional hex HMAC key to verify envelope.signature. When "
            "omitted, the verifier still checks per-row row_hash + "
            "chain continuity."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"audit-chain-verifier schema {SCHEMA_VERSION}",
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits 2 on parse error; map to our usage code.
        if exc.code in (None, 0):
            return EXIT_PASS
        return EXIT_USAGE

    path: Path = args.export_path
    if not path.is_file():
        print(f"FAIL: export file not found: {path}", file=sys.stderr)
        return EXIT_MALFORMED

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"FAIL: could not read export: {exc}", file=sys.stderr)
        return EXIT_MALFORMED

    try:
        export = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"FAIL: export is not valid JSON: {exc}", file=sys.stderr)
        return EXIT_MALFORMED

    if not isinstance(export, dict):
        print("FAIL: export root must be a JSON object", file=sys.stderr)
        return EXIT_MALFORMED

    result = verify_export(export, hmac_key_hex=args.hmac_key)

    for failure in result.failures:
        print(failure)

    if result.passed:
        hmac_label = "validated" if result.hmac_checked else "not-checked"
        print(
            "VERIFICATION: PASS "
            f"rows_verified={result.rows_verified} "
            f"hmac={hmac_label} "
            f"chain_intact={'true' if result.chain_intact else 'false'}"
        )
        return EXIT_PASS

    print(
        "VERIFICATION: FAIL "
        f"rows_verified={result.rows_verified} "
        f"failures={len(result.failures)}"
    )
    # Distinguish malformed vs integrity: any malformed-row failure
    # message contains the phrase "malformed".
    if any("malformed" in f.lower() for f in result.failures):
        return EXIT_MALFORMED
    return EXIT_INTEGRITY


if __name__ == "__main__":
    sys.exit(main())
