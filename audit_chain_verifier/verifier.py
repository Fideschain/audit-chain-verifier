"""Audit-chain verifier core.

Three independent checks per chain:

  1. Per-row integrity. Recompute SHA-256 over the canonical form of
     every row and compare to the stored ``row_hash``. Detects any
     mutation of ``customer_id`` / ``ts`` / ``action`` /
     ``payload_redacted`` after the row was written.
  2. Chain continuity. Row ids must be strictly monotonic by +1.
     Detects deleted or re-ordered rows.
  3. Envelope HMAC (optional). When ``--hmac-key`` is supplied,
     recompute HMAC-SHA-256 over ``envelope.data_sha256`` with the
     supplied key and compare to ``envelope.signature``. Detects
     forged envelopes.

The verifier reports PASS only when all enabled checks pass.

Exit codes (see :mod:`verify` CLI):

  * 0  PASS
  * 2  chain-integrity violation
  * 3  malformed input
  * 64 usage error
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any

from .anchor import compute_merkle_root, verify_anchor_on_chain
from .canonical import row_hash_hex


@dataclass
class VerifyResult:
    """Structured outcome. The CLI projects this onto stdout +
    exit codes; library callers can read the fields directly."""

    passed: bool
    rows_verified: int
    failures: list[str] = field(default_factory=list)
    hmac_checked: bool = False
    hmac_ok: bool | None = None
    chain_intact: bool = True
    schema_version: str | None = None
    # Session 4.5c.7 — Ethereum-anchor verification outcome.
    # ``None`` when the export carries no anchor field OR no
    # ``anchor_rpc_url`` was supplied. ``True`` when the on-chain
    # calldata equals the recomputed Merkle root. ``False`` on
    # mismatch — which the CLI maps to exit code 2 (integrity).
    anchor_verified: bool | None = None
    anchor_block_number: int | None = None
    anchor_block_timestamp: str | None = None
    anchor_skip_reason: str | None = None


def verify_export(
    export: dict[str, Any],
    *,
    hmac_key_hex: str | None = None,
    anchor_rpc_url: str | None = None,
) -> VerifyResult:
    """Run all three integrity checks on a parsed export.

    ``export`` is the JSON envelope as returned by
    ``GET /v1/me/audit/export?format=json`` — the dict
    ``{"envelope": {...}, "data": [...]}``.
    """
    result = VerifyResult(passed=False, rows_verified=0)

    envelope = export.get("envelope")
    data = export.get("data")
    if not isinstance(envelope, dict) or not isinstance(data, list):
        result.failures.append(
            "FAIL: malformed export — missing 'envelope' or 'data'"
        )
        return result

    customer_id = envelope.get("customer_id")
    if not isinstance(customer_id, str) or not customer_id:
        result.failures.append("FAIL: malformed export — envelope.customer_id missing")
        return result

    result.schema_version = (
        envelope.get("schema_version") or envelope.get("version")
    )

    # ---- per-row integrity + chain continuity
    last_id: int | None = None
    for row in data:
        if not isinstance(row, dict):
            result.failures.append("FAIL: malformed row — not a JSON object")
            continue
        rid = row.get("id")
        if not isinstance(rid, int):
            result.failures.append(
                f"FAIL: malformed row — id is not an integer ({row.get('id')!r})"
            )
            continue
        if last_id is not None and rid != last_id + 1:
            result.failures.append(
                f"FAIL: gap in chain — expected id={last_id + 1} got id={rid}"
            )
            result.chain_intact = False
        last_id = rid

        ts = row.get("ts")
        action = row.get("action")
        payload = row.get("payload_redacted")
        stored_hash = row.get("row_hash")
        if (
            not isinstance(ts, str)
            or not isinstance(action, str)
            or not isinstance(payload, dict)
            or not isinstance(stored_hash, str)
        ):
            result.failures.append(
                f"FAIL: malformed row at id={rid} — missing ts/action/"
                "payload_redacted/row_hash or wrong type"
            )
            continue

        computed = row_hash_hex(customer_id, ts, action, payload)
        if not _hashes_equal(computed, stored_hash):
            result.failures.append(
                f"FAIL: row_hash mismatch at id={rid} "
                f"expected={stored_hash[:16]}… got={computed[:16]}…"
            )
        result.rows_verified += 1

    # ---- optional envelope HMAC
    if hmac_key_hex is not None:
        result.hmac_checked = True
        sig = envelope.get("signature")
        data_hash = envelope.get("data_sha256")
        if not isinstance(sig, str) or not isinstance(data_hash, str):
            result.failures.append(
                "FAIL: malformed envelope — signature or data_sha256 missing"
            )
            result.hmac_ok = False
        else:
            # Verify the envelope's claimed data_sha256 matches the
            # actual canonical hash of the data array first; otherwise
            # an attacker who knows the HMAC key could swap rows AND
            # the claimed hash.
            recomputed_data_hash = _data_sha256(data)
            if not _hashes_equal(recomputed_data_hash, data_hash):
                result.failures.append(
                    f"FAIL: envelope.data_sha256 mismatch "
                    f"expected={data_hash[:16]}… got={recomputed_data_hash[:16]}…"
                )
                result.hmac_ok = False
            else:
                expected_sig = _hmac_sha256(hmac_key_hex, data_hash)
                if hmac.compare_digest(sig, expected_sig):
                    result.hmac_ok = True
                else:
                    result.failures.append(
                        "FAIL: envelope HMAC signature does not match "
                        "the supplied key"
                    )
                    result.hmac_ok = False

    # ---- optional Ethereum anchor (Session 4.5c.7)
    anchor = envelope.get("anchor") if isinstance(envelope, dict) else None
    if anchor_rpc_url is None:
        result.anchor_verified = None
        result.anchor_skip_reason = "no-rpc"
    elif not isinstance(anchor, dict):
        result.anchor_verified = None
        result.anchor_skip_reason = "no-anchor-in-export"
    else:
        merkle_root_hex = anchor.get("merkle_root_hex")
        tx_hash = anchor.get("tx_hash")
        if not isinstance(merkle_root_hex, str) or not isinstance(tx_hash, str):
            result.failures.append(
                "FAIL: malformed envelope.anchor — missing merkle_root_hex "
                "or tx_hash"
            )
            result.anchor_verified = False
        else:
            # Recompute the Merkle root over the export's row_hashes
            # FIRST — the export's claimed root must equal the
            # recomputed root before we even talk to the chain.
            row_hashes = [
                r["row_hash"] for r in data if isinstance(r, dict) and r.get("row_hash")
            ]
            recomputed_root = compute_merkle_root(row_hashes)
            if recomputed_root.lower() != merkle_root_hex.lower():
                result.failures.append(
                    f"FAIL: anchor Merkle root mismatch against export rows "
                    f"expected={merkle_root_hex[:16]}… got={recomputed_root[:16]}…"
                )
                result.anchor_verified = False
            else:
                try:
                    on_chain = verify_anchor_on_chain(
                        anchor_rpc_url, tx_hash, merkle_root_hex
                    )
                except ConnectionError as exc:
                    # Network unreachable is not an integrity failure —
                    # the regulator should retry rather than escalate.
                    result.anchor_skip_reason = f"rpc-unreachable: {exc}"
                    result.anchor_verified = None
                except ValueError as exc:
                    # RPC-level error (e.g. tx_hash not found) IS an
                    # integrity failure — the claimed tx doesn't exist.
                    result.failures.append(
                        f"FAIL: anchor tx not found on chain — {exc}"
                    )
                    result.anchor_verified = False
                else:
                    if on_chain["calldata_matches"]:
                        result.anchor_verified = True
                        result.anchor_block_number = on_chain["block_number"]
                        result.anchor_block_timestamp = on_chain[
                            "block_timestamp_iso"
                        ]
                    else:
                        result.failures.append(
                            f"FAIL: anchor calldata mismatch — "
                            f"on-chain={on_chain['calldata_hex'][:16]}… "
                            f"expected={merkle_root_hex[:16]}…"
                        )
                        result.anchor_verified = False

    result.passed = not result.failures
    return result


def _hashes_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.lower(), b.lower())


def _data_sha256(data: list[Any]) -> str:
    """Canonical SHA-256 over the data array — same shape as the
    backend's :func:`backend.app.audit_export.data_sha256_json`."""
    body = json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _hmac_sha256(key_hex: str, message: str) -> str:
    """HMAC-SHA-256 over ``message`` with a hex-encoded key. Mirrors
    the backend's :func:`backend.app.audit_export.sign`, which uses
    ``key.encode("utf-8")`` against the hex-string key (NOT
    ``bytes.fromhex``). The verifier does the same so the bytes-on-
    the-wire match."""
    return hmac.new(
        key_hex.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


__all__ = ["VerifyResult", "verify_export"]
