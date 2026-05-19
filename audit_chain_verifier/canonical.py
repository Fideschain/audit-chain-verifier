"""Canonical-row form for a FidesChain audit-chain export row.

The exact bytes that are SHA-256'd into ``row_hash``. This module is
the hardcoded contract between the FidesChain backend and the
open-source verifier; the form is the same one in
``backend/app/audit.py:canonical_row_hash``.

If the canonical form ever changes:

  1. Bump :data:`SCHEMA_VERSION` here AND in
     ``backend/app/audit.py:SCHEMA_VERSION`` in the SAME commit.
  2. Add a backwards-compatible reader in :func:`canonical_form` if
     older exports must still verify.

If the verifier's canonical form ever drifts from the backend's, the
verifier silently lies — that is the worst possible failure mode for
a trust artifact. The byte-for-byte parity is enforced by the
backend canary at ``backend/tests/test_audit_chain_verifier.py``,
which exports a real audit chain and verifies it via this module.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# Pinned alongside ``backend/app/audit.py:SCHEMA_VERSION``. Any future
# canonical-form change bumps both atomically.
#
# History:
#   v1  — initial release. Canonical row form + envelope signature.
#   v2  — adds optional envelope.anchor (Ethereum-mainnet Merkle
#         anchor, Session 4.5c.7). Row canonical form is UNCHANGED —
#         v1 row hashes recompute identically under v2 because the
#         only change is an additive envelope field. v1 exports parse
#         under v2 readers (the anchor field is simply absent).
SCHEMA_VERSION: str = "v2"
SCHEMA_VERSIONS_SUPPORTED: tuple[str, ...] = ("v1", "v2")


def canonical_form(
    customer_id: str,
    ts: str,
    action: str,
    payload_redacted: dict[str, Any],
) -> bytes:
    """Return the UTF-8 bytes of the canonical row form.

    Format (newline-separated, single trailing payload JSON, no
    terminating newline)::

        "{customer_id}\\n{ts}\\n{action}\\n{payload_json}"

    where:

      * ``customer_id`` is the lowercase hyphenated UUID string.
      * ``ts`` is the ISO-8601 UTC timestamp with microsecond
        precision and a trailing ``Z`` (``+00:00`` rewritten as
        ``Z``). The verifier accepts whatever the export emits and
        normalises it here, so a row whose ``ts`` arrives as
        ``2026-05-19T07:42:00+00:00`` and one as
        ``2026-05-19T07:42:00.000000Z`` hash identically.
      * ``payload_json`` is :func:`json.dumps` with
        ``sort_keys=True``, ``separators=(",", ":")``,
        ``ensure_ascii=False`` — i.e. RFC-8785-shaped canonical JSON.
    """
    cid = customer_id.lower()
    ts_norm = _normalise_ts(ts)
    payload_str = json.dumps(
        payload_redacted,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return f"{cid}\n{ts_norm}\n{action}\n{payload_str}".encode()


def row_hash_hex(
    customer_id: str,
    ts: str,
    action: str,
    payload_redacted: dict[str, Any],
) -> str:
    """SHA-256 hex digest of the canonical row form."""
    return hashlib.sha256(
        canonical_form(customer_id, ts, action, payload_redacted)
    ).hexdigest()


def _normalise_ts(ts: str) -> str:
    """Normalise a JSON-exported timestamp back to the backend's
    canonical microsecond-precision ``Z`` form.

    Acceptable inputs:

      * ``2026-05-19T07:42:00.123456+00:00``  → microsecond-precision Z
      * ``2026-05-19T07:42:00.123456Z``       → unchanged
      * ``2026-05-19T07:42:00+00:00``         → padded to microsecond Z
      * ``2026-05-19T07:42:00Z``              → padded to microsecond Z

    Anything else is returned unchanged so the verifier reports a
    hash mismatch rather than silently rewriting the input.
    """
    if not isinstance(ts, str) or len(ts) < 19:
        return ts
    # Trim trailing 'Z' for parsing; treat as UTC.
    raw = ts[:-1] if ts.endswith("Z") else ts
    # Common backend export shape: "+00:00" suffix.
    if raw.endswith("+00:00"):
        raw = raw[:-6]
    # Now raw is "<date>T<time>" possibly with a ".<microseconds>" tail.
    if "T" not in raw:
        return ts
    date_part, time_part = raw.split("T", 1)
    if "." in time_part:
        head, _, fractional = time_part.partition(".")
        fractional = (fractional + "000000")[:6]
        return f"{date_part}T{head}.{fractional}Z"
    return f"{date_part}T{time_part}.000000Z"


__all__ = [
    "SCHEMA_VERSION",
    "SCHEMA_VERSIONS_SUPPORTED",
    "canonical_form",
    "row_hash_hex",
]
