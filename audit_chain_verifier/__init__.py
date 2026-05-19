"""Open-source verifier for FidesChain audit-chain exports.

Public API:

  * :func:`audit_chain_verifier.verifier.verify_export` — verify a
    parsed export dict; returns a :class:`VerifyResult` with
    per-failure messages + exit-code-mappable booleans.
  * :func:`audit_chain_verifier.canonical.canonical_form` — the
    byte-for-byte canonical row form pinned to schema ``v1``.

The package has zero non-stdlib runtime dependencies. ``verify.py``
in the parent directory is the CLI entry point.
"""

from .canonical import SCHEMA_VERSION, canonical_form, row_hash_hex
from .verifier import VerifyResult, verify_export

__all__ = [
    "SCHEMA_VERSION",
    "VerifyResult",
    "canonical_form",
    "row_hash_hex",
    "verify_export",
]
