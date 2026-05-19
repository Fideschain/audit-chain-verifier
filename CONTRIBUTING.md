# Contributing

This repository is the **public, independent verifier** for FidesChain audit
chain exports. Its job is to let a regulator, auditor, or skeptical third
party re-derive every row hash in an export and confirm the audit chain is
intact — without trusting (or needing access to) FidesChain infrastructure.

Because the verifier is the trust root, contributions are intentionally
narrow:

## What we accept

- **Bug reports** — especially false PASS results (verifier accepted a
  tampered or gapped export) or false FAIL results (verifier rejected an
  export the FidesChain backend produced).
- **Stdlib-only fixes** — patches that use only the Python standard library.
  Zero non-stdlib runtime dependencies is a hard contract: a regulator must
  be able to clone and run on an air-gapped Python 3.11 box.
- **Documentation clarifications** — the README is supervisor-voice and
  must remain so. Suggest changes via PR.

## What we do NOT accept

- New dependencies (runtime or test).
- Changes to `SCHEMA_VERSION` — that constant is pinned to the FidesChain
  backend (`backend/app/audit.py` and `backend/app/me/defense_bundle.py`).
  Schema changes happen in the backend first, then we ship a major version
  bump here.
- Features that change canonical-form semantics (`canonical_form()` in
  `audit_chain_verifier/canonical.py`). The canonical form IS the contract
  with the backend; touching it silently breaks every prior export.

## Reporting a verification failure

Open an issue with:

1. The verifier exit code (0, 2, 3, or 64).
2. The export envelope's `exported_at` timestamp.
3. The row `id` the verifier flagged, if any.
4. **Do not** paste the full export — it may contain PII. Redact
   `customer_id`, `ts`, `action`, and `payload` fields, keep only the
   structural fields (`schema_version`, `envelope`, row `id` and
   `row_hash`).

## Running tests locally

```bash
python -m unittest discover tests -v
```

Should report 13 tests passing on Python 3.11, 3.12, and 3.13.

## Security

For verifier security issues (e.g. a way to forge an export that the
verifier accepts as authentic), email **security@fideschain.fr** — please
do not open a public issue.
