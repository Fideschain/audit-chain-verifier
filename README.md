# audit-chain-verifier

This program verifies that a FidesChain audit-chain export is internally
consistent and cryptographically intact: every row's hash recomputes
correctly, the row-id sequence has no gaps, and (when an HMAC key is
supplied) the envelope's signature validates. It does **not** prove
that the original screening decision was correct, that the customer
actually applied it, or that the regulator should be satisfied with the
outcome. It proves only that the records you are reading have not been
altered, deleted, or forged after they were written. The promise and
the limit live in the same paragraph because that is what gives the
promise its weight.

## Why this exists

A FidesChain customer hands a regulator a JSON export of their audit
chain. The regulator wants to verify the export was not tampered with
between the customer's database and their inbox — without trusting
FidesChain, without trusting the customer, and without installing
FidesChain's own code. This script is that verification, end to end,
in 200 lines of Python with zero third-party dependencies.

The verifier is MIT-licensed. It runs on any system with Python 3.11
or later. A regulator can read it in one sitting.

## Limitations

Before you trust this verifier, understand what it does not check.

1. **The original decision.** If a customer correctly recorded that
   they cleared a sanctioned applicant, the verifier will return PASS.
   It checks records, not judgment.
2. **Completeness of the export.** A customer can export a subset of
   their chain by filtering on action or timestamp; the verifier
   checks only the rows in the file you give it. If a row was omitted
   from the export, the verifier cannot tell. It can only detect gaps
   inside the exported range — id 5 next to id 7 with nothing
   between.
3. **Off-chain context.** Documents, screenshots, regulator
   correspondence — none of that is in the audit chain. The chain
   records that decisions were made, not what the decisions referred
   to outside the system.
4. **Time itself.** The verifier confirms that the timestamps in the
   export are consistent with the row hashes. It cannot confirm that
   the customer's clock was correct.

When the verifier returns PASS, you know the rows have not been
changed since they were written. You still need everything else a
regulator normally relies on.

## How to use

```
python3 verify.py path/to/export.json
```

Add `--hmac-key <hex>` if the customer published the signing key
alongside the export (most do; the key is rotated quarterly and the
current value is in the customer's compliance documentation).

The script prints a single line. Exit codes are designed for shell
scripting:

```
0   PASS — every row's hash recomputes and the id sequence is intact.
2   chain-integrity violation. A row has been changed, removed, or
    the envelope signature did not validate. This is the escalation
    signal.
3   malformed input. The file is not a valid FidesChain export.
    Ask the customer for a fresh copy.
64  usage error. You called the script wrong.
```

A successful run looks like this:

```
$ python3 verify.py tests/fixtures/clean.json
VERIFICATION: PASS rows_verified=3 hmac=not-checked chain_intact=true
```

A tampered chain looks like this:

```
$ python3 verify.py tests/fixtures/tampered.json
FAIL: row_hash mismatch at id=2 expected=387380d57f556cb1… got=39fda2d956548116…
VERIFICATION: FAIL rows_verified=3 failures=1
```

## How it works

Each row in a FidesChain audit chain carries a SHA-256 hash computed
over four canonical fields: the customer id, the timestamp in
ISO-8601 UTC with microsecond precision, the action string, and the
payload as canonical JSON (RFC-8785-shaped). Those four fields,
joined by newlines, in that order, in UTF-8 bytes, are the canonical
row form. The hash is independent per-row — there is no chained-hash
link from one row to the next. The "chain" property comes from the
combination of (a) per-row hash integrity and (b) strictly
monotonic id sequencing.

A verifier reproduces that hash from each row's contents and compares
to the value the customer exported. If they match, the row was not
altered. The id sequencing check detects deletion. The optional
envelope HMAC check detects forgery of the entire export.

The canonical form is pinned at schema **v1**. If FidesChain changes
the form, the corresponding schema version on both sides
(`backend/app/audit.py:SCHEMA_VERSION` and
`audit_chain_verifier/canonical.py:SCHEMA_VERSION`) bumps in the
same commit. This document refers to schema v1; check the version
pin before relying on this verifier against an export that claims a
different schema.

## Installing

The verifier is a script. You do not need to install it. Copy
`verify.py` and the `audit_chain_verifier/` package directory to any
location and run the script with Python 3.11+:

```
git clone https://github.com/nicochevrier206/audit-chain-verifier
cd audit-chain-verifier
python3 verify.py tests/fixtures/clean.json
```

If you prefer a `pip` install:

```
pip install .
```

There are no runtime dependencies. `pip install .` succeeds with an
empty `dependencies = []` array. `pip install ruff` is the only build-
time dependency, and only if you intend to run the linter.

## What's in the package

```
verify.py                                  the CLI entry point
audit_chain_verifier/canonical.py          the canonical row form
audit_chain_verifier/verifier.py           the three integrity checks
tests/test_verifier.py                     stdlib-unittest suite
tests/fixtures/clean.json                  a 3-row clean export
tests/fixtures/tampered.json               id=2 payload mutated
tests/fixtures/gapped.json                 id=2 missing
.github/workflows/verify.yml               CI: ruff + unittest
LICENSE                                    MIT
```

## Running the test suite

The verifier ships with stdlib-unittest tests against the handcrafted
fixtures above:

```
python3 -m unittest discover tests -v
```

CI runs the same command on Python 3.11, 3.12, and 3.13. No
third-party test runner — `unittest` from the standard library is
sufficient.

## Reporting an issue

Verification failures on a real customer export are the regulator's
escalation signal. If you suspect the verifier itself is broken — a
false PASS or a false FAIL on a known-good chain — open an issue at
`https://github.com/nicochevrier206/audit-chain-verifier/issues` with the
export file (redacted where appropriate) and the exact command you
ran. A reproducer wins more than a description.

## License

MIT. See `LICENSE`. You may use, modify, redistribute, or fork this
verifier without restriction. We ask that you preserve the
attribution so future readers know where the canonical form came
from.
