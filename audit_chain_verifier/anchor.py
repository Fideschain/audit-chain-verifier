"""Ethereum-mainnet Merkle anchoring (Session 4.5c.7).

Pure stdlib. The verifier side of the anchoring contract:

  * :func:`compute_merkle_root` — RFC-9162 / CT-style Merkle root over
    a list of row_hash hex strings. Leaf and inner-node domain
    separation via prefix bytes ``\\x00`` / ``\\x01`` so a leaf hash
    can never collide with an inner-node hash (second-preimage guard).
  * :func:`compute_inclusion_proof` — left/right sibling sequence for
    a target leaf.
  * :func:`verify_inclusion_proof` — recomputes the root from a
    leaf + proof and checks equality.
  * :func:`fetch_anchor_calldata` — raw urllib JSON-RPC against any
    Ethereum node; returns the tx's input bytes + block_number +
    block_timestamp. 10s timeout. Raises ``ConnectionError`` on RPC
    failure (network issue, not integrity issue — callers must
    distinguish).
  * :func:`verify_anchor_on_chain` — wraps the fetch + compares the
    calldata bytes against ``expected_root_hex``; returns a structured
    result the verifier CLI projects onto its single-line output.

Zero non-stdlib deps. The JSON-RPC path uses ``urllib.request`` so
a regulator with nothing but a fresh Python 3.11 box can fetch + check
the on-chain anchor without a pip install.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Literal

# CT / RFC-9162 domain-separation prefixes. A leaf hash is
# ``SHA-256(LEAF_PREFIX || raw_leaf_bytes)``; an inner node is
# ``SHA-256(INNER_PREFIX || left_hash || right_hash)``. The two prefixes
# guarantee a leaf-hash output can never collide with an inner-node
# output, defeating second-preimage attacks against the tree shape.
LEAF_PREFIX: bytes = b"\x00"
INNER_PREFIX: bytes = b"\x01"

# Network constants — chainId -> human label. The verifier prints the
# inferred network in its output line so a regulator can confirm
# they're checking mainnet vs sepolia.
_CHAIN_ID_TO_NETWORK: dict[int, str] = {
    1: "mainnet",
    11155111: "sepolia",
}

# JSON-RPC defaults.
_RPC_TIMEOUT_SECONDS: float = 10.0
_RPC_USER_AGENT: str = "audit-chain-verifier/1.1 (+https://fideschain.fr)"


# ---------------------------------------------------------- Merkle math


def _leaf_hash(row_hash_hex: str) -> bytes:
    """``SHA-256(LEAF_PREFIX || row_hash_bytes)``."""
    raw = bytes.fromhex(row_hash_hex)
    return hashlib.sha256(LEAF_PREFIX + raw).digest()


def _inner_hash(left: bytes, right: bytes) -> bytes:
    """``SHA-256(INNER_PREFIX || left || right)``."""
    return hashlib.sha256(INNER_PREFIX + left + right).digest()


def compute_merkle_root(row_hashes_hex: list[str]) -> str:
    """Return the hex SHA-256 Merkle root over the row_hashes.

    Empty input returns ``sha256(b"")`` per the CT convention (so an
    empty audit range still has a defined root and can be anchored).
    Odd-numbered levels duplicate the last node — also per CT.
    """
    if not row_hashes_hex:
        return hashlib.sha256(b"").hexdigest()

    level = [_leaf_hash(h) for h in row_hashes_hex]
    while len(level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            next_level.append(_inner_hash(left, right))
        level = next_level
    return level[0].hex()


def compute_inclusion_proof(
    row_hashes_hex: list[str], target_idx: int
) -> list[tuple[str, Literal["L", "R"]]]:
    """Return ``[(sibling_hex, side), ...]`` proving ``target_idx`` is
    in the tree. ``side='L'`` means the sibling is the LEFT node at
    that level (i.e. concatenated as sibling||self when re-hashing);
    ``side='R'`` means the sibling is to the right.

    Empty list when there's a single leaf (the root is the leaf hash
    itself; nothing to prove against).
    """
    if not 0 <= target_idx < len(row_hashes_hex):
        raise IndexError(
            f"target_idx={target_idx} out of range for {len(row_hashes_hex)} leaves"
        )
    if len(row_hashes_hex) == 1:
        return []

    level = [_leaf_hash(h) for h in row_hashes_hex]
    idx = target_idx
    proof: list[tuple[str, Literal["L", "R"]]] = []
    while len(level) > 1:
        # Duplicate the last node if level length is odd — pair logic
        # mirrors compute_merkle_root.
        if idx % 2 == 0:
            sibling_idx = idx + 1 if idx + 1 < len(level) else idx
            side: Literal["L", "R"] = "R"
        else:
            sibling_idx = idx - 1
            side = "L"
        proof.append((level[sibling_idx].hex(), side))
        # Advance to the parent level.
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            next_level.append(_inner_hash(left, right))
        level = next_level
        idx //= 2
    return proof


def verify_inclusion_proof(
    leaf_hex: str,
    proof: list[tuple[str, Literal["L", "R"]]],
    expected_root_hex: str,
) -> bool:
    """Recompute the root from ``leaf_hex`` + ``proof`` and compare to
    ``expected_root_hex``. Constant-time comparison via hex equality
    (the input is hex, not bytes; SHA-256 collision resistance is the
    actual security property)."""
    current = _leaf_hash(leaf_hex)
    for sibling_hex, side in proof:
        sibling = bytes.fromhex(sibling_hex)
        current = (
            _inner_hash(sibling, current)
            if side == "L"
            else _inner_hash(current, sibling)
        )
    return current.hex().lower() == expected_root_hex.lower()


# ---------------------------------------------------------- JSON-RPC


def _rpc_call(url: str, method: str, params: list) -> object:
    """Minimal JSON-RPC client. Returns the ``result`` field or raises.

    ``ConnectionError`` on network / timeout. ``ValueError`` on
    protocol-level RPC error (eth_-method returning an error object).
    """
    body = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": _RPC_USER_AGENT,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(
            req, timeout=_RPC_TIMEOUT_SECONDS
        ) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise ConnectionError(f"RPC unreachable: {exc}") from exc
    except TimeoutError as exc:
        raise ConnectionError(f"RPC timeout after {_RPC_TIMEOUT_SECONDS}s") from exc
    except json.JSONDecodeError as exc:
        raise ConnectionError(f"RPC returned non-JSON: {exc}") from exc

    if "error" in payload:
        err = payload["error"]
        raise ValueError(f"RPC error: {err}")
    return payload.get("result")


def _hex_to_int(value: str | None) -> int:
    if not isinstance(value, str):
        raise ValueError(f"expected hex string, got {value!r}")
    return int(value, 16)


def fetch_anchor_calldata(
    rpc_url: str, tx_hash: str
) -> tuple[bytes, int, int]:
    """Return ``(input_bytes, block_number, block_timestamp_unix)`` for
    a confirmed Ethereum transaction.

    Raises ``ConnectionError`` on RPC unreachable / timeout.
    Raises ``ValueError`` on protocol error or unconfirmed tx
    (``blockNumber == null`` in mempool state).
    """
    tx = _rpc_call(rpc_url, "eth_getTransactionByHash", [tx_hash])
    if not isinstance(tx, dict):
        raise ValueError(f"tx not found: {tx_hash}")
    input_hex = tx.get("input")
    if not isinstance(input_hex, str) or not input_hex.startswith("0x"):
        raise ValueError(f"tx has no input field: {tx_hash}")
    block_number_hex = tx.get("blockNumber")
    if block_number_hex is None:
        raise ValueError(f"tx not yet mined: {tx_hash}")
    block_number = _hex_to_int(block_number_hex)

    block = _rpc_call(
        rpc_url, "eth_getBlockByNumber", [block_number_hex, False]
    )
    if not isinstance(block, dict):
        raise ValueError(f"block not found: {block_number}")
    timestamp_hex = block.get("timestamp")
    if timestamp_hex is None:
        raise ValueError(f"block missing timestamp: {block_number}")
    block_timestamp = _hex_to_int(timestamp_hex)

    input_bytes = bytes.fromhex(input_hex[2:]) if len(input_hex) > 2 else b""
    return input_bytes, block_number, block_timestamp


def _infer_network(rpc_url: str) -> str:
    """Best-effort chainId → human label. Returns ``"unknown"`` on RPC
    failure or unmapped chainId (does not raise — the network label is
    informational, not a security property)."""
    try:
        chain_id_hex = _rpc_call(rpc_url, "eth_chainId", [])
    except (ConnectionError, ValueError):
        return "unknown"
    if not isinstance(chain_id_hex, str):
        return "unknown"
    try:
        chain_id = _hex_to_int(chain_id_hex)
    except ValueError:
        return "unknown"
    return _CHAIN_ID_TO_NETWORK.get(chain_id, "unknown")


def verify_anchor_on_chain(
    rpc_url: str, tx_hash: str, expected_root_hex: str
) -> dict:
    """Fetch the on-chain tx + verify calldata equals ``expected_root_hex``.

    Returns a dict the verifier CLI can render. Does NOT raise on
    calldata mismatch — that's a regular failure path, not an
    exception. Raises ``ConnectionError`` only when the network is
    unreachable.
    """
    input_bytes, block_number, block_timestamp = fetch_anchor_calldata(
        rpc_url, tx_hash
    )
    network = _infer_network(rpc_url)
    expected = bytes.fromhex(expected_root_hex)
    calldata_matches = input_bytes == expected
    return {
        "confirmed": True,
        "block_number": block_number,
        "block_timestamp_iso": datetime.fromtimestamp(
            block_timestamp, tz=UTC
        )
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "block_timestamp_unix": block_timestamp,
        "calldata_matches": calldata_matches,
        "calldata_hex": input_bytes.hex(),
        "network_inferred": network,
    }


__all__ = [
    "INNER_PREFIX",
    "LEAF_PREFIX",
    "compute_inclusion_proof",
    "compute_merkle_root",
    "fetch_anchor_calldata",
    "verify_anchor_on_chain",
    "verify_inclusion_proof",
]
