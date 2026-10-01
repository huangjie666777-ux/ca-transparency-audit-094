"""Canonical wire format binding a signed tree head to log identity.

Kept dependency-light (hashlib/base64 only) so the independent verifier
(:mod:`app.audit_verify`) and the server share one format without the
verifier having to import any signing or database code.
"""

from __future__ import annotations

import base64
import hashlib
import struct

# Bumped only if the signed bytes ever change incompatibly.
HEAD_VERSION = 1
HEAD_DOMAIN = b"LOCAL-CA-AUDIT-LOG-HEAD-V1\x00"

# Ed25519 signatures and SHA-256 hashes are both exactly 32 bytes.
HASH_LEN = 32
PUBKEY_LEN = 32
SIGNATURE_LEN = 64


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("base64url value must be a string")
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def log_id_for_public_key(public_key_raw: bytes) -> bytes:
    """The log identity is the SHA-256 of the Ed25519 public key (raw)."""
    if len(public_key_raw) != PUBKEY_LEN:
        raise ValueError("Ed25519 public key must be 32 raw bytes")
    return hashlib.sha256(public_key_raw).digest()


def build_head_input(log_id: bytes, tree_size: int, root_hash: bytes) -> bytes:
    """Deterministic bytes covered by the tree-head Ed25519 signature."""
    if len(log_id) != HASH_LEN:
        raise ValueError("log id must be 32 bytes")
    if len(root_hash) != HASH_LEN:
        raise ValueError("root hash must be 32 bytes")
    if tree_size < 0 or tree_size > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("tree size out of range")
    return (
        HEAD_DOMAIN
        + log_id
        + struct.pack(">Q", tree_size)
        + root_hash
    )
