"""Independent verification logic for transparency log proofs.

This module has no database or network access. A verifier trusts only a
pre-distributed Ed25519 public key, the certificate DER, and the tree
head/proof data. It never trusts the public key returned by a response.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from . import merkle
from .audit import HEAD_PREFIX, LOG_ID_LEN
from .log_signing import verify_signature


class VerificationError(ValueError):
    """Raised when a proof or tree head fails verification."""


@dataclass(frozen=True)
class TreeHead:
    log_id: bytes
    tree_size: int
    root: bytes


def parse_signed_data(signed_data: bytes) -> TreeHead:
    """Parse the canonical signed tree-head message.

    Layout: HEAD_PREFIX || log_id(16) || tree_size(8 BE) || root(32).
    """
    header_len = len(HEAD_PREFIX)
    expected_len = header_len + LOG_ID_LEN + 8 + merkle.HASH_SIZE
    if len(signed_data) != expected_len:
        raise VerificationError(
            f"signed data has wrong length: expected {expected_len}, "
            f"got {len(signed_data)}"
        )
    if not signed_data.startswith(HEAD_PREFIX):
        raise VerificationError("signed data has an unknown domain separator")
    offset = header_len
    log_id = signed_data[offset:offset + LOG_ID_LEN]
    offset += LOG_ID_LEN
    tree_size = struct.unpack(">Q", signed_data[offset:offset + 8])[0]
    offset += 8
    root = signed_data[offset:offset + merkle.HASH_SIZE]
    return TreeHead(log_id=log_id, tree_size=tree_size, root=root)


def verify_tree_head(
    public_key: bytes,
    signed_data: bytes,
    signature: bytes,
    *,
    expected_log_id: bytes | None = None,
) -> TreeHead:
    """Verify a signed tree head against a pre-trusted public key.

    Returns the parsed head on success; raises VerificationError on any
    failure (bad signature, malformed signed data, or log identity
    mismatch).
    """
    head = parse_signed_data(signed_data)
    if expected_log_id is not None and head.log_id != expected_log_id:
        raise VerificationError("log identity does not match the trusted log")
    if not verify_signature(public_key, signature, signed_data):
        raise VerificationError("tree head signature is invalid")
    return head


def verify_inclusion(
    leaf_hash_value: bytes,
    leaf_index: int,
    tree_size: int,
    proof: list[bytes],
    root: bytes,
) -> None:
    """Verify an inclusion proof, raising VerificationError on failure."""
    if not merkle.verify_inclusion(
        leaf_index, tree_size, leaf_hash_value, proof, root
    ):
        raise VerificationError("inclusion proof verification failed")


def verify_consistency(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: list[bytes],
) -> None:
    """Verify a consistency proof, raising VerificationError on failure."""
    if not merkle.verify_consistency(
        old_size, new_size, old_root, new_root, proof
    ):
        raise VerificationError("consistency proof verification failed")


def cert_leaf_hash(cert_der: bytes) -> bytes:
    """Leaf hash for a certificate DER: SHA256(0x00 || DER)."""
    return merkle.leaf_hash(cert_der)
