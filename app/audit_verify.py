"""Independent transparency verification.

This module deliberately imports neither the HTTP layer nor the database nor
the signing key. Given only:

* a pre-provisioned, trusted Ed25519 public key (raw 32 bytes),
* a certificate (complete DER),
* one or two signed tree heads, and
* an inclusion / consistency proof,

it decides whether the certificate is included in the log and whether a
newer tree head extends an older one. The public key inside any response is
never consulted: trust comes solely from the key handed in by the caller.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import merkle
from .audit_wire import (
    HASH_LEN,
    PUBKEY_LEN,
    build_head_input,
    log_id_for_public_key,
)


class VerificationError(ValueError):
    """Raised when a tree head or proof cannot be independently verified."""


def load_trusted_public_key(raw: bytes) -> ed25519.Ed25519PublicKey:
    """Parse and sanity-check the out-of-band trusted log key."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != PUBKEY_LEN:
        raise VerificationError("trusted log key must be 32 raw Ed25519 bytes")
    try:
        return ed25519.Ed25519PublicKey.from_public_bytes(bytes(raw))
    except Exception as exc:
        raise VerificationError(f"invalid Ed25519 public key: {exc}") from exc


def verify_tree_head(
    trusted_public_key: ed25519.Ed25519PublicKey | bytes,
    *,
    log_id: bytes,
    tree_size: int,
    root_hash: bytes,
    signature: bytes,
) -> None:
    """Validate a tree head against the trusted key and its claimed identity.

    The ``log_id`` in the response must equal SHA-256 of the *trusted* key;
    any key advertised alongside the head is ignored.
    """
    if isinstance(trusted_public_key, (bytes, bytearray)):
        key = load_trusted_public_key(bytes(trusted_public_key))
        trusted_raw = bytes(trusted_public_key)
    else:
        key = trusted_public_key
        trusted_raw = _raw(key)
    expected_log_id = log_id_for_public_key(trusted_raw)
    if not isinstance(log_id, (bytes, bytearray)) or bytes(log_id) != expected_log_id:
        raise VerificationError(
            "tree head log id does not match the trusted public key"
        )
    if not isinstance(tree_size, int) or isinstance(tree_size, bool) or tree_size < 0:
        raise VerificationError("tree size must be a non-negative integer")
    if not isinstance(root_hash, (bytes, bytearray)) or len(root_hash) != HASH_LEN:
        raise VerificationError("root hash must be 32 bytes")
    if (
        not isinstance(signature, (bytes, bytearray))
        or len(signature) != 64
    ):
        raise VerificationError("tree head signature must be 64 bytes")
    signed_bytes = build_head_input(expected_log_id, tree_size, bytes(root_hash))
    try:
        key.verify(bytes(signature), signed_bytes)
    except InvalidSignature as exc:
        raise VerificationError("tree head signature is invalid") from exc


def _raw(key: ed25519.Ed25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def verify_certificate_inclusion(
    trusted_public_key: ed25519.Ed25519PublicKey | bytes,
    cert_der: bytes,
    tree_head: dict,
    inclusion_path: list[bytes],
    *,
    leaf_index: int,
) -> None:
    """End-to-end inclusion check for one certificate.

    ``tree_head`` carries log_id/tree_size/root_hash/signature as produced by
    the audit endpoint. Its embedded identity and signature are checked
    against the trusted key before the Merkle path is evaluated.
    """
    if not isinstance(cert_der, (bytes, bytearray)) or not cert_der:
        raise VerificationError("certificate DER must be non-empty bytes")
    verify_tree_head(trusted_public_key, **_head_kwargs(tree_head))
    try:
        merkle.verify_inclusion(
            leaf_index=leaf_index,
            tree_size=tree_head["tree_size"],
            proof=list(inclusion_path),
            leaf_hash=merkle.hash_leaf(bytes(cert_der)),
            root_hash=bytes(tree_head["root_hash"]),
        )
    except merkle.ProofError as exc:
        raise VerificationError(str(exc)) from exc


def verify_history_consistency(
    trusted_public_key: ed25519.Ed25519PublicKey | bytes,
    old_head: dict,
    new_head: dict,
    consistency_path: list[bytes],
) -> None:
    """Verify that ``new_head`` is an extension of ``old_head``.

    Both heads are independently signature-checked, sizes must be ordered,
    and the Merkle consistency proof must bind the two signed roots.
    """
    verify_tree_head(trusted_public_key, **_head_kwargs(old_head))
    verify_tree_head(trusted_public_key, **_head_kwargs(new_head))
    first, second = old_head["tree_size"], new_head["tree_size"]
    if first > second:
        raise VerificationError("old tree head is larger than the new one")
    if first > 0 and first != second and not consistency_path:
        raise VerificationError("consistency proof for growing tree is empty")
    try:
        merkle.verify_consistency(
            first=first,
            second=second,
            proof=list(consistency_path),
            first_hash=bytes(old_head["root_hash"]),
            second_hash=bytes(new_head["root_hash"]),
        )
    except merkle.ProofError as exc:
        raise VerificationError(str(exc)) from exc


def _head_kwargs(head: dict) -> dict:
    required = ("log_id", "tree_size", "root_hash", "signature")
    if not isinstance(head, dict) or not all(k in head for k in required):
        raise VerificationError(
            "tree head must contain log_id, tree_size, root_hash, signature"
        )
    return {
        "log_id": head["log_id"],
        "tree_size": head["tree_size"],
        "root_hash": head["root_hash"],
        "signature": head["signature"],
    }
