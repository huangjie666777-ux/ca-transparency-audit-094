"""RFC 6962 (Certificate Transparency) Merkle tree primitives.

Only SHA-256 is used:

* empty tree:  MTH({}) = SHA256("")
* leaf:        SHA256(0x00 || leaf_data)
* node:        SHA256(0x01 || left || right)

See https://www.rfc-editor.org/rfc/rfc6962#section-2.1
"""

from __future__ import annotations

import hashlib

LEAF_HASH_PREFIX = b"\x00"
NODE_HASH_PREFIX = b"\x01"
HASH_SIZE = 32


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 section 2.1: SHA256(0x00 || leaf_data)."""
    return hashlib.sha256(LEAF_HASH_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 section 2.1: SHA256(0x01 || left || right)."""
    return hashlib.sha256(NODE_HASH_PREFIX + left + right).digest()


def empty_tree_hash() -> bytes:
    """RFC 6962 section 2.1: MTH({}) = SHA256("")."""
    return hashlib.sha256(b"").digest()


def largest_power_of_two_less_than(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    if n < 2:
        raise ValueError("n must be >= 2")
    return 1 << ((n - 1).bit_length() - 1)


def verify_inclusion(
    leaf_index: int,
    tree_size: int,
    leaf_hash_value: bytes,
    proof: list[bytes],
    root: bytes,
) -> bool:
    """Verify an RFC 6962 inclusion proof (section 2.1.3.2).

    Recomputes the root from the leaf hash and the proof and compares it to
    the trusted root. Rejects illegal sizes and proofs with extra nodes.
    """
    if leaf_index < 0 or tree_size <= 0 or leaf_index >= tree_size:
        return False
    if len(leaf_hash_value) != HASH_SIZE or len(root) != HASH_SIZE:
        return False
    if any(len(node) != HASH_SIZE for node in proof):
        return False

    fn = leaf_index
    sn = tree_size - 1
    r = leaf_hash_value
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            # Shift until LSB(fn) is set or fn reaches 0.
            while fn != 0 and fn % 2 == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: list[bytes],
) -> bool:
    """Verify an RFC 6962 consistency proof (section 2.1.4.2).

    Confirms that the first ``old_size`` leaves of the tree of size
    ``new_size`` hash to ``old_root``. Rejects illegal sizes and proofs
    with extra nodes.
    """
    if old_size < 0 or new_size < 0 or old_size > new_size:
        return False
    if len(old_root) != HASH_SIZE or len(new_root) != HASH_SIZE:
        return False
    if any(len(node) != HASH_SIZE for node in proof):
        return False

    if old_size == new_size:
        return len(proof) == 0 and old_root == new_root
    if old_size == 0:
        return len(proof) == 0

    # When the old tree is a complete subtree, its root is a node in the
    # new tree; prepend it to the proof so both tracks start from it.
    if old_size & (old_size - 1) == 0:
        proof = [old_root] + proof
    if len(proof) == 0:
        return False

    fn = old_size - 1
    sn = new_size - 1
    # Shift until LSB(fn) is unset.
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = proof[0]
    sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            # Shift until LSB(fn) is set or fn reaches 0.
            while fn != 0 and fn % 2 == 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0
