"""RFC 6962 §2.1 (as clarified by RFC 9162 §2.1) Merkle tree math.

The module is deliberately transport- and storage-agnostic: it only knows
SHA-256 hashing, the leaf/node domain-separation prefixes and the inclusion /
consistency proof verification pseudocode. It never needs all leaves at once
to verify a proof, and it is the single source of truth shared by the log's
on-disk tree (:mod:`app.audit_store`) and the independent verifier
(:mod:`app.audit_verify`).
"""

from __future__ import annotations

import hashlib

# RFC 6962 §2.1: domain-separation prefixes.
LEAF_HASH_PREFIX = b"\x00"
NODE_HASH_PREFIX = b"\x01"

# SHA-256 of the empty string: MTH({}) = HASH().
EMPTY_TREE_HASH = hashlib.sha256(b"").digest()

HASH_LEN = 32


class ProofError(ValueError):
    """Raised when a proof is malformed, has the wrong length or does not
    verify against the claimed root."""


def hash_leaf(leaf_data: bytes) -> bytes:
    """Leaf hash over the *complete* leaf input (the full certificate DER)."""
    return hashlib.sha256(LEAF_HASH_PREFIX + leaf_data).digest()


def hash_nodes(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_HASH_PREFIX + left + right).digest()


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def _lowest_set_bit(n: int) -> int:
    # RFC 9162 §2.1.4.1 helper: k = 1 if n is odd, else the largest power of
    # two that divides n. Used when appending to a persisted frontier.
    return n & -n


def max_inclusion_path_len(tree_size: int) -> int:
    """Upper bound on an inclusion proof's node count for a tree of n.

    RFC 6962 defines the proof as the *shortest* path, so the exact length
    varies with the leaf's position (e.g. n=7 gives 2 or 3 nodes) but never
    exceeds ceil(log2(n)).
    """
    if tree_size <= 1:
        return 0
    return (tree_size - 1).bit_length()


# ------------------------------------------------------------- root from data
# These helpers operate on in-memory data and are only used by tests and the
# one-shot legacy migration. Live serving never rebuilds the tree this way.


def tree_root_from_leaves(leaves: list[bytes]) -> bytes:
    """Compute MTH over a list of complete leaf inputs. Convenience/test aid."""
    if not leaves:
        return EMPTY_TREE_HASH
    return _subtree([hash_leaf(d) for d in leaves])


def _subtree(level: list[bytes]) -> bytes:
    n = len(level)
    if n == 1:
        return level[0]
    k = 1 << (n.bit_length() - 1)
    if k == n:  # n is a power of two: split exactly in half
        k >>= 1
    return hash_nodes(_subtree(level[:k]), _subtree(level[k:]))


# ------------------------------------------------------------ inclusion proof
# RFC 9162 §2.1.3.2 (single running-hash verifier).


def verify_inclusion(
    leaf_index: int,
    tree_size: int,
    proof: list[bytes],
    leaf_hash: bytes,
    root_hash: bytes,
) -> None:
    """Verify an inclusion proof. Raises :class:`ProofError` on any mismatch."""
    if tree_size < 0 or leaf_index < 0:
        raise ProofError("negative tree size or leaf index")
    if leaf_index >= tree_size:
        raise ProofError("leaf index is out of range for the tree size")
    if len(leaf_hash) != HASH_LEN or len(root_hash) != HASH_LEN:
        raise ProofError("hashes must be 32 bytes")
    if any(len(p) != HASH_LEN for p in proof):
        raise ProofError("every proof node must be a 32-byte hash")
    # The shortest path never exceeds ceil(log2(tree_size)); reject anything
    # longer before the running-hash walk rejects the surplus implicitly.
    if len(proof) > max_inclusion_path_len(tree_size):
        raise ProofError("proof carries more nodes than the tree has levels")

    fn = leaf_index
    sn = tree_size - 1
    r = leaf_hash
    for p in proof:
        if sn == 0:
            raise ProofError("proof is too long for the claimed tree size")
        if (fn & 1) == 1 or fn == sn:
            # p is the left sibling.
            r = hash_nodes(p, r)
            if (fn & 1) == 0:
                # fn == sn here; align fn, sn equally until fn is odd or 0.
                while fn != 0 and (fn & 1) == 0:
                    fn >>= 1
                    sn >>= 1
        else:
            # p is the right sibling.
            r = hash_nodes(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ProofError("proof is too short for the claimed tree size")
    if r != root_hash:
        raise ProofError("calculated root does not match the signed root")


# ---------------------------------------------------------- consistency proof
# RFC 9162 §2.1.4.2.


def verify_consistency(
    first: int,
    second: int,
    proof: list[bytes],
    first_hash: bytes,
    second_hash: bytes,
) -> None:
    """Verify that the tree of ``second`` extends the tree of ``first``."""
    if first < 0 or second < 0:
        raise ProofError("negative tree size")
    if first > second:
        raise ProofError("first tree size must not exceed the second")
    if len(first_hash) != HASH_LEN or len(second_hash) != HASH_LEN:
        raise ProofError("hashes must be 32 bytes")
    if any(len(p) != HASH_LEN for p in proof):
        raise ProofError("every proof node must be a 32-byte hash")

    # A prefix of size 0 is trivially consistent; the empty root is fixed.
    if first == 0:
        if proof:
            raise ProofError("consistency proof for an empty prefix must be empty")
        if first_hash != EMPTY_TREE_HASH:
            raise ProofError("root of an empty tree must be the empty-tree hash")
        return

    if first == second:
        if proof:
            raise ProofError("consistency proof for equal sizes must be empty")
        if first_hash != second_hash:
            raise ProofError("equal sizes require equal roots")
        return

    if not proof:
        raise ProofError("consistency proof for two non-empty trees cannot be empty")
    # RFC 9162 §2.1.4.1: the generated proof is bounded by ceil(log2(n)) + 1.
    if len(proof) > max_inclusion_path_len(second) + 1:
        raise ProofError("consistency proof carries more nodes than allowed")

    path = list(proof)
    # RFC 9162: when the old size is an exact power of two, the old root
    # itself is the implicit first proof node.
    if _is_power_of_two(first):
        path = [first_hash] + path

    fn = first - 1
    sn = second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            raise ProofError("proof is too long for the claimed sizes")
        if (fn & 1) == 1 or fn == sn:
            fr = hash_nodes(c, fr)
            sr = hash_nodes(c, sr)
            if (fn & 1) == 0:
                while fn != 0 and (fn & 1) == 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = hash_nodes(sr, c)
        fn >>= 1
        sn >>= 1

    if sn != 0:
        raise ProofError("proof is too short for the claimed sizes")
    if fr != first_hash:
        raise ProofError("proof does not reconstruct the first root")
    if sr != second_hash:
        raise ProofError("proof does not reconstruct the second root")
