"""Tests for RFC 6962 Merkle primitives and proof verification."""

from __future__ import annotations

import hashlib

import pytest

from app import merkle
from app.verify import (
    VerificationError,
    cert_leaf_hash,
    verify_consistency,
    verify_inclusion,
)


def test_empty_tree_hash():
    # RFC 6962 section 2.1: MTH({}) = SHA256("").
    assert merkle.empty_tree_hash() == hashlib.sha256(b"").digest()


def test_leaf_hash_uses_zero_prefix():
    data = b"certificate der"
    assert merkle.leaf_hash(data) == hashlib.sha256(b"\x00" + data).digest()


def test_node_hash_uses_one_prefix():
    left = b"l" * 32
    right = b"r" * 32
    assert merkle.node_hash(left, right) == hashlib.sha256(
        b"\x01" + left + right
    ).digest()


def test_largest_power_of_two_less_than():
    assert merkle.largest_power_of_two_less_than(2) == 1
    assert merkle.largest_power_of_two_less_than(3) == 2
    assert merkle.largest_power_of_two_less_than(4) == 2
    assert merkle.largest_power_of_two_less_than(5) == 4
    assert merkle.largest_power_of_two_less_than(7) == 4
    assert merkle.largest_power_of_two_less_than(8) == 4
    assert merkle.largest_power_of_two_less_than(9) == 8


# --------------------------------------------------------------------- fuzz


def _build_tree(n: int) -> list[bytes]:
    """Build leaf hashes for n leaves."""
    return [merkle.leaf_hash(f"leaf-{i}".encode()) for i in range(n)]


def _mth(leaves: list[bytes]) -> bytes:
    """Reference MTH computation for testing (recomputes from leaves)."""
    if not leaves:
        return merkle.empty_tree_hash()
    if len(leaves) == 1:
        return leaves[0]
    k = merkle.largest_power_of_two_less_than(len(leaves))
    return merkle.node_hash(_mth(leaves[:k]), _mth(leaves[k:]))


def _inclusion_path(leaves: list[bytes], m: int) -> list[bytes]:
    """Reference inclusion proof generation."""
    n = len(leaves)
    if n == 1:
        return []
    k = merkle.largest_power_of_two_less_than(n)
    if m < k:
        return _inclusion_path(leaves[:k], m) + [_mth(leaves[k:])]
    return _inclusion_path(leaves[k:], m - k) + [_mth(leaves[:k])]


def _subproof(leaves: list[bytes], m: int, b: bool) -> list[bytes]:
    """RFC 6962 SUBPROOF(m, D[n], b)."""
    n = len(leaves)
    if m == n:
        return [] if b else [_mth(leaves)]
    k = merkle.largest_power_of_two_less_than(n)
    if m <= k:
        return _subproof(leaves[:k], m, b) + [_mth(leaves[k:])]
    return _subproof(leaves[k:], m - k, False) + [_mth(leaves[:k])]


def _consistency_path(leaves: list[bytes], m: int) -> list[bytes]:
    """Reference consistency proof generation."""
    return _subproof(leaves, m, True)


@pytest.mark.parametrize("n", range(1, 41))
def test_inclusion_proof_fuzz(n):
    leaves = _build_tree(n)
    root = _mth(leaves)
    for m in range(n):
        proof = _inclusion_path(leaves, m)
        assert merkle.verify_inclusion(m, n, leaves[m], proof, root)
        # The independent verifier agrees.
        verify_inclusion(leaves[m], m, n, proof, root)


@pytest.mark.parametrize("n", range(2, 41))
def test_consistency_proof_fuzz(n):
    leaves = _build_tree(n)
    new_root = _mth(leaves)
    for m in range(1, n):
        old_root = _mth(leaves[:m])
        proof = _consistency_path(leaves, m)
        assert merkle.verify_consistency(m, n, old_root, new_root, proof)
        verify_consistency(m, n, old_root, new_root, proof)


def test_consistency_empty_and_equal():
    root = _mth(_build_tree(3))
    assert merkle.verify_consistency(0, 3, merkle.empty_tree_hash(), root, [])
    assert merkle.verify_consistency(3, 3, root, root, [])
    # Non-empty proof for equal sizes is rejected.
    assert not merkle.verify_consistency(3, 3, root, root, [b"x" * 32])
    # Empty old size with a proof is rejected.
    assert not merkle.verify_consistency(0, 3, merkle.empty_tree_hash(), root, [b"x" * 32])


def test_inclusion_rejects_illegal_sizes():
    leaves = _build_tree(3)
    root = _mth(leaves)
    proof = _inclusion_path(leaves, 0)
    assert not merkle.verify_inclusion(3, 3, leaves[0], proof, root)  # index == size
    assert not merkle.verify_inclusion(-1, 3, leaves[0], proof, root)
    assert not merkle.verify_inclusion(0, 0, leaves[0], proof, root)  # empty tree


def test_inclusion_rejects_tampered_leaf():
    leaves = _build_tree(3)
    root = _mth(leaves)
    proof = _inclusion_path(leaves, 0)
    tampered = merkle.leaf_hash(b"tampered")
    assert not merkle.verify_inclusion(0, 3, tampered, proof, root)
    with pytest.raises(VerificationError):
        verify_inclusion(tampered, 0, 3, proof, root)


def test_inclusion_rejects_tampered_proof():
    leaves = _build_tree(5)
    root = _mth(leaves)
    proof = _inclusion_path(leaves, 2)
    tampered = [proof[0] ^ b"\x01" if False else bytes([proof[0][0] ^ 1]) + proof[0][1:]] + proof[1:]
    assert not merkle.verify_inclusion(2, 5, leaves[2], tampered, root)


def test_inclusion_rejects_extra_nodes():
    leaves = _build_tree(4)
    root = _mth(leaves)
    proof = _inclusion_path(leaves, 1)
    extra = proof + [b"e" * 32]
    assert not merkle.verify_inclusion(1, 4, leaves[1], extra, root)


def test_consistency_rejects_tampered_root():
    leaves = _build_tree(6)
    new_root = _mth(leaves)
    old_root = _mth(leaves[:3])
    proof = _consistency_path(leaves, 3)
    tampered_old = bytes([old_root[0] ^ 1]) + old_root[1:]
    assert not merkle.verify_consistency(3, 6, tampered_old, new_root, proof)
    tampered_new = bytes([new_root[0] ^ 1]) + new_root[1:]
    assert not merkle.verify_consistency(3, 6, old_root, tampered_new, proof)


def test_consistency_rejects_extra_nodes():
    leaves = _build_tree(6)
    new_root = _mth(leaves)
    old_root = _mth(leaves[:3])
    proof = _consistency_path(leaves, 3)
    extra = proof + [b"e" * 32]
    assert not merkle.verify_consistency(3, 6, old_root, new_root, extra)


def test_consistency_rejects_old_larger_than_new():
    root = _mth(_build_tree(3))
    assert not merkle.verify_consistency(5, 3, root, root, [])


def test_cert_leaf_hash():
    der = b"test der bytes"
    assert cert_leaf_hash(der) == merkle.leaf_hash(der)
