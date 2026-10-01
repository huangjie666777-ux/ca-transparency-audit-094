"""Tests for the transparency log HTTP endpoints."""

from __future__ import annotations

import base64

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app import merkle
from app.verify import (
    VerificationError,
    verify_consistency,
    verify_inclusion,
    verify_tree_head,
)
from tests.conftest import make_csr_pem


def _issue(client, csr_pem, days=7, key="key-1"):
    return client.post(
        "/certificates",
        json={"csr": csr_pem.decode(), "days": days, "idempotency_key": key},
    )


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_public_key_endpoint(env):
    resp = env.client.get("/log/public-key")
    assert resp.status_code == 200
    body = resp.json()
    assert body["encoding"] == "ed25519-raw-base64url"
    raw = _b64url_decode(body["public_key"])
    assert len(raw) == 32
    assert body["log_id"] == env.audit.log_id().hex()
    # The PEM is also available.
    assert "BEGIN PUBLIC KEY" in body["public_key_pem"]


def test_latest_head_endpoint(env):
    resp = env.client.get("/log/head")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tree_size"] == 0
    assert body["root_hash"] == merkle.empty_tree_hash().hex()
    # The signature verifies against the server's own public key only if
    # the caller trusts it; here we just check the fields are well-formed.
    signed_data = base64.b64decode(body["signed_data"])
    signature = base64.b64decode(body["signature"])
    assert len(signature) == 64
    assert len(signed_data) == len(b"ltca-transparency-log-head\x00") + 16 + 8 + 32


def test_historical_head_endpoint(env):
    for i in range(3):
        _issue(env.client, make_csr_pem(dns_names=[f"h{i}.lab.test"]), key=f"h{i}")
    resp = env.client.get("/log/head/1")
    assert resp.status_code == 200
    assert resp.json()["tree_size"] == 1
    resp = env.client.get("/log/head/2")
    assert resp.status_code == 200
    assert resp.json()["tree_size"] == 2
    # Out-of-range historical head.
    resp = env.client.get("/log/head/99")
    assert resp.status_code == 404


def test_inclusion_proof_endpoint(env):
    for i in range(4):
        _issue(env.client, make_csr_pem(dns_names=[f"p{i}.lab.test"]), key=f"p{i}")
    resp = env.client.get("/log/proof/inclusion/2")
    assert resp.status_code == 200
    body = resp.json()
    assert body["leaf_index"] == 2
    assert body["tree_size"] == 4
    proof = [bytes.fromhex(node) for node in body["proof"]]
    leaf_hash = bytes.fromhex(body["leaf_hash"])
    root = bytes.fromhex(body["root_hash"])
    verify_inclusion(leaf_hash, 2, 4, proof, root)


def test_inclusion_proof_with_explicit_size(env):
    for i in range(5):
        _issue(env.client, make_csr_pem(dns_names=[f"s{i}.lab.test"]), key=f"s{i}")
    resp = env.client.get("/log/proof/inclusion/1?size=3")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tree_size"] == 3
    proof = [bytes.fromhex(node) for node in body["proof"]]
    verify_inclusion(
        bytes.fromhex(body["leaf_hash"]), 1, 3, proof,
        bytes.fromhex(body["root_hash"]),
    )


def test_inclusion_proof_out_of_range(env):
    for i in range(2):
        _issue(env.client, make_csr_pem(dns_names=[f"o{i}.lab.test"]), key=f"o{i}")
    resp = env.client.get("/log/proof/inclusion/5")
    assert resp.status_code == 400
    resp = env.client.get("/log/proof/inclusion/-1")
    assert resp.status_code == 400


def test_consistency_proof_endpoint(env):
    for i in range(6):
        _issue(env.client, make_csr_pem(dns_names=[f"c{i}.lab.test"]), key=f"c{i}")
    resp = env.client.get("/log/proof/consistency?old=2&new=6")
    assert resp.status_code == 200
    body = resp.json()
    assert body["old_size"] == 2
    assert body["new_size"] == 6
    proof = [bytes.fromhex(node) for node in body["proof"]]
    verify_consistency(
        2, 6,
        bytes.fromhex(body["old_root"]),
        bytes.fromhex(body["new_root"]),
        proof,
    )


def test_consistency_proof_old_larger_than_new(env):
    for i in range(3):
        _issue(env.client, make_csr_pem(dns_names=[f"e{i}.lab.test"]), key=f"e{i}")
    resp = env.client.get("/log/proof/consistency?old=5&new=3")
    assert resp.status_code == 400


def test_proof_uses_consistent_snapshot(env):
    """A proof must read root and nodes from the same snapshot."""
    for i in range(4):
        _issue(env.client, make_csr_pem(dns_names=[f"sn{i}.lab.test"]), key=f"sn{i}")
    # Request a proof for a historical size; the root and proof must match.
    resp = env.client.get("/log/proof/inclusion/0?size=2")
    body = resp.json()
    assert body["tree_size"] == 2
    # The root must equal the historical head at size 2.
    head_resp = env.client.get("/log/head/2")
    assert body["root_hash"] == head_resp.json()["root_hash"]


def test_signed_head_verifies_with_trusted_key(env):
    for i in range(2):
        _issue(env.client, make_csr_pem(dns_names=[f"v{i}.lab.test"]), key=f"v{i}")
    # Trust the public key obtained out of band (here from the fixture).
    trusted_key = env.audit.public_key_bytes()
    resp = env.client.get("/log/head")
    body = resp.json()
    signed_data = base64.b64decode(body["signed_data"])
    signature = base64.b64decode(body["signature"])
    head = verify_tree_head(
        trusted_key, signed_data, signature,
        expected_log_id=bytes.fromhex(body["log_id"]),
    )
    assert head.tree_size == 2
    assert head.root == bytes.fromhex(body["root_hash"])


def test_signed_head_rejects_untrusted_key(env):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    other_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    resp = env.client.get("/log/head")
    body = resp.json()
    signed_data = base64.b64decode(body["signed_data"])
    signature = base64.b64decode(body["signature"])
    with pytest.raises(VerificationError):
        verify_tree_head(other_key, signed_data, signature)


def test_nonexistent_log_head_404(env):
    # The fixture initializes the log, so test a size beyond the latest.
    resp = env.client.get("/log/head/0")
    assert resp.status_code == 200  # size 0 head exists
    resp = env.client.get("/log/head/1000")
    assert resp.status_code == 404
