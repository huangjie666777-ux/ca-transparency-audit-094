"""Tests for transparency log persistence through issuance."""

from __future__ import annotations

import sqlite3
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app import merkle
from app.log_store import LogStore
from tests.conftest import make_csr_pem


def _issue(client, csr_pem, days=7, key="key-1"):
    return client.post(
        "/certificates",
        json={"csr": csr_pem.decode(), "days": days, "idempotency_key": key},
    )


def _log_conn(env):
    conn = sqlite3.connect(env.log_store._db_path)
    conn.row_factory = sqlite3.Row
    return conn


def test_empty_log_genesis(env):
    assert env.log_store.latest_size() == 0
    head = env.log_store.head()
    assert head.tree_size == 0
    assert head.root == merkle.empty_tree_hash()
    assert env.log_store.leaf_count() == 0


def test_issuance_appends_contiguous_leaves(env):
    serials = []
    for i in range(5):
        resp = _issue(env.client, make_csr_pem(dns_names=[f"l{i}.lab.test"]), key=f"l{i}")
        assert resp.status_code == 200
        serials.append(resp.json()["serial"])

    assert env.log_store.latest_size() == 5
    assert env.log_store.leaf_count() == 5
    with _log_conn(env) as conn:
        rows = conn.execute(
            "SELECT leaf_index, serial_hex FROM log_leaves ORDER BY leaf_index"
        ).fetchall()
    assert [row["leaf_index"] for row in rows] == [0, 1, 2, 3, 4]
    assert [row["serial_hex"] for row in rows] == serials


def test_leaf_hash_is_sha256_of_full_der(env):
    resp = _issue(env.client, make_csr_pem(dns_names=["der.lab.test"]), key="der")
    cert_pem = resp.json()["certificate"]
    cert_der = x509.load_pem_x509_certificate(cert_pem.encode()).public_bytes(
        serialization.Encoding.DER
    )
    with _log_conn(env) as conn:
        row = conn.execute(
            "SELECT cert_der, leaf_hash FROM log_leaves WHERE leaf_index = 0"
        ).fetchone()
    assert bytes(row["cert_der"]) == cert_der
    assert bytes(row["leaf_hash"]) == merkle.leaf_hash(cert_der)


def test_root_recomputes_from_stored_nodes(env):
    for i in range(6):
        _issue(env.client, make_csr_pem(dns_names=[f"r{i}.lab.test"]), key=f"r{i}")
    head = env.log_store.head()
    assert head.tree_size == 6
    # Independently recompute the root from the stored leaf hashes.
    with _log_conn(env) as conn:
        rows = conn.execute(
            "SELECT leaf_hash FROM log_leaves ORDER BY leaf_index"
        ).fetchall()
    leaves = [bytes(row["leaf_hash"]) for row in rows]
    root = _reference_mth(leaves)
    assert head.root == root


def _reference_mth(leaves: list[bytes]) -> bytes:
    if not leaves:
        return merkle.empty_tree_hash()
    if len(leaves) == 1:
        return leaves[0]
    k = merkle.largest_power_of_two_less_than(len(leaves))
    return merkle.node_hash(_reference_mth(leaves[:k]), _reference_mth(leaves[k:]))


def test_idempotent_replay_adds_no_leaf(env):
    csr_pem = make_csr_pem(dns_names=["idem.lab.test"])
    first = _issue(env.client, csr_pem, key="idem-log")
    assert first.status_code == 200
    size_after_first = env.log_store.latest_size()

    second = _issue(env.client, csr_pem, key="idem-log")
    assert second.status_code == 200
    assert second.json()["replayed"] is True
    assert env.log_store.latest_size() == size_after_first


def test_revocation_keeps_history(env):
    resp = _issue(env.client, make_csr_pem(dns_names=["rev.lab.test"]), key="rev")
    serial = resp.json()["serial"]
    size_before = env.log_store.latest_size()
    env.client.post(
        f"/certificates/{serial}/revoke", json={"reason": "key_compromise"}
    )
    # Revocation does not remove or alter leaves.
    assert env.log_store.latest_size() == size_before
    assert env.log_store.leaf_count() == size_before
    with _log_conn(env) as conn:
        row = conn.execute(
            "SELECT serial_hex FROM log_leaves WHERE serial_hex = ?", (serial,)
        ).fetchone()
    assert row is not None


def test_concurrent_issuance_no_duplicate_or_skip(env):
    csr_pem = make_csr_pem(dns_names=["race-log.lab.test"])
    results: list = []
    errors: list = []

    def worker():
        try:
            resp = _issue(env.client, csr_pem, key=f"race-{threading.get_ident()}")
            results.append(resp.json()["serial"])
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(results) == 8
    # Each distinct idempotency key issues a distinct cert, so 8 leaves.
    assert env.log_store.latest_size() == 8
    with _log_conn(env) as conn:
        rows = conn.execute(
            "SELECT leaf_index FROM log_leaves ORDER BY leaf_index"
        ).fetchall()
    assert [row["leaf_index"] for row in rows] == list(range(8))


def test_acme_issuance_appends_leaf(env, challenge_server):
    from tests.acme_helpers import AcmeAccount, AcmeClient

    client = AcmeClient(http=env.client, account=AcmeAccount.create())
    client.new_account()
    order_path, authz_path, finalize_path = _order_objects(client)
    _solve(client, env, authz_path, challenge_server)
    der = _csr_der("acme-log.lab.test")
    resp = client.finalize(finalize_path, der)
    assert resp.status_code == 200
    assert env.log_store.latest_size() == 1
    with _log_conn(env) as conn:
        row = conn.execute(
            "SELECT serial_hex FROM log_leaves WHERE leaf_index = 0"
        ).fetchone()
    assert row is not None


def _order_objects(client):
    resp = client.new_order("acme-log.lab.test")
    order = resp.json()
    base = "http://testserver"
    order_path = "/" + resp.headers["Location"].split("/", 3)[3]
    authz_path = "/" + order["authorizations"][0].split("/", 3)[3]
    finalize_path = "/" + order["finalize"].split("/", 3)[3]
    return order_path, authz_path, finalize_path


def _solve(client, env, authz_path, challenge_server):
    authz = client.fetch_authz(authz_path).json()
    challenge = authz["challenges"][0]
    challenge_path = "/" + challenge["url"].split("/", 3)[3]
    challenge_server.payload = (
        challenge["token"] + "." + client.account.thumbprint
    ).encode()
    resp = client.solve_challenge(challenge_path)
    assert resp.status_code == 200


def _csr_der(domain):
    from tests.conftest import make_key

    pem = make_csr_pem(make_key(), dns_names=[domain])
    return x509.load_pem_x509_csr(pem).public_bytes(serialization.Encoding.DER)
