"""Tests for the RFC 6962 transparency audit log and its independent verifier."""

from __future__ import annotations

import os
import sqlite3
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app import merkle
from app.audit_key import LOG_KEY_FILE, LogKeyError
from app.audit_store import AuditError, AuditLog, TreeSizeUnavailable
from app.audit_verify import VerificationError, verify_history_consistency
from app.audit_verify import verify_certificate_inclusion
from app.audit_wire import b64u_decode
from tests.conftest import make_csr_pem


# --------------------------------------------------------------- pure merkle


def test_empty_tree_hash_is_hash_of_empty_string():
    import hashlib

    assert merkle.EMPTY_TREE_HASH == hashlib.sha256(b"").digest()


def test_leaf_and_node_prefixes():
    import hashlib

    data = b"der-bytes"
    assert merkle.hash_leaf(data) == hashlib.sha256(b"\x00" + data).digest()
    assert merkle.hash_nodes(b"a" * 32, b"b" * 32) == hashlib.sha256(
        b"\x01" + b"a" * 32 + b"b" * 32
    ).digest()


def test_inclusion_and_consistency_verify_for_many_tree_sizes():
    leaves = [f"cert-{i}".encode() for i in range(130)]
    for n in (list(range(1, 18)) + [31, 32, 33, 63, 64, 65, 127, 130]):
        data = leaves[:n]
        root = merkle.tree_root_from_leaves(data)
        for m in range(n):
            path = _inclusion_path(m, data)
            merkle.verify_inclusion(
                m, n, path, merkle.hash_leaf(data[m]), root
            )
        for f in range(1, n):
            proof = _consistency_proof(f, data)
            merkle.verify_consistency(
                f, n, proof,
                merkle.tree_root_from_leaves(data[:f]),
                root,
            )


def test_inclusion_rejects_out_of_range_and_tampering():
    data = [b"a", b"b", b"c"]
    root = merkle.tree_root_from_leaves(data)
    good = _inclusion_path(0, data)
    with pytest.raises(merkle.ProofError, match="out of range"):
        merkle.verify_inclusion(3, 3, good, merkle.hash_leaf(data[0]), root)
    with pytest.raises(merkle.ProofError, match="out of range"):
        merkle.verify_inclusion(0, 0, [], merkle.hash_leaf(data[0]), root)
    # Tampered leaf.
    with pytest.raises(merkle.ProofError, match="root"):
        merkle.verify_inclusion(0, 3, good, merkle.hash_leaf(b"x"), root)
    # Tampered proof node.
    bad = [good[0][:31] + bytes([good[0][31] ^ 1])] + good[1:]
    with pytest.raises(merkle.ProofError):
        merkle.verify_inclusion(0, 3, bad, merkle.hash_leaf(data[0]), root)
    # Extra node is rejected.
    with pytest.raises(merkle.ProofError):
        merkle.verify_inclusion(
            0, 3, good + [b"\x00" * 32], merkle.hash_leaf(data[0]), root
        )


def test_consistency_rejects_tampering_and_bad_sizes():
    data = [f"c{i}".encode() for i in range(10)]
    first_root = merkle.tree_root_from_leaves(data[:4])
    second_root = merkle.tree_root_from_leaves(data)
    proof = _consistency_proof(4, data)
    merkle.verify_consistency(4, 10, proof, first_root, second_root)

    with pytest.raises(merkle.ProofError):
        merkle.verify_consistency(
            4, 10, [p[::-1] for p in proof], first_root, second_root
        )
    with pytest.raises(merkle.ProofError, match="must not exceed"):
        merkle.verify_consistency(10, 4, proof, first_root, second_root)
    with pytest.raises(merkle.ProofError, match="empty"):
        merkle.verify_consistency(4, 10, [], first_root, second_root)
    # Equal sizes: empty proof, roots must agree.
    merkle.verify_consistency(4, 4, [], first_root, first_root)
    with pytest.raises(merkle.ProofError):
        merkle.verify_consistency(4, 4, [], first_root, second_root)
    # Empty prefix.
    merkle.verify_consistency(
        0, 4, [], merkle.EMPTY_TREE_HASH, second_root
    )
    with pytest.raises(merkle.ProofError):
        merkle.verify_consistency(0, 4, [b"x" * 32], merkle.EMPTY_TREE_HASH, second_root)


# RFC 9162 pseudocode reference (independent re-implementation for tests).
def _inclusion_path(m, data):
    n = len(data)
    if n == 1:
        return []
    k = 1 << (n.bit_length() - 1)
    if k == n:
        k >>= 1
    if m < k:
        return _inclusion_path(m, data[:k]) + [merkle.tree_root_from_leaves(data[k:])]
    return _inclusion_path(m - k, data[k:]) + [
        merkle.tree_root_from_leaves(data[:k])
    ]


def _consistency_subproof(m, data, b):
    n = len(data)
    if m == n:
        return [] if b else [merkle.tree_root_from_leaves(data)]
    k = 1 << (n.bit_length() - 1)
    if k == n:
        k >>= 1
    if m <= k:
        return _consistency_subproof(m, data[:k], b) + [
            merkle.tree_root_from_leaves(data[k:])
        ]
    return _consistency_subproof(m - k, data[k:], False) + [
        merkle.tree_root_from_leaves(data[:k])
    ]


def _consistency_proof(m, data):
    return _consistency_subproof(m, data, True)


# --------------------------------------------------------------- integration


def _issue(client, domain="a.lab.test", key=None):
    return client.post(
        "/certificates",
        json={
            "csr": make_csr_pem(dns_names=[domain]).decode(),
            "days": 7,
            "idempotency_key": key or f"key-{domain}",
        },
    )


def _head_json(raw: dict) -> dict:
    return {
        "log_id": b64u_decode(raw["log_id"]),
        "tree_size": raw["tree_size"],
        "root_hash": b64u_decode(raw["sha256_root_hash"]),
        "signature": b64u_decode(raw["signature"]),
    }


def test_bootstrap_empty_log_has_signed_empty_head(env):
    assert env.audit.current_size() == 0
    resp = env.client.get("/audit/v1/head")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tree_size"] == 0
    assert b64u_decode(body["sha256_root_hash"]) == merkle.EMPTY_TREE_HASH
    assert body["signature_type"] == "ed25519"
    key = b64u_decode(env.client.get("/audit/v1/key").json()["public_key"])
    verify_certificate_inclusion  # import sanity
    # The empty head verifies against the pinned key.
    from app.audit_verify import verify_tree_head

    verify_tree_head(key, **_head_json(body))


def test_issuance_appends_contiguous_leaves_and_moves_root(env):
    serials = []
    for i in range(5):
        resp = _issue(env.client, f"leaf{i}.lab.test", f"k{i}")
        assert resp.status_code == 200
        serials.append(resp.json()["serial"])
    assert env.audit.current_size() == 5

    rows = env.audit._connect().execute(
        "SELECT leaf_index, cert_serial_hex FROM audit_leaves ORDER BY leaf_index"
    ).fetchall()
    assert [r["leaf_index"] for r in rows] == [0, 1, 2, 3, 4]
    assert [r["cert_serial_hex"] for r in rows] == serials

    # Every historical size has a stored head and a valid root.
    for size in range(6):
        wanted, root, _sig, _ts = env.audit.get_sth(size)
        assert wanted == size


def test_idempotent_replay_adds_no_leaf(env):
    csr = make_csr_pem(dns_names=["idem.lab.test"]).decode()
    payload = {"csr": csr, "days": 7, "idempotency_key": "same"}
    assert env.client.post("/certificates", json=payload).status_code == 200
    assert env.client.post("/certificates", json=payload).json()["replayed"] is True
    assert env.audit.current_size() == 1


def test_revocation_keeps_log_history(env):
    serial = _issue(env.client, "rev.lab.test", "r").json()["serial"]
    before = env.client.get("/audit/v1/head").json()["sha256_root_hash"]
    env.client.post(
        f"/certificates/{serial}/revoke", json={"reason": "key_compromise"}
    )
    after = env.client.get("/audit/v1/head").json()
    # Size and root are unchanged; the leaf is still served.
    assert after["tree_size"] == 1
    assert after["sha256_root_hash"] == before
    inc = env.client.get("/audit/v1/inclusion/0").json()
    assert inc["leaf_index"] == 0


def test_concurrent_issuance_contiguous_indices_no_gaps_or_dupes(env):
    n = 12
    barrier = threading.Barrier(n)
    indices: list = []
    errors: list = []

    def worker(i):
        barrier.wait()
        try:
            resp = _issue(env.client, f"c{i}.lab.test", f"race-{i}")
            assert resp.status_code == 200
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
        indices.append(i)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    conn = sqlite3.connect(env.store._db_path)
    try:
        rows = conn.execute(
            "SELECT leaf_index, COUNT(*) c FROM audit_leaves "
            "GROUP BY leaf_index ORDER BY leaf_index"
        ).fetchall()
        serials = conn.execute(
            "SELECT serial_hex, COUNT(*) c FROM certificates GROUP BY serial_hex"
        ).fetchall()
    finally:
        conn.close()
    assert [r[0] for r in rows] == list(range(n))
    assert all(r[1] == 1 for r in rows)
    assert all(r[1] == 1 for r in serials)
    assert env.audit.current_size() == n


# ---------------------------------------------------------- HTTP + verifier


def _pinned_key(env) -> bytes:
    return b64u_decode(env.client.get("/audit/v1/key").json()["public_key"])


def test_inclusion_endpoint_verifies_independently_over_http(env):
    pinned = _pinned_key(env)
    issued = []
    for i in range(7):
        issued.append(_issue(env.client, f"v{i}.lab.test", f"v{i}").json())

    for idx in range(7):
        body = env.client.get(f"/audit/v1/inclusion/{idx}").json()
        cert_der = b64u_decode(body["cert_der"])
        # The served DER is exactly the issued certificate DER.
        cert = x509.load_pem_x509_certificate(issued[idx]["certificate"].encode())
        assert cert_der == cert.public_bytes(serialization.Encoding.DER)
        head = _head_json(body["tree_head"])
        path = [b64u_decode(p) for p in body["proof"]]
        # Only the pre-provisioned pinned key is trusted.
        verify_certificate_inclusion(
            pinned, cert_der, head, path, leaf_index=body["leaf_index"]
        )


def test_historical_head_and_consistency_endpoint(env):
    pinned = _pinned_key(env)
    for i in range(6):
        _issue(env.client, f"h{i}.lab.test", f"h{i}")
    # Historical tree head for size 3.
    old = env.client.get("/audit/v1/head", params={"tree_size": 3}).json()
    assert old["tree_size"] == 3
    cur = env.client.get("/audit/v1/head").json()

    body = env.client.get(
        "/audit/v1/consistency", params={"first": 3, "second": 6}
    ).json()
    assert body["first_size"] == 3 and body["second_size"] == 6
    verify_history_consistency(
        pinned,
        _head_json(body["first_tree_head"]),
        _head_json(body["second_tree_head"]),
        [b64u_decode(p) for p in body["proof"]],
    )
    # Consistency from the empty prefix and for equal sizes is also offered.
    zero = env.client.get(
        "/audit/v1/consistency", params={"first": 0, "second": 6}
    ).json()
    assert zero["proof"] == []
    verify_history_consistency(
        pinned,
        _head_json(zero["first_tree_head"]),
        _head_json(zero["second_tree_head"]),
        [],
    )
    same = env.client.get(
        "/audit/v1/consistency", params={"first": 6, "second": 6}
    ).json()
    assert same["proof"] == []


def test_response_supplied_key_cannot_impersonate_log(env):
    # Pin the real key, then pretend a different key arrived in a response:
    # the log_id in the head is bound to the pinned key, so it must fail.
    pinned = _pinned_key(env)
    _issue(env.client, "x.lab.test", "x")
    body = env.client.get("/audit/v1/inclusion/0").json()
    head = _head_json(body["tree_head"])
    attacker = ed25519.Ed25519PrivateKey.generate().public_key()
    attacker_raw = attacker.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # Verifier handed the attacker key rejects the genuine head (id mismatch).
    with pytest.raises(VerificationError, match="log id"):
        verify_certificate_inclusion(
            attacker_raw,
            b64u_decode(body["cert_der"]),
            head,
            [b64u_decode(p) for p in body["proof"]],
            leaf_index=0,
        )
    # Conversely the pinned key rejects a head re-signed by the attacker.
    forged_sig = ed25519.Ed25519PrivateKey.generate().sign(
        b"".join([head["log_id"], head["root_hash"]])
    )
    with pytest.raises(VerificationError, match="signature"):
        verify_certificate_inclusion(
            pinned,
            b64u_decode(body["cert_der"]),
            {**head, "signature": forged_sig},
            [b64u_decode(p) for p in body["proof"]],
            leaf_index=0,
        )


def test_tampered_proof_and_illegal_sizes_rejected(env):
    pinned = _pinned_key(env)
    for i in range(5):
        _issue(env.client, f"t{i}.lab.test", f"t{i}")
    body = env.client.get("/audit/v1/inclusion/0").json()
    head = _head_json(body["tree_head"])
    path = [b64u_decode(p) for p in body["proof"]]
    der = b64u_decode(body["cert_der"])

    flipped = [path[0][:-1] + bytes([path[0][-1] ^ 0xFF])] + path[1:]
    with pytest.raises(VerificationError):
        verify_certificate_inclusion(pinned, der, head, flipped, leaf_index=0)
    with pytest.raises(VerificationError):
        verify_certificate_inclusion(
            pinned, der, head, path + [b"\x00" * 32], leaf_index=0
        )
    with pytest.raises(VerificationError):
        verify_certificate_inclusion(pinned, der, head, path, leaf_index=1)

    # Tampered size while keeping signature invalidates the signature.
    bad_size = {**head, "tree_size": 4}
    with pytest.raises(VerificationError, match="signature"):
        verify_certificate_inclusion(pinned, der, bad_size, path, leaf_index=0)


def test_out_of_range_requests_are_explicitly_rejected(env):
    for i in range(3):
        _issue(env.client, f"o{i}.lab.test", f"o{i}")
    assert env.client.get("/audit/v1/head", params={"tree_size": 99}).status_code == 404
    assert env.client.get("/audit/v1/inclusion/3").status_code == 404
    assert env.client.get("/audit/v1/inclusion/0", params={"tree_size": 99}).status_code == 404
    bad_order = env.client.get(
        "/audit/v1/consistency", params={"first": 3, "second": 1}
    )
    assert bad_order.status_code == 400
    future = env.client.get(
        "/audit/v1/consistency", params={"first": 1, "second": 99}
    )
    assert future.status_code == 404
    negative = env.client.get("/audit/v1/inclusion/-1")
    assert negative.status_code in (400, 404, 422)


# --------------------------------------------------------------- migration


def test_legacy_certificates_migrated_in_numeric_serial_order(tmp_path):
    from app.ca import load_or_create_ca
    from app.service import CAService
    from app.storage import CAStore

    data_dir = str(tmp_path / "data")
    ca = load_or_create_ca(data_dir)
    store = CAStore(data_dir)  # audit intentionally not wired
    service = CAService(ca, store)
    for i in range(6):
        service.issue(
            make_csr_pem(dns_names=[f"old{i}.lab.test"]),
            days=3,
            idempotency_key=f"old-{i}",
        )

    audit = AuditLog(data_dir)
    audit.bootstrap()  # one-time legacy backfill
    assert audit.current_size() == 6

    conn = sqlite3.connect(os.path.join(data_dir, "ca.sqlite3"))
    try:
        rows = conn.execute(
            "SELECT leaf_index, cert_serial_hex FROM audit_leaves ORDER BY leaf_index"
        ).fetchall()
    finally:
        conn.close()
    serials = [int(r[1], 16) for r in rows]
    assert serials == sorted(serials)
    assert len(serials) == 6
    # Every migrated leaf verifies independently.
    for idx, _row in enumerate(rows):
        cert_der, leaf_hash = audit.get_leaf(idx, 6)
        path, _lh, root = audit.inclusion_proof(idx, 6)
        merkle.verify_inclusion(idx, 6, path, leaf_hash, root)
        assert merkle.hash_leaf(cert_der) == leaf_hash


def test_failed_migration_rolls_back_the_whole_batch(tmp_path):
    from app.ca import load_or_create_ca
    from app.storage import CAStore

    data_dir = str(tmp_path / "data")
    ca = load_or_create_ca(data_dir)
    store = CAStore(data_dir)
    service_store = CAStore(data_dir)
    # One good certificate.
    from app.service import CAService

    CAService(ca, service_store).issue(
        make_csr_pem(dns_names=["good.lab.test"]), days=2, idempotency_key="g"
    )
    # Corrupt one row so leaf construction must fail mid-migration.
    conn = sqlite3.connect(store._db_path)
    try:
        conn.execute(
            "INSERT INTO certificates(serial_hex,csr_der,days,cert_pem,san,"
            "not_before,not_after) VALUES(?,?,?,?,?,?,?)",
            ("deadbeef", b"", 1, "not-a-pem", "bad.lab.test", "a", "b"),
        )
        conn.commit()
    finally:
        conn.close()

    audit = AuditLog(data_dir)
    with pytest.raises(Exception):
        audit.bootstrap()

    conn = sqlite3.connect(store._db_path)
    try:
        leaves = conn.execute("SELECT COUNT(*) FROM audit_leaves").fetchone()[0]
        has_identity = conn.execute(
            "SELECT COUNT(*) FROM audit_meta WHERE key = 'log_id'"
        ).fetchone()[0]
        certs = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
    finally:
        conn.close()
    assert leaves == 0 and has_identity == 0
    assert certs == 2  # original certificate rows untouched

    # Once the bad row is removed, the batch migration succeeds.
    conn = sqlite3.connect(store._db_path)
    conn.execute("DELETE FROM certificates WHERE serial_hex = 'deadbeef'")
    conn.commit()
    conn.close()
    AuditLog(data_dir).bootstrap()
    assert AuditLog(data_dir).current_size() == 1


# --------------------------------------------------------------- restart/key


def test_restart_preserves_indices_roots_and_identity(tmp_path):
    from app.ca import load_or_create_ca
    from app.service import CAService
    from app.storage import CAStore

    data_dir = str(tmp_path / "data")
    ca = load_or_create_ca(data_dir)
    store = CAStore(data_dir)
    audit = AuditLog(data_dir)
    audit.bootstrap()
    store.audit = audit
    CAService(ca, store).issue(
        make_csr_pem(dns_names=["keep.lab.test"]), days=4, idempotency_key="k"
    )
    identity = audit.log_id
    size = audit.current_size()
    _, root_at_1, _, _ = audit.get_sth(1)

    # Restart: new objects, same files. Identity/indices/roots only verified.
    ca2 = load_or_create_ca(data_dir)
    store2 = CAStore(data_dir)
    audit2 = AuditLog(data_dir)
    audit2.bootstrap()
    assert audit2.log_id == identity
    assert audit2.current_size() == size
    _, root2, _, _ = audit2.get_sth(1)
    assert root2 == root_at_1
    store2.audit = audit2
    # Issuance continues at the next index.
    CAService(ca2, store2).issue(
        make_csr_pem(dns_names=["keep2.lab.test"]), days=4, idempotency_key="k2"
    )
    assert audit2.current_size() == 2


def test_missing_log_key_with_existing_log_refuses_startup(tmp_path):
    data_dir = str(tmp_path / "data")
    from app.ca import load_or_create_ca
    from app.storage import CAStore

    load_or_create_ca(data_dir)
    CAStore(data_dir)  # ensures the certificates table exists
    audit = AuditLog(data_dir)
    audit.bootstrap()
    os.unlink(os.path.join(data_dir, LOG_KEY_FILE))
    with pytest.raises(LogKeyError, match="missing"):
        AuditLog(data_dir).bootstrap()


def test_mismatched_log_key_refuses_startup(tmp_path):
    data_dir = str(tmp_path / "data")
    from app.ca import load_or_create_ca
    from app.storage import CAStore

    load_or_create_ca(data_dir)
    CAStore(data_dir)
    audit = AuditLog(data_dir)
    audit.bootstrap()
    other = ed25519.Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(os.path.join(data_dir, LOG_KEY_FILE), "wb") as handle:
        handle.write(other)
    with pytest.raises(LogKeyError, match="identity"):
        AuditLog(data_dir).bootstrap()
