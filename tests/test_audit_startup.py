"""Tests for log migration, restart persistence and startup refusal."""

from __future__ import annotations

import os
import sqlite3

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app import merkle
from app.audit import AuditService
from app.ca import load_or_create_ca
from app.log_signing import (
    LOG_KEY_FILE,
    LogKeyError,
    load_or_create_log_key,
)
from app.log_store import LogStore
from app.service import CAService
from app.storage import CAStore
from tests.conftest import make_csr_pem, make_key


def _make_legacy_db(data_dir, n=3):
    """Create a database with legacy certificates but no log."""
    ca = load_or_create_ca(data_dir)
    store = CAStore(data_dir)
    service = CAService(ca, store)
    serials = []
    for i in range(n):
        record, _ = service.issue(
            make_csr_pem(dns_names=[f"legacy{i}.lab.test"]),
            days=7,
            idempotency_key=f"legacy-{i}",
        )
        serials.append(int(record.serial_hex, 16))
    return ca, store, sorted(serials)


def test_migration_orders_by_serial_numeric(tmp_path):
    data_dir = str(tmp_path / "data")
    ca, store, expected_serials = _make_legacy_db(data_dir, n=5)

    # The log does not exist yet.
    log_store = LogStore(data_dir)
    log_store.ensure_schema()
    assert not log_store.is_initialized()

    log_key = load_or_create_log_key(data_dir, log_store)
    audit = AuditService(log_store, log_key)
    audit.initialize_or_migrate()

    assert log_store.is_initialized()
    assert log_store.latest_size() == 5
    with sqlite3.connect(log_store._db_path) as conn:
        rows = conn.execute(
            "SELECT serial_hex FROM log_leaves ORDER BY leaf_index"
        ).fetchall()
    migrated_serials = [int(row[0], 16) for row in rows]
    assert migrated_serials == expected_serials


def test_migration_preserves_root_across_restart(tmp_path):
    data_dir = str(tmp_path / "data")
    _make_legacy_db(data_dir, n=4)

    log_store = LogStore(data_dir)
    log_store.ensure_schema()
    log_key = load_or_create_log_key(data_dir, log_store)
    audit = AuditService(log_store, log_key)
    audit.initialize_or_migrate()
    root_before = log_store.head().root
    log_id_before = audit.log_id()

    # Full restart: rebuild everything.
    ca2 = load_or_create_ca(data_dir)
    log_store2 = LogStore(data_dir)
    log_store2.ensure_schema()
    log_key2 = load_or_create_log_key(data_dir, log_store2)
    audit2 = AuditService(log_store2, log_key2)
    audit2.initialize_or_migrate()

    assert audit2.log_id() == log_id_before
    assert log_store2.head().root == root_before
    assert log_store2.latest_size() == 4


def test_migration_failure_rolls_back(tmp_path, monkeypatch):
    data_dir = str(tmp_path / "data")
    _make_legacy_db(data_dir, n=3)

    log_store = LogStore(data_dir)
    log_store.ensure_schema()
    log_key = load_or_create_log_key(data_dir, log_store)

    # Force the leaf append to fail after the first leaf.
    call_count = 0
    original = log_store._append_on_conn

    def fail_after_first(conn, serial_hex, cert_der):
        nonlocal call_count
        call_count += 1
        if call_count > 1:
            raise RuntimeError("simulated migration failure")
        return original(conn, serial_hex, cert_der)

    monkeypatch.setattr(LogStore, "_append_on_conn", staticmethod(fail_after_first))

    audit = AuditService(log_store, log_key)
    with pytest.raises(RuntimeError, match="simulated"):
        audit.initialize_or_migrate()

    # The log must not be partially initialized.
    assert not log_store.is_initialized()
    with sqlite3.connect(log_store._db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM log_leaves").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM log_heads").fetchone()[0] == 0


def test_missing_log_key_refuses_startup(tmp_path):
    data_dir = str(tmp_path / "data")
    ca = load_or_create_ca(data_dir)
    log_store = LogStore(data_dir)
    log_store.ensure_schema()
    log_key = load_or_create_log_key(data_dir, log_store)
    audit = AuditService(log_store, log_key)
    audit.initialize_or_migrate()

    # Remove the signing key.
    os.unlink(os.path.join(data_dir, LOG_KEY_FILE))

    log_store2 = LogStore(data_dir)
    log_store2.ensure_schema()
    with pytest.raises(LogKeyError, match="missing"):
        load_or_create_log_key(data_dir, log_store2)


def test_mismatched_log_key_refuses_startup(tmp_path):
    data_dir = str(tmp_path / "data")
    ca = load_or_create_ca(data_dir)
    log_store = LogStore(data_dir)
    log_store.ensure_schema()
    log_key = load_or_create_log_key(data_dir, log_store)
    audit = AuditService(log_store, log_key)
    audit.initialize_or_migrate()

    # Replace the signing key with a different one.
    other = load_or_create_log_key  # noqa: F841
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    other_key = Ed25519PrivateKey.generate()
    other_pem = other_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(os.path.join(data_dir, LOG_KEY_FILE), "wb") as f:
        f.write(other_pem)

    log_store2 = LogStore(data_dir)
    log_store2.ensure_schema()
    with pytest.raises(LogKeyError, match="does not match"):
        load_or_create_log_key(data_dir, log_store2)


def test_new_issuance_after_migration_appends(tmp_path):
    data_dir = str(tmp_path / "data")
    ca = load_or_create_ca(data_dir)
    store = CAStore(data_dir)
    service = CAService(ca, store)
    service.issue(
        make_csr_pem(dns_names=["old.lab.test"]), days=7, idempotency_key="old"
    )

    log_store = LogStore(data_dir)
    log_store.ensure_schema()
    log_key = load_or_create_log_key(data_dir, log_store)
    audit = AuditService(log_store, log_key)
    audit.initialize_or_migrate()
    assert log_store.latest_size() == 1

    # New issuance appends leaf 1.
    service2 = CAService(ca, store, log_store=log_store)
    service2.issue(
        make_csr_pem(dns_names=["new.lab.test"]), days=7, idempotency_key="new"
    )
    assert log_store.latest_size() == 2
    with sqlite3.connect(log_store._db_path) as conn:
        rows = conn.execute(
            "SELECT leaf_index FROM log_leaves ORDER BY leaf_index"
        ).fetchall()
    assert [row[0] for row in rows] == [0, 1]
