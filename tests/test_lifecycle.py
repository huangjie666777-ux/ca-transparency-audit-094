from __future__ import annotations

import datetime as dt
import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.api import create_app
from app.ca import CAError, CA_CERT_FILE, CA_KEY_FILE, load_or_create_ca
from app.service import CAService
from app.storage import CAStore
from tests.conftest import make_csr_pem, make_short_ca


def _service(data_dir: str) -> CAService:
    ca = load_or_create_ca(data_dir)
    return CAService(ca, CAStore(data_dir))


def test_restart_reuses_ca_and_idempotent_history(tmp_path):
    data_dir = str(tmp_path / "data")
    service = _service(data_dir)
    csr_pem = make_csr_pem(dns_names=["restart.lab.test"])
    record, replayed = service.issue(csr_pem, days=5, idempotency_key="k1")
    assert replayed is False

    # Simulate full process restart: reload CA and database from disk.
    service2 = _service(data_dir)
    assert service2.ca.cert.fingerprint(hashes.SHA256()) == service.ca.cert.fingerprint(
        hashes.SHA256()
    )
    record2, replayed2 = service2.issue(csr_pem, days=5, idempotency_key="k1")
    assert replayed2 is True
    assert record2.serial_hex == record.serial_hex
    assert record2.cert_pem == record.cert_pem


def test_private_key_file_is_local_only(tmp_path):
    data_dir = str(tmp_path / "data")
    _service(data_dir)
    mode = os.stat(os.path.join(data_dir, CA_KEY_FILE)).st_mode & 0o777
    assert mode == 0o600


def test_missing_ca_with_existing_db_refuses_startup(tmp_path):
    data_dir = str(tmp_path / "data")
    _service(data_dir)
    os.unlink(os.path.join(data_dir, CA_KEY_FILE))
    os.unlink(os.path.join(data_dir, CA_CERT_FILE))
    with pytest.raises(CAError, match="missing"):
        load_or_create_ca(data_dir)


def test_only_one_ca_file_refuses_startup(tmp_path):
    data_dir = str(tmp_path / "data")
    _service(data_dir)
    os.unlink(os.path.join(data_dir, CA_CERT_FILE))
    with pytest.raises(CAError, match="together"):
        load_or_create_ca(data_dir)


def test_replacement_ca_mismatch_refuses_startup(tmp_path):
    data_dir = str(tmp_path / "data")
    _service(data_dir)
    # Attacker/operator drops in a different self-signed CA key+cert.
    other = make_short_ca(valid_days=30)
    with open(os.path.join(data_dir, CA_KEY_FILE), "wb") as f:
        f.write(other.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with open(os.path.join(data_dir, CA_CERT_FILE), "wb") as f:
        f.write(other.cert.public_bytes(serialization.Encoding.PEM))
    with pytest.raises(CAError, match="fingerprint"):
        load_or_create_ca(data_dir)


def test_cert_validity_capped_at_ca_expiry(tmp_path):
    data_dir = str(tmp_path / "data")
    short_ca = make_short_ca(valid_days=3)
    # Bind a fresh database directly to the short CA for the unit test.
    store = CAStore(data_dir)
    store.initialize(short_ca)
    service = CAService(short_ca, store)

    record, _ = service.issue(
        make_csr_pem(dns_names=["short.lab.test"]),
        days=30,
        idempotency_key="k",
    )
    cert = x509.load_pem_x509_certificate(record.cert_pem.encode())
    assert cert.not_valid_after_utc <= short_ca.not_after()
