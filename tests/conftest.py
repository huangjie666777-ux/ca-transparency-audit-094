from __future__ import annotations

import datetime as dt
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.api import create_app
from app.acme_challenge import Http01Config
from app.acme_service import AcmeService
from app.acme_store import ACMEStore
from app.audit import AuditService
from app.ca import CertificateAuthority, load_or_create_ca
from app.log_signing import load_or_create_log_key
from app.log_store import LogStore
from app.service import CAService
from app.storage import CAStore


def make_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def make_csr_pem(
    key: rsa.RSAPrivateKey | None = None,
    *,
    bits: int = 2048,
    cn: str | None = "api.lab.test",
    dns_names: list[str] | None = None,
    extra_san: list[x509.GeneralName] | None = None,
    corrupt_signature: bool = False,
) -> bytes:
    key = key or make_key(bits)
    if dns_names is None:
        dns_names = ["api.lab.test"]
    attributes = []
    if cn is not None:
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    general_names: list[x509.GeneralName] = [
        x509.DNSName(name) for name in dns_names
    ]
    if extra_san:
        general_names.extend(extra_san)
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(attributes)
    )
    if general_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(general_names), critical=False
        )
    csr = builder.sign(key, hashes.SHA256())
    pem = csr.public_bytes(serialization.Encoding.PEM)
    if corrupt_signature:
        # Flip a byte inside the DER signature content; structure stays parseable.
        der = csr.public_bytes(serialization.Encoding.DER)
        der = der[:-20] + bytes([der[-20] ^ 0xFF]) + der[-19:]
        csr2 = x509.load_der_x509_csr(der)
        pem = csr2.public_bytes(serialization.Encoding.PEM)
    return pem


@pytest.fixture()
def env(tmp_path):
    data_dir = tmp_path / "data"
    ca = load_or_create_ca(str(data_dir))
    store = CAStore(str(data_dir))
    acme_store = ACMEStore(str(data_dir))
    acme_store.ensure_schema()
    log_store = LogStore(str(data_dir))
    log_store.ensure_schema()
    log_key = load_or_create_log_key(str(data_dir), log_store)
    audit = AuditService(log_store, log_key)
    audit.initialize_or_migrate()
    service = CAService(ca, store, log_store=log_store)
    service.publish_crl()  # initial empty CRL
    acme_service = AcmeService(
        ca=ca,
        store=acme_store,
        cert_store=store,
        http01_config=Http01Config(port=80, timeout=5.0, max_bytes=8192),
        log_store=log_store,
    )
    app = create_app(service, acme_service, audit)
    with TestClient(app) as client:
        yield type("Env", (), {
            "data_dir": str(data_dir),
            "ca": ca,
            "store": store,
            "acme_store": acme_store,
            "log_store": log_store,
            "audit": audit,
            "log_key": log_key,
            "service": service,
            "acme": acme_service,
            "client": client,
        })()


def make_short_ca(valid_days: int = 5) -> CertificateAuthority:
    key = make_key(2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Short CA")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(key, hashes.SHA256())
    )
    return CertificateAuthority(cert=cert, private_key=key)


class ChallengeServer:
    """Local stand-in for the domain owner's HTTP server (127.0.0.1)."""

    def __init__(self):
        self.mode = "ok"
        self.payload = b"correct"
        self.records: list[tuple[str, str]] = []
        self._lock = threading.Lock()

        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def do_GET(self):
                with outer._lock:
                    outer.records.append((self.headers.get("Host", ""), self.path))
                if outer.mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://elsewhere/other")
                    self.end_headers()
                elif outer.mode == "oversize":
                    self.send_response(200)
                    body = b"x" * 20000
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(outer.payload)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()


@pytest.fixture()
def challenge_server(env):
    server = ChallengeServer()
    env.acme.configure_http01(
        Http01Config(port=server.port, timeout=5.0, max_bytes=8192)
    )
    yield server
    server.stop()
