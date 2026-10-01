"""Tests for the ACME (RFC 8555 subset) endpoints."""

from __future__ import annotations

import datetime as dt
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from app.acme_challenge import Http01Config
from app.jws import b64url
from tests.acme_helpers import AcmeAccount, AcmeClient
from tests.conftest import make_csr_pem, make_key


# --------------------------------------------------------------------- helpers


class MutableClock:
    def __init__(self):
        self.shift = dt.timedelta()

    def __call__(self) -> dt.datetime:
        return dt.datetime.now(dt.timezone.utc) + self.shift


def csr_der(domain: str, key=None) -> bytes:
    pem = make_csr_pem(key or make_key(), dns_names=[domain])
    return x509.load_pem_x509_csr(pem).public_bytes(serialization.Encoding.DER)


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


@pytest.fixture()
def clock(env):
    clock = MutableClock()
    env.acme.set_clock(clock)
    return clock


def _registered(env) -> AcmeClient:
    client = AcmeClient(http=env.client, account=AcmeAccount.create())
    resp = client.new_account()
    assert resp.status_code == 201, resp.text
    return client


def _order_objects(client: AcmeClient, domain: str = "api.lab.test"):
    resp = client.new_order(domain)
    assert resp.status_code == 201, resp.text
    order = resp.json()
    order_path = "/" + resp.headers["Location"].split("/", 3)[3]
    authz_path = "/" + order["authorizations"][0].split("/", 3)[3]
    finalize_path = "/" + order["finalize"].split("/", 3)[3]
    return order_path, authz_path, finalize_path


def _solve(client: AcmeClient, env, authz_path: str, challenge_server) -> dict:
    authz = client.fetch_authz(authz_path).json()
    challenge = authz["challenges"][0]
    assert challenge["type"] == "http-01"
    challenge_path = "/" + challenge["url"].split("/", 3)[3]
    challenge_server.payload = (
        challenge["token"] + "." + client.account.thumbprint
    ).encode()
    resp = client.solve_challenge(challenge_path)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "valid"
    return challenge


# ------------------------------------------------------------- directory/nonce


def test_directory_and_nonce(env):
    directory = env.client.get("/acme/directory")
    assert directory.status_code == 200
    body = directory.json()
    assert body["newAccount"].endswith("/acme/new-account")
    assert body["newOrder"].endswith("/acme/new-order")
    assert body["newNonce"].endswith("/acme/new-nonce")
    assert "revokeCert" not in body  # ACME revocation is out of scope
    assert directory.headers["cache-control"] == "no-store"

    head = env.client.head("/acme/new-nonce")
    assert head.status_code == 204
    assert head.headers["Replay-Nonce"]
    get = env.client.get("/acme/new-nonce")
    assert get.status_code == 204
    assert get.headers["Replay-Nonce"] != head.headers["Replay-Nonce"]


# ------------------------------------------------------------------ accounts


def test_register_and_reuse_account(env):
    client = AcmeClient(http=env.client, account=AcmeAccount.create())
    first = client.new_account()
    assert first.status_code == 201
    assert first.json()["status"] == "valid"
    account_url = first.headers["Location"]

    # Same public key: RFC 8555 says reuse the existing account (200).
    client2 = AcmeClient(http=env.client, account=client.account)
    again = client2.new_account()
    assert again.status_code == 200
    assert again.headers["Location"] == account_url


def test_only_return_existing_unknown_key(env):
    client = AcmeClient(http=env.client, account=AcmeAccount.create())
    resp = client.post_jwk(
        "/acme/new-account",
        {"onlyReturnExisting": True},
    )
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("accountDoesNotExist")


def test_other_account_cannot_read_order(env, challenge_server):
    owner = _registered(env)
    order_path, _, _ = _order_objects(owner)

    intruder = _registered(env)
    resp = intruder.fetch_order(order_path)
    assert resp.status_code == 404


def test_small_account_key_rejected(env):
    small = AcmeClient(http=env.client, account=AcmeAccount.create(bits=1024))
    resp = small.new_account()
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("badSignatureAlgorithm")


# --------------------------------------------------------------- JWS security


def test_bad_signature_rejected(env):
    client = AcmeClient(http=env.client, account=AcmeAccount.create())
    foreign = make_key()
    resp = client.post_jwk(
        "/acme/new-account",
        {"termsOfServiceAgreed": True},
        sign_key=foreign,
    )
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("unauthorized")


def test_wrong_protected_url_rejected(env):
    client = _registered(env)
    resp = client.post_kid(
        "/acme/new-order",
        {"identifiers": [{"type": "dns", "value": "api.lab.test"}]},
        url_override="http://testserver/acme/somewhere-else",
    )
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("unauthorized")


def test_replayed_nonce_only_succeeds_once(env):
    client = _registered(env)
    nonce = client.get_nonce()
    payload = {"identifiers": [{"type": "dns", "value": "a.lab.test"}]}

    results: list[int] = []
    barrier = threading.Barrier(2)

    def worker():
        barrier.wait()
        results.append(
            client.post_kid("/acme/new-order", payload, nonce=nonce).status_code
        )

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [201, 400]
    # Third use is plainly invalid too.
    third = client.post_kid("/acme/new-order", payload, nonce=nonce)
    assert third.status_code == 400
    assert third.json()["type"].endswith("badNonce")


def test_expired_nonce_rejected(env, clock):
    client = AcmeClient(http=env.client, account=AcmeAccount.create())
    nonce = client.get_nonce()
    clock.shift = dt.timedelta(minutes=6)  # nonces live 5 minutes
    resp = client.post_jwk(
        "/acme/new-account", {"termsOfServiceAgreed": True}, nonce=nonce
    )
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("badNonce")
    assert resp.headers["Replay-Nonce"]


def test_non_rs256_alg_rejected(env):
    client = AcmeClient(http=env.client, account=AcmeAccount.create())
    resp = client.post_jwk(
        "/acme/new-account",
        {"termsOfServiceAgreed": True},
        protected_overrides={"alg": "ES256"},
    )
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("badSignatureAlgorithm")


def test_kid_required_after_registration(env):
    client = _registered(env)
    resp = client.post_kid(
        "/acme/new-order",
        {"identifiers": [{"type": "dns", "value": "api.lab.test"}]},
        jwk_instead_of_kid=True,
    )
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("malformed")


def test_unknown_kid_rejected(env):
    client = _registered(env)
    resp = client.post_kid(
        "/acme/new-order",
        {"identifiers": [{"type": "dns", "value": "api.lab.test"}]},
        kid_override="http://testserver/acme/account/999999",
    )
    assert resp.status_code == 400


def test_post_as_get_requires_empty_payload(env):
    client = _registered(env)
    order_path, _, _ = _order_objects(client)
    resp = client.post_kid(order_path, {"unexpected": 1})
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("malformed")


def test_wrong_content_type_rejected(env):
    resp = env.client.post(
        "/acme/new-account", content=b"{}", headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("malformed")


# --------------------------------------------------------------------- orders


@pytest.mark.parametrize(
    "identifiers",
    [
        [],
        [
            {"type": "dns", "value": "a.lab.test"},
            {"type": "dns", "value": "b.lab.test"},
        ],
        [{"type": "ip", "value": "127.0.0.1"}],
    ],
)
def test_order_identifier_shape_rejected(env, identifiers):
    client = _registered(env)
    resp = client.post_kid("/acme/new-order", {"identifiers": identifiers})
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("malformed")


@pytest.mark.parametrize("domain", ["evil.com", "*.lab.test", "lab.test.evil.com"])
def test_order_domain_policy_rejected(env, domain):
    client = _registered(env)
    resp = client.new_order(domain)
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("rejectedIdentifier")


# --------------------------------------------------------------- http-01 flow


def test_full_http01_flow_uses_host_header_and_path(
    env, challenge_server
):
    client = _registered(env)
    order_path, authz_path, finalize_path = _order_objects(client, "a.lab.test")
    challenge = _solve(client, env, authz_path, challenge_server)

    # The verifier connected to 127.0.0.1 but spoke for the validated name.
    host, path = challenge_server.records[-1]
    assert host == "a.lab.test"
    assert path == f"/.well-known/acme-challenge/{challenge['token']}"

    order = client.fetch_order(order_path).json()
    assert order["status"] == "ready"

    der = csr_der("a.lab.test")
    finalized = client.finalize(finalize_path, der)
    assert finalized.status_code == 200, finalized.text
    order = finalized.json()
    assert order["status"] == "valid"
    assert order["certificate"].endswith(f"/acme/cert/{order_path.rsplit('/',1)[1]}")

    cert_path = "/" + order["certificate"].split("/", 3)[3]
    downloaded = client.download_cert(cert_path)
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"] == "application/pem-certificate-chain"
    chain_pem = downloaded.content
    leaf = x509.load_pem_x509_certificate(chain_pem)
    assert leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName) == ["a.lab.test"]
    env.ca.cert.public_key().verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        padding.PKCS1v15(),
        leaf.signature_hash_algorithm,
    )
    validity = leaf.not_valid_after_utc - leaf.not_valid_before_utc
    assert dt.timedelta(days=6, hours=23) <= validity <= dt.timedelta(days=7, hours=1)
    # Chain includes the CA certificate after the leaf.
    assert env.ca.cert_pem.decode() in chain_pem.decode()


def test_wrong_key_authorization_keeps_challenge_pending(
    env, challenge_server
):
    client = _registered(env)
    _, authz_path, _ = _order_objects(client, "b.lab.test")
    authz = client.fetch_authz(authz_path).json()
    challenge = authz["challenges"][0]
    challenge_path = "/" + challenge["url"].split("/", 3)[3]

    challenge_server.payload = b"totally-wrong"
    failed = client.solve_challenge(challenge_path)
    assert failed.status_code == 400
    assert failed.json()["type"].endswith("incorrectResponse")
    # Retry with the correct value within the order lifetime succeeds.
    challenge_server.payload = (
        challenge["token"] + "." + client.account.thumbprint
    ).encode()
    ok = client.solve_challenge(challenge_path)
    assert ok.status_code == 200
    assert ok.json()["status"] == "valid"


def test_redirect_rejected(env, challenge_server):
    client = _registered(env)
    _, authz_path, _ = _order_objects(client, "c.lab.test")
    challenge = client.fetch_authz(authz_path).json()["challenges"][0]
    challenge_path = "/" + challenge["url"].split("/", 3)[3]
    challenge_server.mode = "redirect"
    resp = client.solve_challenge(challenge_path)
    assert resp.status_code == 400
    assert "redirect" in resp.json()["detail"]


def test_oversized_response_rejected(env, challenge_server):
    client = _registered(env)
    _, authz_path, _ = _order_objects(client, "d.lab.test")
    challenge = client.fetch_authz(authz_path).json()["challenges"][0]
    challenge_path = "/" + challenge["url"].split("/", 3)[3]
    challenge_server.mode = "oversize"
    resp = client.solve_challenge(challenge_path)
    assert resp.status_code == 400
    assert "too large" in resp.json()["detail"]


def test_challenge_payload_must_be_empty_object(env, challenge_server):
    client = _registered(env)
    _, authz_path, _ = _order_objects(client, "e.lab.test")
    challenge = client.fetch_authz(authz_path).json()["challenges"][0]
    challenge_path = "/" + challenge["url"].split("/", 3)[3]
    resp = client.post_kid(challenge_path, {"keyAuthorization": "x"})
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("malformed")


# ------------------------------------------------------------------ finalize


def test_finalize_before_validation_rejected(env, challenge_server):
    client = _registered(env)
    _, _, finalize_path = _order_objects(client, "f.lab.test")
    resp = client.finalize(finalize_path, csr_der("f.lab.test"))
    assert resp.status_code == 403
    assert resp.json()["type"].endswith("orderNotReady")


def test_finalize_after_order_expiry_rejected(env, challenge_server, clock):
    client = _registered(env)
    order_path, authz_path, finalize_path = _order_objects(client, "g.lab.test")
    _solve(client, env, authz_path, challenge_server)
    assert client.fetch_order(order_path).json()["status"] == "ready"

    clock.shift = dt.timedelta(minutes=11)  # orders live 10 minutes
    resp = client.finalize(finalize_path, csr_der("g.lab.test"))
    assert resp.status_code == 403
    assert resp.json()["type"].endswith("orderNotReady")


def test_finalize_csr_san_must_match_order(env, challenge_server):
    client = _registered(env)
    _, authz_path, finalize_path = _order_objects(client, "h.lab.test")
    _solve(client, env, authz_path, challenge_server)
    resp = client.finalize(finalize_path, csr_der("other.lab.test"))
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("badCSR")


def test_finalize_rejects_non_der_csr(env, challenge_server):
    client = _registered(env)
    _, authz_path, finalize_path = _order_objects(client, "i.lab.test")
    _solve(client, env, authz_path, challenge_server)
    resp = client.post_kid(finalize_path, {"csr": b64url(b"not a csr")})
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("badCSR")


def test_finalize_different_csr_conflict(env, challenge_server):
    client = _registered(env)
    _, authz_path, finalize_path = _order_objects(client, "j.lab.test")
    _solve(client, env, authz_path, challenge_server)
    first = client.finalize(finalize_path, csr_der("j.lab.test"))
    assert first.status_code == 200
    second = client.finalize(finalize_path, csr_der("j.lab.test", make_key()))
    assert second.status_code == 409
    assert second.json()["type"].endswith("orderAlreadyIssued")


def test_concurrent_finalize_same_csr_issues_one_cert(env, challenge_server):
    owner = _registered(env)
    order_path, authz_path, finalize_path = _order_objects(owner, "k.lab.test")
    _solve(owner, env, authz_path, challenge_server)

    der = csr_der("k.lab.test")
    statuses: list[int] = []
    barrier = threading.Barrier(8)

    def worker():
        client = AcmeClient(http=env.client, account=owner.account)
        client.get_nonce()
        barrier.wait()
        statuses.append(client.finalize(finalize_path, der).status_code)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert statuses == [200] * 8

    import sqlite3

    conn = sqlite3.connect(env.store._db_path)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM idempotency WHERE idempotency_key = ?",
            (f"acme-order:{order_path.rsplit('/', 1)[1]}",),
        ).fetchone()[0]
        cert_count = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
    finally:
        conn.close()
    assert count == 1
    assert cert_count == 1


def test_no_orphan_certificate_when_signing_fails(
    env, challenge_server, monkeypatch
):
    client = _registered(env)
    _, authz_path, finalize_path = _order_objects(client, "l.lab.test")
    _solve(client, env, authz_path, challenge_server)

    def boom(*args, **kwargs):
        raise RuntimeError("simulated CA failure")

    # CertificateAuthority is a frozen dataclass; patch the class (undone by
    # monkeypatch after the test).
    monkeypatch.setattr(type(env.acme.ca), "issue_cert", boom)
    resp = client.finalize(finalize_path, csr_der("l.lab.test"))
    assert resp.status_code == 500

    import sqlite3

    conn = sqlite3.connect(env.store._db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0] == 0
        order_status = conn.execute(
            "SELECT status, cert_serial_hex FROM acme_orders"
        ).fetchone()
    finally:
        conn.close()
    assert order_status == ("pending", None)


# ------------------------------------------------------------------ restart


def test_restart_preserves_order_and_certificate(env, challenge_server, tmp_path):
    client = _registered(env)
    order_path, authz_path, finalize_path = _order_objects(client, "m.lab.test")
    _solve(client, env, authz_path, challenge_server)
    client.finalize(finalize_path, csr_der("m.lab.test"))
    order = client.fetch_order(order_path).json()
    cert_path = "/" + order["certificate"].split("/", 3)[3]
    before = client.download_cert(cert_path).content

    # Full process restart: rebuild every component from the data directory.
    from app.api import create_app
    from app.ca import load_or_create_ca
    from app.acme_service import AcmeService
    from app.acme_store import ACMEStore
    from app.service import CAService
    from app.storage import CAStore
    from fastapi.testclient import TestClient

    ca = load_or_create_ca(env.data_dir)
    store = CAStore(env.data_dir)
    acme_store = ACMEStore(env.data_dir)
    acme_store.ensure_schema()
    service = CAService(ca, store)
    acme_service = AcmeService(
        ca=ca,
        store=acme_store,
        cert_store=store,
        http01_config=Http01Config(port=challenge_server.port, timeout=5, max_bytes=8192),
    )
    app = create_app(service, acme_service)
    with TestClient(app) as restarted_http:
        restarted = AcmeClient(
            http=restarted_http, account=client.account
        )
        restarted.get_nonce()
        order_resp = restarted.fetch_order(order_path)
        assert order_resp.status_code == 200
        assert order_resp.json()["status"] == "valid"
        after = restarted.download_cert(cert_path)
        assert after.status_code == 200
        assert after.content == before


# --------------------------------------------------------- legacy regressions


def test_legacy_days_rejects_bool_and_string(env):
    csr_pem = make_csr_pem(dns_names=["legacy.lab.test"]).decode()
    for bad_days in (True, "7"):
        resp = env.client.post(
            "/certificates",
            json={
                "csr": csr_pem,
                "days": bad_days,
                "idempotency_key": f"days-{bad_days!r}",
            },
        )
        assert resp.status_code == 422, bad_days


def test_acme_cert_visible_to_legacy_api_and_crl(env, challenge_server):
    client = _registered(env)
    _, authz_path, finalize_path = _order_objects(client, "n.lab.test")
    _solve(client, env, authz_path, challenge_server)
    client.finalize(finalize_path, csr_der("n.lab.test"))

    import sqlite3

    conn = sqlite3.connect(env.store._db_path)
    try:
        serial = conn.execute(
            "SELECT cert_serial_hex FROM acme_orders"
        ).fetchone()[0]
    finally:
        conn.close()
    legacy = env.client.get(f"/certificates/{serial}")
    assert legacy.status_code == 200
    assert legacy.json()["san"] == ["n.lab.test"]
    assert legacy.json()["status"] == "valid"
    # ACME-issued certs reuse the legacy issuance policy: fixed 7-day lifetime.
    assert env.store.get_certificate(serial).days == 7

    # ACME-issued certs can be revoked through the legacy API and hit the CRL.
    revoked = env.client.post(
        f"/certificates/{serial}/revoke", json={"reason": "key_compromise"}
    )
    assert revoked.status_code == 200
    crl = env.client.post("/crl/publish").json()["crl"]
    parsed_crl = x509.load_pem_x509_crl(crl.encode())
    assert format(list(parsed_crl)[0].serial_number, "x") == serial
