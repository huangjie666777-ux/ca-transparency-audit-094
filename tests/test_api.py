from __future__ import annotations

import datetime as dt
import threading

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

from tests.conftest import make_csr_pem, make_key, make_short_ca


def _issue(client, csr_pem, days=7, key="key-1"):
    return client.post(
        "/certificates",
        json={
            "csr": csr_pem.decode(),
            "days": days,
            "idempotency_key": key,
        },
    )


def test_health_and_ca_download(env):
    assert env.client.get("/health").json() == {"status": "ok"}
    resp = env.client.get("/ca/certificate")
    assert resp.status_code == 200
    ca = x509.load_pem_x509_certificate(resp.content)
    assert ca.subject == env.ca.cert.subject


def test_issue_and_query_and_certificate_shape(env):
    csr_pem = make_csr_pem(dns_names=["api.lab.test", "lab.test"])
    resp = _issue(env.client, csr_pem)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["replayed"] is False
    serial_hex = body["serial"]
    assert int(serial_hex, 16) > 0
    assert body["san"] == ["api.lab.test", "lab.test"]

    cert = x509.load_pem_x509_certificate(body["certificate"].encode())
    assert cert.issuer == env.ca.cert.subject
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature and ku.key_encipherment
    assert not ku.key_cert_sign and not ku.crl_sign
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == [
        "api.lab.test",
        "lab.test",
    ]
    # CSR extensions (none custom here) are never copied: only policy extensions.
    assert cert.signature_hash_algorithm.name == "sha256"
    # Issued cert is verifiable against the downloaded CA.
    env.ca.cert.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )

    got = env.client.get(f"/certificates/{serial_hex}")
    assert got.status_code == 200
    assert got.json()["status"] == "valid"


def test_policy_rejections_over_http(env):
    assert _issue(env.client, b"not a pem").status_code == 422
    assert _issue(env.client, make_csr_pem(dns_names=["evil.com"])).status_code == 422
    assert _issue(env.client, make_csr_pem(bits=1024)).status_code == 422
    assert _issue(env.client, make_csr_pem(), days=0).status_code == 422
    assert _issue(env.client, make_csr_pem(), days=31).status_code == 422


def test_idempotency_replay_and_conflict(env):
    csr_pem = make_csr_pem(dns_names=["a.lab.test"])
    first = _issue(env.client, csr_pem, days=7, key="idem")
    serial = first.json()["serial"]

    second = _issue(env.client, csr_pem, days=7, key="idem")
    assert second.status_code == 200
    assert second.json()["serial"] == serial
    assert second.json()["replayed"] is True

    different_days = _issue(env.client, csr_pem, days=8, key="idem")
    assert different_days.status_code == 409

    other_csr = make_csr_pem(dns_names=["b.lab.test"])
    conflict = _issue(env.client, other_csr, days=7, key="idem")
    assert conflict.status_code == 409
    # The original certificate is still retrievable unchanged.
    assert env.client.get(f"/certificates/{serial}").json()["status"] == "valid"


def test_concurrent_same_idempotency_key_single_record(env):
    csr_pem = make_csr_pem(dns_names=["race.lab.test"])
    results: list = []
    errors: list = []

    def worker():
        try:
            results.append(_issue(env.client, csr_pem, key="race-key").json()["serial"])
        except BaseException as exc:  # pragma: no cover - diagnostic only
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(results) == 8
    assert set(results) == {results[0]}


def test_revocation_and_crl(env):
    serial = _issue(
        env.client, make_csr_pem(dns_names=["rev.lab.test"]), key="r1"
    ).json()["serial"]

    rev = env.client.post(
        f"/certificates/{serial}/revoke", json={"reason": "key_compromise"}
    )
    assert rev.status_code == 200
    revoked_at = rev.json()["revoked_at"]
    assert rev.json()["replayed"] is False

    # Same reason is idempotent and preserves the first time.
    again = env.client.post(
        f"/certificates/{serial}/revoke", json={"reason": "key_compromise"}
    )
    assert again.status_code == 200
    assert again.json()["revoked_at"] == revoked_at
    assert again.json()["replayed"] is True

    # Different reason conflicts; revocation cannot be withdrawn.
    conflict = env.client.post(
        f"/certificates/{serial}/revoke", json={"reason": "superseded"}
    )
    assert conflict.status_code == 409

    bad_reason = env.client.post(
        f"/certificates/{serial}/revoke", json={"reason": "nope"}
    )
    assert bad_reason.status_code == 422

    unknown = env.client.post(
        "/certificates/deadbeef/revoke", json={"reason": "unspecified"}
    )
    assert unknown.status_code == 404

    published = env.client.post("/crl/publish").json()
    assert published["crl_number"] == 2  # fixture already published number 1
    crl = x509.load_pem_x509_crl(published["crl"].encode())
    assert crl.is_signature_valid(env.ca.cert.public_key())
    assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 2
    revoked = list(crl)
    assert len(revoked) == 1
    assert format(revoked[0].serial_number, "x") == serial
    reason = revoked[0].extensions.get_extension_for_class(x509.CRLReason).value
    assert reason.reason == x509.ReasonFlags.key_compromise

    current = env.client.get("/crl/current.pem")
    assert current.headers["x-crl-number"] == "2"
    downloaded = x509.load_pem_x509_crl(current.content)
    assert downloaded.is_signature_valid(env.ca.cert.public_key())


def test_crl_contains_all_revoked_and_numbers_increment(env):
    serials = []
    for i in range(3):
        serials.append(
            _issue(
                env.client,
                make_csr_pem(dns_names=[f"h{i}.lab.test"]),
                key=f"h{i}",
            ).json()["serial"]
        )
    env.client.post(
        f"/certificates/{serials[0]}/revoke", json={"reason": "unspecified"}
    )
    n1 = env.client.post("/crl/publish").json()["crl_number"]
    env.client.post(
        f"/certificates/{serials[2]}/revoke",
        json={"reason": "cessation_of_operation"},
    )
    n2 = env.client.post("/crl/publish").json()["crl_number"]
    assert n2 == n1 + 1
    crl = x509.load_pem_x509_crl(
        env.client.get("/crl/current").json()["crl"].encode()
    )
    assert {format(e.serial_number, "x") for e in crl} == {
        serials[0],
        serials[2],
    }


def test_concurrent_crl_publish_consistent_numbers(env):
    bodies = []
    lock = threading.Lock()

    def worker():
        body = env.client.post("/crl/publish").json()
        with lock:
            bodies.append(body["crl_number"])

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(bodies) == [2, 3, 4, 5, 6]
