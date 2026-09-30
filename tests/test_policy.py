from __future__ import annotations

import ipaddress

import pytest
from cryptography import x509

from app import policy
from app.service import parse_csr
from tests.conftest import make_csr_pem


def _san(csr_pem: bytes) -> list[str]:
    return policy.validate_csr(parse_csr(csr_pem))


def test_accepts_lab_test_and_subdomains():
    assert _san(make_csr_pem(dns_names=["lab.test"])) == ["lab.test"]
    assert _san(make_csr_pem(dns_names=["a.lab.test"])) == ["a.lab.test"]
    assert _san(make_csr_pem(dns_names=["deep.a.lab.test"])) == [
        "deep.a.lab.test"
    ]


@pytest.mark.parametrize(
    "name",
    [
        "notlab.test",
        "lab.test.evil.com",
        "labtest",
        "evillab.test",
        "*.lab.test",
        "lab.*.test",
        "a.lab..test",
        "-bad.lab.test",
    ],
)
def test_forbidden_domains(name):
    csr_pem = make_csr_pem(cn=name, dns_names=[name])
    with pytest.raises(policy.PolicyError):
        _san(csr_pem)


@pytest.mark.parametrize("name", ["LAB.TEST", "Api.Lab.Test"])
def test_uppercase_normalized(name):
    csr_pem = make_csr_pem(cn=name.lower(), dns_names=[name])
    assert _san(csr_pem) == [name.lower()]


def test_rejects_wildcard_explicitly():
    with pytest.raises(policy.PolicyError, match="wildcard"):
        _san(make_csr_pem(dns_names=["*.lab.test"]))


def test_missing_san_rejected_even_with_cn():
    with pytest.raises(policy.PolicyError, match="subjectAltName"):
        _san(make_csr_pem(cn="api.lab.test", dns_names=[]))


def test_non_dns_san_rejected():
    csr_pem = make_csr_pem(
        dns_names=["api.lab.test"],
        extra_san=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
    )
    with pytest.raises(policy.PolicyError, match="only contain DNS"):
        _san(csr_pem)


def test_small_rsa_key_rejected():
    with pytest.raises(policy.PolicyError, match="2048"):
        _san(make_csr_pem(bits=1024))


def test_bad_signature_rejected():
    with pytest.raises(policy.PolicyError, match="invalid"):
        _san(make_csr_pem(corrupt_signature=True))


def test_days_and_key_validation():
    assert policy.validate_days(1) == 1
    assert policy.validate_days(30) == 30
    for bad in (0, 31, -1, 1.5, "7", True, None):
        with pytest.raises(policy.PolicyError):
            policy.validate_days(bad)
    assert policy.validate_idempotency_key("  k1  ") == "k1"
    with pytest.raises(policy.PolicyError):
        policy.validate_idempotency_key("   ")


def test_san_normalized_sorted_dedup():
    csr_pem = make_csr_pem(
        dns_names=["B.lab.test", "a.lab.test", "a.lab.test", "lab.test"]
    )
    assert _san(csr_pem) == ["a.lab.test", "b.lab.test", "lab.test"]
