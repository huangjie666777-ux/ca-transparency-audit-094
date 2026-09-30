"""Root CA lifecycle: creation, reuse, certificate and CRL signing."""

from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CA_KEY_BITS = 4096
CA_VALIDITY_DAYS = 3650
CRL_NEXT_UPDATE_DAYS = 7

CA_KEY_FILE = "ca_key.pem"
CA_CERT_FILE = "ca_cert.pem"


class CAError(RuntimeError):
    """Raised when the on-disk CA state is missing or inconsistent."""


@dataclass(frozen=True)
class CertificateAuthority:
    cert: x509.Certificate
    private_key: rsa.RSAPrivateKey

    @property
    def cert_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def not_after(self) -> dt.datetime:
        return self.cert.not_valid_after_utc

    def issue_cert(
        self,
        csr: x509.CertificateSigningRequest,
        dns_names: list[str],
        serial_number: int,
        not_before: dt.datetime,
        not_after: dt.datetime,
    ) -> x509.Certificate:
        # Copy the CSR subject (e.g. CN) but never copy arbitrary extensions;
        # the issued cert only carries the extensions this CA sets itself.
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial_number)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(name) for name in dns_names]
                ),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.cert.public_key()
                ),
                critical=False,
            )
        )
        return builder.sign(
            private_key=self.private_key,
            algorithm=hashes.SHA256(),
        )

    def build_crl(
        self,
        revoked_entries: list[x509.RevokedCertificate],
        crl_number: int,
        now: dt.datetime,
    ) -> x509.CertificateRevocationList:
        next_update = min(
            now + dt.timedelta(days=CRL_NEXT_UPDATE_DAYS),
            self.not_after(),
        )
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.cert.subject)
            .last_update(now)
            .next_update(next_update)
            .add_extension(x509.CRLNumber(crl_number), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.cert.public_key()
                ),
                critical=False,
            )
        )
        for entry in revoked_entries:
            builder = builder.add_revoked_certificate(entry)
        return builder.sign(
            private_key=self.private_key,
            algorithm=hashes.SHA256(),
        )


def _generate_ca(now: dt.datetime) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=CA_KEY_BITS)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Test CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Local Test Root CA"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return cert, key


def _write_private_key(path: str, key: rsa.RSAPrivateKey) -> None:
    data = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Create with owner-only permissions; private key never leaves this host.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except Exception:
        try:
            os.unlink(path)
        finally:
            raise


def load_or_create_ca(data_dir: str) -> CertificateAuthority:
    """Load the CA from data_dir, creating it for an empty directory.

    Existing application data without matching CA material, or a key/cert
    pair that does not match, is a fatal startup error.
    """
    from .storage import CAStore

    os.makedirs(data_dir, exist_ok=True)
    key_path = os.path.join(data_dir, CA_KEY_FILE)
    cert_path = os.path.join(data_dir, CA_CERT_FILE)
    store = CAStore(data_dir)
    store_exists = store.exists()

    key_exists = os.path.exists(key_path)
    cert_exists = os.path.exists(cert_path)

    if not key_exists and not cert_exists:
        if store_exists:
            raise CAError(
                "database exists but CA key and certificate are missing; "
                "refusing to start"
            )
        now = dt.datetime.now(dt.timezone.utc)
        cert, key = _generate_ca(now)
        _write_private_key(key_path, key)
        with open(cert_path, "wb") as handle:
            handle.write(cert.public_bytes(serialization.Encoding.PEM))
        os.chmod(cert_path, 0o644)
        ca = CertificateAuthority(cert=cert, private_key=key)
        store.initialize(ca)
        return ca

    if not (key_exists and cert_exists):
        raise CAError(
            "CA key and certificate must be present together; "
            "refusing to start"
        )

    with open(key_path, "rb") as handle:
        key = serialization.load_pem_private_key(handle.read(), password=None)
    with open(cert_path, "rb") as handle:
        cert = x509.load_pem_x509_certificate(handle.read())
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CAError("CA private key is not an RSA key")
    if (key.public_key().public_numbers()
            != cert.public_key().public_numbers()):
        raise CAError("CA certificate does not match CA private key")

    ca = CertificateAuthority(cert=cert, private_key=key)
    if store_exists:
        stored_fingerprint = store.load_ca_fingerprint()
        actual_fingerprint = cert.fingerprint(hashes.SHA256())
        if stored_fingerprint != actual_fingerprint:
            raise CAError(
                "stored CA fingerprint does not match the CA certificate; "
                "refusing to start"
            )
    else:
        # CA files predate the database: bind the new database to this CA.
        store.initialize(ca)
    return ca
