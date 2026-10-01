"""Persistent, independent Ed25519 key that signs audit-log tree heads.

The tree-head key is separate from the 4096-bit RSA CA key on purpose: it
only authenticates log state, never certificates. It is stored in its own
file, owner-only, and reused across restarts. A database that already
contains audit-log state without a matching key is a fatal startup error.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .audit_wire import PUBKEY_LEN, log_id_for_public_key

LOG_KEY_FILE = "log_key.pem"
# Raw 32-byte Ed25519 public key, written next to the private key so an
# operator can pin it through a trusted, out-of-band channel. Verifiers must
# use a pinned copy of this; they never trust a key sent inside a tree head.
LOG_PUBKEY_FILE = "log_pubkey.raw"


class LogKeyError(RuntimeError):
    """Raised when the on-disk log signing key is missing or inconsistent."""


class LogSigner:
    def __init__(self, private_key: ed25519.Ed25519PrivateKey):
        self._private = private_key
        self._public = private_key.public_key()
        self._public_raw = self._public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def public_key_raw(self) -> bytes:
        return self._public_raw

    @property
    def log_id(self) -> bytes:
        return log_id_for_public_key(self._public_raw)

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)

    def verify(self, signature: bytes, data: bytes) -> None:
        self._public.verify(signature, data)


def _write_private_key(path: str, key: ed25519.Ed25519PrivateKey) -> None:
    data = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except Exception:
        try:
            os.unlink(path)
        finally:
            raise


def load_or_create_log_key(data_dir: str, expected_log_id: bytes | None) -> LogSigner:
    """Load the log key, creating it on first use.

    ``expected_log_id`` is the identity recorded in the database. When the
    database already has a log, the key on disk must match it or startup is
    refused; a database with a log but no key is likewise fatal.
    """
    os.makedirs(data_dir, exist_ok=True)
    path = os.path.join(data_dir, LOG_KEY_FILE)
    key_exists = os.path.exists(path)

    if expected_log_id is None:
        # No log rows yet: reuse an existing key if present, else mint one.
        if key_exists:
            signer = _load(path)
        else:
            key = ed25519.Ed25519PrivateKey.generate()
            _write_private_key(path, key)
            signer = LogSigner(key)
        _write_public_key(data_dir, signer)
        return signer

    if not key_exists:
        raise LogKeyError(
            "audit log exists in the database but log_key.pem is missing; "
            "refusing to start"
        )
    signer = _load(path)
    if signer.log_id != expected_log_id:
        raise LogKeyError(
            "log_key.pem does not match the log identity stored in the "
            "database; refusing to start"
        )
    _write_public_key(data_dir, signer)
    return signer


def _write_public_key(data_dir: str, signer: LogSigner) -> None:
    path = os.path.join(data_dir, LOG_PUBKEY_FILE)
    # World-readable pin file; it is a public key.
    with open(path, "wb") as handle:
        handle.write(signer.public_key_raw)
    os.chmod(path, 0o644)


def _load(path: str) -> LogSigner:
    with open(path, "rb") as handle:
        key = serialization.load_pem_private_key(handle.read(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise LogKeyError("log signing key is not an Ed25519 key")
    return LogSigner(key)
