"""Ed25519 signing key for the transparency log tree heads.

The log identity is an independent, persistent Ed25519 key stored in the
data directory. It is deliberately separate from the CA RSA key: the CA
signs certificates and CRLs, while this key signs only tree heads. The
public key is exposed over HTTP; the private key never leaves the host.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .log_store import LOG_META_PUBLIC_KEY, LogStore

LOG_KEY_FILE = "log_key.pem"


class LogKeyError(RuntimeError):
    """Raised when the on-disk log signing key is missing or inconsistent."""


def _write_private_key(path: str, key: Ed25519PrivateKey) -> None:
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


def _public_key_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_or_create_log_key(
    data_dir: str, log_store: LogStore
) -> Ed25519PrivateKey:
    """Load the log signing key, creating it on first startup.

    If the log is already initialized, the key file must exist and its
    public key must match the public key bound to the log at genesis;
    otherwise startup is refused.
    """
    os.makedirs(data_dir, exist_ok=True)
    key_path = os.path.join(data_dir, LOG_KEY_FILE)

    if not log_store.is_initialized():
        # Log genesis: create a fresh signing key. The log store binds the
        # matching public key when the first head is written.
        if os.path.exists(key_path):
            # A key file from an earlier, failed genesis: reuse it rather
            # than silently rotating the log identity.
            with open(key_path, "rb") as handle:
                key = serialization.load_pem_private_key(handle.read(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise LogKeyError("log signing key is not Ed25519")
            return key
        key = Ed25519PrivateKey.generate()
        _write_private_key(key_path, key)
        return key

    # Existing log: the signing key must be present and match.
    if not os.path.exists(key_path):
        raise LogKeyError(
            "transparency log exists but its signing key is missing; "
            "refusing to start"
        )
    with open(key_path, "rb") as handle:
        key = serialization.load_pem_private_key(handle.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise LogKeyError("log signing key is not Ed25519")
    stored_public = log_store.get_meta(LOG_META_PUBLIC_KEY)
    if stored_public is None:
        raise LogKeyError("log is missing its bound public key")
    if _public_key_bytes(key) != stored_public:
        raise LogKeyError(
            "log signing key does not match the public key bound to the log; "
            "refusing to start"
        )
    return key


def public_key_pem(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_signature(public_key: bytes, signature: bytes, data: bytes) -> bool:
    """Verify an Ed25519 signature, returning False on any failure."""
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False
