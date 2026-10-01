"""Audit service: signed tree heads and proof orchestration.

The service binds a tree head (log identity, size, root hash) to an
Ed25519 signature using the independent log signing key. Proofs are read
through :class:`LogStore` in a single consistent snapshot.
"""

from __future__ import annotations

import base64
import datetime as dt
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .log_store import LOG_META_LOG_ID, LogStore
# Domain separator for signed tree heads. The signed message is:
#   HEAD_PREFIX || log_id (16 bytes) || tree_size (8 bytes, big-endian)
#                || root_hash (32 bytes)
HEAD_PREFIX = b"ltca-transparency-log-head\x00"
LOG_ID_LEN = 16


class AuditError(RuntimeError):
    pass


@dataclass(frozen=True)
class SignedTreeHead:
    log_id: bytes
    tree_size: int
    root: bytes
    signed_data: bytes
    signature: bytes

    def to_dict(self) -> dict:
        return {
            "log_id": self.log_id.hex(),
            "tree_size": self.tree_size,
            "root_hash": self.root.hex(),
            "signed_data": base64.b64encode(self.signed_data).decode("ascii"),
            "signature": base64.b64encode(self.signature).decode("ascii"),
        }


def build_signed_data(log_id: bytes, tree_size: int, root: bytes) -> bytes:
    if len(log_id) != LOG_ID_LEN:
        raise AuditError("log identity must be 16 bytes")
    return (
        HEAD_PREFIX
        + log_id
        + struct.pack(">Q", tree_size)
        + root
    )


class AuditService:
    def __init__(self, log_store: LogStore, signing_key: Ed25519PrivateKey):
        self._store = log_store
        self._key = signing_key

    @property
    def store(self) -> LogStore:
        return self._store

    @property
    def signing_key(self) -> Ed25519PrivateKey:
        return self._key

    def log_id(self) -> bytes:
        log_id = self._store.get_meta(LOG_META_LOG_ID)
        if log_id is None:
            raise AuditError("log is not initialized")
        return log_id

    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign_head(self, tree_size: int | None = None) -> SignedTreeHead:
        head = self._store.head(tree_size)
        log_id = self.log_id()
        signed_data = build_signed_data(log_id, head.tree_size, head.root)
        signature = self._key.sign(signed_data)
        return SignedTreeHead(
            log_id=log_id,
            tree_size=head.tree_size,
            root=head.root,
            signed_data=signed_data,
            signature=signature,
        )

    def latest_size(self) -> int:
        return self._store.latest_size()

    def inclusion_proof(self, leaf_index: int, tree_size: int | None = None):
        return self._store.inclusion_proof(leaf_index, tree_size)

    def consistency_proof(self, old_size: int, new_size: int | None = None):
        return self._store.consistency_proof(old_size, new_size)

    def initialize_or_migrate(self) -> None:
        """Genesis for an empty database, or one-shot migration of old certs."""
        if self._store.is_initialized():
            return
        now_iso = _utcnow_iso()
        migrated = self._store.migrate_legacy_certificates(
            self.public_key_bytes(), now_iso
        )
        if migrated == 0:
            # No legacy certificates: create the empty log.
            import secrets

            self._store.initialize_genesis(
                secrets.token_bytes(LOG_ID_LEN),
                self.public_key_bytes(),
                now_iso,
            )


def _utcnow_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()
