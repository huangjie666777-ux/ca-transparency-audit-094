"""HTTP endpoints for the RFC 6962 transparency log.

Read-only endpoints expose the log signing public key, signed tree heads
(latest and historical), inclusion proofs and consistency proofs. Proofs
are read in a single transaction so a response never mixes snapshots.
"""

from __future__ import annotations

import base64

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from . import log_signing
from .audit import AuditError, AuditService
from .log_store import LogNotInitialized, LogStoreError


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_audit_router(audit: AuditService) -> APIRouter:
    router = APIRouter(prefix="/log")

    def _error(exc: Exception) -> JSONResponse:
        if isinstance(exc, (LogNotInitialized, LogStoreError, AuditError)):
            status = 404 if isinstance(exc, LogNotInitialized) else 400
            return JSONResponse({"detail": str(exc)}, status_code=status)
        if isinstance(exc, IndexError):
            return JSONResponse({"detail": str(exc)}, status_code=400)
        raise exc  # pragma: no cover - defensive

    @router.get("/public-key")
    def public_key():
        raw = audit.public_key_bytes()
        pem = log_signing.public_key_pem(audit.signing_key)
        return {
            "log_id": audit.log_id().hex(),
            "public_key": _b64url(raw),
            "encoding": "ed25519-raw-base64url",
            "public_key_pem": pem.decode("ascii"),
            "signed_message_format": (
                "SHA-256 tree head signed with Ed25519. The signed message is "
                "HEAD_PREFIX || log_id(16 bytes) || tree_size(8 bytes, "
                "big-endian uint64) || root_hash(32 bytes). HEAD_PREFIX is "
                "the ASCII string 'ltca-transparency-log-head' followed by "
                "one zero byte."
            ),
        }

    @router.get("/head")
    def latest_head():
        try:
            return audit.sign_head().to_dict()
        except (LogNotInitialized, LogStoreError, AuditError) as exc:
            return _error(exc)

    @router.get("/head/{tree_size}")
    def historical_head(tree_size: int):
        try:
            return audit.sign_head(tree_size).to_dict()
        except (LogNotInitialized, LogStoreError, AuditError) as exc:
            return _error(exc)

    @router.get("/proof/inclusion/{leaf_index}")
    def inclusion_proof(leaf_index: int, size: int | None = None):
        try:
            proof = audit.inclusion_proof(leaf_index, size)
        except (LogNotInitialized, LogStoreError, AuditError, IndexError) as exc:
            return _error(exc)
        return {
            "leaf_index": proof.leaf_index,
            "tree_size": proof.tree_size,
            "leaf_hash": proof.leaf_hash.hex(),
            "proof": [node.hex() for node in proof.proof],
            "root_hash": proof.root.hex(),
        }

    @router.get("/proof/consistency")
    def consistency_proof(old: int, new: int | None = None):
        try:
            proof = audit.consistency_proof(old, new)
        except (LogNotInitialized, LogStoreError, AuditError, IndexError) as exc:
            return _error(exc)
        return {
            "old_size": proof.old_size,
            "new_size": proof.new_size,
            "old_root": proof.old_root.hex(),
            "new_root": proof.new_root.hex(),
            "proof": [node.hex() for node in proof.proof],
        }

    return router
