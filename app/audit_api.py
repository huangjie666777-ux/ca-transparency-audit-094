"""HTTP layer for the transparency audit endpoints (read-only).

Mounted by :func:`app.api.create_app`. Every response is plain JSON with
binary hashes/keys/signatures encoded as unpadded base64url. Tree heads are
signed by the log's independent Ed25519 key; the public key endpoint exists
for bootstrapping but verifiers must pin it out of band and never trust a
key that rides along inside a tree-head response.
"""

from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from . import audit_wire
from .audit_store import AuditLog, TreeSizeUnavailable


def _head_json(log_id: bytes, size: int, root: bytes, sig: bytes, ts: str) -> dict:
    return {
        "version": audit_wire.HEAD_VERSION,
        "log_id": audit_wire.b64u(log_id),
        "tree_size": size,
        "sha256_root_hash": audit_wire.b64u(root),
        "timestamp": ts,
        "signature": audit_wire.b64u(sig),
        "signature_type": "ed25519",
    }


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse(
        {"error": message},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


def create_audit_router(audit: AuditLog) -> APIRouter:
    router = APIRouter(prefix="/audit/v1")

    @router.get("/key")
    def log_key():
        return {
            "version": audit_wire.HEAD_VERSION,
            "log_id": audit_wire.b64u(audit.log_id),
            "hash_algorithm": "sha256",
            "signature_algorithm": "ed25519",
            # Raw 32-byte Ed25519 public key (RFC 8032), unpadded base64url.
            "public_key": audit_wire.b64u(audit.signer.public_key_raw),
            "public_key_format": "raw-ed25519-32-base64url",
        }

    @router.get("/head")
    def get_head(tree_size: int | None = Query(default=None, ge=0)):
        try:
            size, root, sig, ts = audit.get_sth(tree_size)
        except TreeSizeUnavailable as exc:
            return _error(404, str(exc))
        return _head_json(audit.log_id, size, root, sig, ts)

    @router.get("/inclusion/{leaf_index}")
    def inclusion(
        leaf_index: int,
        tree_size: int | None = Query(default=None, ge=0),
    ):
        if leaf_index < 0:
            return _error(400, "leaf_index must be non-negative")
        try:
            (
                size,
                cert_der,
                leaf_hash,
                path,
                root,
                sig,
                ts,
            ) = audit.inclusion_snapshot(leaf_index, tree_size)
        except TreeSizeUnavailable as exc:
            return _error(404, str(exc))
        except IndexError:
            wanted = tree_size if tree_size is not None else audit.current_size()
            return _error(404, f"leaf {leaf_index} does not exist at size {wanted}")
        return {
            "leaf_index": leaf_index,
            "tree_size": size,
            "leaf_hash": audit_wire.b64u(leaf_hash),
            "cert_der": audit_wire.b64u(cert_der),
            "proof": [audit_wire.b64u(p) for p in path],
            "tree_head": _head_json(audit.log_id, size, root, sig, ts),
        }

    @router.get("/consistency")
    def consistency(
        first: int = Query(..., ge=0),
        second: int | None = Query(default=None, ge=0),
    ):
        try:
            (
                second_size,
                path,
                first_root,
                f_sig,
                f_ts,
                second_root,
                s_sig,
                s_ts,
            ) = audit.consistency_snapshot(first, second)
        except TreeSizeUnavailable as exc:
            return _error(404, str(exc))
        except ValueError as exc:
            return _error(400, str(exc))
        return {
            "first_size": first,
            "second_size": second_size,
            "first_sha256_root_hash": audit_wire.b64u(first_root),
            "second_sha256_root_hash": audit_wire.b64u(second_root),
            "proof": [audit_wire.b64u(p) for p in path],
            "first_tree_head": _head_json(
                audit.log_id, first, first_root, f_sig, f_ts
            ),
            "second_tree_head": _head_json(
                audit.log_id, second_size, second_root, s_sig, s_ts
            ),
        }

    return router
