"""SQLite persistence for ACME accounts, nonces, orders and authorizations.

The ACME tables live in the same database file as :mod:`app.storage` so an
issued certificate is one transaction away from its order: finalization
inserts the certificate and links the order atomically, which means a failed
finalization can never leave an orphan certificate behind.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from typing import Callable

from cryptography import x509

STATUS_PENDING = "pending"
STATUS_VALID = "valid"
STATUS_PROCESSING = "processing"
STATUS_READY = "ready"

CHALLENGE_HTTP01 = "http-01"

# Signing callback receives the allocated serial, returns the same tuple
# shape CAStore.issue_certificate uses.
SignCallback = Callable[[int], tuple[str, list[str], str, str]]


class AcmeStoreError(RuntimeError):
    pass


class OrderNotFound(AcmeStoreError):
    pass


class OrderConflict(AcmeStoreError):
    """The order was already finalized with a different CSR."""


@dataclass(frozen=True)
class Account:
    id: int
    jwk_thumbprint: str
    jwk_json: str
    contact: tuple[str, ...]
    created_at: str


@dataclass(frozen=True)
class OrderRecord:
    id: str
    account_id: int
    status: str
    expires_at: str
    identifiers: tuple[dict, ...]
    csr_der: bytes | None
    cert_serial_hex: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class AuthzRecord:
    id: str
    order_id: str
    account_id: int
    ident_type: str
    ident_value: str
    status: str
    expires_at: str
    validated_at: str | None


@dataclass(frozen=True)
class ChallengeRecord:
    id: str
    authz_id: str
    type: str
    token: str
    status: str
    validated_at: str | None


SCHEMA = """
CREATE TABLE IF NOT EXISTS acme_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    jwk_thumbprint TEXT NOT NULL UNIQUE,
    jwk_json TEXT NOT NULL,
    contact_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS acme_nonces (
    nonce TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS acme_orders (
    id TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    identifiers_json TEXT NOT NULL,
    csr_der BLOB,
    cert_serial_hex TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (account_id) REFERENCES acme_accounts(id),
    FOREIGN KEY (cert_serial_hex) REFERENCES certificates(serial_hex)
);
CREATE TABLE IF NOT EXISTS acme_authorizations (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL,
    account_id INTEGER NOT NULL,
    ident_type TEXT NOT NULL,
    ident_value TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    validated_at TEXT,
    FOREIGN KEY (order_id) REFERENCES acme_orders(id),
    FOREIGN KEY (account_id) REFERENCES acme_accounts(id)
);
CREATE TABLE IF NOT EXISTS acme_challenges (
    id TEXT PRIMARY KEY,
    authz_id TEXT NOT NULL,
    type TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    validated_at TEXT,
    FOREIGN KEY (authz_id) REFERENCES acme_authorizations(id)
);
CREATE INDEX IF NOT EXISTS idx_acme_orders_account ON acme_orders(account_id);
CREATE INDEX IF NOT EXISTS idx_acme_authz_order ON acme_authorizations(order_id);
CREATE INDEX IF NOT EXISTS idx_acme_challenges_authz ON acme_challenges(authz_id);
"""


def new_token(nbytes: int = 32) -> str:
    # token_urlsafe uses exactly the RFC 7235 token-compatible alphabet
    # allowed by RFC 8555 for challenge tokens.
    return secrets.token_urlsafe(nbytes)


class ACMEStore:
    def __init__(self, data_dir: str):
        self._db_path = os.path.join(data_dir, "ca.sqlite3")
        self._lock = threading.RLock()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    def ensure_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------ nonces

    def issue_nonce(self, now_iso: str) -> str:
        nonce = new_token()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO acme_nonces(nonce, created_at) VALUES(?, ?)",
                (nonce, now_iso),
            )
        return nonce

    def consume_nonce(self, nonce: str, not_before_iso: str) -> bool:
        """Atomically delete one nonce.

        Returns True only for the single request that deletes it; an unknown,
        expired or concurrently replayed nonce returns False.
        """
        with self._lock, self._connect() as conn:
            conn.execute(
                "DELETE FROM acme_nonces WHERE created_at < ?",
                (not_before_iso,),
            )
            cur = conn.execute(
                "DELETE FROM acme_nonces WHERE nonce = ?", (nonce,)
            )
            return cur.rowcount == 1

    # ---------------------------------------------------------------- accounts

    @staticmethod
    def _row_to_account(row: sqlite3.Row) -> Account:
        return Account(
            id=row["id"],
            jwk_thumbprint=row["jwk_thumbprint"],
            jwk_json=row["jwk_json"],
            contact=tuple(json.loads(row["contact_json"])),
            created_at=row["created_at"],
        )

    def get_account(self, account_id: int) -> Account | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM acme_accounts WHERE id = ?", (account_id,)
            ).fetchone()
        return None if row is None else self._row_to_account(row)

    def get_account_by_thumbprint(self, thumbprint: str) -> Account | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM acme_accounts WHERE jwk_thumbprint = ?",
                (thumbprint,),
            ).fetchone()
        return None if row is None else self._row_to_account(row)

    def create_account(
        self, jwk_thumbprint: str, jwk_json: str, contact: list[str], now_iso: str
    ) -> Account:
        with self._lock, self._connect() as conn:
            try:
                cur = conn.execute(
                    "INSERT INTO acme_accounts("
                    "jwk_thumbprint, jwk_json, contact_json, created_at) "
                    "VALUES(?,?,?,?)",
                    (
                        jwk_thumbprint,
                        jwk_json,
                        json.dumps(list(contact)),
                        now_iso,
                    ),
                )
            except sqlite3.IntegrityError:
                # Concurrent registration with the same key: reuse it.
                row = conn.execute(
                    "SELECT * FROM acme_accounts WHERE jwk_thumbprint = ?",
                    (jwk_thumbprint,),
                ).fetchone()
                return self._row_to_account(row)
            row = conn.execute(
                "SELECT * FROM acme_accounts WHERE id = ?", (cur.lastrowid,)
            ).fetchone()
            return self._row_to_account(row)

    # ----------------------------------------------------------------- orders

    @staticmethod
    def _row_to_order(row: sqlite3.Row) -> OrderRecord:
        return OrderRecord(
            id=row["id"],
            account_id=row["account_id"],
            status=row["status"],
            expires_at=row["expires_at"],
            identifiers=tuple(json.loads(row["identifiers_json"])),
            csr_der=bytes(row["csr_der"]) if row["csr_der"] is not None else None,
            cert_serial_hex=row["cert_serial_hex"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def create_order(
        self,
        account_id: int,
        identifiers: list[dict],
        expires_at: str,
        now_iso: str,
    ) -> OrderRecord:
        """Create order, authorization and http-01 challenge atomically."""
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                order_id = new_token(16)
                conn.execute(
                    "INSERT INTO acme_orders("
                    "id, account_id, status, expires_at, identifiers_json, "
                    "created_at, updated_at) VALUES(?,?,?,?,?,?,?)",
                    (
                        order_id,
                        account_id,
                        STATUS_PENDING,
                        expires_at,
                        json.dumps(identifiers),
                        now_iso,
                        now_iso,
                    ),
                )
                for ident in identifiers:
                    authz_id = new_token(16)
                    conn.execute(
                        "INSERT INTO acme_authorizations("
                        "id, order_id, account_id, ident_type, ident_value, "
                        "status, expires_at) VALUES(?,?,?,?,?,?,?)",
                        (
                            authz_id,
                            order_id,
                            account_id,
                            ident["type"],
                            ident["value"],
                            STATUS_PENDING,
                            expires_at,
                        ),
                    )
                    conn.execute(
                        "INSERT INTO acme_challenges("
                        "id, authz_id, type, token, status) "
                        "VALUES(?,?,?,?,?)",
                        (
                            new_token(16),
                            authz_id,
                            CHALLENGE_HTTP01,
                            new_token(),
                            STATUS_PENDING,
                        ),
                    )
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            row = conn.execute(
                "SELECT * FROM acme_orders WHERE id = ?", (order_id,)
            ).fetchone()
            return self._row_to_order(row)

    def get_order(self, order_id: str) -> OrderRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM acme_orders WHERE id = ?", (order_id,)
            ).fetchone()
        return None if row is None else self._row_to_order(row)

    def list_authz_for_order(self, order_id: str) -> list[AuthzRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM acme_authorizations WHERE order_id = ? ORDER BY id",
                (order_id,),
            ).fetchall()
        return [self._row_to_authz(row) for row in rows]

    # ---------------------------------------------------------- authorizations

    @staticmethod
    def _row_to_authz(row: sqlite3.Row) -> AuthzRecord:
        return AuthzRecord(
            id=row["id"],
            order_id=row["order_id"],
            account_id=row["account_id"],
            ident_type=row["ident_type"],
            ident_value=row["ident_value"],
            status=row["status"],
            expires_at=row["expires_at"],
            validated_at=row["validated_at"],
        )

    def get_authz(self, authz_id: str) -> AuthzRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM acme_authorizations WHERE id = ?", (authz_id,)
            ).fetchone()
        return None if row is None else self._row_to_authz(row)

    def list_challenges_for_authz(self, authz_id: str) -> list[ChallengeRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM acme_challenges WHERE authz_id = ? ORDER BY id",
                (authz_id,),
            ).fetchall()
        return [self._row_to_challenge(row) for row in rows]

    def get_challenge(self, challenge_id: str) -> ChallengeRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM acme_challenges WHERE id = ?", (challenge_id,)
            ).fetchone()
        return None if row is None else self._row_to_challenge(row)

    @staticmethod
    def _row_to_challenge(row: sqlite3.Row) -> ChallengeRecord:
        return ChallengeRecord(
            id=row["id"],
            authz_id=row["authz_id"],
            type=row["type"],
            token=row["token"],
            status=row["status"],
            validated_at=row["validated_at"],
        )

    def mark_challenge_valid(self, challenge_id: str, now_iso: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "UPDATE acme_challenges SET status = ?, validated_at = ? "
                    "WHERE id = ? AND status != ?",
                    (STATUS_VALID, now_iso, challenge_id, STATUS_VALID),
                )
                conn.execute(
                    "UPDATE acme_authorizations SET status = ?, validated_at = ? "
                    "WHERE id = (SELECT authz_id FROM acme_challenges WHERE id = ?)"
                    " AND status != ?",
                    (STATUS_VALID, now_iso, challenge_id, STATUS_VALID),
                )
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    # --------------------------------------------------------------- finalize

    def finalize_order(
        self,
        order_id: str,
        csr_der: bytes,
        dns_names: list[str],
        days: int,
        sign: SignCallback,
        now_iso: str,
        log_store: object | None = None,
    ) -> tuple[OrderRecord, CertificateRecordShim]:
        """Finalize an order and issue its certificate in one transaction.

        Same order + same CSR replays the original certificate; same order
        with a different CSR raises :class:`OrderConflict`. A signing/insert
        failure rolls the whole transaction back. When ``log_store`` is
        given, the transparency log leaf is appended in the same
        transaction.
        """
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM acme_orders WHERE id = ?", (order_id,)
                ).fetchone()
                if row is None:
                    raise OrderNotFound(f"unknown order: {order_id}")
                order = self._row_to_order(row)
                if order.cert_serial_hex is not None:
                    if order.csr_der != csr_der:
                        raise OrderConflict(
                            "order was already finalized with a different CSR"
                        )
                    cert_row = conn.execute(
                        "SELECT * FROM certificates WHERE serial_hex = ?",
                        (order.cert_serial_hex,),
                    ).fetchone()
                    conn.execute("ROLLBACK")
                    return order, _cert_row_to_pem(cert_row)

                for _ in range(5):
                    serial = x509.random_serial_number()
                    serial_hex = format(serial, "x")
                    cert_pem, san, not_before, not_after = sign(serial)
                    try:
                        conn.execute(
                            "INSERT INTO certificates("
                            "serial_hex, csr_der, days, cert_pem, san, "
                            "not_before, not_after) VALUES(?,?,?,?,?,?,?)",
                            (
                                serial_hex,
                                csr_der,
                                days,
                                cert_pem,
                                ",".join(san),
                                not_before,
                                not_after,
                            ),
                        )
                    except sqlite3.IntegrityError:
                        continue
                    idempotency_key = f"acme-order:{order_id}"
                    conn.execute(
                        "INSERT INTO idempotency("
                        "idempotency_key, serial_hex, csr_der, days) "
                        "VALUES(?,?,?,?)",
                        (idempotency_key, serial_hex, csr_der, days),
                    )
                    conn.execute(
                        "UPDATE acme_orders SET status = ?, csr_der = ?, "
                        "cert_serial_hex = ?, updated_at = ? WHERE id = ?",
                        (STATUS_VALID, csr_der, serial_hex, now_iso, order_id),
                    )
                    if log_store is not None:
                        from .log_store import pem_to_der

                        log_store.append_certificate(
                            conn, serial_hex, pem_to_der(cert_pem)
                        )
                    conn.execute("COMMIT")
                    final_order = self._row_to_order(
                        conn.execute(
                            "SELECT * FROM acme_orders WHERE id = ?", (order_id,)
                        ).fetchone()
                    )
                    return final_order, CertificateRecordShim(
                        serial_hex=serial_hex, cert_pem=cert_pem
                    )
                conn.execute("ROLLBACK")
                raise AcmeStoreError(
                    "could not allocate a unique certificate serial"
                )
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise


@dataclass(frozen=True)
class CertificateRecordShim:
    serial_hex: str
    cert_pem: str


def _cert_row_to_pem(row: sqlite3.Row) -> CertificateRecordShim:
    return CertificateRecordShim(
        serial_hex=row["serial_hex"], cert_pem=row["cert_pem"]
    )
