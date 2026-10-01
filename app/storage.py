"""SQLite persistence for certificates, idempotency keys and CRL state."""

from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import dataclass
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import random_serial_number

DB_FILE = "ca.sqlite3"
STATUS_VALID = "valid"
STATUS_REVOKED = "revoked"


class StoreError(RuntimeError):
    pass


class IdempotencyConflict(StoreError):
    def __init__(self, serial_hex: str):
        super().__init__("idempotency key was already used with different input")
        self.serial_hex = serial_hex


class CertificateNotFound(StoreError):
    pass


class RevocationReasonConflict(StoreError):
    def __init__(self, existing_reason: str, new_reason: str):
        super().__init__(
            f"certificate already revoked with reason {existing_reason!r}, "
            f"cannot change to {new_reason!r}"
        )
        self.existing_reason = existing_reason
        self.new_reason = new_reason


@dataclass(frozen=True)
class CertificateRecord:
    serial_hex: str
    cert_pem: str
    csr_der: bytes
    days: int
    san: list[str]
    not_before: str
    not_after: str
    status: str
    revoked_at: str | None
    reason: str | None


@dataclass(frozen=True)
class RevokedRecord:
    serial: int
    revoked_at: str
    reason: str


@dataclass(frozen=True)
class IssueResult:
    record: CertificateRecord
    replayed: bool


SignCallback = Callable[[int], tuple[str, list[str], str, str]]
BuildCrlCallback = Callable[[list[RevokedRecord], int, str], str]


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS certificates (
    serial_hex TEXT PRIMARY KEY,
    csr_der BLOB NOT NULL,
    days INTEGER NOT NULL,
    cert_pem TEXT NOT NULL,
    san TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'valid',
    revoked_at TEXT,
    reason TEXT
);
CREATE TABLE IF NOT EXISTS idempotency (
    idempotency_key TEXT PRIMARY KEY,
    serial_hex TEXT NOT NULL,
    csr_der BLOB NOT NULL,
    days INTEGER NOT NULL,
    FOREIGN KEY (serial_hex) REFERENCES certificates(serial_hex)
);
CREATE TABLE crl_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    number INTEGER NOT NULL,
    crl_pem TEXT NOT NULL,
    published_at TEXT NOT NULL
);
"""


class CAStore:
    def __init__(self, data_dir: str):
        self._db_path = os.path.join(data_dir, DB_FILE)
        self._lock = threading.RLock()

    def _ensure_dir(self) -> None:
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)

    def exists(self) -> bool:
        return os.path.exists(self._db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    def initialize(self, ca: object) -> None:
        """Create schema and bind the database to the given CA certificate."""
        fingerprint = ca.cert.fingerprint(hashes.SHA256())  # type: ignore[attr-defined]
        self._ensure_dir()
        with self._lock, self._connect() as conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?)",
                ("ca_sha256_fingerprint", fingerprint),
            )

    def load_ca_fingerprint(self) -> bytes:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'ca_sha256_fingerprint'"
            ).fetchone()
        if row is None:
            raise StoreError("database is missing the CA fingerprint")
        return bytes(row["value"])

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> CertificateRecord:
        return CertificateRecord(
            serial_hex=row["serial_hex"],
            cert_pem=row["cert_pem"],
            csr_der=bytes(row["csr_der"]),
            days=row["days"],
            san=[part for part in row["san"].split(",") if part],
            not_before=row["not_before"],
            not_after=row["not_after"],
            status=row["status"],
            revoked_at=row["revoked_at"],
            reason=row["reason"],
        )

    def get_certificate(self, serial_hex: str) -> CertificateRecord:
        normalized = serial_hex.lower().strip()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE serial_hex = ?",
                (normalized,),
            ).fetchone()
        if row is None:
            raise CertificateNotFound(f"unknown certificate serial: {serial_hex}")
        return self._row_to_record(row)

    def issue_certificate(
        self,
        idempotency_key: str,
        csr_der: bytes,
        days: int,
        sign: SignCallback,
        log_store: object | None = None,
    ) -> IssueResult:
        """Idempotently persist a certificate.

        Same key + same CSR DER + same days replays the original certificate;
        same key with different content raises IdempotencyConflict.
        A process-wide lock plus one transaction guarantees one record even
        under concurrent retries; a signing/insert failure leaves nothing.
        When ``log_store`` is given, the transparency log leaf is appended
        in the same transaction, so a failure rolls back both.
        """
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = conn.execute(
                    "SELECT * FROM idempotency WHERE idempotency_key = ?",
                    (idempotency_key,),
                ).fetchone()
                if existing is not None:
                    if (
                        bytes(existing["csr_der"]) == csr_der
                        and existing["days"] == days
                    ):
                        row = conn.execute(
                            "SELECT * FROM certificates WHERE serial_hex = ?",
                            (existing["serial_hex"],),
                        ).fetchone()
                        return IssueResult(self._row_to_record(row), replayed=True)
                    raise IdempotencyConflict(existing["serial_hex"])

                for _ in range(5):
                    serial = random_serial_number()
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
                        # Vanishingly unlikely serial collision: try again.
                        continue
                    conn.execute(
                        "INSERT INTO idempotency("
                        "idempotency_key, serial_hex, csr_der, days) "
                        "VALUES(?,?,?,?)",
                        (
                            idempotency_key,
                            serial_hex,
                            csr_der,
                            days,
                        ),
                    )
                    if log_store is not None:
                        from .log_store import pem_to_der

                        log_store.append_certificate(
                            conn, serial_hex, pem_to_der(cert_pem)
                        )
                    conn.execute("COMMIT")
                    row = conn.execute(
                        "SELECT * FROM certificates WHERE serial_hex = ?",
                        (serial_hex,),
                    ).fetchone()
                    return IssueResult(self._row_to_record(row), replayed=False)
                conn.execute("ROLLBACK")
                raise StoreError("could not allocate a unique certificate serial")
            except BaseException:
                # Roll back unless the transaction already ended (commit error).
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def revoke(
        self, serial_hex: str, reason: str, now_iso: str
    ) -> tuple[CertificateRecord, bool]:
        """Revoke a certificate. Returns (record, changed_now).

        First revocation time/reason are preserved forever. Repeating with
        the same reason is idempotent; a different reason raises a conflict.
        """
        normalized = serial_hex.lower().strip()
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM certificates WHERE serial_hex = ?",
                    (normalized,),
                ).fetchone()
                if row is None:
                    raise CertificateNotFound(
                        f"unknown certificate serial: {serial_hex}"
                    )
                if row["status"] == STATUS_REVOKED:
                    if row["reason"] != reason:
                        raise RevocationReasonConflict(row["reason"], reason)
                    record = self._row_to_record(row)
                    return record, False
                conn.execute(
                    "UPDATE certificates SET status = ?, revoked_at = ?, "
                    "reason = ? WHERE serial_hex = ?",
                    (STATUS_REVOKED, now_iso, reason, normalized),
                )
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            row = conn.execute(
                "SELECT * FROM certificates WHERE serial_hex = ?", (normalized,)
            ).fetchone()
            return self._row_to_record(row), True

    def list_revoked(self) -> list[RevokedRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT serial_hex, revoked_at, reason FROM certificates "
                "WHERE status = ? ORDER BY revoked_at",
                (STATUS_REVOKED,),
            ).fetchall()
        return [
            RevokedRecord(
                serial=int(row["serial_hex"], 16),
                revoked_at=row["revoked_at"],
                reason=row["reason"],
            )
            for row in rows
        ]

    def publish_crl(self, build: BuildCrlCallback) -> tuple[str, int]:
        """Atomically bump the persisted CRL number and store the new CRL."""
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT number FROM crl_state WHERE id = 1"
                ).fetchone()
                number = (row["number"] if row is not None else 0) + 1
                now_iso = _utcnow_iso()
                entries = [
                    RevokedRecord(
                        serial=int(r["serial_hex"], 16),
                        revoked_at=r["revoked_at"],
                        reason=r["reason"],
                    )
                    for r in conn.execute(
                        "SELECT serial_hex, revoked_at, reason FROM certificates "
                        "WHERE status = ? ORDER BY revoked_at",
                        (STATUS_REVOKED,),
                    ).fetchall()
                ]
                crl_pem = build(entries, number, now_iso)
                conn.execute(
                    "INSERT INTO crl_state(id, number, crl_pem, published_at) "
                    "VALUES(1, ?, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET number = excluded.number, "
                    "crl_pem = excluded.crl_pem, "
                    "published_at = excluded.published_at",
                    (number, crl_pem, now_iso),
                )
                conn.execute("COMMIT")
                return crl_pem, number
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def get_current_crl(self) -> tuple[str, int] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT crl_pem, number FROM crl_state WHERE id = 1"
            ).fetchone()
        if row is None:
            return None
        return row["crl_pem"], row["number"]


def _utcnow_iso() -> str:
    import datetime as dt

    return dt.datetime.now(dt.timezone.utc).isoformat()
