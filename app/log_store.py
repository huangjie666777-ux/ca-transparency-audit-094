"""SQLite persistence for the RFC 6962 transparency log.

The log lives in the same SQLite database as the certificates so that an
issuance and its log entry commit atomically. Leaves are appended in index
order starting at 0; tree nodes are persisted and only the nodes on the
path of a new leaf are written. Non-full trees are supported: roots and
proofs are computed from the stored nodes, never by re-reading the whole
leaf set.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import merkle

LOG_META_LOG_ID = "log_id"
LOG_META_PUBLIC_KEY = "log_public_key"


class LogStoreError(RuntimeError):
    pass


class LogNotInitialized(LogStoreError):
    pass


class LogKeyMismatch(LogStoreError):
    pass


@dataclass(frozen=True)
class TreeHead:
    tree_size: int
    root: bytes


@dataclass(frozen=True)
class InclusionProof:
    leaf_index: int
    tree_size: int
    leaf_hash: bytes
    proof: list[bytes]
    root: bytes


@dataclass(frozen=True)
class ConsistencyProof:
    old_size: int
    new_size: int
    old_root: bytes
    new_root: bytes
    proof: list[bytes]


SCHEMA = """
CREATE TABLE IF NOT EXISTS log_meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS log_leaves (
    leaf_index INTEGER PRIMARY KEY,
    serial_hex TEXT NOT NULL UNIQUE,
    cert_der BLOB NOT NULL,
    leaf_hash BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS log_nodes (
    level INTEGER NOT NULL,
    node_index INTEGER NOT NULL,
    hash BLOB NOT NULL,
    PRIMARY KEY (level, node_index)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS log_heads (
    tree_size INTEGER PRIMARY KEY,
    root BLOB NOT NULL,
    created_at TEXT NOT NULL
);
"""


def pem_to_der(cert_pem: str) -> bytes:
    return x509.load_pem_x509_certificate(cert_pem.encode("ascii")).public_bytes(
        serialization.Encoding.DER
    )


class LogStore:
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

    # ------------------------------------------------------------------ meta

    def is_initialized(self) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM log_meta WHERE key = ?", (LOG_META_LOG_ID,)
            ).fetchone()
        return row is not None

    def get_meta(self, key: str) -> bytes | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM log_meta WHERE key = ?", (key,)
            ).fetchone()
        return None if row is None else bytes(row["value"])

    def initialize_genesis(
        self, log_id: bytes, public_key: bytes, now_iso: str
    ) -> None:
        """Create the empty log (size 0) with its identity, in one transaction."""
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if self.is_initialized_on(conn):
                    raise LogStoreError("log is already initialized")
                conn.execute(
                    "INSERT INTO log_meta(key, value) VALUES(?, ?)",
                    (LOG_META_LOG_ID, log_id),
                )
                conn.execute(
                    "INSERT INTO log_meta(key, value) VALUES(?, ?)",
                    (LOG_META_PUBLIC_KEY, public_key),
                )
                conn.execute(
                    "INSERT INTO log_heads(tree_size, root, created_at) "
                    "VALUES(?, ?, ?)",
                    (0, merkle.empty_tree_hash(), now_iso),
                )
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    @staticmethod
    def is_initialized_on(conn: sqlite3.Connection) -> bool:
        row = conn.execute(
            "SELECT 1 FROM log_meta WHERE key = ?", (LOG_META_LOG_ID,)
        ).fetchone()
        return row is not None

    # ------------------------------------------------------------- migration

    def migrate_legacy_certificates(
        self, public_key: bytes, now_iso: str
    ) -> int:
        """Build the log for certificates that predate the audit feature.

        Certificates are ordered by serial number, numerically ascending
        (serial_hex is lowercase hex without leading zeroes, so ordering by
        length then text is the numeric order). The whole batch commits or
        rolls back together. Returns the number of migrated certificates;
        with zero certificates the log is left uninitialized so the caller
        can run the empty-tree genesis.
        """
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if self.is_initialized_on(conn):
                    raise LogStoreError("log is already initialized")
                rows = conn.execute(
                    "SELECT serial_hex, cert_pem FROM certificates "
                    "ORDER BY LENGTH(serial_hex), serial_hex"
                ).fetchall()
                if not rows:
                    conn.execute("ROLLBACK")
                    return 0
                for row in rows:
                    self._append_on_conn(
                        conn, row["serial_hex"], pem_to_der(row["cert_pem"])
                    )
                # Bind the log identity and signing key only after the batch
                # succeeds, so a failure rolls back the whole migration.
                import secrets

                conn.execute(
                    "INSERT INTO log_meta(key, value) VALUES(?, ?)",
                    (LOG_META_LOG_ID, secrets.token_bytes(16)),
                )
                conn.execute(
                    "INSERT INTO log_meta(key, value) VALUES(?, ?)",
                    (LOG_META_PUBLIC_KEY, public_key),
                )
                conn.execute("COMMIT")
                return len(rows)
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    # -------------------------------------------------------------- appends

    def append_certificate(
        self, conn: sqlite3.Connection, serial_hex: str, cert_der: bytes
    ) -> int:
        """Append a certificate leaf on an existing write transaction.

        Must be called inside a BEGIN IMMEDIATE transaction. The leaf index
        is allocated from the current maximum, so concurrent appenders
        (serialized by the write lock) can never duplicate or skip an index.
        """
        return self._append_on_conn(conn, serial_hex, cert_der)

    @staticmethod
    def _append_on_conn(
        conn: sqlite3.Connection, serial_hex: str, cert_der: bytes
    ) -> int:
        row = conn.execute(
            "SELECT COALESCE(MAX(leaf_index), -1) + 1 AS next_index "
            "FROM log_leaves"
        ).fetchone()
        next_index = row["next_index"]
        leaf_hash_value = merkle.leaf_hash(cert_der)
        conn.execute(
            "INSERT INTO log_leaves(leaf_index, serial_hex, cert_der, leaf_hash) "
            "VALUES(?, ?, ?, ?)",
            (next_index, serial_hex, cert_der, leaf_hash_value),
        )
        # Level 0 is the leaf itself.
        conn.execute(
            "INSERT INTO log_nodes(level, node_index, hash) VALUES(?, ?, ?)",
            (0, next_index, leaf_hash_value),
        )
        # Bubble up: a parent exists at level l when bit l of next_index is 1.
        cur = leaf_hash_value
        i = next_index
        level = 0
        while i & 1:
            sibling = conn.execute(
                "SELECT hash FROM log_nodes WHERE level = ? AND node_index = ?",
                (level, i - 1),
            ).fetchone()
            if sibling is None:
                raise LogStoreError(
                    f"missing sibling node at level {level} index {i - 1}"
                )
            cur = merkle.node_hash(bytes(sibling["hash"]), cur)
            i >>= 1
            level += 1
            conn.execute(
                "INSERT INTO log_nodes(level, node_index, hash) VALUES(?, ?, ?)",
                (level, i, cur),
            )
        # Persist the root for the new tree size.
        root = LogStore._compute_root_on(conn, next_index + 1)
        conn.execute(
            "INSERT INTO log_heads(tree_size, root, created_at) VALUES(?, ?, ?)",
            (next_index + 1, root, _utcnow_iso()),
        )
        return next_index

    # --------------------------------------------------------------- reads

    def latest_size(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT MAX(tree_size) AS size FROM log_heads"
            ).fetchone()
        size = row["size"]
        if size is None:
            raise LogNotInitialized("log has no tree heads")
        return size

    def head(self, tree_size: int | None = None) -> TreeHead:
        with self._connect() as conn:
            if tree_size is None:
                row = conn.execute(
                    "SELECT tree_size, root FROM log_heads "
                    "ORDER BY tree_size DESC LIMIT 1"
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT tree_size, root FROM log_heads WHERE tree_size = ?",
                    (tree_size,),
                ).fetchone()
            if row is None:
                raise LogNotInitialized(f"no tree head for size {tree_size}")
            return TreeHead(tree_size=row["tree_size"], root=bytes(row["root"]))

    def leaf_count(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM log_leaves"
            ).fetchone()
        return row["n"]

    def get_leaf(self, leaf_index: int) -> bytes:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT cert_der FROM log_leaves WHERE leaf_index = ?",
                (leaf_index,),
            ).fetchone()
        if row is None:
            raise IndexError(f"no leaf at index {leaf_index}")
        return bytes(row["cert_der"])

    # ----------------------------------------------------------- proofs

    def inclusion_proof(
        self, leaf_index: int, tree_size: int | None = None
    ) -> InclusionProof:
        """Build an inclusion proof, reading everything in one snapshot."""
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN")
            try:
                head = self._head_on(conn, tree_size)
                if leaf_index < 0 or leaf_index >= head.tree_size:
                    raise IndexError(
                        f"leaf index {leaf_index} is out of range for "
                        f"tree size {head.tree_size}"
                    )
                leaf_row = conn.execute(
                    "SELECT leaf_hash FROM log_leaves WHERE leaf_index = ?",
                    (leaf_index,),
                ).fetchone()
                if leaf_row is None:
                    raise LogStoreError(f"missing leaf {leaf_index}")
                proof = self._inclusion_path_on(
                    conn, leaf_index, head.tree_size
                )
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        return InclusionProof(
            leaf_index=leaf_index,
            tree_size=head.tree_size,
            leaf_hash=bytes(leaf_row["leaf_hash"]),
            proof=proof,
            root=head.root,
        )

    def consistency_proof(
        self, old_size: int, new_size: int | None = None
    ) -> ConsistencyProof:
        """Build a consistency proof, reading everything in one snapshot."""
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN")
            try:
                new_head = self._head_on(conn, new_size)
                if old_size < 0 or old_size > new_head.tree_size:
                    raise IndexError(
                        f"old size {old_size} is out of range for "
                        f"tree size {new_head.tree_size}"
                    )
                old_head = self._head_on(conn, old_size)
                proof = self._consistency_path_on(
                    conn, old_size, new_head.tree_size
                )
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        return ConsistencyProof(
            old_size=old_size,
            new_size=new_head.tree_size,
            old_root=old_head.root,
            new_root=new_head.root,
            proof=proof,
        )

    @staticmethod
    def _head_on(conn: sqlite3.Connection, tree_size: int | None) -> TreeHead:
        if tree_size is None:
            row = conn.execute(
                "SELECT tree_size, root FROM log_heads "
                "ORDER BY tree_size DESC LIMIT 1"
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT tree_size, root FROM log_heads WHERE tree_size = ?",
                (tree_size,),
            ).fetchone()
        if row is None:
            raise LogNotInitialized(f"no tree head for size {tree_size}")
        return TreeHead(tree_size=row["tree_size"], root=bytes(row["root"]))

    @staticmethod
    def _node_on(
        conn: sqlite3.Connection, level: int, node_index: int, max_size: int
    ) -> bytes:
        """Read a stored node, rejecting reads that exceed the tree size."""
        # A node at (level, index) spans leaves
        # [index * 2^level, (index + 1) * 2^level); it may only be used when
        # that whole range is within the tree being proved.
        if (node_index + 1) * (1 << level) > max_size:
            raise LogStoreError(
                f"node ({level}, {node_index}) is not complete within "
                f"tree size {max_size}"
            )
        row = conn.execute(
            "SELECT hash FROM log_nodes WHERE level = ? AND node_index = ?",
            (level, node_index),
        ).fetchone()
        if row is None:
            raise LogStoreError(f"missing node at level {level} index {node_index}")
        return bytes(row["hash"])

    @staticmethod
    def _leaf_hash_on(conn: sqlite3.Connection, index: int) -> bytes:
        row = conn.execute(
            "SELECT leaf_hash FROM log_leaves WHERE leaf_index = ?", (index,)
        ).fetchone()
        if row is None:
            raise LogStoreError(f"missing leaf {index}")
        return bytes(row["leaf_hash"])

    @classmethod
    def _range_hash_on(
        cls, conn: sqlite3.Connection, a: int, b: int, max_size: int
    ) -> bytes:
        """MTH over leaves [a, b), read from stored nodes in one snapshot."""
        n = b - a
        if n == 0:
            return merkle.empty_tree_hash()
        if n == 1:
            return cls._leaf_hash_on(conn, a)
        k = merkle.largest_power_of_two_less_than(n)
        return merkle.node_hash(
            cls._range_hash_on(conn, a, a + k, max_size),
            cls._range_hash_on(conn, a + k, b, max_size),
        )

    @classmethod
    def _compute_root_on(cls, conn: sqlite3.Connection, tree_size: int) -> bytes:
        """MTH over leaves [0, tree_size), read from stored nodes."""
        if tree_size == 0:
            return merkle.empty_tree_hash()
        return cls._range_hash_on(conn, 0, tree_size, tree_size)

    @classmethod
    def _inclusion_path_on(
        cls,
        conn: sqlite3.Connection,
        leaf: int,
        tree_size: int,
        offset: int = 0,
    ) -> list[bytes]:
        """RFC 6962 section 2.1.1 PATH(m, D[n]).

        ``offset`` is the global leaf index of the first leaf in the
        current subtree, so proof-node reads use the correct indices.
        """
        if tree_size == 1:
            return []
        k = merkle.largest_power_of_two_less_than(tree_size)
        if leaf < k:
            return cls._inclusion_path_on(conn, leaf, k, offset) + [
                cls._range_hash_on(conn, offset + k, offset + tree_size, tree_size)
            ]
        return cls._inclusion_path_on(
            conn, leaf - k, tree_size - k, offset + k
        ) + [cls._range_hash_on(conn, offset, offset + k, tree_size)]

    @classmethod
    def _subproof_on(
        cls,
        conn: sqlite3.Connection,
        m: int,
        n: int,
        b: bool,
        offset: int,
        max_size: int,
    ) -> list[bytes]:
        """RFC 6962 section 2.1.2 SUBPROOF(m, D[n], b).

        ``b`` is true when the current subtree contains leaf 0 (the leftmost
        subtree). The base case with ``b=false`` includes the subtree's MTH
        as a proof node; ``b=true`` contributes nothing.
        """
        if m == n:
            if b:
                return []
            return [cls._range_hash_on(conn, offset, offset + m, max_size)]
        k = merkle.largest_power_of_two_less_than(n)
        if m <= k:
            return cls._subproof_on(conn, m, k, b, offset, max_size) + [
                cls._range_hash_on(conn, offset + k, offset + n, max_size)
            ]
        return cls._subproof_on(
            conn, m - k, n - k, False, offset + k, max_size
        ) + [cls._range_hash_on(conn, offset, offset + k, max_size)]

    @classmethod
    def _consistency_path_on(
        cls, conn: sqlite3.Connection, old_size: int, new_size: int
    ) -> list[bytes]:
        """RFC 6962 section 2.1.2 PROOF(m, D[n])."""
        if old_size == 0:
            return []
        return cls._subproof_on(conn, old_size, new_size, True, 0, new_size)


def _utcnow_iso() -> str:
    import datetime as dt

    return dt.datetime.now(dt.timezone.utc).isoformat()
