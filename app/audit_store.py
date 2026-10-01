"""Append-only certificate transparency audit log (RFC 6962 subset).

All audit tables live in the same SQLite file as the CA/ACME tables so a
certificate, its ACME order linkage and its log leaf commit in one
transaction. The Merkle tree is *persisted*:

* ``audit_leaves``  - one row per logged certificate (index from 0);
* ``audit_nodes``   - every finalized level/index node hash; an append only
                      materializes the O(log n) nodes on its promotion path;
* ``audit_sth``     - the signed tree head for every committed size, so
                      historical roots survive a restart;
* ``audit_meta``    - the fixed log identity (SHA-256 of the Ed25519 key)
                      and the current tree size.

Roots and proofs are answered from persisted nodes only; the full leaf table
is never rescanned to rebuild a tree.
"""

from __future__ import annotations

import datetime as dt
import os
import sqlite3
import threading

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import merkle
from .audit_key import LogSigner, load_or_create_log_key
from .audit_wire import build_head_input

META_LOG_ID = "log_id"
META_SIZE = "current_size"


class AuditError(RuntimeError):
    pass


class TreeSizeUnavailable(AuditError):
    """Requested tree size was never committed."""


SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_leaves (
    leaf_index INTEGER PRIMARY KEY,
    cert_serial_hex TEXT NOT NULL UNIQUE,
    leaf_hash BLOB NOT NULL,
    cert_der BLOB NOT NULL,
    FOREIGN KEY (cert_serial_hex) REFERENCES certificates(serial_hex)
);
CREATE TABLE IF NOT EXISTS audit_nodes (
    level INTEGER NOT NULL,
    node_index INTEGER NOT NULL,
    hash BLOB NOT NULL,
    PRIMARY KEY (level, node_index)
);
CREATE TABLE IF NOT EXISTS audit_sth (
    tree_size INTEGER PRIMARY KEY,
    root_hash BLOB NOT NULL,
    signature BLOB NOT NULL,
    timestamp TEXT NOT NULL
);
"""


def _utcnow_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def cert_pem_to_der(cert_pem: str) -> bytes:
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    return cert.public_bytes(serialization.Encoding.DER)


class AuditLog:
    def __init__(self, data_dir: str):
        self._db_path = os.path.join(data_dir, "ca.sqlite3")
        self._lock = threading.RLock()
        self._signer: LogSigner | None = None

    # ----------------------------------------------------------- connections
    def _connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        conn = sqlite3.connect(self._db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    @property
    def signer(self) -> LogSigner:
        if self._signer is None:
            raise AuditError("audit log has not been bootstrapped yet")
        return self._signer

    @property
    def log_id(self) -> bytes:
        return self.signer.log_id

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _meta(conn: sqlite3.Connection, key: str) -> bytes | None:
        row = conn.execute(
            "SELECT value FROM audit_meta WHERE key = ?", (key,)
        ).fetchone()
        return None if row is None else bytes(row["value"])

    @staticmethod
    def _set_meta(conn: sqlite3.Connection, key: str, value: bytes) -> None:
        conn.execute(
            "INSERT INTO audit_meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def _node(self, conn: sqlite3.Connection, level: int, index: int) -> bytes:
        row = conn.execute(
            "SELECT hash FROM audit_nodes WHERE level = ? AND node_index = ?",
            (level, index),
        ).fetchone()
        if row is None:
            raise AuditError(f"missing persisted tree node ({level},{index})")
        return bytes(row["hash"])

    def _root_for_size(self, conn: sqlite3.Connection, size: int) -> bytes:
        """Reconstruct MTH for any committed size from persisted nodes only."""
        if size == 0:
            return merkle.EMPTY_TREE_HASH
        # Decompose into finalized perfect subtrees, highest block first,
        # then fold from the right to match the RFC 6962 MTH split order.
        roots: list[bytes] = []
        start = 0
        for level in range(size.bit_length() - 1, -1, -1):
            if size & (1 << level):
                roots.append(self._node(conn, level, start >> level))
                start += 1 << level
        acc = roots[-1]
        for node_hash in reversed(roots[:-1]):
            acc = merkle.hash_nodes(node_hash, acc)
        return acc

    def _sign_head(
        self, size: int, root_hash: bytes, timestamp: str
    ) -> bytes:
        return self.signer.sign(
            build_head_input(self.signer.log_id, size, root_hash)
        )

    def _store_head(
        self, conn: sqlite3.Connection, size: int, timestamp: str
    ) -> bytes:
        root_hash = self._root_for_size(conn, size)
        signature = self._sign_head(size, root_hash, timestamp)
        conn.execute(
            "INSERT INTO audit_sth(tree_size, root_hash, signature, timestamp) "
            "VALUES(?,?,?,?)",
            (size, root_hash, signature, timestamp),
        )
        self._set_meta(conn, META_SIZE, str(size).encode("ascii"))
        return root_hash

    # ------------------------------------------------------------- append API
    def append_within_txn(
        self, conn: sqlite3.Connection, cert_serial_hex: str, cert_pem: str
    ) -> int:
        """Append one leaf using the caller's open write transaction.

        Must be called inside the same BEGIN IMMEDIATE transaction that
        inserts the certificate (and ACME order link). Allocates the next
        contiguous index and materializes only the promotion-path nodes.
        Returns the new leaf index. Raising rolls the whole issuance back.
        """
        der = cert_pem_to_der(cert_pem)
        leaf_hash = merkle.hash_leaf(der)
        row = conn.execute(
            "SELECT COALESCE(MAX(leaf_index), -1) + 1 AS next_index "
            "FROM audit_leaves"
        ).fetchone()
        index = int(row["next_index"])

        conn.execute(
            "INSERT INTO audit_leaves("
            "leaf_index, cert_serial_hex, leaf_hash, cert_der) "
            "VALUES(?,?,?,?)",
            (index, cert_serial_hex, leaf_hash, der),
        )
        conn.execute(
            "INSERT INTO audit_nodes(level, node_index, hash) VALUES(0,?,?)",
            (index, leaf_hash),
        )
        level = 0
        node_index = index
        node_hash = leaf_hash
        # Promote while this node completes a pair: only O(log n) new rows.
        while node_index & 1:
            left = self._node(conn, level, node_index - 1)
            node_hash = merkle.hash_nodes(left, node_hash)
            node_index >>= 1
            level += 1
            conn.execute(
                "INSERT INTO audit_nodes(level, node_index, hash) VALUES(?,?,?)",
                (level, node_index, node_hash),
            )
        self._store_head(conn, index + 1, _utcnow_iso())
        return index

    # -------------------------------------------------------------- bootstrap
    def bootstrap(self) -> None:
        """Create schema/key, perform the one-time legacy migration, verify.

        Runs once at startup before issuance is served. Legacy certificates
        already in ``certificates`` are logged in ascending numeric serial
        order inside a single transaction; any failure rolls the whole batch
        back. On restart the persisted identity, indices and roots are only
        checked, never rebuilt.
        """
        with self._lock, self._connect() as conn:
            # DDL first: executescript() implicitly commits, so it must not
            # run inside the migration transaction.
            conn.executescript(SCHEMA)
            conn.execute("BEGIN IMMEDIATE")
            try:
                log_id = self._meta(conn, META_LOG_ID)
                if log_id is None:
                    self._initialize_fresh(conn)
                else:
                    self._signer = load_or_create_log_key(
                        os.path.dirname(self._db_path), log_id
                    )
                    self._verify_persisted_state(conn)
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def _initialize_fresh(self, conn: sqlite3.Connection) -> None:
        # Either a brand-new database or an old CA database that predates the
        # audit log. Mint (or reuse) the independent log key first so the log
        # identity is fixed before any leaf exists.
        self._signer = load_or_create_log_key(
            os.path.dirname(self._db_path), None
        )
        self._set_meta(conn, META_LOG_ID, self._signer.log_id)

        # One-time backfill: legacy certificates ordered by numeric serial.
        legacy = conn.execute(
            "SELECT serial_hex, cert_pem FROM certificates"
        ).fetchall()
        ordered = sorted(legacy, key=lambda r: int(r["serial_hex"], 16))
        for row in ordered:
            self.append_within_txn(conn, row["serial_hex"], row["cert_pem"])
        if not ordered:
            # Signed empty-tree head so size 0 is a verifiable snapshot too.
            self._store_head(conn, 0, _utcnow_iso())

    def _verify_persisted_state(self, conn: sqlite3.Connection) -> None:
        size_value = self._meta(conn, META_SIZE)
        leaf_count = conn.execute(
            "SELECT COUNT(*) AS c, COALESCE(MAX(leaf_index), -1) AS max_index, "
            "COALESCE(MIN(leaf_index), 0) AS min_index FROM audit_leaves"
        ).fetchone()
        count, max_index, min_index = (
            int(leaf_count["c"]),
            int(leaf_count["max_index"]),
            int(leaf_count["min_index"]),
        )
        if count > 0 and (min_index != 0 or max_index != count - 1):
            raise AuditError("audit leaf indices are not contiguous from 0")
        size = 0 if size_value is None else int(size_value.decode("ascii"))
        if size != count:
            raise AuditError("persisted tree size does not match leaf count")
        # Root recomputation touches only O(log n) finalized nodes.
        recomputed = self._root_for_size(conn, size)
        sth_row = conn.execute(
            "SELECT root_hash, signature FROM audit_sth WHERE tree_size = ?",
            (size,),
        ).fetchone()
        if sth_row is None:
            raise AuditError("current tree size has no stored tree head")
        if bytes(sth_row["root_hash"]) != recomputed:
            raise AuditError("persisted root does not match the tree nodes")
        self.signer.verify(
            bytes(sth_row["signature"]),
            build_head_input(self.log_id, size, recomputed),
        )

    # ------------------------------------------------------------------ reads
    def _begin_read(self, conn: sqlite3.Connection) -> None:
        # A deferred transaction pins one WAL read snapshot for every SELECT
        # in the call, so a proof and its signed head come from the same
        # commit even if an append lands concurrently.
        conn.execute("BEGIN")

    @staticmethod
    def _current_size_locked(conn: sqlite3.Connection) -> int:
        value = AuditLog._meta(conn, META_SIZE)
        return 0 if value is None else int(value.decode("ascii"))

    def current_size(self) -> int:
        with self._connect() as conn:
            return self._current_size_locked(conn)

    def get_sth(self, size: int | None = None) -> tuple[int, bytes, bytes, str]:
        """Return (size, root_hash, signature, timestamp) for a committed size."""
        with self._lock, self._connect() as conn:
            self._begin_read(conn)
            try:
                current = self._current_size_locked(conn)
                wanted = current if size is None else size
                if wanted < 0 or wanted > current:
                    raise TreeSizeUnavailable(
                        f"tree size {wanted} is not available (current {current})"
                    )
                row = conn.execute(
                    "SELECT root_hash, signature, timestamp FROM audit_sth "
                    "WHERE tree_size = ?",
                    (wanted,),
                ).fetchone()
                if row is None:
                    raise TreeSizeUnavailable(
                        f"no stored tree head for size {wanted}"
                    )
                return (
                    wanted,
                    bytes(row["root_hash"]),
                    bytes(row["signature"]),
                    row["timestamp"],
                )
            finally:
                conn.execute("COMMIT")

    def get_leaf(self, leaf_index: int, tree_size: int) -> tuple[bytes, bytes]:
        """Return (cert_der, leaf_hash) read from one committed snapshot."""
        with self._lock, self._connect() as conn:
            self._begin_read(conn)
            try:
                return self._leaf_snapshot(conn, leaf_index, tree_size)[:2]
            finally:
                conn.execute("COMMIT")

    def _resolve_size(
        self, conn: sqlite3.Connection, tree_size: int | None
    ) -> int:
        return (
            self._current_size_locked(conn)
            if tree_size is None
            else tree_size
        )

    def _leaf_snapshot(
        self, conn: sqlite3.Connection, leaf_index: int, tree_size: int
    ) -> tuple[bytes, bytes, list[bytes], bytes, bytes, str]:
        """Leaf + inclusion path + signed head for one size, single snapshot."""
        self._require_committed_size(conn, tree_size)
        if tree_size == 0 or leaf_index < 0 or leaf_index >= tree_size:
            raise IndexError("leaf index out of range")
        leaf_row = conn.execute(
            "SELECT cert_der, leaf_hash FROM audit_leaves WHERE leaf_index = ?",
            (leaf_index,),
        ).fetchone()
        if leaf_row is None:
            raise IndexError("leaf index out of range")
        cert_der = bytes(leaf_row["cert_der"])
        leaf_hash = bytes(leaf_row["leaf_hash"])
        path = self._path(conn, leaf_index, 0, tree_size)
        root_hash = self._root_for_size(conn, tree_size)
        head = conn.execute(
            "SELECT root_hash, signature, timestamp FROM audit_sth "
            "WHERE tree_size = ?",
            (tree_size,),
        ).fetchone()
        if head is None or bytes(head["root_hash"]) != root_hash:
            raise AuditError("stored tree head disagrees with the snapshot")
        return (
            cert_der,
            leaf_hash,
            path,
            root_hash,
            bytes(head["signature"]),
            head["timestamp"],
        )

    def inclusion_snapshot(
        self, leaf_index: int, tree_size: int | None = None
    ) -> tuple[int, bytes, bytes, list[bytes], bytes, bytes, str]:
        """Resolve latest (if needed) and read all inclusion data in one txn."""
        with self._lock, self._connect() as conn:
            self._begin_read(conn)
            try:
                size = self._resolve_size(conn, tree_size)
                cert_der, leaf_hash, path, root, sig, ts = self._leaf_snapshot(
                    conn, leaf_index, size
                )
                return size, cert_der, leaf_hash, path, root, sig, ts
            finally:
                conn.execute("COMMIT")

    def inclusion_proof(
        self, leaf_index: int, tree_size: int
    ) -> tuple[list[bytes], bytes, bytes]:
        """Return (path, leaf_hash, root_hash) for index at a committed size.

        Leaf, nodes and root come from the same read snapshot; the returned
        root is exactly the one signed in the stored head for that size.
        """
        _size, _cert, leaf_hash, path, root_hash, _sig, _ts = (
            self.inclusion_snapshot(leaf_index, tree_size)
        )
        return path, leaf_hash, root_hash

    def consistency_snapshot(
        self, first: int, second: int | None = None
    ) -> tuple[int, list[bytes], bytes, bytes, bytes, str, bytes, str]:
        """Consistency path plus both signed heads from one read snapshot."""
        with self._lock, self._connect() as conn:
            self._begin_read(conn)
            try:
                second_size = self._resolve_size(conn, second)
                self._require_committed_size(conn, second_size)
                if first < 0 or first > second_size:
                    raise ValueError("invalid consistency size range")
                if first > 0:
                    self._require_committed_size(conn, first)
                path = (
                    []
                    if first == 0 or first == second_size
                    else self._subproof(conn, first, 0, second_size, True)
                )
                first_root = self._root_for_size(conn, first)
                second_root = self._root_for_size(conn, second_size)
                first_head = conn.execute(
                    "SELECT signature, timestamp FROM audit_sth "
                    "WHERE tree_size = ?",
                    (first,),
                ).fetchone()
                second_head = conn.execute(
                    "SELECT signature, timestamp FROM audit_sth "
                    "WHERE tree_size = ?",
                    (second_size,),
                ).fetchone()
                if first_head is None or second_head is None:
                    raise TreeSizeUnavailable(
                        "stored tree head missing for a size"
                    )
                return (
                    second_size,
                    path,
                    first_root,
                    bytes(first_head["signature"]),
                    first_head["timestamp"],
                    second_root,
                    bytes(second_head["signature"]),
                    second_head["timestamp"],
                )
            finally:
                conn.execute("COMMIT")

    def consistency_proof(
        self, first: int, second: int
    ) -> tuple[list[bytes], bytes, bytes]:
        """Return (path, first_root, second_root) for two committed sizes."""
        _second, path, first_root, _fs, _fts, second_root, _ss, _sts = (
            self.consistency_snapshot(first, second)
        )
        return path, first_root, second_root

    def _require_committed_size(
        self, conn: sqlite3.Connection, size: int
    ) -> None:
        if size < 0:
            raise ValueError("negative tree size")
        row = conn.execute(
            "SELECT 1 FROM audit_sth WHERE tree_size = ?", (size,)
        ).fetchone()
        if row is None:
            raise TreeSizeUnavailable(f"tree size {size} was never committed")

    # RFC 9162 §2.1.3.1 PATH. ``m`` is relative to the block starting at the
    # absolute leaf position ``start``; sibling subtree roots resolve from the
    # persisted nodes.
    def _path(
        self, conn: sqlite3.Connection, m: int, start: int, n: int
    ) -> list[bytes]:
        if n == 1:
            return []
        k = 1 << (n.bit_length() - 1)
        if k == n:
            k >>= 1
        if m < k:
            return self._path(conn, m, start, k) + [
                self._subtree_root(conn, start + k, n - k)
            ]
        return self._path(conn, m - k, start + k, n - k) + [
            self._subtree_root(conn, start, k)
        ]

    # RFC 9162 §2.1.4.1 SUBPROOF.
    def _subproof(
        self, conn: sqlite3.Connection, m: int, start: int, n: int, b: bool
    ) -> list[bytes]:
        if m == n:
            return [] if b else [self._subtree_root(conn, start, n)]
        k = 1 << (n.bit_length() - 1)
        if k == n:
            k >>= 1
        if m <= k:
            return self._subproof(conn, m, start, k, b) + [
                self._subtree_root(conn, start + k, n - k)
            ]
        return self._subproof(conn, m - k, start + k, n - k, False) + [
            self._subtree_root(conn, start, k)
        ]

    def _subtree_root(
        self, conn: sqlite3.Connection, start: int, size: int
    ) -> bytes:
        """MTH of the aligned block [start, start+size) from stored nodes.

        A power-of-two block is one persisted node; any other slice (only the
        short right-hand suffix of an MTH split reaches here) recurses into a
        power-of-two left half and at most one smaller suffix, so it reads
        O(log size) persisted nodes rather than rescanning leaves.
        """
        if size == 1:
            return self._node(conn, 0, start)
        block = 1 << (size.bit_length() - 1)
        if block == size:
            # Perfect block: its root was materialized on append.
            return self._node(conn, size.bit_length() - 1, start // size)
        return merkle.hash_nodes(
            self._subtree_root(conn, start, block),
            self._subtree_root(conn, start + block, size - block),
        )
