#!/usr/bin/env python3
"""Standalone transparency audit verification demo.

This script talks to a running local CA, but it trusts *nothing* the server
says about its own identity. It needs only:

* the pinned log public key  -- 32 raw Ed25519 bytes, obtained once through a
  trusted channel (by default ``data/log_pubkey.raw`` written at startup);
* the JSON served by the audit endpoints (tree heads and proofs);
* the certificate DER embedded in the inclusion response.

It verifies, using ``app.audit_verify`` (which imports no database or signing
code):

1. every tree head's Ed25519 signature against the pinned key, and that the
   head's log_id equals SHA-256 of the pinned key;
2. an inclusion proof binding a certificate to a signed tree head;
3. a consistency proof showing the current tree extends an older head;
4. rejection of a tampered proof/head and of a foreign (response-supplied)
   key.

Usage:
    LOCAL_CA_DATA_DIR=./data .venv/bin/python scripts/audit_demo.py \
        [--base http://127.0.0.1:8000] [--pinned-key data/log_pubkey.raw]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

# Allow running straight from the repo root without installing the package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import audit_wire  # noqa: E402
from app.audit_verify import (  # noqa: E402
    VerificationError,
    verify_certificate_inclusion,
    verify_history_consistency,
    verify_tree_head,
)


def _get(base: str, path: str) -> dict:
    with urllib.request.urlopen(base + path, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _head(raw: dict) -> dict:
    return {
        "log_id": audit_wire.b64u_decode(raw["log_id"]),
        "tree_size": raw["tree_size"],
        "root_hash": audit_wire.b64u_decode(raw["sha256_root_hash"]),
        "signature": audit_wire.b64u_decode(raw["signature"]),
    }


def _check(label: str, fn) -> bool:
    try:
        fn()
    except VerificationError as exc:
        print(f"  [REJECT] {label}: {exc}")
        return False
    print(f"  [  OK  ] {label}")
    return True


def _expect_reject(label: str, fn) -> bool:
    """A negative test: it passes only if verification refuses."""
    try:
        fn()
    except VerificationError as exc:
        print(f"  [  OK  ] {label} (rejected: {exc})")
        return True
    print(f"  [REJECT] {label}: forgery was ACCEPTED")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_dir = os.environ.get("LOCAL_CA_DATA_DIR", "./data")
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--pinned-key", default=os.path.join(default_dir, "log_pubkey.raw")
    )
    args = parser.parse_args()

    # Trust anchor: read through a channel independent of the HTTP response.
    with open(args.pinned_key, "rb") as handle:
        pinned = handle.read()
    print(f"Pinned log key ({len(pinned)} bytes): {pinned.hex()}")

    key_info = _get(args.base, "/audit/v1/key")
    served_key = audit_wire.b64u_decode(key_info["public_key"])
    print(
        "Key endpoint matches pin: "
        f"{served_key == pinned} (informational only; the pin is authoritative)"
    )

    head_raw = _get(args.base, "/audit/v1/head")
    head = _head(head_raw)
    print(f"\nCurrent tree: size={head['tree_size']} "
          f"root={head['root_hash'].hex()}")

    ok = True
    ok &= _check(
        "current tree head signature + log_id against pinned key",
        lambda: verify_tree_head(pinned, **head),
    )

    if head["tree_size"] >= 1:
        leaf_index = 0
        inc = _get(args.base, f"/audit/v1/inclusion/{leaf_index}")
        cert_der = audit_wire.b64u_decode(inc["cert_der"])
        path = [audit_wire.b64u_decode(p) for p in inc["proof"]]
        inc_head = _head(inc["tree_head"])
        print(f"\nInclusion leaf {leaf_index}: {len(path)} proof node(s), "
              f"cert {len(cert_der)} DER bytes")
        ok &= _check(
            "certificate inclusion under the signed head",
            lambda: verify_certificate_inclusion(
                pinned, cert_der, inc_head, path, leaf_index=leaf_index
            ),
        )

        # Tamper demonstrations: each MUST be rejected.
        tampered_path = (
            [path[0][::-1]] + path[1:]
            if path
            else [b"\x00" * 32]  # size-1 tree: any node is one too many
        )
        print("\nNegative tests (all must be rejected):")
        ok &= _expect_reject(
            "tampered inclusion proof node",
            lambda: verify_certificate_inclusion(
                pinned, cert_der, inc_head, tampered_path,
                leaf_index=leaf_index,
            ),
        )
        bad_sig_head = dict(inc_head)
        bad_sig_head["signature"] = (
            bytes([inc_head["signature"][0] ^ 0xFF])
            + inc_head["signature"][1:]
        )
        ok &= _expect_reject(
            "tree head with one flipped signature byte",
            lambda: verify_tree_head(pinned, **bad_sig_head),
        )

    # Consistency: pick an older size (at least 2 leaves make it interesting).
    size = head["tree_size"]
    if size >= 2:
        first = max(1, size // 2)
        con = _get(
            args.base, f"/audit/v1/consistency?first={first}&second={size}"
        )
        con_path = [audit_wire.b64u_decode(p) for p in con["proof"]]
        old_head = _head(con["first_tree_head"])
        new_head = _head(con["second_tree_head"])
        print(f"\nConsistency {first} -> {size}: {len(con_path)} node(s)")
        ok &= _check(
            "newer tree is a signed extension of the older head",
            lambda: verify_history_consistency(
                pinned, old_head, new_head, con_path
            ),
        )
        tampered_consistency = (
            [con_path[0][::-1]] + con_path[1:] if con_path else con_path
        )
        if tampered_consistency:
            ok &= _expect_reject(
                "tampered consistency proof",
                lambda: verify_history_consistency(
                    pinned, old_head, new_head, tampered_consistency
                ),
            )

    # A foreign key riding along in a response must never be trusted: hand
    # the verifier a freshly generated key and confirm it rejects the head.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    foreign = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    ok &= _expect_reject(
        "head rejected when pinned to a foreign (response-supplied) key",
        lambda: verify_tree_head(foreign, **head),
    )

    print("\nRESULT:", "ALL CHECKS PASSED" if ok else "VERIFICATION FAILURE")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
