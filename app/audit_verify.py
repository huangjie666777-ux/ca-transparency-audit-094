"""Independent audit verification demo.

Verifies a certificate's inclusion in the transparency log and the
consistency between two tree heads, using only a pre-trusted public key
file. The public key returned by the server is never used for verification;
the operator must supply the key out of band.

Usage:
    python -m app.audit_verify \
        --base-url http://127.0.0.1:8000 \
        --trust-key log_pub.b64 \
        --cert server.pem \
        [--old-size 0]
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import verify as verify_mod


def _http_get(url: str) -> dict:
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read())


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _load_trusted_key(path: str) -> bytes:
    with open(path, "rb") as handle:
        data = handle.read().strip()
    # Accept raw base64url, PEM, or hex.
    text = data.decode("ascii")
    if "BEGIN" in text:
        key = serialization.load_pem_public_key(data)
        return key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    try:
        return _b64url_decode(text)
    except Exception:
        return bytes.fromhex(text)


def _load_cert_der(path: str) -> bytes:
    with open(path, "rb") as handle:
        data = handle.read()
    if b"BEGIN CERTIFICATE" in data:
        return x509.load_pem_x509_certificate(data).public_bytes(
            serialization.Encoding.DER
        )
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify transparency log proofs")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--trust-key", required=True, help="trusted Ed25519 public key file")
    parser.add_argument("--cert", required=True, help="certificate PEM/DER to verify")
    parser.add_argument("--old-size", type=int, default=0, help="historical tree size for consistency")
    args = parser.parse_args(argv)

    base = args.base_url.rstrip("/")
    trusted_key = _load_trusted_key(args.trust_key)
    cert_der = _load_cert_der(args.cert)
    leaf_hash = verify_mod.cert_leaf_hash(cert_der)

    print(f"trusted public key: {trusted_key.hex()}")
    print(f"cert leaf hash:     {leaf_hash.hex()}")

    # Latest tree head.
    head = _http_get(f"{base}/log/head")
    signed_data = base64.b64decode(head["signed_data"])
    signature = base64.b64decode(head["signature"])
    try:
        parsed = verify_mod.verify_tree_head(
            trusted_key, signed_data, signature,
            expected_log_id=bytes.fromhex(head["log_id"]),
        )
        print(f"latest head:        size={parsed.tree_size} root={parsed.root.hex()}")
        print("head signature:     OK")
    except verify_mod.VerificationError as exc:
        print(f"head signature:     FAIL ({exc})")
        return 1

    # Inclusion proof for the certificate.
    proof = _http_get(
        f"{base}/log/proof/inclusion/0?size={parsed.tree_size}"
    )
    # Find the leaf index by matching the leaf hash.
    if bytes.fromhex(proof["leaf_hash"]) != leaf_hash:
        # Scan leaves to find the matching index.
        index = None
        for i in range(parsed.tree_size):
            leaf_proof = _http_get(f"{base}/log/proof/inclusion/{i}")
            if bytes.fromhex(leaf_proof["leaf_hash"]) == leaf_hash:
                proof = leaf_proof
                index = i
                break
        if index is None:
            print("inclusion proof:    FAIL (certificate not found in log)")
            return 1
    else:
        index = 0
    proof_nodes = [bytes.fromhex(node) for node in proof["proof"]]
    try:
        verify_mod.verify_inclusion(
            leaf_hash, index, parsed.tree_size, proof_nodes, parsed.root
        )
        print(f"inclusion proof:    OK (leaf {index} of {parsed.tree_size})")
    except verify_mod.VerificationError as exc:
        print(f"inclusion proof:    FAIL ({exc})")
        return 1

    # Consistency proof between the historical head and the latest head.
    if args.old_size > 0 and args.old_size < parsed.tree_size:
        old_head = _http_get(f"{base}/log/head/{args.old_size}")
        old_signed = base64.b64decode(old_head["signed_data"])
        old_signature = base64.b64decode(old_head["signature"])
        try:
            old_parsed = verify_mod.verify_tree_head(
                trusted_key, old_signed, old_signature,
                expected_log_id=bytes.fromhex(old_head["log_id"]),
            )
            print(f"old head:           size={old_parsed.tree_size} root={old_parsed.root.hex()}")
        except verify_mod.VerificationError as exc:
            print(f"old head signature: FAIL ({exc})")
            return 1
        consistency = _http_get(
            f"{base}/log/proof/consistency?old={args.old_size}&new={parsed.tree_size}"
        )
        consistency_nodes = [bytes.fromhex(node) for node in consistency["proof"]]
        try:
            verify_mod.verify_consistency(
                old_parsed.tree_size, parsed.tree_size,
                old_parsed.root, parsed.root, consistency_nodes,
            )
            print(f"consistency proof:  OK ({old_parsed.tree_size} -> {parsed.tree_size})")
        except verify_mod.VerificationError as exc:
            print(f"consistency proof:  FAIL ({exc})")
            return 1
    elif args.old_size == parsed.tree_size:
        print("consistency proof:  skipped (old size equals latest)")
    else:
        print("consistency proof:  skipped (no historical size requested)")

    print("\nverification passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
