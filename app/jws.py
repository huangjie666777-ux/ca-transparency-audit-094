"""JWS (RFC 7515) and JWK (RFC 7638) primitives for the ACME subset.

Only RS256 with RSA public keys of at least 2048 bits is supported.
This module is intentionally transport-agnostic: it parses and verifies
JWS objects but knows nothing about nonces or accounts.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MIN_RSA_KEY_SIZE = 2048
ALG_RS256 = "RS256"

# RFC 7517: only the bare RSA public members are accepted; private members
# (d, p, q, ...) or metadata (x5c, kid, ...) are rejected outright.
_JWK_ALLOWED = frozenset({"kty", "n", "e"})


class JwsError(ValueError):
    """A malformed or unverifiable JWS, tagged with an ACME error URN."""

    def __init__(self, acme_type: str, detail: str, status: int = 400):
        super().__init__(detail)
        self.acme_type = acme_type
        self.status = status
        self.detail = detail


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        value = value.decode("ascii")
    if not isinstance(value, str):
        raise JwsError("malformed", "base64url value must be a string")
    # Standard base64url never carries padding or non-alphabet characters.
    if not all(c.isascii() and (c.isalnum() or c in "-_") for c in value):
        raise JwsError("malformed", "invalid base64url encoding")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise JwsError("malformed", "invalid base64url encoding") from exc


def _int_to_b64url(number: int) -> str:
    length = max(1, (number.bit_length() + 7) // 8)
    return b64url(number.to_bytes(length, "big"))


def public_jwk(key: rsa.RSAPublicKey) -> dict[str, str]:
    numbers = key.public_numbers()
    return {
        "kty": "RSA",
        "n": _int_to_b64url(numbers.n),
        "e": _int_to_b64url(numbers.e),
    }


def load_jwk(jwk: object) -> rsa.RSAPublicKey:
    if not isinstance(jwk, dict):
        raise JwsError("malformed", "JWK must be a JSON object")
    if set(jwk) != _JWK_ALLOWED:
        raise JwsError(
            "malformed",
            "JWK must contain exactly kty, n and e (RSA public key)",
        )
    if jwk.get("kty") != "RSA":
        raise JwsError(
            "badSignatureAlgorithm", "only RSA account keys are supported"
        )
    try:
        modulus = int.from_bytes(b64url_decode(jwk["n"]), "big")
        exponent = int.from_bytes(b64url_decode(jwk["e"]), "big")
        key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    except (ValueError, TypeError, KeyError) as exc:
        raise JwsError("malformed", f"invalid RSA JWK: {exc}") from exc
    if modulus.bit_length() < MIN_RSA_KEY_SIZE:
        raise JwsError(
            "badSignatureAlgorithm",
            f"RSA account key must be at least {MIN_RSA_KEY_SIZE} bits",
        )
    return key


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint: SHA-256 over the canonical JWK."""
    try:
        canonical = json.dumps(
            {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (KeyError, TypeError) as exc:
        raise JwsError("malformed", "JWK is missing kty/n/e") from exc
    digest = hashes.Hash(hashes.SHA256())
    digest.update(canonical)
    return b64url(digest.finalize())


@dataclass(frozen=True)
class JwsObject:
    protected_b64: str
    protected: dict
    payload: str
    signature: bytes


def parse_jws(raw_body: bytes) -> JwsObject:
    """Parse a flattened JWS JSON serialization into its raw parts."""
    try:
        envelope = json.loads(raw_body)
    except (ValueError, TypeError) as exc:
        raise JwsError("malformed", "request body must be JWS JSON") from exc
    if not isinstance(envelope, dict):
        raise JwsError("malformed", "JWS envelope must be a JSON object")
    if not set(envelope) >= {"protected", "payload", "signature"}:
        raise JwsError(
            "malformed", "JWS must contain protected, payload and signature"
        )
    protected_b64, payload, signature_raw = (
        envelope["protected"],
        envelope["payload"],
        envelope["signature"],
    )
    if not all(isinstance(part, str) for part in (protected_b64, payload, signature_raw)):
        raise JwsError("malformed", "JWS parts must be strings")
    try:
        protected = json.loads(b64url_decode(protected_b64))
    except (ValueError, TypeError) as exc:
        raise JwsError("malformed", "protected header is not valid JSON") from exc
    if not isinstance(protected, dict):
        raise JwsError("malformed", "protected header must be a JSON object")
    try:
        signature = b64url_decode(signature_raw)
    except JwsError as exc:
        raise JwsError("malformed", "invalid JWS signature encoding") from exc
    return JwsObject(
        protected_b64=protected_b64,
        protected=protected,
        payload=payload,
        signature=signature,
    )


def verify_jws(jws_obj: JwsObject, key: rsa.RSAPublicKey) -> None:
    """Verify an RS256 signature over the ASCII signing input."""
    signing_input = (jws_obj.protected_b64 + "." + jws_obj.payload).encode("ascii")
    try:
        key.verify(
            jws_obj.signature,
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise JwsError("unauthorized", "JWS signature verification failed") from exc


def sign_jws(
    payload: bytes,
    key: rsa.RSAPrivateKey,
    url: str,
    nonce: str,
    *,
    jwk: dict | None = None,
    kid: str | None = None,
) -> dict:
    """Build a flattened JWS object (used by tests and local tooling)."""
    if (jwk is None) == (kid is None):
        raise ValueError("exactly one of jwk or kid must be provided")
    protected: dict = {"alg": ALG_RS256, "nonce": nonce, "url": url}
    if jwk is not None:
        protected["jwk"] = jwk
    else:
        protected["kid"] = kid
    protected_b64 = b64url(
        json.dumps(protected, separators=(",", ":"), sort_keys=True).encode("ascii")
    )
    payload_b64 = b64url(payload)
    signing_input = (protected_b64 + "." + payload_b64).encode("ascii")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64url(signature),
    }
