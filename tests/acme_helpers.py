"""Minimal ACME client for tests: account key, nonces and JWS POSTs."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import rsa

from app.jws import (
    b64url,
    b64url_decode,
    jwk_thumbprint,
    public_jwk,
    sign_jws,
)
from tests.conftest import make_key


@dataclass
class AcmeAccount:
    key: rsa.RSAPrivateKey
    jwk: dict
    thumbprint: str
    account_url: str | None = None

    @classmethod
    def create(cls, bits: int = 2048) -> "AcmeAccount":
        key = make_key(bits)
        jwk = public_jwk(key.public_key())
        return cls(key=key, jwk=jwk, thumbprint=jwk_thumbprint(jwk))


@dataclass
class AcmeClient:
    """JWS client over a FastAPI TestClient.

    Tracks nonces like a real client. Set ``sign_kwargs`` / ``tamper`` to
    produce deliberately invalid requests.
    """

    http: object
    account: AcmeAccount
    base: str = "http://testserver"
    nonces: list[str] = field(default_factory=list)

    def get_nonce(self) -> str:
        resp = self.http.get("/acme/new-nonce")
        return resp.headers["Replay-Nonce"]

    def _take_nonce(self) -> str:
        if not self.nonces:
            return self.get_nonce()
        return self.nonces.pop(0)

    def queue_nonce(self) -> str:
        """Fetch a nonce and keep it as the next consumed nonce."""
        nonce = self.get_nonce()
        self.nonces.append(nonce)
        return nonce

    def _headers(self, extra: dict | None = None) -> dict:
        headers = {"Content-Type": "application/jose+json"}
        if extra:
            headers.update(extra)
        return headers

    def post_jwk(
        self,
        path: str,
        payload: dict | None,
        *,
        nonce: str | None = None,
        raw_payload: str | None = None,
        protected_overrides: dict | None = None,
        jwk_override: dict | None = None,
        url_override: str | None = None,
        sign_key: rsa.RSAPrivateKey | None = None,
    ):
        url = url_override or (self.base + path)
        protected_nonce = nonce if nonce is not None else self._take_nonce()
        body = self._build(
            url,
            payload,
            key=sign_key or self.account.key,
            nonce=protected_nonce,
            identity={"jwk": jwk_override or self.account.jwk},
            raw_payload=raw_payload,
            protected_overrides=protected_overrides,
        )
        return self.http.post(path, content=json.dumps(body), headers=self._headers())

    def post_kid(
        self,
        path: str,
        payload: dict | None,
        *,
        nonce: str | None = None,
        raw_payload: str | None = None,
        protected_overrides: dict | None = None,
        kid_override: str | None = None,
        url_override: str | None = None,
        sign_key: rsa.RSAPrivateKey | None = None,
        jwk_instead_of_kid: bool = False,
    ):
        url = url_override or (self.base + path)
        protected_nonce = nonce if nonce is not None else self._take_nonce()
        kid = kid_override or self.account.account_url
        identity = (
            {"jwk": self.account.jwk} if jwk_instead_of_kid else {"kid": kid}
        )
        body = self._build(
            url,
            payload,
            key=sign_key or self.account.key,
            nonce=protected_nonce,
            identity=identity,
            raw_payload=raw_payload,
            protected_overrides=protected_overrides,
        )
        return self.http.post(path, content=json.dumps(body), headers=self._headers())

    def post_as_get(self, path: str, **kwargs):
        return self.post_kid(path, None, raw_payload="", **kwargs)

    def _build(
        self,
        url: str,
        payload: dict | None,
        *,
        key: rsa.RSAPrivateKey,
        nonce: str,
        identity: dict,
        raw_payload: str | None,
        protected_overrides: dict | None,
    ) -> dict:
        if raw_payload is not None:
            payload_bytes: bytes = raw_payload.encode("ascii")
        elif payload is None:
            payload_bytes = b""
        else:
            payload_bytes = json.dumps(payload).encode("ascii")
        body = sign_jws(payload_bytes, key, url, nonce, **identity)
        if protected_overrides:
            protected = json.loads(b64url_decode(body["protected"]))
            protected.update(protected_overrides)
            body["protected"] = b64url(
                json.dumps(protected, separators=(",", ":"), sort_keys=True).encode()
            )
            # Re-sign so the override stays consistent (e.g. a foreign alg with
            # a still-valid signature).
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding

            signing_input = (body["protected"] + "." + body["payload"]).encode()
            body["signature"] = b64url(
                key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
            )
        return body

    # -------------------------------------------------------- protocol flow

    def new_account(self, payload: dict | None = None) -> object:
        resp = self.post_jwk(
            "/acme/new-account",
            payload if payload is not None else {"termsOfServiceAgreed": True},
        )
        if resp.status_code in (200, 201):
            self.account.account_url = resp.headers["Location"]
        return resp

    def new_order(self, domain: str) -> object:
        return self.post_kid(
            "/acme/new-order",
            {"identifiers": [{"type": "dns", "value": domain}]},
        )

    def fetch_order(self, order_url_path: str) -> object:
        return self.post_as_get(order_url_path)

    def fetch_authz(self, authz_url_path: str) -> object:
        return self.post_as_get(authz_url_path)

    def solve_challenge(self, challenge_url_path: str) -> object:
        return self.post_kid(challenge_url_path, {})

    def finalize(self, finalize_path: str, csr_der: bytes) -> object:
        return self.post_kid(finalize_path, {"csr": b64url(csr_der)})

    def download_cert(self, cert_path: str) -> object:
        return self.post_as_get(cert_path)
