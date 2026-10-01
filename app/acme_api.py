"""HTTP layer for the ACME (RFC 8555 subset) endpoints.

Mounted under ``/acme`` by :func:`app.api.create_app`. Every state-changing
or resource-fetch request is a JWS-signed POST; reads use POST-as-GET with
an empty payload.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from . import jws as jws_mod
from .acme_service import AcmeError, AcmeService
from .acme_store import Account, STATUS_VALID
from .jws import JwsError

JOSE_CONTENT_TYPE = "application/jose+json"
CERT_CHAIN_CONTENT_TYPE = "application/pem-certificate-chain"

PATH_DIRECTORY = "/acme/directory"
PATH_NEW_NONCE = "/acme/new-nonce"
PATH_NEW_ACCOUNT = "/acme/new-account"
PATH_NEW_ORDER = "/acme/new-order"
PATH_ACCOUNT = "/acme/account/{account_id}"
PATH_ORDER = "/acme/order/{order_id}"
PATH_FINALIZE = "/acme/order/{order_id}/finalize"
PATH_AUTHZ = "/acme/authz/{authz_id}"
PATH_CHALLENGE = "/acme/challenge/{challenge_id}"
PATH_CERT = "/acme/cert/{order_id}"


@dataclass(frozen=True)
class Authenticated:
    account: Account | None  # None only on new-account (jwk form)
    thumbprint: str
    payload: Any  # parsed JSON object, or None for POST-as-GET
    jwk: dict | None = None  # canonical public JWK, only on new-account


def create_acme_router(service: AcmeService) -> APIRouter:
    router = APIRouter(prefix="/acme")

    # ------------------------------------------------------------- utilities

    def _base_url(request: Request) -> str:
        return str(request.base_url).rstrip("/")

    def _account_url(request: Request, account_id: int) -> str:
        return f"{_base_url(request)}/acme/account/{account_id}"

    def _order_url(request: Request, order_id: str) -> str:
        return f"{_base_url(request)}/acme/order/{order_id}"

    def _authz_url(request: Request, authz_id: str) -> str:
        return f"{_base_url(request)}/acme/authz/{authz_id}"

    def _challenge_url(request: Request, challenge_id: str) -> str:
        return f"{_base_url(request)}/acme/challenge/{challenge_id}"

    def _finalize_url(request: Request, order_id: str) -> str:
        return f"{_base_url(request)}/acme/order/{order_id}/finalize"

    def _cert_url(request: Request, order_id: str) -> str:
        return f"{_base_url(request)}/acme/cert/{order_id}"

    def _nonce_headers(request: Request) -> dict[str, str]:
        return {
            "Replay-Nonce": service.issue_nonce(),
            "Cache-Control": "no-store",
            "Link": f'<{_base_url(request)}{PATH_DIRECTORY}>;rel="index"',
        }

    def _problem(exc: Exception, request: Request) -> JSONResponse:
        if isinstance(exc, AcmeError):
            problem_type = exc.type
            status = exc.status
            detail = exc.detail
        elif isinstance(exc, JwsError):
            problem_type = "urn:ietf:params:acme:error:" + exc.acme_type
            status = exc.status
            detail = exc.detail
        else:  # pragma: no cover - defensive catch-all
            problem_type = "urn:ietf:params:acme:error:serverInternal"
            status = 500
            detail = str(exc) or "internal error"
        return JSONResponse(
            {"type": problem_type, "detail": detail, "status": status},
            status_code=status,
            headers=_nonce_headers(request),
            media_type="application/problem+json",
        )

    def _decode_payload(parsed: jws_mod.JwsObject, *, empty_ok: bool) -> Any:
        if parsed.payload == "":
            if not empty_ok:
                raise JwsError("malformed", "request payload must not be empty")
            return None
        if empty_ok:
            # POST-as-GET is the only form with an empty payload; a non-empty
            # one on a read endpoint is not a POST-as-GET request.
            raise JwsError(
                "malformed", "POST-as-GET requests must carry an empty payload"
            )
        try:
            payload = json.loads(jws_mod.b64url_decode(parsed.payload))
        except (ValueError, TypeError) as exc:
            raise JwsError("malformed", "payload is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise JwsError("malformed", "payload must be a JSON object")
        return payload

    async def _authenticate(
        request: Request, *, identity: str, empty_ok: bool
    ) -> Authenticated:
        """Verify the JWS envelope, nonce and account identity."""
        content_type = request.headers.get("content-type", "")
        if content_type.split(";")[0].strip() != JOSE_CONTENT_TYPE:
            raise JwsError(
                "malformed",
                f"Content-Type must be {JOSE_CONTENT_TYPE}",
            )
        raw_body = await request.body()
        parsed = jws_mod.parse_jws(raw_body)
        protected = parsed.protected

        alg = protected.get("alg")
        if not isinstance(alg, str) or alg != jws_mod.ALG_RS256:
            raise JwsError(
                "badSignatureAlgorithm",
                "only RS256 JWS signatures are supported",
            )
        nonce = protected.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            raise JwsError("badNonce", "protected header must carry a nonce")
        protected_url = protected.get("url")
        if not isinstance(protected_url, str) or protected_url != str(request.url):
            raise JwsError("unauthorized", "protected url does not match the request")
        if "jwk" in protected and "kid" in protected:
            raise JwsError("malformed", "jwk and kid are mutually exclusive")

        payload = _decode_payload(parsed, empty_ok=empty_ok)

        if identity == "jwk":
            if "kid" in protected:
                raise JwsError(
                    "malformed", "new-account must be signed with a jwk, not kid"
                )
            raw_jwk = protected.get("jwk")
            public_key = jws_mod.load_jwk(raw_jwk)
            jws_mod.verify_jws(parsed, public_key)
            canonical_jwk = {
                "e": raw_jwk["e"],
                "kty": "RSA",
                "n": raw_jwk["n"],
            }
            thumbprint = jws_mod.jwk_thumbprint(canonical_jwk)
            account = None
            jwk_out: dict | None = canonical_jwk
        else:
            if "jwk" in protected:
                raise JwsError(
                    "malformed", "this endpoint must be signed with a kid, not jwk"
                )
            kid = protected.get("kid")
            if not isinstance(kid, str):
                raise JwsError("malformed", "protected header must carry a kid")
            expected_prefix = f"{_base_url(request)}/acme/account/"
            if not kid.startswith(expected_prefix):
                raise JwsError(
                    "unauthorized", "kid does not identify an account on this server"
                )
            try:
                account_id = int(kid[len(expected_prefix):])
            except ValueError as exc:
                raise JwsError("unauthorized", "invalid account kid") from exc
            account = service.require_account(account_id)
            stored_jwk = json.loads(account.jwk_json)
            public_key = jws_mod.load_jwk(stored_jwk)
            jws_mod.verify_jws(parsed, public_key)
            thumbprint = account.jwk_thumbprint
            jwk_out = None

        # Atomic single-use check: only one concurrent request can win.
        if not service.consume_nonce(nonce):
            raise JwsError(
                "badNonce",
                "nonce is unknown, expired (older than 5 minutes) or replayed",
            )
        return Authenticated(
            account=account,
            thumbprint=thumbprint,
            payload=payload,
            jwk=jwk_out,
        )

    # ------------------------------------------------------------- views

    def _challenge_view(request: Request, challenge) -> dict[str, Any]:
        view = {
            "type": challenge.type,
            "url": _challenge_url(request, challenge.id),
            "status": challenge.status,
            "token": challenge.token,
        }
        if challenge.validated_at is not None:
            view["validated"] = challenge.validated_at
        return view

    def _authz_view(request: Request, authz) -> dict[str, Any]:
        challenges = service.challenges_for_authz(authz.id)
        return {
            "status": service.authz_status(authz),
            "expires": authz.expires_at,
            "identifier": {"type": authz.ident_type, "value": authz.ident_value},
            "challenges": [_challenge_view(request, c) for c in challenges],
        }

    def _order_view(request: Request, order) -> dict[str, Any]:
        authzs = service.authorizations_for_order(order.id)
        body: dict[str, Any] = {
            "status": service.order_status(order),
            "expires": order.expires_at,
            "identifiers": list(order.identifiers),
            "authorizations": [_authz_url(request, a.id) for a in authzs],
            "finalize": _finalize_url(request, order.id),
        }
        if order.cert_serial_hex is not None:
            body["certificate"] = _cert_url(request, order.id)
        return body

    # ----------------------------------------------------------- endpoints

    @router.get("/directory")
    def directory(request: Request):
        base = _base_url(request)
        return JSONResponse(
            {
                "newNonce": f"{base}{PATH_NEW_NONCE}",
                "newAccount": f"{base}{PATH_NEW_ACCOUNT}",
                "newOrder": f"{base}{PATH_NEW_ORDER}",
                "meta": {
                    "externalAccountRequired": False,
                    # keyChange/revokeCert are intentionally absent (out of scope).
                },
            },
            headers={"Cache-Control": "no-store"},
        )

    @router.api_route("/new-nonce", methods=["GET", "HEAD"])
    def new_nonce(request: Request):
        return Response(
            status_code=204,
            headers={
                "Replay-Nonce": service.issue_nonce(),
                "Cache-Control": "no-store",
                "Link": f'<{_base_url(request)}{PATH_DIRECTORY}>;rel="index"',
            },
        )

    @router.post("/new-account")
    async def new_account(request: Request):
        try:
            auth = await _authenticate(request, identity="jwk", empty_ok=False)
            account, created = service.register(
                auth.thumbprint,
                json.dumps(auth.jwk, sort_keys=True, separators=(",", ":")),
                auth.payload,
            )
        except Exception as exc:
            return _problem(exc, request)
        return JSONResponse(
            {"status": STATUS_VALID, "contact": list(account.contact)},
            status_code=201 if created else 200,
            headers={
                "Location": _account_url(request, account.id),
                **_nonce_headers(request),
            },
        )

    @router.post("/new-order")
    async def new_order(request: Request):
        try:
            auth = await _authenticate(request, identity="kid", empty_ok=False)
            order = service.create_order(auth.account, auth.payload)
            return JSONResponse(
                _order_view(request, order),
                status_code=201,
                headers={
                    "Location": _order_url(request, order.id),
                    **_nonce_headers(request),
                },
            )
        except Exception as exc:
            return _problem(exc, request)

    @router.post("/account/{account_id}")
    async def get_account(request: Request, account_id: str):
        try:
            auth = await _authenticate(request, identity="kid", empty_ok=True)
            # The kid is the account URL; it must identify the URL in the path.
            if str(auth.account.id) != account_id or str(request.url) != (
                _account_url(request, auth.account.id)
            ):
                raise JwsError("unauthorized", "kid does not match request URL")
            return JSONResponse(
                {"status": STATUS_VALID, "contact": list(auth.account.contact)},
                headers=_nonce_headers(request),
            )
        except Exception as exc:
            return _problem(exc, request)

    @router.post("/order/{order_id}")
    async def get_order(request: Request, order_id: str):
        try:
            auth = await _authenticate(request, identity="kid", empty_ok=True)
            order = service.get_order(order_id, auth.account)
            return JSONResponse(
                _order_view(request, order), headers=_nonce_headers(request)
            )
        except Exception as exc:
            return _problem(exc, request)

    @router.post("/authz/{authz_id}")
    async def get_authz(request: Request, authz_id: str):
        try:
            auth = await _authenticate(request, identity="kid", empty_ok=True)
            authz = service.get_authz(authz_id, auth.account)
            return JSONResponse(
                _authz_view(request, authz), headers=_nonce_headers(request)
            )
        except Exception as exc:
            return _problem(exc, request)

    @router.post("/challenge/{challenge_id}")
    async def respond_challenge(request: Request, challenge_id: str):
        try:
            auth = await _authenticate(request, identity="kid", empty_ok=False)
            if auth.payload != {}:
                raise JwsError(
                    "malformed", "challenge acknowledgement payload must be {}"
                )
            challenge, authz = service.respond_to_challenge(challenge_id, auth.account)
            fresh_challenge = service.refresh_challenge(challenge)
            return JSONResponse(
                _challenge_view(request, fresh_challenge),
                headers=_nonce_headers(request),
            )
        except Exception as exc:
            return _problem(exc, request)

    @router.post("/order/{order_id}/finalize")
    async def finalize_order(request: Request, order_id: str):
        try:
            auth = await _authenticate(request, identity="kid", empty_ok=False)
            order = service.finalize(order_id, auth.account, auth.payload)
            return JSONResponse(
                _order_view(request, order), headers=_nonce_headers(request)
            )
        except Exception as exc:
            return _problem(exc, request)

    @router.post("/cert/{order_id}")
    async def download_certificate(request: Request, order_id: str):
        try:
            auth = await _authenticate(request, identity="kid", empty_ok=True)
            _serial, chain = service.certificate_pem(order_id, auth.account)
            return Response(
                content=chain,
                media_type=CERT_CHAIN_CONTENT_TYPE,
                headers={
                    "Cache-Control": "no-store",
                    **_nonce_headers(request),
                },
            )
        except Exception as exc:
            return _problem(exc, request)

    return router
