"""ACME (RFC 8555 subset) protocol orchestration.

The service owns the account/order/authorization state machine and reuses
the existing issuance machinery (:mod:`app.policy`, :class:`CertificateAuthority`)
for the actual certificate. Persistence lives in :class:`ACMEStore`; http-01
network checks live in :mod:`app.acme_challenge`.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import policy
from .acme_challenge import Http01Config, verify_http_01
from .acme_store import (
    ACMEStore,
    Account,
    AuthzRecord,
    ChallengeRecord,
    OrderConflict,
    OrderRecord,
    STATUS_PENDING,
    STATUS_PROCESSING,
    STATUS_VALID,
)
from .ca import CertificateAuthority
from .jws import b64url_decode
from .storage import CAStore

NONCE_TTL = dt.timedelta(minutes=5)
ORDER_TTL = dt.timedelta(minutes=10)
CERT_VALIDITY_DAYS = 7

ACME_ERROR_PREFIX = "urn:ietf:params:acme:error:"


class AcmeError(Exception):
    def __init__(self, sub_type: str, detail: str, status: int = 400):
        super().__init__(detail)
        self.type = ACME_ERROR_PREFIX + sub_type
        self.status = status
        self.detail = detail


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class AcmeService:
    def __init__(
        self,
        ca: CertificateAuthority,
        store: ACMEStore,
        cert_store: CAStore,
        http01_config: Http01Config,
        log_store: object | None = None,
        *,
        clock: Callable[[], dt.datetime] = _utcnow,
        nonce_ttl: dt.timedelta = NONCE_TTL,
        order_ttl: dt.timedelta = ORDER_TTL,
        cert_days: int = CERT_VALIDITY_DAYS,
    ):
        self._ca = ca
        self._store = store
        self._cert_store = cert_store
        self._http01 = http01_config
        self._log_store = log_store
        self._clock = clock
        self._nonce_ttl = nonce_ttl
        self._order_ttl = order_ttl
        self._cert_days = cert_days

    @property
    def ca(self) -> CertificateAuthority:
        return self._ca

    def configure_http01(self, config: Http01Config) -> None:
        self._http01 = config

    def set_clock(self, clock: Callable[[], dt.datetime]) -> None:
        """Test hook: override the wall clock used for nonce/order expiry."""
        self._clock = clock

    def now(self) -> dt.datetime:
        return self._clock()

    # ----------------------------------------------------------------- nonces

    def issue_nonce(self) -> str:
        return self._store.issue_nonce(self._clock().isoformat())

    def consume_nonce(self, nonce: str) -> bool:
        not_before = (self._clock() - self._nonce_ttl).isoformat()
        return self._store.consume_nonce(nonce, not_before)

    # --------------------------------------------------------------- accounts

    def register(
        self, jwk_thumbprint: str, jwk_json: str, payload: dict[str, Any]
    ) -> tuple[Account, bool]:
        existing = self._store.get_account_by_thumbprint(jwk_thumbprint)
        if existing is not None:
            # RFC 8555 §7.3: a repeated registration with the same key reuses
            # the existing account.
            return existing, False
        if payload.get("onlyReturnExisting"):
            raise AcmeError(
                "accountDoesNotExist", "no account matches the provided key", 400
            )
        contact = payload.get("contact", [])
        if not isinstance(contact, list) or not all(
            isinstance(item, str) for item in contact
        ):
            raise AcmeError("invalidContact", "contact must be a list of strings")
        for item in contact:
            if not item.startswith("mailto:"):
                raise AcmeError(
                    "invalidContact", "only mailto: contact entries are supported"
                )
        account = self._store.create_account(
            jwk_thumbprint, jwk_json, contact, self._clock().isoformat()
        )
        return account, True

    def require_account(self, account_id: int) -> Account:
        account = self._store.get_account(account_id)
        if account is None:
            raise AcmeError("accountDoesNotExist", "unknown account", 400)
        return account

    # ----------------------------------------------------------------- orders

    def create_order(self, account: Account, payload: dict[str, Any]) -> OrderRecord:
        identifiers = payload.get("identifiers")
        if not isinstance(identifiers, list) or len(identifiers) != 1:
            raise AcmeError(
                "malformed",
                "exactly one identifier is required per order in this subset",
            )
        ident = identifiers[0]
        if not isinstance(ident, dict) or ident.get("type") != "dns":
            raise AcmeError("malformed", "identifier must be {'type': 'dns', ...}")
        raw_value = ident.get("value")
        if not isinstance(raw_value, str) or "*" in raw_value:
            # policy._normalize_dns_name also rejects wildcards, but fail early
            # with an explicit message.
            raise AcmeError(
                "rejectedIdentifier",
                "wildcard identifiers are not supported",
            )
        try:
            domain = policy._normalize_dns_name(raw_value)
        except policy.PolicyError as exc:
            raise AcmeError("rejectedIdentifier", str(exc)) from exc
        now = self._clock()
        return self._store.create_order(
            account.id,
            [{"type": "dns", "value": domain}],
            (now + self._order_ttl).isoformat(),
            now.isoformat(),
        )

    def get_order(self, order_id: str, account: Account) -> OrderRecord:
        order = self._store.get_order(order_id)
        if order is None or order.account_id != account.id:
            # Do not reveal the existence of another account's resource.
            raise AcmeError("unauthorized", "order not found", 404)
        return order

    def order_status(self, order: OrderRecord) -> str:
        if order.status == STATUS_VALID:
            return STATUS_VALID
        if self._is_expired(order.expires_at):
            return "invalid"
        if order.status == STATUS_PROCESSING:
            return STATUS_PROCESSING
        if order.status == STATUS_PENDING:
            authzs = self._store.list_authz_for_order(order.id)
            if authzs and all(self._authz_effective_status(a) == STATUS_VALID for a in authzs):
                return "ready"
        return order.status

    def _is_expired(self, expires_at_iso: str) -> bool:
        return self._clock() >= dt.datetime.fromisoformat(expires_at_iso)

    # ---------------------------------------------------- view helpers (API)

    def authz_status(self, authz: AuthzRecord) -> str:
        return self._authz_effective_status(authz)

    def challenges_for_authz(self, authz_id: str) -> list[ChallengeRecord]:
        return self._store.list_challenges_for_authz(authz_id)

    def authorizations_for_order(self, order_id: str) -> list[AuthzRecord]:
        return self._store.list_authz_for_order(order_id)

    def refresh_challenge(self, challenge: ChallengeRecord) -> ChallengeRecord:
        return self._store.get_challenge(challenge.id)

    # -------------------------------------------------------- authorizations

    def get_authz(self, authz_id: str, account: Account) -> AuthzRecord:
        authz = self._store.get_authz(authz_id)
        if authz is None or authz.account_id != account.id:
            raise AcmeError("unauthorized", "authorization not found", 404)
        return authz

    def _authz_effective_status(self, authz: AuthzRecord) -> str:
        # A validated authorization stays valid for this order; the order's
        # own 10-minute expiry gates finalization. Pending authorizations
        # become invalid once their deadline passes.
        if authz.status != STATUS_VALID and self._is_expired(authz.expires_at):
            return "invalid"
        return authz.status

    # -------------------------------------------------------------- challenges

    def get_challenge(
        self, challenge_id: str, account: Account
    ) -> tuple[ChallengeRecord, AuthzRecord]:
        challenge = self._store.get_challenge(challenge_id)
        if challenge is None:
            raise AcmeError("unauthorized", "challenge not found", 404)
        authz = self._store.get_authz(challenge.authz_id)
        if authz is None or authz.account_id != account.id:
            raise AcmeError("unauthorized", "challenge not found", 404)
        return challenge, authz

    def respond_to_challenge(
        self, challenge_id: str, account: Account
    ) -> tuple[ChallengeRecord, AuthzRecord]:
        challenge, authz = self.get_challenge(challenge_id, account)
        if self._authz_effective_status(authz) == "invalid":
            raise AcmeError("unauthorized", "authorization has expired", 403)
        if challenge.status == STATUS_VALID:
            return challenge, authz
        if challenge.type != "http-01":
            raise AcmeError(
                "malformed", f"unsupported challenge type: {challenge.type}"
            )
        key_authorization = challenge.token + "." + account.jwk_thumbprint
        result = verify_http_01(
            identifier=authz.ident_value,
            token=challenge.token,
            key_authorization=key_authorization,
            config=self._http01,
        )
        if not result.valid:
            # The challenge remains pending so the client can fix the server
            # and retry within the order lifetime.
            raise AcmeError(
                "incorrectResponse",
                f"http-01 validation failed: {result.detail}",
                400,
            )
        self._store.mark_challenge_valid(challenge.id, self._clock().isoformat())
        return self._store.get_challenge(challenge.id), self._store.get_authz(authz.id)

    # --------------------------------------------------------------- finalize

    def finalize(
        self, order_id: str, account: Account, payload: dict[str, Any]
    ) -> OrderRecord:
        order = self.get_order(order_id, account)
        status = self.order_status(order)
        if status == "invalid":
            raise AcmeError("orderNotReady", "order has expired", 403)
        if status not in ("ready", STATUS_PROCESSING, STATUS_VALID):
            raise AcmeError(
                "orderNotReady",
                "authorization is not valid yet",
                403,
            )

        csr_b64 = payload.get("csr")
        if not isinstance(csr_b64, str):
            raise AcmeError("malformed", "payload.csr must be a base64url string")
        try:
            csr_der = b64url_decode(csr_b64)
            csr = x509.load_der_x509_csr(csr_der)
        except Exception as exc:
            raise AcmeError("badCSR", f"invalid DER CSR: {exc}") from exc

        try:
            dns_names = policy.validate_csr(csr)
        except policy.PolicyError as exc:
            raise AcmeError("badCSR", str(exc)) from exc

        requested = {ident["value"] for ident in order.identifiers}
        if set(dns_names) != requested or len(dns_names) != 1:
            raise AcmeError(
                "badCSR",
                "CSR subjectAltName must exactly match the order identifier",
            )

        now = self._clock()
        not_before = now - dt.timedelta(minutes=1)
        not_after = min(
            now + dt.timedelta(days=self._cert_days), self._ca.not_after()
        )
        if not_after <= not_before:
            raise AcmeError(
                "orderNotReady", "CA validity period is too short to issue"
            )

        def sign(serial: int) -> tuple[str, list[str], str, str]:
            cert = self._ca.issue_cert(
                csr=csr,
                dns_names=dns_names,
                serial_number=serial,
                not_before=not_before,
                not_after=not_after,
            )
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
            return (
                cert_pem,
                dns_names,
                not_before.isoformat(),
                not_after.isoformat(),
            )

        try:
            order, _cert = self._store.finalize_order(
                order_id=order.id,
                csr_der=csr_der,
                dns_names=dns_names,
                days=self._cert_days,
                sign=sign,
                now_iso=now.isoformat(),
                log_store=self._log_store,
            )
        except OrderConflict as exc:
            raise AcmeError("orderAlreadyIssued", str(exc), 409) from exc
        return order

    def certificate_pem(self, order_id: str, account: Account) -> tuple[str, bytes]:
        """Return (serial_hex, PEM chain bytes) for a finalized order."""
        order = self.get_order(order_id, account)
        if order.cert_serial_hex is None or self.order_status(order) != STATUS_VALID:
            raise AcmeError("orderNotReady", "certificate is not available", 403)
        record = self._cert_store.get_certificate(order.cert_serial_hex)
        chain = record.cert_pem.encode("ascii") + self._ca.cert_pem
        return order.cert_serial_hex, chain
