"""http-01 challenge verification (RFC 8555 §8.3).

Local-lab constraints, deliberately stricter than the RFC:

* only plain HTTP is used;
* the connection always goes to 127.0.0.1 (DNS is never resolved) while the
  HTTP ``Host`` header carries the identifier being validated;
* redirects are never followed and explicitly fail the challenge;
* the timeout and response body size are capped.
"""

from __future__ import annotations

import http.client
from dataclasses import dataclass

CHALLENGE_TYPE = "http-01"
CHALLENGE_PATH_PREFIX = "/.well-known/acme-challenge/"
# RFC 8555: a key authorization must fit in this many characters.
MAX_KEY_AUTHORIZATION_LEN = 1024
HTTP_OK = 200
HTTP_REDIRECT_MIN = 300
HTTP_REDIRECT_MAX = 399


@dataclass(frozen=True)
class Http01Config:
    port: int
    timeout: float
    max_bytes: int


@dataclass(frozen=True)
class ChallengeResult:
    valid: bool
    detail: str = ""


def verify_http_01(
    identifier: str,
    token: str,
    key_authorization: str,
    config: Http01Config,
) -> ChallengeResult:
    if len(key_authorization) > MAX_KEY_AUTHORIZATION_LEN:
        return ChallengeResult(False, "key authorization too long")
    path = CHALLENGE_PATH_PREFIX + token
    try:
        conn = http.client.HTTPConnection("127.0.0.1", config.port, timeout=config.timeout)
        try:
            # Host is the validated identifier; the TCP peer is always localhost.
            conn.request(
                "GET",
                path,
                headers={
                    "Host": identifier,
                    "Accept": "*/*",
                    "Accept-Encoding": "identity",
                    "User-Agent": "LocalTestCA-ACME/1.0",
                },
            )
            response = conn.getresponse()
            status = response.status
            # Reject redirects explicitly instead of relying on the client
            # default (http.client does not follow them, but be defensive).
            if HTTP_REDIRECT_MIN <= status <= HTTP_REDIRECT_MAX:
                return ChallengeResult(False, f"redirect ({status}) is not allowed")
            if status != HTTP_OK:
                return ChallengeResult(False, f"unexpected HTTP status {status}")
            content_length = response.getheader("Content-Length")
            if content_length is not None:
                try:
                    if int(content_length) > config.max_bytes:
                        return ChallengeResult(False, "response body too large")
                except ValueError:
                    return ChallengeResult(False, "invalid Content-Length")
            # Read one byte beyond the cap so oversized chunked responses fail.
            body = response.read(config.max_bytes + 1)
            if len(body) > config.max_bytes:
                return ChallengeResult(False, "response body too large")
        finally:
            conn.close()
    except (http.client.HTTPException, OSError) as exc:
        return ChallengeResult(False, f"challenge request failed: {exc}")

    # RFC 8555: trim trailing whitespace only; everything else must match
    # byte for byte. A non-UTF-8 body cannot be the key authorization (an
    # ASCII string), so reject it instead of crashing with a 500.
    try:
        served = body.decode("utf-8", errors="strict").rstrip()
    except UnicodeDecodeError:
        return ChallengeResult(False, "challenge response is not valid UTF-8")
    if served != key_authorization:
        return ChallengeResult(False, "key authorization mismatch")
    return ChallengeResult(True)
