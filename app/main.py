"""Application entry point.

The CA is created/reused from the data directory at import time so that a
missing/mismatched CA aborts startup instead of serving a broken service.
Set LOCAL_CA_DATA_DIR to override the default ./data location.
"""

from __future__ import annotations

import os

from .acme_challenge import Http01Config
from .acme_service import AcmeService
from .acme_store import ACMEStore
from .api import create_app
from .audit import AuditService
from .ca import CAError, load_or_create_ca
from .log_signing import LogKeyError, load_or_create_log_key
from .log_store import LogStore
from .service import CAService
from .storage import CAStore

DEFAULT_DATA_DIR = os.path.join(os.getcwd(), "data")
DATA_DIR = os.environ.get("LOCAL_CA_DATA_DIR", DEFAULT_DATA_DIR)

# http-01 checks always connect to 127.0.0.1; the destination port and the
# request limits are configurable for the local lab.
HTTP01_PORT = int(os.environ.get("LOCAL_CA_HTTP01_PORT", "80"))
HTTP01_TIMEOUT = float(os.environ.get("LOCAL_CA_HTTP01_TIMEOUT", "5"))
HTTP01_MAX_BYTES = int(os.environ.get("LOCAL_CA_HTTP01_MAX_BYTES", "8192"))

try:
    _ca = load_or_create_ca(DATA_DIR)
except CAError:
    # Let uvicorn fail loudly with the diagnostic instead of hiding it.
    raise

_store = CAStore(DATA_DIR)
_acme_store = ACMEStore(DATA_DIR)
_acme_store.ensure_schema()

# Transparency log: create the schema, load/create the independent signing
# key, then run one-shot migration for any pre-existing certificates before
# issuance is opened. A missing or mismatched signing key with an existing
# log is a fatal startup error.
_log_store = LogStore(DATA_DIR)
_log_store.ensure_schema()
try:
    _log_key = load_or_create_log_key(DATA_DIR, _log_store)
except LogKeyError:
    raise
_audit = AuditService(_log_store, _log_key)
_audit.initialize_or_migrate()

service = CAService(_ca, _store, log_store=_log_store)
acme_service = AcmeService(
    ca=_ca,
    store=_acme_store,
    cert_store=_store,
    http01_config=Http01Config(
        port=HTTP01_PORT, timeout=HTTP01_TIMEOUT, max_bytes=HTTP01_MAX_BYTES
    ),
    log_store=_log_store,
)
if _store.get_current_crl() is None:
    service.publish_crl()

app = create_app(service, acme_service, _audit)
