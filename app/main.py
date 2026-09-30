"""Application entry point.

The CA is created/reused from the data directory at import time so that a
missing/mismatched CA aborts startup instead of serving a broken service.
Set LOCAL_CA_DATA_DIR to override the default ./data location.
"""

from __future__ import annotations

import os

from .api import create_app
from .ca import CAError, load_or_create_ca
from .service import CAService
from .storage import CAStore

DEFAULT_DATA_DIR = os.path.join(os.getcwd(), "data")
DATA_DIR = os.environ.get("LOCAL_CA_DATA_DIR", DEFAULT_DATA_DIR)

try:
    _ca = load_or_create_ca(DATA_DIR)
except CAError:
    # Let uvicorn fail loudly with the diagnostic instead of hiding it.
    raise

_store = CAStore(DATA_DIR)
service = CAService(_ca, _store)
if _store.get_current_crl() is None:
    service.publish_crl()

app = create_app(service)
