# Local Test CA

Python 3.10.12 / FastAPI scaffold. Only a health endpoint is implemented.

Project dependencies are installed in `.venv`.

```sh
.venv/bin/python -m pip install -r requirements.lock.txt
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
.venv/bin/python -m pytest
```

No certificate authority, keys, application tests or certificate lifecycle logic are included yet.
