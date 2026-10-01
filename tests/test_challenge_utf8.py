"""Regression test: non-UTF-8 challenge response must not 500."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.acme_challenge import Http01Config
from tests.acme_helpers import AcmeAccount, AcmeClient


class BinaryChallengeServer:
    """Serves non-UTF-8 bytes at the challenge path."""

    def __init__(self):
        self.records = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.records.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                # Invalid UTF-8 sequence.
                self.wfile.write(b"\xff\xfe\x00\x01invalid")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()


def test_non_utf8_challenge_response_returns_400_not_500(env):
    client = AcmeClient(http=env.client, account=AcmeAccount.create())
    client.new_account()
    resp = client.new_order("utf8.lab.test")
    order = resp.json()
    authz_path = "/" + order["authorizations"][0].split("/", 3)[3]
    authz = client.fetch_authz(authz_path).json()
    challenge = authz["challenges"][0]
    challenge_path = "/" + challenge["url"].split("/", 3)[3]

    server = BinaryChallengeServer()
    try:
        env.acme.configure_http01(
            Http01Config(port=server.port, timeout=5.0, max_bytes=8192)
        )
        resp = client.solve_challenge(challenge_path)
        assert resp.status_code == 400, resp.text
        assert "UTF-8" in resp.json()["detail"]
    finally:
        server.stop()
