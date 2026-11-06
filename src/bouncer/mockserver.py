"""A local, deliberately-vulnerable mock server for exercising the validators
WITHOUT touching any real target. Started via `python -m bouncer mockserver`.

Endpoints:
  /xss?q=...                  reflects q into a <script> block (reflected XSS)
  /safe?q=...                 HTML-encodes q (should NOT validate)
  /item?id=...                boolean SQLi: id=1 -> "found", else "not found"
  /api/orders/<id>            IDOR: returns order data; authz depends on Cookie
"""
from __future__ import annotations

import html
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# order_id -> (owner_session, data)
_ORDERS = {
    "1001": ("session=alice", {"order": 1001, "owner": "alice", "total": "12.00"}),
    "1002": ("session=bob", {"order": 1002, "owner": "bob", "total": "99.50"}),
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8"):
        payload = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path
        q = parse_qs(parts.query, keep_blank_values=True)

        if path == "/xss":
            val = q.get("q", [""])[0]
            # VULNERABLE: reflects raw into an executable script context.
            self._send(200, f"<html><body><h1>search</h1>"
                            f"<script>var term = '{val}';</script></body></html>")
            return

        if path == "/safe":
            val = q.get("q", [""])[0]
            # SAFE: HTML-encoded, inert text node.
            self._send(200, f"<html><body>results for: {html.escape(val)}</body></html>")
            return

        if path == "/item":
            raw = q.get("id", [""])[0]
            # VULNERABLE boolean SQLi sim: evaluate "<n> AND <a>=<b>".
            found = self._sqli_eval(raw)
            if found:
                self._send(200, "<html><body><div id=result>Item found: Widget</div></body></html>")
            else:
                self._send(200, "<html><body><div id=result>No such item</div></body></html>")
            return

        mo = re.match(r"^/api/orders/(\w+)$", path)
        if mo:
            oid = mo.group(1)
            if oid not in _ORDERS:
                self._send(404, json.dumps({"error": "not found"}), "application/json")
                return
            owner_cookie, data = _ORDERS[oid]
            cookie = self.headers.get("Cookie", "")
            # VULNERABLE: any authenticated session can read any order (IDOR).
            # Unauthenticated requests are rejected (so it is NOT public).
            if not cookie:
                self._send(401, json.dumps({"error": "auth required"}), "application/json")
                return
            self._send(200, json.dumps(data), "application/json")
            return

        self._send(404, "<html><body>not found</body></html>")

    @staticmethod
    def _sqli_eval(raw: str) -> bool:
        """Simulate a backend that concatenates `id` into WHERE id=<raw>.
        A bare valid id (1001/1) is 'found'. `AND 1=1` keeps it true;
        `AND 1=2` makes it false. Anything else: not found."""
        raw = raw.strip()
        m = re.match(r"^(\d+)(?:\s+AND\s+(\d+)\s*=\s*(\d+))?$", raw, re.IGNORECASE)
        if not m:
            return False
        base_ok = m.group(1) == "1"
        if m.group(2) is None:
            return base_ok
        return base_ok and (m.group(2) == m.group(3))


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"bouncer mock server on http://{host}:{port} (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def start_background(host: str = "127.0.0.1", port: int = 0):
    """Start on an ephemeral port in a daemon thread; return (server, port)."""
    import threading
    server = ThreadingHTTPServer((host, port), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, server.server_address[1]
