#!/usr/bin/env python3
"""Loopback-only test TLS relay; credentials and payloads are never logged."""
import base64
import os
import select
import socket
import stat
import time
import urllib.parse
import http.client
import http.server
import json
import ssl
import sys

LIMIT_IN = 16 * 1024 * 1024
LIMIT_OUT = 32 * 1024 * 1024

def load_ws_config(path):
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 4096:
        raise ValueError("invalid protected WebSocket configuration")
    with open(path, encoding="utf-8") as source:
        value = json.load(source)
    if set(value) != {"port", "origin"} or type(value["port"]) is not int or not 1 <= value["port"] <= 65535:
        raise ValueError("invalid WebSocket target")
    origin = urllib.parse.urlsplit(value["origin"])
    if origin.scheme not in {"http", "https"} or origin.hostname not in {"localhost", "127.0.0.1", "::1"} or origin.username or origin.password or origin.path or origin.query or origin.fragment:
        raise ValueError("invalid WebSocket origin")
    return value


def validate_ws(headers, path, origin):
    parsed = urllib.parse.urlsplit(path)
    if parsed.path != "/xrpc/blue.catbird.chat.subscribeEvents" or parsed.scheme or parsed.netloc or parsed.fragment:
        raise ValueError("unsupported WebSocket path")
    for name in ("Host", "Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version"):
        if len(headers.get_all(name, [])) != 1:
            raise ValueError("missing or duplicate WebSocket header")
    if headers["Host"].lower() not in {"chat.catbird.blue", "chat.catbird.blue:443"}:
        raise ValueError("unsupported WebSocket authority")
    connection = {v.strip().lower() for v in headers["Connection"].split(",")}
    if headers["Upgrade"].lower() != "websocket" or "upgrade" not in connection or "close" in connection or headers["Sec-WebSocket-Version"] != "13":
        raise ValueError("invalid WebSocket upgrade")
    if len(base64.b64decode(headers["Sec-WebSocket-Key"], validate=True)) != 16:
        raise ValueError("invalid WebSocket key")
    origins = headers.get_all("Origin", [])
    if len(origins) > 1 or origins and origins[0] != origin:
        raise ValueError("WebSocket origin mismatch")
    lengths = headers.get_all("Content-Length", [])
    if len(lengths) > 1 or lengths and lengths[0] != "0" or headers.get("Transfer-Encoding"):
        raise ValueError("WebSocket body forbidden")
    if len(path) > 8192:
        raise ValueError("WebSocket query too large")


def main():
    certificate, private_key, raw_port, upstream_port, hosts_file, ws_config_file = sys.argv[1:]
    with open(hosts_file, encoding="utf-8") as source:
        hosts = set(json.load(source))
    if not hosts or any(not isinstance(h, str) or ":" in h or "/" in h for h in hosts):
        raise ValueError("invalid fixture host inventory")

    class Handler(http.server.BaseHTTPRequestHandler):
        def handle_method(self):
            self.connection.settimeout(45)
            host = self.headers.get("Host", "").split(":", 1)[0].lower()
            lengths = self.headers.get_all("Content-Length", [])
            if host not in hosts or not self.path.startswith("/") or self.path.startswith("//"):
                self.send_error(400)
                return
            if self.headers.get("Upgrade"):
                self.handle_websocket(ws_config_file)
                return
            conn = None
            try:
                if len(lengths) > 1 or self.headers.get("Transfer-Encoding"):
                    self.send_error(400)
                    return
                length = int(lengths[0]) if lengths else 0
                if length < 0 or length > LIMIT_IN:
                    self.send_error(413)
                    return
                body = self.rfile.read(length)
                if len(body) != length:
                    self.send_error(400)
                    return
                headers = {k: v for k, v in self.headers.items()
                           if k.lower() not in {"connection", "proxy-authorization", "transfer-encoding"}}
                conn = http.client.HTTPConnection("127.0.0.1", int(upstream_port), timeout=45)
                conn.request(self.command, self.path, body=body, headers=headers)
                response = conn.getresponse()
                data = response.read(LIMIT_OUT + 1)
                if len(data) > LIMIT_OUT:
                    self.send_error(502)
                    return
                self.send_response(response.status)
                for key in ("Content-Type", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
                            "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Vary"):
                    if response.getheader(key):
                        self.send_header(key, response.getheader(key))
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (OSError, ValueError, http.client.HTTPException):
                self.send_error(502)
            finally:
                if conn:
                    conn.close()

        def handle_websocket(self, config_path):
            upstream = None
            try:
                config = load_ws_config(config_path)
                if self.command != "GET":
                    raise ValueError("WebSocket requires GET")
                validate_ws(self.headers, self.path, config["origin"])
            except (OSError, ValueError, KeyError):
                self.send_error(400)
                return
            try:
                upstream = socket.create_connection(("127.0.0.1", config["port"]), timeout=5)
                # The query is copied byte-for-byte; the shipping router alone
                # consumes/validates the ticket. Never expose session cookies to it.
                head = f"GET {self.path} HTTP/1.1\r\n" + "".join(
                    f"{k}: {v}\r\n" for k, v in self.headers.items()
                    if k.lower() not in {"proxy-authorization", "authorization", "cookie"}) + "\r\n"
                upstream.sendall(head.encode("latin-1"))
                deadline = time.monotonic() + 3600
                last_activity = time.monotonic()
                while time.monotonic() < deadline and time.monotonic() - last_activity < 120:
                    ready = [self.connection] if self.connection.pending() else select.select([self.connection, upstream], [], [], 1)[0]
                    for source in ready:
                        chunk = source.recv(65536)
                        if not chunk:
                            return
                        target = upstream if source is self.connection else self.connection
                        target.sendall(chunk)
                        last_activity = time.monotonic()
            except (OSError, ValueError):
                pass  # No ticket, headers, credentials, or payload in logs.
            finally:
                self.close_connection = True
                if upstream:
                    upstream.close()
                self.connection.close()

        do_GET = handle_method
        do_POST = handle_method
        do_OPTIONS = handle_method

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", int(raw_port)), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(json.dumps({"port": server.server_port}), flush=True)
    server.serve_forever()

def self_test():
    import email
    import tempfile
    import unittest
    class Guards(unittest.TestCase):
        def headers(self, extra=""):
            return email.message_from_string("Host: chat.catbird.blue\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Key: " + base64.b64encode(bytes(16)).decode() + "\nSec-WebSocket-Version: 13\n" + extra)
        def test_valid_and_invalid_upgrade(self):
            origin="http://127.0.0.1:5173"
            path="/xrpc/blue.catbird.chat.subscribeEvents?ticket=opaque&cursor=opaque"
            validate_ws(self.headers(),path,origin)
            for extra in ["Host: attacker.invalid\n", "Origin: https://attacker.invalid\n", "Content-Length: 1\n", "Transfer-Encoding: chunked\n", "Sec-WebSocket-Version: 12\n"]:
                with self.assertRaises(ValueError): validate_ws(self.headers(extra),path,origin)
            with self.assertRaises(ValueError): validate_ws(self.headers(),"/other?ticket=opaque",origin)
        def test_native_absent_and_browser_exact_origin(self):
            origin="http://127.0.0.1:5173"
            path="/xrpc/blue.catbird.chat.subscribeEvents?ticket=opaque&cursor=opaque"
            # Native clients omit Origin. The shipping route still requires its one-use ticket.
            validate_ws(self.headers(),path,origin)
            validate_ws(self.headers("Origin: " + origin + "\n"),path,origin)
            for extra in ["Origin: " + origin + "\nOrigin: " + origin + "\n", "Origin: https://attacker.invalid\n", "Origin: null\n"]:
                with self.assertRaises(ValueError): validate_ws(self.headers(extra),path,origin)
        def test_protected_target(self):
            with tempfile.TemporaryDirectory() as d:
                p=os.path.join(d,"config.json")
                with open(p,"w",encoding="utf-8") as f: json.dump({"port":12345,"origin":"http://127.0.0.1:5173"},f)
                os.chmod(p,0o600)
                self.assertEqual(load_ws_config(p)["port"],12345)
                os.chmod(p,0o644)
                with self.assertRaises(ValueError): load_ws_config(p)
    result=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Guards))
    if not result.wasSuccessful(): raise SystemExit(1)

if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        main()
