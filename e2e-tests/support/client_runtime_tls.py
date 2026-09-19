#!/usr/bin/env python3
"""Loopback-only test TLS relay; credentials and payloads are never logged."""
import http.client
import http.server
import json
import ssl
import sys

LIMIT_IN = 16 * 1024 * 1024
LIMIT_OUT = 32 * 1024 * 1024

def main():
    certificate, private_key, raw_port, upstream_port, hosts_file = sys.argv[1:]
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

if __name__ == "__main__":
    main()
