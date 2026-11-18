#!/usr/bin/env python3
"""Withhold one successful synthetic deletion response on an opt-in client tunnel.

The original delivery service validates and executes the signed request. Its
first successful response is recorded privately, then the client connection
closes. While the receipt is pending, repeats wait for the operator to write
allow-retry.json containing the recorded operationId. The next ordinary client
retry then goes back to the delivery service, and its actual reply is returned.
"""

import argparse
import base64
import contextlib
import hashlib
import http.client
import http.server
import json
import os
import re
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from pathlib import Path

from mobile_qualification_frontend import HOP, LIMIT, LOOPBACK, HttpHandler, put_json

NSID = "blue.catbird.labyrinth.deleteAccountData"
PATH = "/xrpc/" + NSID


def decode_json(value):
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


class ReceiptHandler(HttpHandler):
    def log_request(self, code="-", size="-"):
        # Keep token values, URL queries, device signatures and bodies out of logs.
        path = urllib.parse.urlsplit(self.path).path
        auth = self.headers.get("Authorization", "").partition(" ")[0]
        scheme = (
            auth
            if auth in {"Bearer", "DPoP", "Atproto-Space-Credential"}
            else "none/other"
        )
        print(
            f"{int(time.time())} {self.command} {path} {code} auth={scheme}",
            file=sys.stderr,
            flush=True,
        )

    def send_body(self, status, payload, headers=()):
        self.send_response(status)
        for k, v in headers:
            if k.lower() not in HOP | {"content-length"}:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        gate = getattr(self.server, "gate", None)
        if (
            not gate
            or self.headers.get("Host", "").split(":")[0] != gate["host"]
            or self.path != PATH
        ):
            return super().do_POST()
        try:
            token = self.headers["Authorization"].removeprefix("Bearer ")
            _, claims, _ = token.split(".")
            if decode_json(claims).get("iss") != gate["did"]:
                return super().do_POST()
            signed = self.headers["Catbird-Labyrinth-Write"]
            operation = decode_json(signed)["operationId"]
            if not re.fullmatch(r"[a-f0-9]{32}", operation):
                return super().do_POST()
        except (AttributeError, ValueError, TypeError, KeyError):
            return super().do_POST()
        # Identifiers above only select this synthetic capture. The service
        # verifies authorization, device signature and proofs on every forward.
        self.close_connection = True
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.send_error(400)
        if not 0 <= length <= LIMIT or self.headers.get("Transfer-Encoding"):
            return self.send_error(413)
        body = self.rfile.read(length)
        receipt = gate["dir"] / "upstream-accepted.json"
        release = gate["dir"] / "allow-retry.json"
        with gate["lock"]:
            if receipt.exists():
                previous = json.loads(receipt.read_text())
                if previous["operationId"] != operation:
                    put_json(
                        gate["dir"] / "changed-operation.json",
                        {
                            "expected": previous["operationId"],
                            "observed": operation,
                            "at": int(time.time()),
                        },
                    )
                    return self.send_body(409, b'{"error":"FixtureOperationChanged"}')
                if (
                    not release.exists()
                    or json.loads(release.read_text()).get("operationId") != operation
                ):
                    return self.send_body(503, b'{"error":"FixtureResponsePending"}')
            headers = {
                k: v
                for k, v in self.headers.items()
                if k.lower() not in HOP | {"host", "content-length"}
            }
            conn = http.client.HTTPConnection(LOOPBACK, gate["port"], timeout=45)
            with contextlib.closing(conn):
                conn.request("POST", PATH, body, headers)
                upstream = conn.getresponse()
                payload = upstream.read(LIMIT + 1)
                if len(payload) > LIMIT:
                    return self.send_error(502)
                data = {
                    "operationId": operation,
                    "receivedAt": int(time.time()),
                    "status": upstream.status,
                    "deviceWriteSha256": hashlib.sha256(signed.encode()).hexdigest(),
                    "requestBodySha256": hashlib.sha256(body).hexdigest(),
                    "responseBodySha256": hashlib.sha256(payload).hexdigest(),
                }
                if receipt.exists():
                    put_json(gate["dir"] / "upstream-retry.json", data)
                elif 200 <= upstream.status < 300:
                    put_json(receipt, data)
                    with contextlib.suppress(OSError):
                        self.connection.shutdown(socket.SHUT_RDWR)
                    return
                else:
                    put_json(gate["dir"] / "upstream-refusal.json", data)
                self.send_body(upstream.status, payload, upstream.getheaders())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--account", required=True, choices=["alice", "bob"])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--observe-only", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    root = args.fixture.resolve()
    if root.stat().st_mode & 0o077:
        parser.error("fixture directory must be private")
    args.output.mkdir(mode=0o700)
    m = json.loads((root / "manifest.json").read_text())
    accounts = json.loads((root / "sessions.json").read_text())["accounts"]
    target = next(a for a in accounts if a["label"] == args.account)
    hosts = m["hosts"]
    names = {host: key for key, host in hosts.items()}
    host = urllib.parse.urlsplit(target["serviceEndpoint"]).hostname
    if host not in names or not all(
        h.endswith(".request-fixture.catbird.blue") for h in names
    ):
        parser.error("invalid fixture host")
    ports = {key: int(meta["port"]) for key, meta in m["processes"].items()}
    with (
        http.server.ThreadingHTTPServer((LOOPBACK, 0), ReceiptHandler) as tls,
        http.server.ThreadingHTTPServer((LOOPBACK, 0), ReceiptHandler) as proxy,
    ):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(root / "server.pem", root / "server.key")
        tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
        tls.fixture = {
            "names": names,
            "accounts": accounts,
            "ports": ports,
            "docs": json.loads((root / "public-directory.json").read_text()),
        }
        tls.gate = {
            "dir": args.output,
            "did": target["did"],
            "host": host,
            "port": ports[names[host]],
            "lock": threading.Lock(),
        }
        if args.observe_only:
            tls.gate = None
        proxy.is_proxy = True
        proxy.tls_port = tls.server_port
        proxy.allowed = {h + ":443" for h in names}
        threading.Thread(target=tls.serve_forever, daemon=True).start()
        put_json(
            args.output / "tunnel.json",
            {
                "proxyPort": proxy.server_port,
                "tlsPort": tls.server_port,
                "account": args.account,
                "home": host,
                "fixturePid": m["pid"],
                "pid": os.getpid(),
            },
        )
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        proxy.serve_forever()


if __name__ == "__main__":
    main()
