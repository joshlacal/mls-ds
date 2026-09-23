#!/usr/bin/env python3
import http.server
import json
import os
import ssl
import sys
import urllib.parse

root, certificate, private_key, raw_port = sys.argv[1:]


def policy_override(*parts):
    """Opt-in per-request policy override under <root>/_policy; None when absent.

    Read on every request so a test can change policy between operations.
    Malformed overrides raise; the handler reports them as HTTP 500.
    """
    path = os.path.join(root, "_policy", *[urllib.parse.quote(part, safe="") for part in parts])
    if not os.path.exists(path):
        return None
    with open(path, "rb") as handle:
        value = json.loads(handle.read())
    if not isinstance(value, dict):
        raise ValueError(f"policy override {path} is not a JSON object")
    return value


class DidHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            self.route()
        except Exception as error:  # malformed override: fail loudly
            body = str(error).encode()
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def route(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        host = self.headers.get("Host", "").split(":", 1)[0].lower()
        if parsed.path == "/xrpc/com.atproto.repo.getRecord":
            repo = query.get("repo", [""])[0]
            collection = query.get("collection", [""])[0]
            rkey = query.get("rkey", [""])[0]
            if (collection != "chat.bsky.actor.declaration" or rkey != "self"
                    or repo != f"did:web:{host}"):
                self.send_error(400)
                return
            value = policy_override("declaration", repo) or {
                "$type": "chat.bsky.actor.declaration",
                "allowIncoming": "all"
            }
            self.send_json({
                "uri": f"at://{repo}/chat.bsky.actor.declaration/self",
                "value": value
            })
            return
        if parsed.path == "/xrpc/app.bsky.graph.getRelationships":
            actor = query.get("actor", [""])[0]
            others = query.get("others", [])
            relationships = []
            for other in others:
                row = {
                    "$type": "app.bsky.graph.defs#relationship",
                    "did": other
                }
                row.update(policy_override("relationship", actor, other) or {})
                relationships.append(row)
            self.send_json({
                "actor": actor,
                "relationships": relationships
            })
            return
        super().do_GET()

    def send_json(self, value):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def translate_path(self, path):
        host = self.headers.get("Host", "").split(":", 1)[0].lower()
        self.directory = f"{root}/{host}"
        return super().translate_path(path)

server = http.server.ThreadingHTTPServer(("127.0.0.1", int(raw_port)), DidHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certificate, private_key)
server.socket = context.wrap_socket(server.socket, server_side=True)
print(json.dumps({"port": server.server_port}), flush=True)
server.serve_forever()
