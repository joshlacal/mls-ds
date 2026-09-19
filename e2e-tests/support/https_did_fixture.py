#!/usr/bin/env python3
import http.server
import json
import ssl
import sys
import urllib.parse

root, certificate, private_key, raw_port = sys.argv[1:]

class DidHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
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
            self.send_json({
                "uri": f"at://{repo}/chat.bsky.actor.declaration/self",
                "value": {
                    "$type": "chat.bsky.actor.declaration",
                    "allowIncoming": "all"
                }
            })
            return
        if parsed.path == "/xrpc/app.bsky.graph.getRelationships":
            actor = query.get("actor", [""])[0]
            others = query.get("others", [])
            self.send_json({
                "actor": actor,
                "relationships": [{
                    "$type": "app.bsky.graph.defs#relationship",
                    "did": other
                } for other in others]
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
