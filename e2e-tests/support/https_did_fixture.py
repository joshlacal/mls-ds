#!/usr/bin/env python3
import http.server
import json
import ssl
import sys

root, certificate, private_key, raw_port = sys.argv[1:]

class DidHandler(http.server.SimpleHTTPRequestHandler):
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
