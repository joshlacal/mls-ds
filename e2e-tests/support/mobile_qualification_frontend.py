#!/usr/bin/env python3
"""Run two private DS processes and independent synthetic account/PDS processes.

First use --initialize DIR to create private credentials, then --serve DIR with
an explicitly supplied disposable local PostgreSQL port and fixture binaries.
The HTTPS and CONNECT services bind to loopback. Only generated hostnames and
public protocol endpoints are reachable via the client-facing listeners.
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
import secrets
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from pathlib import Path

LOOPBACK = "127.0.0.1"
SUFFIX = ".request-fixture.catbird.blue"
SEATBELT = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))'
HOP = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "transfer-encoding",
    "proxy-authorization",
    "proxy-authenticate",
}
LIMIT = 16 << 20


def put_json(path, value):
    tmp = path.with_name(path.name + ".new")
    tmp.write_text(json.dumps(value, indent=2) + "\n")
    os.replace(tmp, path)


def init(directory, with_upgrade_account=False):
    directory.mkdir(mode=0o700)
    homes = {"alice": "ds1", "bob": "ds2"}
    if with_upgrade_account:
        homes["carol"] = "ds1"
    # Petrel admits delivery-service origins that share the gateway run suffix.
    run_suffix = secrets.token_hex(4) + SUFFIX
    hosts = {
        name: name + "-" + run_suffix
        for name in ("ds1", "ds2", *homes, "gateway")
    }

    def openssl(*args):
        subprocess.run(
            ["openssl", *args], check=True, cwd=directory, capture_output=True
        )

    openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-subj",
        "/CN=Catbird private fixture CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    )
    openssl(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "server.key",
        "-out",
        "server.csr",
        "-subj",
        "/CN=" + hosts["gateway"],
    )
    (directory / "san.cnf").write_text(
        "subjectAltName="
        + ",".join("DNS:" + h for h in hosts.values())
        + "\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
    )
    openssl(
        "x509",
        "-req",
        "-in",
        "server.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-days",
        "2",
        "-extfile",
        "san.cnf",
        "-out",
        "server.pem",
    )
    endpoint = {
        "gatewayEndpoint": "https://" + hosts["gateway"],
        "hosts": hosts,
        "homeDids": {ds: "did:web:" + hosts[ds] for ds in ("ds1", "ds2")},
        "ca": str(directory / "ca.pem"),
    }
    put_json(directory / "endpoints.json", endpoint)
    accounts = []
    for label, ds in homes.items():
        accounts.append(
            {
                "label": label,
                "handle": hosts[label],
                "did": "did:web:" + hosts[label],
                "password": secrets.token_urlsafe(40),
                "session": secrets.token_urlsafe(40),
                "refresh": secrets.token_urlsafe(40),
                "deliveryService": endpoint["homeDids"][ds],
                "serviceEndpoint": "https://" + hosts[ds],
                "pdsEndpoint": "https://" + hosts[label],
                "gatewayEndpoint": endpoint["gatewayEndpoint"],
            }
        )
    put_json(directory / "sessions.json", {"accounts": accounts})


def relay(left, right):
    with contextlib.suppress(OSError):
        while True:
            for reader in select.select([left, right], [], [], 90)[0]:
                data = reader.recv(65536)
                if not data:
                    return
                (right if reader is left else left).sendall(data)


class HttpHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *unused):
        pass  # credentials, query strings and bodies stay out of evidence

    def do_CONNECT(self):
        if (
            not getattr(self.server, "is_proxy", False)
            or self.path not in self.server.allowed
        ):
            return self.send_error(403)
        with socket.create_connection((LOOPBACK, self.server.tls_port), 10) as upstream:
            self.send_response_only(200)
            self.end_headers()
            relay(self.connection, upstream)
        self.close_connection = True

    def forward(self):
        self.close_connection = True
        if getattr(self.server, "is_proxy", False):
            return self.send_error(403)
        host = self.headers.get("Host", "").split(":")[0].lower()
        state = self.server.fixture
        key = state["names"].get(host)
        url = urllib.parse.urlsplit(self.path)
        if (
            key is None
            or url.scheme
            or url.netloc
            or not self.path.startswith("/")
            or url.fragment
        ):
            return self.send_error(403)
        well_known = {"/.well-known/did.json", "/.well-known/atproto-did"}
        if (
            self.command == "GET"
            and url.path in well_known
            and "did:web:" + host in state["docs"]
        ):
            did = "did:web:" + host
            if url.path.endswith("did.json"):
                payload = json.dumps(state["docs"][did]).encode()
                mime = "application/json"
            else:
                payload = did.encode()
                mime = "text/plain"
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if url.path != "/auth/session" and not re.fullmatch(
            r"/xrpc/[a-zA-Z0-9.]+", url.path
        ):
            return self.send_error(404)
        if key == "gateway":
            bearer = self.headers.get("Authorization", "").removeprefix("Bearer ")
            cookie = self.headers.get("Cookie", "")
            matched = next(
                (
                    a
                    for a in state["accounts"]
                    if a["session"] == bearer
                    or any(
                        p.strip()
                        in {"catbird_session=" + a["session"], "sid=" + a["session"]}
                        for p in cookie.split(";")
                    )
                ),
                None,
            )
            # Unauthenticated public directory queries may use either PDS.
            if not matched and url.path not in {
                "/xrpc/com.atproto.identity.resolveDid",
                "/xrpc/com.atproto.identity.resolveHandle",
            }:
                return self.send_error(401)
            key = matched["label"] if matched else "alice"
        if key not in state["ports"]:
            return self.send_error(503)
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.send_error(400)
        if not 0 <= length <= LIMIT or self.headers.get("Transfer-Encoding"):
            return self.send_error(413)
        headers = {
            k: v
            for k, v in self.headers.items()
            if k.lower() not in HOP | {"host", "content-length"}
        }
        body = self.rfile.read(length) if length else None
        print(f"{key} {self.command} {url.path}", file=sys.stderr, flush=True)
        if self.headers.get("Upgrade", "").lower() == "websocket":
            if url.path != "/xrpc/blue.catbird.chat.subscribeEvents":
                return self.send_error(404)
            with socket.create_connection((LOOPBACK, state["ports"][key]), 10) as conn:
                lines = [
                    f"GET {self.path} HTTP/1.1",
                    f"Host: {host}",
                    "Connection: Upgrade",
                    "Upgrade: websocket",
                ]
                lines.extend(k + ": " + v for k, v in headers.items())
                conn.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin1"))
                relay(self.connection, conn)
            return
        try:
            upstream = http.client.HTTPConnection(
                LOOPBACK, state["ports"][key], timeout=30
            )
            with contextlib.closing(upstream):
                upstream.request(self.command, self.path, body, headers)
                resp = upstream.getresponse()
                self.send_response(resp.status)
                for name, val in resp.getheaders():
                    if name.lower() not in HOP:
                        self.send_header(name, val)
                self.send_header("Connection", "close")
                self.end_headers()
                while block := resp.read(65536):
                    self.wfile.write(block)
        except OSError:
            self.close_connection = True

    do_GET = forward
    do_POST = forward


def signing_key():
    return subprocess.check_output(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
        ]
    )


def public_jwk(key):
    der = subprocess.check_output(
        ["openssl", "pkey", "-pubout", "-outform", "DER"], input=key
    )
    raw = der[-65:]
    if raw[0] != 4:
        raise RuntimeError("invalid P-256 public key")
    enc = lambda data: base64.urlsafe_b64encode(data).decode().rstrip("=")
    return {"kty": "EC", "crv": "P-256", "x": enc(raw[1:33]), "y": enc(raw[33:])}


def serve(args):
    root = args.serve
    if root.stat().st_mode & 0o077:
        raise ValueError("fixture directory must be private")
    if (root / "manifest.json").exists():
        raise FileExistsError("fixture already launched; initialize a fresh directory")
    ep = json.loads((root / "endpoints.json").read_text())
    accounts = json.loads((root / "sessions.json").read_text())["accounts"]
    hosts = ep["hosts"]
    if any(
        not re.fullmatch(r"[a-z0-9-]+\.request-fixture\.catbird\.blue", h)
        for h in hosts.values()
    ):
        raise ValueError("invalid fixture host")
    state = {
        "names": {h: k for k, h in hosts.items()},
        "accounts": accounts,
        "ports": {},
        "docs": {},
    }
    registry = root / "public-directory.json"
    run = root / ("run-" + uuid.uuid4().hex)
    run.mkdir(mode=0o700)
    # Other workspace builds may replace target/debug binaries during a long
    # mobile run. Pin the actual bytes before launching either process.
    delivery_binary = run / "delivery-fixture"
    pds_binary = run / "account-fixture"
    shutil.copy2(args.delivery_binary, delivery_binary)
    shutil.copy2(args.pds_binary, pds_binary)
    dbs = {}
    migrations = {}
    children = []
    processes = {}
    ds_configs = {}

    def launch(binary, label, env, config=None):
        log = (run / (label + ".log")).open("ab")
        with log:
            child = subprocess.Popen(
                ["/usr/bin/sandbox-exec", "-p", SEATBELT, str(binary.resolve())],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=log,
                env=env,
            )
        children.append(child)
        processes[label] = child
        if config:
            child.stdin.write(json.dumps(config).encode())
        child.stdin.close()
        if not select.select([child.stdout], [], [], 180)[0]:
            raise RuntimeError(f"{label} readiness timed out; inspect {log.name}")
        data = child.stdout.readline()
        if not data:
            raise RuntimeError(f"{label} exited; inspect {log.name}")
        ready = json.loads(data)
        parsed = urllib.parse.urlsplit(ready["baseUrl"])
        if parsed.hostname != LOOPBACK or parsed.scheme != "http" or not parsed.port:
            raise ValueError("child must bind loopback")
        state["ports"][label] = parsed.port
        return ready

    def register(ds, registration):
        for actor in registration:
            conn = http.client.HTTPConnection(LOOPBACK, state["ports"][ds], timeout=10)
            with contextlib.closing(conn):
                conn.request(
                    "POST",
                    "/_test/clean-slate/register-did",
                    json.dumps(actor),
                    {"Content-Type": "application/json"},
                )
                reply = conn.getresponse()
                if reply.status != 200:
                    raise RuntimeError(
                        f"{ds} DID registration HTTP {reply.status}: {reply.read()[:200]}"
                    )

    with (
        http.server.ThreadingHTTPServer((LOOPBACK, args.tls_port), HttpHandler) as tls,
        http.server.ThreadingHTTPServer(
            (LOOPBACK, args.proxy_port), HttpHandler
        ) as proxy,
    ):
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(root / "server.pem", root / "server.key")
        tls.socket = server_tls.wrap_socket(tls.socket, server_side=True)
        tls.fixture = state
        proxy.is_proxy = True
        proxy.tls_port = tls.server_port
        proxy.allowed = {host + ":443" for host in hosts.values()}
        for listener in [tls, proxy]:
            threading.Thread(target=listener.serve_forever, daemon=True).start()
        # Inherit no database, proxy, shared service, analytics or user secrets.
        env = {
            key: os.environ[key]
            for key in ("PATH", "TMPDIR", "LANG", "CTL_AGENT")
            if key in os.environ
        }
        env.update(
            {
                "APP_ENV": "test",
                "NO_PROXY": "*",
                "TOKIO_WORKER_THREADS": "3",
                "REQUEST_FIXTURE_DID_HOSTS": ",".join(hosts.values()),
                "REQUEST_FIXTURE_DID_CA_PEM": str(root / "ca.pem"),
                "REQUEST_FIXTURE_DID_PORT": str(tls.server_port),
            }
        )
        services, registration = {}, []
        try:
            s2s = secrets.token_urlsafe(48)
            for ds in ("ds1", "ds2"):
                did = ep["homeDids"][ds]
                db = "clean_slate_fed_" + uuid.uuid4().hex
                subprocess.run(
                    ["createdb", "-h", LOOPBACK, "-p", str(args.pg_port), db],
                    check=True,
                    env=env,
                )
                dbs[ds] = db
                kek = run / (ds + ".kek")
                kek.write_bytes(secrets.token_bytes(32))
                key = signing_key()
                ds_env = env | {
                    "TEST_DATABASE_URL": f"postgresql://{LOOPBACK}:{args.pg_port}/{db}",
                    "SERVICE_DID": did,
                    "SIGNING_KEY_PEM": key.decode(),
                    "RECEIPT_SIGNING_KEY_PEM": signing_key().decode(),
                    "FEDERATION_GROUP_RELAY_HMAC_SECRET": s2s,
                    "CHAT_SUBSCRIPTION_ENDPOINT": "wss://"
                    + hosts[ds]
                    + "/xrpc/blue.catbird.chat.subscribeEvents",
                    "LABYRINTH_RECOVERY_SHARE_KEK_FILE": str(kek),
                    "LABYRINTH_RECOVERY_SHARE_KEK_ID": ds,
                    "LABYRINTH_RECOVERY_SHARE_TOMBSTONE_FILE": str(
                        run / (ds + ".journal")
                    ),
                }
                ds_env["CLEAN_SLATE_OUTBOUND_WORKER"] = "1"
                ready = launch(delivery_binary, ds, ds_env)
                ds_configs[ds] = ds_env | {
                    "CLEAN_SLATE_RESUME": "1",
                    "CLEAN_SLATE_LISTEN": f"{LOOPBACK}:{state['ports'][ds]}",
                }
                put_json(run / (ds + ".private.json"), ds_configs[ds])
                migrations[ds] = subprocess.check_output(
                    [
                        "psql",
                        "-XAt",
                        "-h",
                        LOOPBACK,
                        "-p",
                        str(args.pg_port),
                        "-d",
                        db,
                        "-c",
                        "SELECT max(version) FROM _sqlx_migrations WHERE success",
                    ],
                    env=env,
                    text=True,
                ).strip()
                doc = ready["didDocument"]
                for s in doc["service"]:
                    s["serviceEndpoint"] = "https://" + hosts[ds]
                state["docs"][did] = doc
                services[did] = ready["baseUrl"]
                registration.append(
                    {
                        "did": did,
                        "didDocument": doc,
                        "p256Jwk": public_jwk(key),
                        "endpointUrl": ready["baseUrl"],
                        "isDs": True,
                    }
                )
            for account in accounts:
                did = account["did"]
                conf = {
                    k: account[k] for k in ("did", "password", "session", "refresh")
                }
                conf.update(
                    {
                        "home": account["deliveryService"],
                        "services": services,
                        "docs": str(registry),
                    }
                )
                ready = launch(pds_binary, account["label"], env, conf)
                state["docs"][did] = ready["didDocument"]
                registration.append(
                    {
                        "did": did,
                        "didDocument": ready["didDocument"],
                        "p256Jwk": ready["publicJwk"],
                        "endpointUrl": ready["baseUrl"],
                        "isDs": False,
                    }
                )
            put_json(registry, state["docs"])
            for ds in ("ds1", "ds2"):
                register(ds, registration)
            with delivery_binary.open("rb") as binary:
                delivery_hash = hashlib.file_digest(binary, "sha256").hexdigest()
            with pds_binary.open("rb") as binary:
                pds_hash = hashlib.file_digest(binary, "sha256").hexdigest()
            put_json(
                root / "manifest.json",
                ep
                | {
                    "deliverySha256": delivery_hash,
                    "pdsSha256": pds_hash,
                    "migrations": migrations,
                    "proxyPort": proxy.server_port,
                    "tlsPort": tls.server_port,
                    "sessions": str(root / "sessions.json"),
                    "processes": {
                        k: {"port": v, "pid": p.pid}
                        for k, v in state["ports"].items()
                        for p in [processes[k]]
                    },
                    "databases": dbs,
                    "runDirectory": str(run),
                    "pid": os.getpid(),
                },
            )
            print("Private mobile fixture ready", flush=True)
            # A private control file explicitly requests a quiescent DS-only restart.
            # Preserve live PDS state even if a new DS fails to start.
            last_request = None
            while all(processes[a["label"]].poll() is None for a in accounts):
                threading.Event().wait(1)
                request = run / "restart.json"
                if not request.exists():
                    continue
                control = json.loads(request.read_text())
                if control == last_request:
                    continue
                last_request = control
                try:
                    expected = control["sha256"]
                    if not re.fullmatch(r"[a-f0-9]{64}", expected):
                        raise ValueError("invalid candidate hash")
                    candidate = run / ("delivery-" + expected)
                    with candidate.open("rb") as binary:
                        if (
                            hashlib.file_digest(binary, "sha256").hexdigest()
                            != expected
                        ):
                            raise ValueError("candidate binary hash mismatch")
                    for ds in ("ds1", "ds2"):
                        if processes[ds].poll() is None:
                            processes[ds].terminate()
                            processes[ds].wait(timeout=20)
                        ready = launch(candidate, ds, ds_configs[ds])
                        if ready["baseUrl"] != services[ep["homeDids"][ds]]:
                            raise ValueError("delivery origin changed on resume")
                        if (
                            ready["didDocument"]["verificationMethod"]
                            != state["docs"][ep["homeDids"][ds]]["verificationMethod"]
                        ):
                            raise ValueError("delivery identity changed on resume")
                        register(ds, registration)
                        migrations[ds] = subprocess.check_output(
                            [
                                "psql",
                                "-XAt",
                                "-h",
                                LOOPBACK,
                                "-p",
                                str(args.pg_port),
                                "-d",
                                dbs[ds],
                                "-c",
                                "SELECT max(version) FROM _sqlx_migrations WHERE success",
                            ],
                            env=env,
                            text=True,
                        ).strip()
                    manifest = json.loads((root / "manifest.json").read_text())
                    manifest.update(deliverySha256=expected, migrations=migrations)
                    for ds in ("ds1", "ds2"):
                        manifest["processes"][ds]["pid"] = processes[ds].pid
                    put_json(root / "manifest.json", manifest)
                    put_json(
                        run / "restart-result.json",
                        {"request": control, "ok": True, "migrations": migrations},
                    )
                except (
                    ValueError,
                    OSError,
                    RuntimeError,
                    subprocess.SubprocessError,
                ) as exc:
                    put_json(
                        run / "restart-result.json",
                        {"request": control, "ok": False, "error": str(exc)},
                    )
            raise RuntimeError("fixture PDS exited")
        finally:
            for proc in children:
                if proc.poll() is None:
                    proc.terminate()
            for proc in children:
                proc.wait(timeout=15)


def check(root, pds_binary, *, fresh):
    """Verify both PDS signatures and the device-less DS response over the client tunnel."""
    if fresh and (root / "signed-smoke.json").exists():
        raise RuntimeError(
            "initial smoke already recorded; use --check-live after enrollment"
        )
    if not __debug__:
        raise RuntimeError("qualification assertions require standard Python execution")
    manifest = json.loads((root / "manifest.json").read_text())
    accounts = json.loads((root / "sessions.json").read_text())["accounts"]
    ctx = ssl.create_default_context(cafile=str(root / "ca.pem"))

    def request(host, path, method="GET", body=None, token=None):
        conn = http.client.HTTPSConnection(
            LOOPBACK, manifest["proxyPort"], timeout=15, context=ctx
        )
        conn.set_tunnel(host, 443)
        with contextlib.closing(conn):
            headers = {"Accept": "*/*"}
            if token:
                headers["Authorization"] = "Bearer " + token
            if body is not None:
                headers["Content-Type"] = "application/json"
            conn.request(
                method, path, json.dumps(body) if body is not None else None, headers
            )
            res = conn.getresponse()
            return res.status, res.read(LIMIT)

    def get_json(host, path, **opts):
        code, content = request(host, path, **opts)
        if code != 200:
            raise RuntimeError(f"fixture returned HTTP {code} on {path.split('?')[0]}")
        return json.loads(content)

    def rpc(nsid, **params):
        return (
            "/xrpc/" + nsid + ("?" + urllib.parse.urlencode(params) if params else "")
        )

    def decode(segment):
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))

    rows = []
    for account in accounts:
        host = account["handle"]
        ds = urllib.parse.urlsplit(account["serviceEndpoint"]).hostname
        did = account["did"]
        session = get_json(
            host,
            rpc("com.atproto.server.createSession"),
            method="POST",
            body={"identifier": host, "password": account["password"]},
        )
        assert session["did"] == did
        cred = session["accessJwt"]
        gateway = urllib.parse.urlsplit(account["gatewayEndpoint"]).hostname
        assert get_json(gateway, "/auth/session", token=cred)["did"] == did
        assert (
            get_json(host, rpc("com.atproto.server.getSession"), token=cred)["did"]
            == did
        )
        assert (
            get_json(host, rpc("com.atproto.space.listSpaces"), token=cred).get(
                "spaces"
            )
            is not None
        )
        doc = get_json(host, "/.well-known/did.json")
        assert get_json(ds, "/.well-known/did.json")["id"] == account["deliveryService"]
        declaration = "blue.catbird.chat.declaration"
        rec = get_json(
            host,
            rpc(
                "com.atproto.repo.getRecord",
                repo=did,
                collection=declaration,
                rkey="self",
            ),
        )
        assert rec["value"]["deliveryService"] == account["deliveryService"]
        assert rec["value"]["protocolVersion"] == "2"
        assert rec["value"]["allowIncoming"] == "all"
        latest = get_json(host, rpc("com.atproto.sync.getLatestCommit", did=did))
        for nsid, args in (
            ("com.atproto.sync.getRepo", {"did": did}),
            ("com.atproto.sync.getBlocks", {"did": did, "cids": latest["cid"]}),
        ):
            status, blocks = request(host, rpc(nsid, **args))
            if status != 200 or len(blocks) <= 64:
                raise RuntimeError(
                    f"current repository evidence unavailable at {nsid}: HTTP {status}"
                )
        status, car = request(
            host,
            rpc(
                "com.atproto.sync.getRecord",
                did=did,
                collection=declaration,
                rkey="self",
            ),
        )
        assert status == 200 and len(car) > 64
        nsid = "blue.catbird.labyrinth.deleteAccountData"
        auth = get_json(
            host,
            rpc(
                "com.atproto.server.getServiceAuth",
                aud=account["deliveryService"],
                lxm=nsid,
            ),
            token=cred,
        )["token"]
        header, claims, signature = auth.split(".")
        assert json.loads(decode(header))["alg"] == "ES256"
        payload = json.loads(decode(claims))
        assert (
            payload["iss"] == did
            and payload["aud"] == account["deliveryService"]
            and payload["lxm"] == nsid
        )
        assert payload["exp"] > time.time() and payload["exp"] - payload["iat"] <= 60
        multi = next(
            vm["publicKeyMultibase"]
            for vm in doc["verificationMethod"]
            if vm["id"] == did + "#atproto"
        )
        assert multi.startswith("z")
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        point = 0
        for char in multi[1:]:
            point = point * 58 + alphabet.index(char)
        point = point.to_bytes((point.bit_length() + 7) // 8, "big")
        assert point[:2] == bytes.fromhex("8024") and len(point) == 35
        spki = (
            bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200")
            + point[2:]
        )
        raw_signature = decode(signature)
        assert len(raw_signature) == 64

        def integer(raw):
            raw = raw.lstrip(bytes([0])) or bytes([0])
            if raw[0] & 128:
                raw = bytes([0]) + raw
            return bytes([2, len(raw)]) + raw

        parts = integer(raw_signature[:32]) + integer(raw_signature[32:])
        with tempfile.TemporaryDirectory(dir=root) as temp:
            tmp = Path(temp)
            (tmp / "key.der").write_bytes(spki)
            (tmp / "sig.der").write_bytes(bytes([48, len(parts)]) + parts)
            subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-keyform",
                    "DER",
                    "-verify",
                    str(tmp / "key.der"),
                    "-signature",
                    str(tmp / "sig.der"),
                ],
                input=(header + "." + claims).encode(),
                capture_output=True,
                check=True,
            )
        if fresh:
            status, response = request(
                ds, rpc(nsid), method="POST", token=auth, body={}
            )
            if status != 401 or json.loads(response).get("error") != "NotAuthorized":
                raise RuntimeError(
                    f"device-less request returned HTTP {status}; expected NotAuthorized"
                )
        evidence = {
            "did": did,
            "document": doc,
            "collection": declaration,
            "rkey": "self",
            "record": rec,
            "car": base64.urlsafe_b64encode(car).decode().rstrip("="),
        }
        result = subprocess.run(
            [str(pds_binary.resolve()), "--verify-record"],
            input=json.dumps(evidence).encode(),
            capture_output=True,
            check=True,
        )
        proof = json.loads(result.stdout)
        rows.append(
            {
                "account": account["label"],
                "serviceDid": account["deliveryService"],
                "signedDeclarationCid": proof["cid"],
                "verifiedRepoRevision": proof["rev"],
                "verifiedServiceTokenMethod": nsid,
                **(
                    {
                        "deviceLessDeleteStatus": 401,
                        "deviceLessDeleteError": "NotAuthorized",
                    }
                    if fresh
                    else {}
                ),
            }
        )
    put_json(
        root / ("signed-smoke.json" if fresh else "live-repositories.json"),
        {
            "twoDistinctServices": len({r["serviceDid"] for r in rows}) == 2,
            "verifiedAt": int(time.time()),
            "accounts": rows,
        },
    )
    print(
        f"Verified {len(rows)} synthetic accounts, signed CAR records and scoped service tokens"
    )
    if fresh:
        print(
            f"All {len(rows)} fresh accounts received an HTTP 401 device-less deletion refusal"
        )


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--initialize", type=Path)
    mode.add_argument("--serve", type=Path)
    mode.add_argument(
        "--check", type=Path, help="initial check before enrolling any device"
    )
    mode.add_argument(
        "--check-live",
        type=Path,
        help="verify the active accounts and public repository proofs",
    )
    parser.add_argument("--delivery-binary", type=Path)
    parser.add_argument("--pds-binary", type=Path)
    parser.add_argument("--pg-port", type=int)
    parser.add_argument("--tls-port", type=int, default=0)
    parser.add_argument("--proxy-port", type=int, default=0)
    parser.add_argument(
        "--with-upgrade-account",
        action="store_true",
        help="initialize a third independent account on the first home for old-app upgrade testing",
    )
    args = parser.parse_args()
    if args.with_upgrade_account and not args.initialize:
        parser.error("--with-upgrade-account applies to --initialize")
    if args.check or args.check_live:
        if not args.pds_binary:
            parser.error("supply the PDS fixture binary to verify CAR proofs")
        check(
            (args.check or args.check_live).resolve(),
            args.pds_binary,
            fresh=bool(args.check),
        )
        return
    if args.initialize:
        init(args.initialize.resolve(), args.with_upgrade_account)
        return
    if (
        not args.pg_port
        or args.pg_port == 5432
        or not args.delivery_binary
        or not args.pds_binary
    ):
        parser.error(
            "supply both fixture binaries and an explicit dedicated PostgreSQL port"
        )
    args.serve = args.serve.resolve()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    serve(args)


if __name__ == "__main__":
    main()
