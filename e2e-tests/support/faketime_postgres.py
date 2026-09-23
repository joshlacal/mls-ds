#!/usr/bin/env python3
"""Throwaway loopback Postgres cluster whose clock a test can advance.

The server takes every protocol instant from Postgres (`clock_timestamp()`,
`transaction_timestamp()`), so deadlines such as the seven-day request import
horizon are reachable only by moving the database clock. This launches a
private cluster under libfaketime; production code and the shared guarded
database are untouched.

  start   --dir D --port P --db catbird_direct_requests_faketime_<suffix>
  advance --dir D --offset +8d      (takes effect on the next query)
  stop    --dir D                   (stops the recorded pid, deletes D)

Schema = the shared guarded database's exact `_sqlx_migrations` ledger,
replayed in order from `mls-ds/server/migrations`; each file's SHA-384 must
equal the shared ledger checksum before it is applied.
"""
import argparse
import glob
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

SHARED_URL = "postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919"
MIGRATIONS = Path(__file__).resolve().parents[2] / "server" / "migrations"
DB_NAME = re.compile(r"^catbird_direct_requests_faketime_[a-z0-9_]{1,40}$")
PG_BIN = Path("/opt/homebrew/opt/postgresql@16/bin")
SQLX_LEDGER = """CREATE TABLE IF NOT EXISTS public._sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
    success BOOLEAN NOT NULL,
    checksum BYTEA NOT NULL,
    execution_time BIGINT NOT NULL)"""


def psql(url, *args, env=None):
    out = subprocess.run(
        ["psql", "-X", "-v", "ON_ERROR_STOP=1", "-At", "-d", url, *args],
        capture_output=True, text=True, check=False, env=env)
    if out.returncode != 0:
        sys.exit(f"psql failed on {url}: {out.stderr.strip()}")
    return out.stdout


def faketime_lib():
    libs = sorted(glob.glob("/opt/homebrew/opt/libfaketime/lib/faketime/libfaketime.1.dylib"))
    if not libs:
        sys.exit("libfaketime missing: brew install libfaketime")
    return libs[0]


def start(a):
    if not DB_NAME.match(a.db):
        sys.exit(f"--db must match {DB_NAME.pattern}")
    if a.port == 5432:
        sys.exit("--port must not be the shared cluster port 5432")
    root = Path(a.dir)
    if root.exists():
        sys.exit(f"{root} already exists; stop it first")
    root.mkdir(parents=True)
    user = os.environ["USER"]
    subprocess.run([PG_BIN / "initdb", "-D", root / "data", "-A", "trust", "-U", user,
                    "--no-sync", "--locale=C", "-E", "UTF8"], check=True, capture_output=True)
    clock = root / "faketime"
    clock.write_text("+0\n")
    # Launch postgres directly: pg_ctl goes through /bin/sh, which SIP strips
    # of DYLD_*. LC_ALL avoids libfaketime making the postmaster multithreaded.
    env = {
        "PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"], "LC_ALL": "C", "LANG": "C",
        "DYLD_INSERT_LIBRARIES": faketime_lib(), "DYLD_FORCE_FLAT_NAMESPACE": "1",
        "FAKETIME_TIMESTAMP_FILE": str(clock), "FAKETIME_NO_CACHE": "1",
        "FAKETIME_DONT_FAKE_MONOTONIC": "1",
    }
    log = open(root / "postgres.log", "w")
    proc = subprocess.Popen(
        [PG_BIN / "postgres", "-D", root / "data", "-p", str(a.port), "-k", str(root),
         "-c", "listen_addresses=127.0.0.1", "-c", "fsync=off"],
        env=env, stdout=log, stderr=log, start_new_session=True)
    (root / "pid").write_text(str(proc.pid))
    admin = f"postgresql://127.0.0.1:{a.port}/postgres"
    for _ in range(80):
        if proc.poll() is not None:
            sys.exit(f"postgres exited: {(root / 'postgres.log').read_text()[-800:]}")
        if subprocess.run(["psql", "-X", "-At", "-d", admin, "-c", "select 1"],
                          capture_output=True, check=False).returncode == 0:
            break
        time.sleep(0.25)
    else:
        sys.exit("postgres did not become ready")
    psql(admin, "-c", f"CREATE DATABASE {a.db}")
    url = f"postgresql://127.0.0.1:{a.port}/{a.db}"
    psql(url, "-c", "CREATE EXTENSION IF NOT EXISTS pgcrypto")
    psql(url, "-c", SQLX_LEDGER)
    ledger_sql = ("SELECT version,description,success,encode(checksum,'hex') "
                  "FROM public._sqlx_migrations ORDER BY version")
    shared = psql(SHARED_URL, "-c", ledger_sql)
    ledger = [line.split("|") for line in shared.splitlines() if line]
    # Per-session activation GUC exactly as the server migrations README
    # prescribes for sqlx migrate; never set globally.
    migrate_env = dict(os.environ, PGOPTIONS="-c chat.operation_claim_activation_approved="
                       "handlers-and-legacy-apis-sealed")
    for version, description, success, checksum in ledger:
        if success != "t":
            sys.exit(f"shared ledger row {version} is not successful")
        files = list(MIGRATIONS.glob(f"{version}_*.sql"))
        if len(files) != 1:
            sys.exit(f"migration {version}: expected one file, found {files}")
        sql = files[0].read_bytes()
        if hashlib.sha384(sql).hexdigest() != checksum:
            sys.exit(f"migration {version}: file checksum differs from shared ledger")
        psql(url, "--single-transaction", "-f", str(files[0]), env=migrate_env)
        psql(url, "-c",
             "INSERT INTO public._sqlx_migrations(version,description,success,checksum,execution_time) "
             f"VALUES ({int(version)}, $d${description}$d$, true, decode('{checksum}','hex'), 0)")
    if psql(url, "-c", ledger_sql) != shared:
        sys.exit("installed ledger differs from shared guarded ledger")
    print(json.dumps({"url": url, "pid": proc.pid, "dir": str(root), "migrations": len(ledger)}))


def advance(a):
    if not re.fullmatch(r"[+-]\d+[smhdy]?", a.offset):
        sys.exit("--offset must look like +8d")
    (Path(a.dir) / "faketime").write_text(a.offset + "\n")
    print(json.dumps({"offset": a.offset}))


def stop(a):
    root = Path(a.dir)
    pid = int((root / "pid").read_text())
    # Only the pid this script recorded; never a name-based kill.
    try:
        os.kill(pid, signal.SIGINT)
        for _ in range(80):
            os.kill(pid, 0)
            time.sleep(0.25)
    except ProcessLookupError:
        pass
    subprocess.run(["rm", "-rf", str(root)], check=True)
    print(json.dumps({"stopped": pid}))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start")
    s.add_argument("--dir", required=True)
    s.add_argument("--port", type=int, required=True)
    s.add_argument("--db", required=True)
    sub.add_parser("advance").add_argument("--dir", required=True)
    sub.choices["advance"].add_argument("--offset", required=True)
    sub.add_parser("stop").add_argument("--dir", required=True)
    a = p.parse_args()
    {"start": start, "advance": advance, "stop": stop}[a.cmd](a)


if __name__ == "__main__":
    main()
