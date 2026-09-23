#!/usr/bin/env python3
"""Throwaway loopback Postgres cluster whose clock a test can advance.

The server takes every protocol instant from Postgres (`clock_timestamp()`,
`transaction_timestamp()`), so deadlines such as the seven-day request import
horizon are reachable only by moving the database clock. This launches a
private cluster under libfaketime; production code and the shared guarded
database are untouched.

  lib                               (print the libfaketime every faked process
                                     must preload; builds it on first use)
  start   --dir D --port P --db catbird_direct_requests_faketime_<suffix>
          [--clock-file F]          (share an existing FAKETIME_TIMESTAMP_FILE,
                                     e.g. the test runner's, so every faked
                                     process moves together)
  advance --dir D --offset +8d      (takes effect on the next query)
  stop    --dir D                   (stops the recorded pid, deletes D)

Schema = the shared guarded database's exact `_sqlx_migrations` ledger,
replayed in order from `mls-ds/server/migrations`; each file's SHA-384 must
equal the shared ledger checksum before it is applied.

Why not the Homebrew libfaketime: with FAKETIME_NO_CACHE=1 every
clock_gettime re-parses the timestamp file into process-global state without
a lock, so in a multi-threaded process (the tokio test runner, the server
fixture) concurrent readers see the un-offset real clock and backwards
Instants (~5% of reads under a +29d offset). That made C22 fail ~1 in 10
with sqlx PoolTimedOut or TokenExpired. The same pinned release built with
PTHREAD_SINGLETHREADED_TIME serializes that path and shows no wrong reads.
"""
import argparse
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


LIBFAKETIME_VERSION = "0.9.13"
LIBFAKETIME_SHA256 = "8e56deeb805682b025107e095f1d94a6ea677472f05824cd475f5c5e6e1a5ddf"
LIBFAKETIME_CACHE = (Path.home() / ".cache" / "catbird-e2e"
                     / f"libfaketime-{LIBFAKETIME_VERSION}-serialized")


def faketime_lib():
    """Pinned libfaketime with the clock path serialized across threads."""
    lib = LIBFAKETIME_CACHE / "libfaketime.1.dylib"
    if lib.is_file():
        return str(lib)
    build = Path(subprocess.run(["mktemp", "-d"], capture_output=True, text=True,
                                check=True).stdout.strip())
    try:
        tarball = build / "libfaketime.tar.gz"
        subprocess.run(["curl", "-sSfL", "-o", str(tarball),
                        "https://github.com/wolfcw/libfaketime/archive/refs/tags/"
                        f"v{LIBFAKETIME_VERSION}.tar.gz"], check=True)
        if hashlib.sha256(tarball.read_bytes()).hexdigest() != LIBFAKETIME_SHA256:
            sys.exit("libfaketime source tarball digest mismatch")
        subprocess.run(["tar", "xzf", str(tarball), "-C", str(build)], check=True)
        src = build / f"libfaketime-{LIBFAKETIME_VERSION}" / "src"
        subprocess.run(["make", "-f", "Makefile.OSX",
                        "FAKETIME_COMPILE_CFLAGS=-DPTHREAD_SINGLETHREADED_TIME",
                        "libfaketime.1.dylib"], cwd=src, check=True, capture_output=True)
        LIBFAKETIME_CACHE.mkdir(parents=True, exist_ok=True)
        staged = LIBFAKETIME_CACHE / f".libfaketime.{os.getpid()}"
        subprocess.run(["cp", str(src / "libfaketime.1.dylib"), str(staged)], check=True)
        os.replace(staged, lib)
    finally:
        subprocess.run(["rm", "-rf", str(build)], check=False)
    return str(lib)


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
    if a.clock_file:
        clock = Path(a.clock_file).resolve()
        if not clock.is_file():
            sys.exit(f"--clock-file {clock} does not exist")
    else:
        clock = root / "faketime"
        clock.write_text("+0\n")
    (root / "clock_path").write_text(str(clock))
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
    target = Path((Path(a.dir) / "clock_path").read_text().strip())
    temp = target.with_name(f"{target.name}.tmp.{os.getpid()}")
    temp.write_text(a.offset + "\n")
    temp.replace(target)
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
    log_file = root / "postgres.log"
    if log_file.is_file():
        lines = log_file.read_text().splitlines()
        print(f"--- POSTGRES LOG TAIL ({len(lines)} lines total) ---", file=sys.stderr)
        for l in lines[-30:]:
            print(f"  {l}", file=sys.stderr)
    subprocess.run(["rm", "-rf", str(root)], check=True)
    print(json.dumps({"stopped": pid}))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start")
    s.add_argument("--dir", required=True)
    s.add_argument("--port", type=int, required=True)
    s.add_argument("--db", required=True)
    s.add_argument("--clock-file")
    sub.add_parser("advance").add_argument("--dir", required=True)
    sub.choices["advance"].add_argument("--offset", required=True)
    sub.add_parser("stop").add_argument("--dir", required=True)
    sub.add_parser("lib")
    a = p.parse_args()
    if a.cmd == "lib":
        print(faketime_lib())
        return
    {"start": start, "advance": advance, "stop": stop}[a.cmd](a)


if __name__ == "__main__":
    main()
