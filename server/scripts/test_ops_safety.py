#!/usr/bin/env python3
"""Regressions for the operations scripts and configuration that CI relies on.

The shell scripts run against stub `psql` and `sqlx` binaries that only log
their arguments, so no database is ever touched.
"""

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest


SERVER = Path(__file__).resolve().parents[1]
REPO = SERVER.parent
SCRIPTS = SERVER / "scripts"
FIXTURES = REPO / "e2e-tests" / "fixtures"
WORKFLOW = REPO / ".github" / "workflows" / "mls-deploy.yml"
E2E_COMPOSE = REPO / "e2e-tests" / "docker-compose.federation.yml"
HOSTILE_GATE = REPO / "scripts" / "federation-hostile-test-gate.sh"
APPROVAL = "handlers-and-legacy-apis-sealed"
SECRET = "pw-8f3e-not-for-logs"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Answers the three queries the scripts make: the reset guard's identity check,
# the repair step's table probe, and the activation-gate probe.
STUB_PSQL = """#!/bin/sh
printf 'psql %s\\n' "$*" >> "$STUB_LOG"
case "$*" in
  *"current_database()"*) echo "$STUB_IDENTITY" ;;
  *"IS NOT NULL"*) echo f ;;
  *"WHEN EXISTS"*) echo pending ;;
esac
"""
STUB_SQLX = """#!/bin/sh
printf 'sqlx PGOPTIONS=%s %s\\n' "${PGOPTIONS:-}" "$*" >> "$STUB_LOG"
"""


def run_script(script, *args, identity="", approved=True):
    """Run SCRIPT with stubbed database tools; return (result, logged calls).

    IDENTITY is what the stub server answers to the reset guard's identity query.
    """
    with tempfile.TemporaryDirectory(prefix="mls-ops-safety-") as tmp:
        stubs = Path(tmp)
        for name, body in (("psql", STUB_PSQL), ("sqlx", STUB_SQLX)):
            (stubs / name).write_text(body)
            (stubs / name).chmod(0o755)
        log = stubs / "calls.log"
        log.touch()
        env = {
            "PATH": f"{stubs}{os.pathsep}/usr/bin{os.pathsep}/bin",
            "STUB_LOG": str(log),
            "STUB_IDENTITY": identity,
        }
        if approved:
            env["CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED"] = APPROVAL
        result = subprocess.run(["bash", str(script), *args], env=env,
                                capture_output=True, text=True, timeout=60)
        return result, log.read_text()


def required_features(cargo_toml):
    """Map each explicit [[test]] target to its required features."""
    targets = {}
    for block in cargo_toml.read_text().split("[[test]]")[1:]:
        block = block.split("\n[", 1)[0]
        name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
        features = re.search(r"^required-features\s*=\s*\[([^\]]*)\]", block, re.M)
        if name:
            targets[name.group(1)] = set(re.findall(r'"([^"]+)"', features.group(1))) if features else set()
    return targets


def cargo_tests(text):
    """Yield (line, features, targets, filters, lib) for each `cargo test` command in TEXT."""
    for line in text.replace("\\\n", " ").splitlines():
        if "cargo test" not in line or line.lstrip().startswith("#"):
            continue
        tokens = shlex.split(line.split("cargo test", 1)[1].split(" -- ", 1)[0])
        features, targets, filters, index = set(), [], [], 0
        while index < len(tokens):
            token = tokens[index]
            if token in ("--features", "--test", "--manifest-path", "-p", "--package"):
                if token == "--features":
                    features.update(tokens[index + 1].split(","))
                elif token == "--test":
                    targets.append(tokens[index + 1])
                index += 2
                continue
            if not token.startswith("-"):
                filters.append(token)
            index += 1
        yield line.strip(), features, targets, filters, "--lib" in tokens


def multikey(pem_path):
    """The P-256 Multikey (`zDn...`) of the private key in PEM_PATH."""
    der = subprocess.run(["openssl", "pkey", "-in", str(pem_path), "-pubout", "-outform", "DER"],
                         check=True, capture_output=True).stdout
    point = der[-65:]
    number = int.from_bytes(bytes([0x80, 0x24, 2 + (point[64] & 1)]) + point[1:33], "big")
    encoded = ""
    while number:
        number, digit = divmod(number, 58)
        encoded = BASE58[digit] + encoded
    return "z" + encoded


class ResetDevDbTests(unittest.TestCase):
    script = SCRIPTS / "reset-dev-db.sh"
    # port -> the identity (database, cluster_name) that port's compose container reports
    stack = {5433: "catbird catbird-federation-ds1", 5434: "catbird catbird-federation-ds2"}
    local_url = f"postgresql://catbird:{SECRET}@localhost:5433/catbird"

    def test_refuses_anything_but_a_local_stack_database_before_connecting(self):
        for url in [
            "",
            f"postgresql://catbird:{SECRET}@localhost:5432/catbird",
            f"postgresql://catbird:{SECRET}@localhost/catbird",
            f"postgresql://catbird:{SECRET}@localhost:5433/catbird_mls",
            f"postgresql://catbird:{SECRET}@localhost:5433/mls_ds1",
            f"postgresql://catbird:{SECRET}@db.example.com:5433/catbird",
            f"postgresql://catbird:{SECRET}@localhost:5433/catbird?dbname=catbird",
            f"postgresql://catbird:{SECRET}@localhost,db.example.com:5433/catbird",
            "postgresql:///catbird",
            f"host=localhost port=5433 dbname=catbird password={SECRET}",
        ]:
            with self.subTest(url=url):
                result, calls = run_script(self.script, url, identity=self.stack[5433])
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, "")
                self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_refuses_without_activation_approval(self):
        result, calls = run_script(self.script, self.local_url, identity=self.stack[5433], approved=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, "")

    def test_refuses_unless_the_live_server_is_that_ports_stack_container(self):
        # Production's database is also catbird: a tunnel to it on a stack port
        # reports catbird with its own (here unset) cluster_name.
        for identity in ("catbird ", self.stack[5434], "catbird_mls catbird-federation-ds1"):
            with self.subTest(identity=identity):
                result, calls = run_script(self.script, self.local_url, identity=identity)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("current_database()", calls)
                self.assertNotIn("DROP DATABASE", calls)

    def test_resets_and_migrates_a_verified_local_database(self):
        for port, identity in self.stack.items():
            with self.subTest(port=port):
                url = f"postgresql://catbird:{SECRET}@localhost:{port}/catbird"
                result, calls = run_script(self.script, url, identity=identity)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                drop = (f"@localhost:{port}/postgres -X -q -v ON_ERROR_STOP=1 "
                        "-c DROP DATABASE IF EXISTS catbird WITH (FORCE) -c CREATE DATABASE catbird")
                migrate = f"sqlx PGOPTIONS=-c chat.operation_claim_activation_approved={APPROVAL} migrate run"
                self.assertIn(drop, calls)
                self.assertIn(migrate, calls)
                self.assertLess(calls.index("current_database()"), calls.index(drop))
                self.assertLess(calls.index(drop), calls.index(migrate))
                self.assertNotIn(SECRET, result.stdout + result.stderr)


class RunMigrationsTests(unittest.TestCase):
    script = SCRIPTS / "run-migrations.sh"

    def test_never_prints_credentials(self):
        for url, shown in [
            (f"postgresql://catbird:{SECRET}@localhost:5433/catbird?sslmode=disable",
             "Database: localhost:5433/catbird"),
            (f"postgres://localhost/catbird?password={SECRET}", "Database: localhost/catbird"),
            (f"postgresql://catbird:{SECRET}@x@localhost/catbird", "Database: (not shown)"),
            (f"host=localhost dbname=catbird password={SECRET}", "Database: (not shown)"),
        ]:
            for approved in (True, False):
                with self.subTest(url=url, approved=approved):
                    result, _ = run_script(self.script, url, approved=approved)
                    output = result.stdout + result.stderr
                    self.assertIn(shown, output)
                    self.assertNotIn(SECRET, output)
                    self.assertEqual(result.returncode, 0 if approved else 1, output)


class TestGateTests(unittest.TestCase):
    workflow = WORKFLOW.read_text()
    hostile_gate = HOSTILE_GATE.read_text()

    def test_postgres_services_are_version_16_or_newer(self):
        versions = re.findall(r"image:\s*postgres:(\d+)", self.workflow)
        self.assertTrue(versions)
        self.assertTrue(all(int(version) >= 16 for version in versions), versions)

    def test_cargo_test_targets_exist_and_get_their_required_features(self):
        required = {**required_features(SERVER / "Cargo.toml"),
                    **required_features(REPO / "e2e-tests" / "Cargo.toml")}
        commands = [*cargo_tests(self.workflow), *cargo_tests(self.hostile_gate)]
        self.assertTrue(commands)
        for line, features, targets, _, _ in commands:
            for target in targets:
                with self.subTest(target=target):
                    self.assertTrue((SERVER / "tests" / f"{target}.rs").is_file()
                                    or (REPO / "e2e-tests" / "tests" / f"{target}.rs").is_file(),
                                    f"{target} is not a test target")
                    self.assertLessEqual(required.get(target, set()), features, line)

    def test_clock_determinism_is_a_required_ci_step(self):
        self.assertIn("--test deterministic_server_clock_test", self.workflow)
        self.assertNotIn("continue-on-error", self.workflow)

    def test_hostile_gate_filters_still_select_tests(self):
        sources = [path.read_text() for path in (SERVER / "src").rglob("*.rs")]
        commands = list(cargo_tests(self.hostile_gate))
        self.assertTrue(commands)
        for line, _, targets, filters, lib in commands:
            with self.subTest(command=line):
                self.assertTrue(filters, "an unfiltered gate command is a different gate")
                for name in filters:
                    if lib:
                        segment = name.rsplit("::", 1)[-1]
                        self.assertTrue(any(segment in source for source in sources), name)
                    for target in targets:
                        self.assertIn(name, (SERVER / "tests" / f"{target}.rs").read_text())


class FederationComposeTests(unittest.TestCase):
    compose = (REPO / "docker-compose.federation.yml").read_text()
    # home -> (DID method, PostgreSQL service of the home that records it as a peer)
    homes = {"ds1": ("did:web:", "postgres-ds2"), "ds2": ("did:plc:", "postgres-ds1")}
    documents = {"ds1": "ds1-local-did.json", "ds2": "ds2-plc-did.json"}

    def document(self, home):
        return json.loads((FIXTURES / self.documents[home]).read_text())

    def test_boots_test_mode_with_activation_approval_and_strict_auth(self):
        self.assertNotIn("placeholder", self.compose.lower())
        for line in ("target: federation-test", "APP_ENV: test", "RECEIPT_ISSUANCE_MODE: issue",
                     f"CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED: {APPROVAL}"):
            self.assertIn(line, self.compose)
        for setting in ("ALLOW_UNSAFE_AUTH", "ENFORCE_LXM", "ENFORCE_JTI",
                        "FEDERATION_EMERGENCY_KILL_SWITCH", "TEST_DID_DOCUMENT_PATHS"):
            self.assertNotIn(setting, self.compose)

    def test_both_two_home_stacks_load_real_service_and_receipt_keys(self):
        compose_files = (("root", self.compose), ("lifecycle", E2E_COMPOSE.read_text()))
        for name, compose in compose_files:
            with self.subTest(compose=name):
                for line in (
                    'SIGNING_KEY_PEM="$$(cat "$$SIGNING_KEY_FILE")"',
                    'RECEIPT_SIGNING_KEY_PEM="$$(cat "$$RECEIPT_SIGNING_KEY_FILE")"',
                    'RECEIPT_DID_DOCUMENT_JSON="$$(cat "$$RECEIPT_DID_DOCUMENT_FILE")"',
                    "export SIGNING_KEY_PEM RECEIPT_SIGNING_KEY_PEM RECEIPT_DID_DOCUMENT_JSON",
                    "exec catbird-server",
                ):
                    self.assertIn(line, compose)
                self.assertNotIn("TEST_DID_DOCUMENT_PATHS", compose)

    def test_ignored_lifecycle_uses_https_did_web_and_did_plc_homes(self):
        lifecycle_compose = E2E_COMPOSE.read_text()
        for line in (
            'SERVICE_DID: "${DS1_SERVICE_DID:-did:web:ds1.catbird.blue}"',
            'SERVICE_DID: "${DS2_SERVICE_DID:-did:plc:dsbfederationlocal24char}"',
            "RECEIPT_DID_DOCUMENT_FILE: /app/fixtures/ds1-local-did.json",
            "RECEIPT_DID_DOCUMENT_FILE: /app/fixtures/ds2-plc-did.json",
            'RECEIPT_VERIFICATION_METHOD: "did:web:ds1.catbird.blue#mls-receipt-1"',
            'RECEIPT_VERIFICATION_METHOD: "did:plc:dsbfederationlocal24char#mls-receipt-1"',
            "RECEIPT_ISSUANCE_MODE: issue",
            "REQUEST_FIXTURE_DID_HOSTS: ds1.catbird.blue,alice.catbird.blue,bob.catbird.blue,plc.directory",
            'network_mode: "service:ds1"',
            'network_mode: "service:ds2"',
        ):
            self.assertIn(line, lifecycle_compose)

    def test_user_home_declarations_use_https_pds_resolution(self):
        homes = (
            ("alice", "did:web:ds1.catbird.blue"),
            ("bob", "did:plc:dsbfederationlocal24char"),
        )
        for actor, home in homes:
            with self.subTest(actor=actor):
                did = f"did:web:{actor}.catbird.blue"
                document = json.loads((FIXTURES / f"{actor}-did.json").read_text())
                self.assertEqual(document["service"], [{
                    "id": f"{did}#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": f"https://{actor}.catbird.blue",
                }])
                declaration = json.loads(
                    (FIXTURES / f"{actor}-chat-declaration.json").read_text()
                )
                self.assertEqual(declaration["$type"], "blue.catbird.chat.declaration")
                self.assertEqual(declaration["protocolVersion"], "1")
                self.assertEqual(declaration["deliveryService"], home)

        for compose in (self.compose, E2E_COMPOSE.read_text()):
            self.assertIn("/fixtures/alice-chat-declaration.json", compose)
            self.assertIn("/fixtures/bob-chat-declaration.json", compose)

    def test_every_fixture_exists_and_is_committable(self):
        names = re.findall(r"/(?:app/)?fixtures/([\w./-]+?\.(?:pem|json))", self.compose)
        self.assertTrue(names)
        for name in names:
            self.assertTrue((FIXTURES / name).is_file(), name)
            # `.gitignore` excludes `*.pem` except directly under e2e-tests/fixtures.
            if shutil.which("git"):
                ignored = subprocess.run(["git", "-C", str(REPO), "check-ignore", "-q", "--no-index",
                                          str((FIXTURES / name).relative_to(REPO))])
                self.assertEqual(ignored.returncode, 1, f"{name} is git-ignored or git failed")

    def test_each_home_migrates_its_own_catbird_database_that_the_reset_guard_recognizes(self):
        # Migration 20250101000000 grants on this database by name, so a home
        # whose database is named anything else cannot migrate and never boots.
        granted = re.search(r"^GRANT ALL PRIVILEGES ON DATABASE (\w+) TO ",
                            (SERVER / "migrations" / "20250101000000_greenfield_schema.sql").read_text(), re.M)
        self.assertIsNotNone(granted)
        database = granted.group(1)
        reset = (SCRIPTS / "reset-dev-db.sh").read_text()
        for home, port in (("ds1", 5433), ("ds2", 5434)):
            with self.subTest(home=home):
                service = re.search(rf"^  postgres-{home}:\n((?:    .*\n)+)", self.compose, re.M)
                self.assertIsNotNone(service)
                self.assertIn(f"      POSTGRES_DB: {database}\n", service.group(1))
                self.assertIn(f'      - "127.0.0.1:{port}:5432"\n', service.group(1))
                self.assertIn(f'"cluster_name=catbird-federation-{home}"', service.group(1))
                self.assertIn(f"      DATABASE_URL: postgresql://catbird:catbird_dev_password@postgres-{home}:5432/"
                              f"{database}\n", self.compose)
                self.assertIn(f"    {port}) cluster=catbird-federation-{home} ;;\n", reset)

    def test_each_home_uses_its_fixture_identity_and_is_the_others_peer(self):
        for home, (method, peer_host) in self.homes.items():
            with self.subTest(home=home):
                document = self.document(home)
                did = document["id"]
                self.assertTrue(did.startswith(method), did)
                endpoint = next(service["serviceEndpoint"] for service in document["service"]
                                if service["id"] == f"{did}#atproto_mls")
                for line in (f"SERVICE_DID: {did}", f"SELF_ENDPOINT: {endpoint}",
                             f"SIGNING_KEY_FILE: /app/fixtures/{home}-key.pem",
                             f"RECEIPT_SIGNING_KEY_FILE: /app/fixtures/{home}-receipt-key.pem",
                             f"RECEIPT_DID_DOCUMENT_FILE: /app/fixtures/{self.documents[home]}",
                             f'RECEIPT_VERIFICATION_METHOD: "{did}#mls-receipt-1"'):
                    self.assertIn(line, self.compose)
                self.assertRegex(self.compose, rf"-h {peer_host} -d catbird .*INSERT INTO federation_peers "
                                               rf"\(ds_did, status\) VALUES \('{re.escape(did)}', 'allow'\)")

    @unittest.skipIf(shutil.which("openssl") is None, "openssl derives the fixture public keys")
    def test_documents_publish_the_service_key_and_a_distinct_receipt_key(self):
        for home in self.homes:
            with self.subTest(home=home):
                document = self.document(home)
                did = document["id"]
                published = {method["id"]: method["publicKeyMultibase"]
                             for method in document["verificationMethod"]}
                self.assertEqual(published[f"{did}#atproto"], multikey(FIXTURES / f"{home}-key.pem"))
                self.assertEqual(published[f"{did}#mls-receipt-1"],
                                 multikey(FIXTURES / f"{home}-receipt-key.pem"))
                self.assertNotEqual(published[f"{did}#atproto"], published[f"{did}#mls-receipt-1"])

    def test_the_did_fixture_serves_every_identity_and_keeps_no_ca_key(self):
        hosts = re.search(r"REQUEST_FIXTURE_DID_HOSTS: &(\S+) (\S+)", self.compose)
        self.assertIsNotNone(hosts)
        self.assertIn(f"DID_RESOLUTION_HOST_ALLOWLIST: *{hosts.group(1)}", self.compose)
        hosts = hosts.group(2).split(",")
        users = re.findall(r"FEDERATION_TEST_LOCAL_USER_DIDS: did:web:(\S+)", self.compose)
        ds1, ds2 = self.document("ds1")["id"], self.document("ds2")["id"]
        self.assertEqual(sorted(hosts), sorted([ds1.removeprefix("did:web:"), *users, "plc.directory"]))
        for host in hosts:
            self.assertIn(f"DNS:{host}", self.compose)
            if host != "plc.directory":
                self.assertIn(f'"$$root/{host}/.well-known/did.json"', self.compose)
        self.assertIn(f'"$$root/plc.directory/{ds2}"', self.compose)
        self.assertIn("rm -f ca-key.pem", self.compose)


class SiblingBuildInputTests(unittest.TestCase):
    """Every build gets the sibling checkouts server/Cargo.toml's path dependencies need."""

    dockerfile = (SERVER / "Dockerfile").read_text()
    workflow = WORKFLOW.read_text()

    def test_every_image_build_supplies_each_named_context_the_dockerfile_copies(self):
        stages = set(re.findall(r"^FROM \S+ AS (\S+)", self.dockerfile, re.M))
        contexts = set(re.findall(r"^COPY --from=(\S+) ", self.dockerfile, re.M)) - stages
        self.assertIn("labyrinth-protocol", contexts)
        builds = []
        for compose in (REPO / "docker-compose.federation.yml", REPO / "e2e-tests" / "docker-compose.federation.yml"):
            for block in re.finditer(r"^( *)additional_contexts:\n((?:\1 +\S.*\n)+)", compose.read_text(), re.M):
                builds.append((compose.relative_to(REPO), set(re.findall(r"^ +([\w-]+): \S+$", block[2], re.M))))
        for block in re.finditer(r"^( *)build-contexts: \|\n((?:\1 +\S.*\n)+)", self.workflow, re.M):
            builds.append((WORKFLOW.name, set(re.findall(r"^ +([\w-]+)=\S+$", block[2], re.M))))
        # The root compose's shared build anchor, the two e2e homes, the CI image.
        self.assertEqual(len(builds), 4, builds)
        for name, supplied in builds:
            self.assertEqual(supplied, contexts, name)

    def test_every_ci_job_that_builds_the_server_clones_its_path_dependencies(self):
        repos = set(re.findall(r'path = "\.\./\.\./([^/"]+)', (SERVER / "Cargo.toml").read_text()))
        self.assertIn("labyrinth", repos)
        jobs = re.split(r"^  (?=[\w-]+:\n)", self.workflow.split("\njobs:\n", 1)[1], flags=re.M)
        builders = [job for job in jobs if "working-directory: ./server" in job or "file: ./server/Dockerfile" in job]
        self.assertEqual(len(builders), 3, [job.split(":", 1)[0] for job in builders])
        for job in builders:
            for repo in repos:
                with self.subTest(job=job.split(":", 1)[0], repo=repo):
                    self.assertRegex(job, rf"git clone --filter=blob:none https://github\.com/joshlacal/{repo}\.git "
                                          rf"\.\./{repo}\n +git -C \.\./{repo} checkout --detach [0-9a-f]{{40}}\n")


class DestructiveRouteTests(unittest.TestCase):
    def test_no_script_runs_destructive_sql_through_doppler(self):
        for script in [*REPO.glob("*.sh"), *SERVER.glob("*.sh"), *SCRIPTS.glob("*.sh")]:
            text = script.read_text()
            if "doppler run" in text:
                for statement in ("TRUNCATE", "DROP DATABASE", "DROP SCHEMA", "reset-dev-db"):
                    self.assertNotIn(statement, text, script)

    def test_make_targets_exist_and_none_wipes_production(self):
        server_makefile = (SERVER / "Makefile").read_text()
        for target in ("deploy-fresh:", "clear-db:", "clear-db-fast:"):
            self.assertNotIn(target, server_makefile)
        self.assertNotIn("mls-ffi", (REPO / "Makefile").read_text())


if __name__ == "__main__":
    unittest.main()
