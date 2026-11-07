#!/usr/bin/env python3
"""End-to-end scenarios for the hivemind.

The hivemind runs for real, against Postgres, a fake oxend and a fake swarm of storage nodes
(fake_network), a fake notifier (fake_notifier) and a fake subscribing client (fake_client).

usage: e2e.py [--build-dir DIR] [--slow] [--sanitizer thread|address] [--mode MODE] [options]
              [SCENARIO...]

Normally run through the build's e2e targets (`make e2e`, `make e2e-burst`, ...), which build the
hivemind and the fakes and pass the build directory.  With no SCENARIO, runs every fast scenario,
plus the slow ones with --slow.  Each runs once against a network without monitor sessions, as
today's is ("legacy"), and once against one with them ("monitor"), unless --mode picks one.  Needs
an existing Postgres database it may empty (see --db), found through the usual libpq environment
(PGHOST, PGUSER, ...).  Linux only: it reads process memory and CPU use from /proc.
tests/e2e/run.sh does all of this inside a container.
"""

import argparse
import base64
import difflib
import hashlib
import json
import os
import struct

import psycopg
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback

# Set from the command line in main().
SRC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILD = None  # The project's build directory: SPNS and the Python module, with the fakes
FAKES = None  # under tests/e2e of it.
SANITIZER = None
WORK = None
DB = None
OXEND_PORT = None
FIRST_QUIC_PORT = None
# Relative to WORK, which every process runs in: a unix socket path must fit sockaddr_un's 108
# bytes, and a relative one keeps that from depending on where WORK is.
HIVEMIND_SOCK = "ipc://hivemind.sock"
# Sanitized builds run several times slower: their timeouts stretch by this much, and they skip the
# timing limits (they look for memory and threading errors; every push must still arrive).
TIME_SCALE = 1
SANITIZED = False
# "legacy" or "monitor": whether the fake storage nodes support monitor sessions.
MODE = None
SANITIZER_REPORT = re.compile(
    r"WARNING: ThreadSanitizer|ERROR: AddressSanitizer|ERROR: LeakSanitizer"
)


class Failure(Exception):
    pass


def check(cond, msg):
    if not cond:
        raise Failure(msg)


def sanitized_env(**extra):
    """The environment for a program of the project's build, with what its sanitizer needs."""
    return dict(
        os.environ,
        # libquic, oxenmq and zmq are not instrumented: their own synchronisation is invisible to
        # TSan, so only races between instrumented accesses count.
        TSAN_OPTIONS="halt_on_error=0 second_deadlock_stack=1 "
        f"ignore_noninstrumented_modules=1 suppressions={SRC}/tests/e2e/tsan.supp",
        # Python's own allocations would drown the leak report; and the hivemind library and its
        # Python module both define libstdc++'s inline globals, which ASan's ODR check counts as
        # duplicates.
        ASAN_OPTIONS="detect_leaks=0 detect_odr_violation=0",
        **extra,
    )


def sanitized_cmd(cmd):
    """`cmd`, run as a program of the project's build needs to be under its sanitizer."""
    if SANITIZER == "thread":
        # TSan cannot map its shadow memory under the kernel's full address randomisation.
        return ["setarch", os.uname().machine, "-R"] + cmd
    return cmd


# --- database ---------------------------------------------------------------------------------


def connect():
    """A connection to DB, through libpq's environment for everything but the database name."""
    return psycopg.connect(dbname=DB, autocommit=True)


def execute(sql):
    with connect() as conn:
        conn.execute(sql)


def query(sql):
    """Returns the rows of a query, as tuples."""
    with connect() as conn:
        return conn.execute(sql).fetchall()


def query1(sql):
    """Returns the one value of a query with one row and one column."""
    rows = query(sql)
    if len(rows) != 1 or len(rows[0]) != 1:
        raise Failure(f"expected one value from {sql!r}, got {rows}")
    return rows[0][0]


def wait_db(timeout=60):
    """Waits for DB to accept connections, as a server started alongside may not yet."""
    deadline = time.time() + timeout
    while True:
        try:
            with connect():
                return
        except psycopg.OperationalError as e:
            if time.time() > deadline:
                sys.exit(f"cannot connect to database {DB}: {e}")
            time.sleep(1)


def drop_tables(schema="public"):
    tables = [
        f'{schema}."{t}"'
        for (t,) in query(f"SELECT tablename FROM pg_tables WHERE schemaname = '{schema}'")
    ]
    if tables:
        execute(f"DROP TABLE {', '.join(tables)} CASCADE")


def migrate_schema(schema=None):
    """Brings DB (in `schema`, if given) up to date as the hivemind does at startup, with
    migrate_schema; returns what it logged."""
    url = f"postgresql:///{DB}" + (f"?options=-csearch_path%3D{schema}" if schema else "")
    r = subprocess.run(
        sanitized_cmd([f"{FAKES}/migrate_schema", url]),
        env=sanitized_env(),
        capture_output=True,
        text=True,
    )
    log = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr)
    check(r.returncode == 0, f"migrate_schema failed ({r.returncode}): {log}")
    return log


def fresh_db():
    """Empties DB, which must exist already, and creates the hivemind's tables in it as the
    hivemind would."""
    drop_tables()
    migrate_schema()


# Account #i is 03 || SHA256(big-endian i), as in fake_network.
ACCOUNT = "decode('03','hex') || sha256(int4send({}))"


def seed(
    first,
    count,
    devices="1",
    namespaces="0",
    sig_ts=None,
    svcdata="NULL",
    service="dummy",
):
    """Subscribes accounts #first.. to `service` directly in the database.  `devices` is an SQL
    expression in `i` giving account #i's number of devices, whose service ids are svcid(i, d)."""
    sig_ts = sig_ts or int(time.time())
    execute(
        f"""
WITH s AS (
    INSERT INTO subscriptions (account, signature, signature_ts, want_data, enc_key, service, svcid, svcdata)
    SELECT {ACCOUNT.format('i')}, decode(repeat('cd', 64), 'hex'), {sig_ts}, true,
           decode(repeat('ab', 32), 'hex'), '{service}', {SVCID_SQL}, {svcdata}
    FROM generate_series({first}, {first + count - 1}) i, LATERAL generate_series(1, {devices}) d
    RETURNING id)
INSERT INTO sub_namespaces SELECT s.id, n FROM s, unnest(ARRAY[{namespaces}]::smallint[]) n"""
    )


# Seeded device d of account i gets a service id the size of a real one, since that size matters
# to what the hivemind holds per subscription: even accounts a 64-hex APNs device token, odd
# accounts 142 characters of URL-safe base64 like a Firebase token.  Derived from (i, d) the same
# way here and in SQL so that scenarios can name them.
SVCID_SQL = """CASE WHEN i % 2 = 0
    THEN encode(sha256(int4send(i) || int4send(d)), 'hex')
    ELSE left(translate(encode(
        sha256(int4send(i) || int4send(d) || int4send(0)) || sha256(int4send(i) || int4send(d) || int4send(1)) ||
        sha256(int4send(i) || int4send(d) || int4send(2)) || sha256(int4send(i) || int4send(d) || int4send(3)),
        'base64'), E'+/=\\n', '-_'), 142)
    END"""


def client_svcid(i):
    """The service id fake_client gives client i."""
    return f"client-{i}-".ljust(40, "a")


def svcid(i, d=1):
    """The service id seed() gave device d of account i; see SVCID_SQL."""
    key = struct.pack(">ii", i, d)
    if i % 2 == 0:
        return hashlib.sha256(key).hexdigest()
    raw = b"".join(hashlib.sha256(key + struct.pack(">i", k)).digest() for k in range(4))
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")[:142]


# --- processes --------------------------------------------------------------------------------


# Every child started, so that whatever a failed scenario leaves behind can be killed before the
# next one: by pid, never by name, since the machine may be running a real hivemind.
CHILDREN = []


def kill_leftovers():
    for p in CHILDREN:
        if p.poll() is None:
            p.send_signal(signal.SIGCONT)
            p.kill()
            p.wait()
    CHILDREN.clear()


class Proc:
    """A child with line-oriented stdin/stdout."""

    def __init__(self, name, cmd, env=None):
        self.name = name
        self.log = open(f"{WORK}/{name}.err", "w")
        self.p = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.log,
            text=True,
            env=env,
            cwd=WORK,
        )
        CHILDREN.append(self.p)
        self.lock = threading.Lock()

    def readline(self, timeout):
        result = []

        def reader():
            result.append(self.p.stdout.readline())

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        t.join(timeout)
        if t.is_alive() or not result or not result[0]:
            raise Failure(
                f"{self.name}: no answer within {timeout}s (exit {self.p.poll()})"
            )
        return result[0].rstrip("\n")

    def cmd(self, line, timeout=60):
        with self.lock:
            self.p.stdin.write(line + "\n")
            self.p.stdin.flush()
            return self.readline(timeout * TIME_SCALE)

    def stop(self, sig=signal.SIGTERM, timeout=10):
        if self.p.poll() is None:
            self.p.send_signal(sig)
            try:
                self.p.wait(timeout)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()
        self.log.close()


class Hivemind:
    def __init__(
        self,
        build_dir,
        filter_lifetime=300,
        log_level="info",
        name="hivemind",
        quic_key=None,
        config="",
    ):
        """`quic_key`: the path of the QUIC key of an earlier instance, to start one the storage
        nodes take for the same; by default a new key.  `config`: more [hivemind] settings."""
        from nacl.signing import SigningKey

        self.log_path = f"{WORK}/{name}.log"
        key = f"{WORK}/hivemind.key"
        with open(key, "wb") as f:
            f.write(os.urandom(32))
        if not quic_key:
            quic_key = f"{WORK}/{name}-quic.key"
            sk = SigningKey.generate()
            with open(quic_key, "wb") as f:
                f.write(bytes(sk) + bytes(sk.verify_key))
        self.quic_key = quic_key
        with open(f"{WORK}/spns.ini", "w") as f:
            f.write(
                f"""[db]
url = postgresql:///{DB}
[log]
level = {log_level}
[hivemind]
listen = {HIVEMIND_SOCK}
oxend_rpc = tcp://127.0.0.1:{OXEND_PORT}
max_connects = 1000
filter_lifetime = {filter_lifetime}
startup_wait = 30
notifiers_expected = dummy
{config}
[keys]
hivemind = {key}
quic = {quic_key}
"""
            )
        self.start_time = time.time()
        self.logf = open(self.log_path, "w")
        self.p = subprocess.Popen(
            sanitized_cmd([f"{build_dir}/SPNS", f"{WORK}/spns.ini"]),
            stdout=self.logf,
            stderr=subprocess.STDOUT,
            env=sanitized_env(PYTHONPATH=f"{SRC}:{build_dir}"),
            cwd=WORK,
        )
        CHILDREN.append(self.p)

    def wait_socket(self, timeout=600):
        path = os.path.join(WORK, HIVEMIND_SOCK[len("ipc://") :])
        deadline = time.time() + timeout
        while not os.path.exists(path):
            check(self.p.poll() is None, f"hivemind exited early ({self.p.returncode})")
            check(time.time() < deadline, "hivemind did not open its socket")
            time.sleep(0.1)

    def rss_mb(self):
        with open(f"/proc/{self.p.pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
        return 0

    def cpu_seconds(self):
        with open(f"/proc/{self.p.pid}/stat") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")

    def log(self):
        if not self.logf.closed:
            self.logf.flush()
        with open(self.log_path, errors="replace") as f:
            return re.sub(r"\x1b\[[0-9;]*m", "", f.read())

    def stop(self, timeout=30):
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGTERM)
            try:
                self.p.wait(timeout)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()
                raise Failure(f"hivemind did not exit within {timeout}s of SIGTERM")
        self.logf.close()
        return self.p.returncode


class Setup:
    """Hivemind, network and notifier, started in the order each needs the other."""

    def __init__(self, build_dir, nodes, swarms=1, network_args=(), **hivemind_args):
        os.makedirs(WORK, exist_ok=True)
        self.build_dir = build_dir
        self.nodes = nodes
        self.hivemind = self.notifier = self.client = None
        self.hivemind_args = hivemind_args
        # Hivemind instances restart_hivemind stopped, for the scenario to check their logs.
        self.stopped = []
        self.network = Proc(
            "network",
            [f"{FAKES}/fake_network"]
            + (["--monitor-sessions"] if MODE == "monitor" else [])
            + list(network_args)
            + [str(nodes), str(swarms), str(OXEND_PORT), str(FIRST_QUIC_PORT)],
        )
        try:
            self.hivemind = Hivemind(build_dir, **hivemind_args)
            self.hivemind.wait_socket()
            self.notifier = Proc(
                "notifier", [f"{FAKES}/fake_notifier", HIVEMIND_SOCK]
            )
            check(
                self.notifier.readline(120) == "registered", "notifier did not register"
            )
            check(
                self.network.readline(900) == "ready",
                "network never saw every node connect",
            )
        except BaseException:
            self.stop()
            raise

    def restart_hivemind(self, name, **overrides):
        """Stops the hivemind and its notifier, then yields, for the scenario to act while it is
        down; resumed, starts a new one as the same QUIC instance with the same settings, but for
        any `overrides` of Hivemind's arguments for this one alone, and a new notifier, and waits
        for it to connect to every node."""
        rc = self.hivemind.stop()
        check(rc == 0, f"hivemind exit code {rc}")
        self.stopped.append(self.hivemind)
        self.notifier.stop()
        yield
        self.network.cmd("mark")
        self.hivemind = Hivemind(
            self.build_dir,
            **{
                **self.hivemind_args,
                **overrides,
                "name": name,
                "quic_key": self.hivemind.quic_key,
            },
        )
        self.hivemind.wait_socket()
        self.notifier = Proc(f"notifier-{name}", [f"{FAKES}/fake_notifier", HIVEMIND_SOCK])
        check(self.notifier.readline(120) == "registered", "new notifier did not register")
        self.wait_conns(60)

    def wait_report(self, timeout=60):
        """Waits for the hivemind to log another periodic status report, whose counters it checks
        against a recount of the accounts (which check_log() then looks for disagreements from):
        for a scenario with status_report_interval set low."""
        before = self.hivemind.log().count("Status report, over the last")
        deadline = time.time() + timeout * TIME_SCALE
        while self.hivemind.log().count("Status report, over the last") == before:
            check(time.time() < deadline, "no status report logged")
            time.sleep(0.5)

    def client_proc(self):
        if not self.client:
            self.client = Proc("client", [f"{FAKES}/fake_client", HIVEMIND_SOCK])
        return self.client

    def counts(self, notifier=None):
        import json

        return json.loads((notifier or self.notifier).cmd("count"))

    def dropped(self, service):
        """The pushes for `service` the hivemind has logged dropping."""
        return sum(
            int(n)
            for n in re.findall(rf"Dropped (\d+) pushes for '{service}'", self.hivemind.log())
        )

    def wait_pushes(
        self, expected, timeout, settle=1.5, notifier=None, service="dummy", sent=None
    ):
        """Waits for `expected` pushes, then `settle` more seconds to catch extras.  `sent`: the
        pushes for `service` the scenario has caused in all, if it knows; once the hivemind has
        dropped so many of them that fewer than `expected` can arrive, returns at once, short, so
        that the scenario's check says so then rather than at the timeout."""
        deadline = time.time() + timeout * TIME_SCALE
        next_drop_check = 0
        while True:
            c = self.counts(notifier)
            if c["pushes"] >= expected:
                time.sleep(settle)
                return self.counts(notifier)
            if time.time() > deadline:
                return c
            if sent is not None and time.time() >= next_drop_check:
                if (dropped := self.dropped(service)) and sent - dropped < expected:
                    print(f"    the hivemind dropped {dropped} pushes for '{service}'")
                    time.sleep(settle)
                    return self.counts(notifier)
                next_drop_check = time.time() + 2
            time.sleep(0.25)

    def check(self, first, count):
        """How accounts #first.. are subscribed on the nodes; see fake_network's check."""
        import json

        return json.loads(self.network.cmd(f"check {first} {count}"))

    def net_counts(self):
        import json

        return json.loads(self.network.cmd("counts"))

    def coverage(self, first, count):
        """How many listed nodes hold each of accounts #first.., and how many each node holds."""
        import json

        return json.loads(self.network.cmd(f"coverage {first} {count}"))

    def stats(self):
        """The hivemind's get_stats, checking the counters that can never be negative."""
        import json

        st = json.loads(self.client_proc().cmd("stats"))
        check(st["pending_connections"] >= 0, f"{st['pending_connections']} connections pending")
        return st

    def check_covered(self, when):
        """Checks that the hivemind counts every account covered."""
        cov = self.stats()["coverage"]
        check(cov["covered"] == cov["accounts"], f"coverage dipped {when}: {cov}")

    def wait_for(self, what, timeout, done, interval=0.5):
        """Polls `what()` until `done` holds for it, failing after `timeout` (scaled)."""
        deadline = time.time() + timeout * TIME_SCALE
        while True:
            got = what()
            if done(got):
                return got
            check(time.time() < deadline, f"timed out waiting: {got}")
            time.sleep(interval)

    def wait_subscribed(self, first, count, timeout, interval=0.5):
        """Waits for accounts #first.. to be subscribed on every node of their swarm and none
        other; returns the last check.  Each check holds up the fake network for a moment per
        100,000 accounts."""
        deadline = time.time() + timeout * TIME_SCALE
        while True:
            c = self.check(first, count)
            if c["missing"] == 0 and c["extra"] == 0:
                return c
            check(time.time() < deadline, f"accounts not subscribed as they should be: {c}")
            time.sleep(interval)

    def max_in_flight(self):
        """The most monitor requests the nodes have had outstanding at once since last asked."""
        import json

        return json.loads(self.network.cmd("inflight"))["max"]

    def wait_conns(self, timeout):
        deadline = time.time() + timeout * TIME_SCALE
        while int(self.network.cmd("conns")) < self.nodes:
            check(time.time() < deadline, "the hivemind did not reconnect to every node")
            time.sleep(0.25)

    def dump(self):
        lines = []
        self.notifier.p.stdin.write("dump\n")
        self.notifier.p.stdin.flush()
        while (line := self.notifier.readline(30)) != "end":
            lines.append(line)
        return lines

    def stop(self):
        rc = self.hivemind.stop() if self.hivemind else None
        for p in (self.client, self.notifier, self.network):
            if p:
                if p.p.poll() is None:
                    p.p.send_signal(signal.SIGCONT)
                p.stop()
        return rc


def check_log(hm):
    log = hm.log()
    reports = SANITIZER_REPORT.findall(log)
    check(not reports, f"{len(reports)} sanitizer report(s) in the hivemind log")
    for bad in (
        "terminate called",
        "Failed to process incoming notification",
        "failed to build notifier message",
        "disagrees with a recount",
    ):
        check(bad not in log, f"hivemind log has '{bad}'")
    negative = re.search(r"-\d+ connecting", log)
    check(not negative, f"hivemind log has '{negative and negative.group(0)}'")


# --- scenarios --------------------------------------------------------------------------------


# The production database as migrations were brought to it: the schema from before them, with
# want_truncated added by hand, and none of the placement tables.
PRODUCTION_SCHEMA = """
CREATE TABLE subscriptions (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    account BYTEA NOT NULL,
    session_ed25519 BYTEA,
    subaccount_tag BYTEA,
    subaccount_sig BYTEA,
    signature BYTEA NOT NULL,
    signature_ts BIGINT NOT NULL,
    want_data BOOLEAN NOT NULL,
    enc_key BYTEA NOT NULL,
    service VARCHAR NOT NULL,
    svcid VARCHAR NOT NULL,
    svcdata BYTEA,
    UNIQUE(account, service, svcid)
);
CREATE INDEX subscriptions_signature_ts_idx ON subscriptions(signature_ts);
CREATE INDEX subscriptions_service_idx ON subscriptions(service);
CREATE TABLE sub_namespaces (
    subscription BIGINT NOT NULL REFERENCES subscriptions ON DELETE CASCADE,
    namespace SMALLINT NOT NULL,
    PRIMARY KEY(subscription, namespace)
);
CREATE TABLE service_stats (
    service VARCHAR NOT NULL,
    name VARCHAR NOT NULL,
    val_str VARCHAR,
    val_int BIGINT,
    PRIMARY KEY(service, name),
    CHECK((val_str IS NULL AND val_int IS NOT NULL) OR (val_str IS NOT NULL AND val_int IS NULL))
);
ALTER TABLE subscriptions ADD COLUMN want_truncated BOOLEAN NOT NULL DEFAULT false;
"""


def scenario_schema(build_dir):
    """The database schema (spns/schema).  full_schema.sql builds the same schema as the
    migrations do, in order, from nothing.  The hivemind's migration step creates a new database
    from full_schema.sql, recording every migration; brings a database in production's state from
    before migrations level with it, running and recording each; and applies nothing the next
    time.  Each schema built is compared with the others column by column, in order, and by its
    constraints and indexes."""
    sql_dir = f"{SRC}/spns/schema"
    # Ordered by name, not filename (see spns/schema/README).
    names = sorted(f[:-4] for f in os.listdir(sql_dir) if f[0].isdigit() and f.endswith(".sql"))
    check(names, "no migrations found")

    def sql(name):
        with open(f"{sql_dir}/{name}.sql") as f:
            return f.read()

    def build(schema, *scripts):
        execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema}")
        for script in scripts:
            execute(f"SET search_path TO {schema};\n{script}")

    def dump(schema):
        """The schema's tables (but migrations_applied): their columns in order, constraints
        and indexes, from the catalogs rather than pg_dump, which refuses a newer server."""
        rows = query(
            f"""
SELECT 'column', table_name, ordinal_position || ' ' || column_name || ' ' || data_type || ' '
    || is_nullable || ' ' || coalesce(column_default, '') || ' ' || is_identity
FROM information_schema.columns
WHERE table_schema = '{schema}' AND table_name <> 'migrations_applied'
UNION ALL
SELECT 'constraint', cl.relname, co.conname || ' ' || pg_get_constraintdef(co.oid)
FROM pg_constraint co
    JOIN pg_class cl ON cl.oid = co.conrelid
    JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = '{schema}' AND cl.relname <> 'migrations_applied'
UNION ALL
SELECT 'index', tablename, indexname || ' ' || indexdef
FROM pg_indexes
WHERE schemaname = '{schema}' AND tablename <> 'migrations_applied'
ORDER BY 1, 2, 3"""
        )
        return "".join(f"{' '.join(r)}\n" for r in rows).replace(schema, "SCHEMA")

    def recorded(schema):
        return [n for (n,) in query(f"SELECT name FROM {schema}.migrations_applied ORDER BY name")]

    schemas = ("spns_full", "spns_chain", "spns_fresh", "spns_production")
    try:
        build("spns_full", sql("full_schema"))
        full = dump("spns_full")
        check("column subscriptions" in full, f"nothing described: {full}")

        build("spns_chain", *(sql(n) for n in names))
        check(
            dump("spns_chain") == full,
            "full_schema.sql differs from the migrations: "
            + "".join(difflib.unified_diff(
                full.splitlines(True), dump("spns_chain").splitlines(True), "full", "migrations"
            )),
        )
        print(f"    full_schema.sql builds what the {len(names)} migrations do: {', '.join(names)}")

        build("spns_fresh")
        log = migrate_schema("spns_fresh")
        check("Created the database schema" in log, f"not created from full_schema: {log}")
        check(dump("spns_fresh") == full, "a new database differs from full_schema.sql")
        check(recorded("spns_fresh") == names, f"recorded {recorded('spns_fresh')}, not {names}")
        print("    a new database: created from full_schema.sql, every migration recorded")

        build("spns_production", PRODUCTION_SCHEMA)
        execute(
            "INSERT INTO spns_production.subscriptions (account, signature, signature_ts, "
            "want_data, enc_key, service, svcid) VALUES ('\\x03', '\\x00', 1, true, '\\x00', "
            "'apns', 'device')"
        )
        log = migrate_schema("spns_production")
        applied = re.findall(r"Applied database migration (\S+)", log)
        check(applied == names, f"applied {applied} to the production database, not {names}")
        check(
            dump("spns_production") == full,
            "the production database, migrated, differs from full_schema.sql: "
            + "".join(difflib.unified_diff(
                full.splitlines(True),
                dump("spns_production").splitlines(True),
                "full",
                "production",
            )),
        )
        check(recorded("spns_production") == names, f"recorded {recorded('spns_production')}")
        check(
            query1("SELECT svcid FROM spns_production.subscriptions") == "device",
            "the production database's subscription was lost",
        )
        print(f"    production's database: {', '.join(applied)} applied, its subscription kept")

        log = migrate_schema("spns_production")
        check(
            "Applied" not in log and "Created" not in log,
            f"a database up to date was migrated again: {log}",
        )
        print("    and nothing applied the next time")
    finally:
        execute(f"DROP SCHEMA IF EXISTS {', '.join(schemas)} CASCADE")



def scenario_correctness(build_dir):
    """Who gets pushed what: duplicates, namespaces, devices, expiry, and subscribe, drop and
    unsubscribe at runtime."""
    fresh_db()
    seed(1, 1, namespaces="0,5", svcdata="convert_to('sd1', 'UTF8')")
    seed(2, 1, devices="2")
    seed(3, 1, sig_ts=int(time.time()) - 15 * 86400)
    s = Setup(build_dir, nodes=3)
    try:
        net = s.network
        net.cmd("send #1 hash-one-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 200")
        net.cmd("send #1 hash-two-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 3 200")
        net.cmd("send #2 hash-three-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 0")
        net.cmd("send #3 hash-four-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 0")
        net.cmd("send #4 hash-five-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 0")
        net.cmd("send #1 hash-one-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 200")
        c = s.wait_pushes(3, 30)
        check(c["pushes"] == 3, f"phase 1: expected 3 pushes, got {c['pushes']}")
        got = sorted(s.dump())
        want = sorted(
            [
                f"{svcid(1)} hash-one-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 200 sd1",
                f"{svcid(2, 1)} hash-three-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 0 -",
                f"{svcid(2, 2)} hash-three-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 0 -",
            ]
        )
        check(got == want, f"phase 1 pushes: {got}")
        check(
            query1(f"SELECT count(*) FROM subscriptions WHERE svcid = '{svcid(3)}'") == 0,
            "the expired subscription is still in the database",
        )

        client = s.client_proc()
        acct5 = client.cmd("account 5")
        # Concurrent subscribes for one device must all succeed, not race on its row.
        check(client.cmd("sub 5 8") == "ok", "concurrent subscribes failed")
        check(client.cmd(f"drop {svcid(2, 1)}") == "ok", "drop failed")
        time.sleep(1)
        net.cmd(f"send {acct5} hash-six-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 200")
        net.cmd("send #2 hash-eight-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 0")
        c = s.wait_pushes(5, 30)
        check(c["pushes"] == 5, f"phase 2: expected 5 pushes in all, got {c['pushes']}")
        got = sorted(s.dump())
        check(
            "client-5-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa hash-six-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 200 -"
            in got,
            f"no push for the runtime subscription: {got}",
        )
        check(
            f"{svcid(2, 2)} hash-eight-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 0 -" in got
            and not any(l.startswith(f"{svcid(2, 1)} hash-eight") for l in got),
            f"dropped device still pushed, or the other one not: {got}",
        )

        check(client.cmd("unsub 5") == "ok", "unsubscribe failed")
        net.cmd(f"send {acct5} hash-seven-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 200")
        c = s.wait_pushes(6, 4)
        check(
            c["pushes"] == 5,
            f"phase 3: unsubscribed account still pushed ({c['pushes']})",
        )
        left = sorted(sid for (sid,) in query("SELECT svcid FROM subscriptions"))
        check(left == sorted([svcid(1), svcid(2, 2)]), f"subscriptions left: {left}")
        check(c["duplicates"] == 0, f"{c['duplicates']} duplicate pushes")
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_burst(build_dir, accounts=50_000, messages=20_000, nodes=5, timeout=120):
    """Every unique message reaches the notifier once when every node sends a burst at once."""
    fresh_db()
    seed(0, accounts)
    s = Setup(build_dir, nodes=nodes)
    try:
        s.network.cmd(f"burst 0 {messages} {accounts} 0 200")
        start = time.time()
        c = s.wait_pushes(messages, timeout, sent=messages)
        took = c["last_ms"] / 1000 - start if c["pushes"] else 0
        print(
            f"    {c['pushes']}/{messages} pushes, {nodes} copies of each, in {took:.2f}s"
        )
        check(
            c["pushes"] == messages and c["duplicates"] == 0,
            f"expected {messages} unique pushes, got {c}",
        )
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_resend(build_dir):
    """A notifier that stops reading (SIGSTOP) loses nothing once it resumes: the pushes held
    back once its window filled are sent then."""
    fresh_db()
    seed(0, 20_000)
    s = Setup(build_dir, nodes=3, log_level="info,hivemind=debug")
    try:
        s.notifier.p.send_signal(signal.SIGSTOP)
        s.network.cmd("burst 0 30000 20000 0 200")
        time.sleep(5)
        s.notifier.p.send_signal(signal.SIGCONT)
        c = s.wait_pushes(30_000, 120, sent=30_000)
        check(
            c["pushes"] == 30_000 and c["duplicates"] == 0,
            f"expected 30000 unique pushes, got {c}",
        )
        check(
            "backlogged pushes" in s.hivemind.log(),
            "the notifier's window never filled: nothing was held back",
        )
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_notifier_restart(build_dir):
    """A notifier that dies with pushes waiting for it, and starts again: the hivemind keeps
    processing, and the waiting pushes go to the new notifier."""
    fresh_db()
    seed(0, 20_000)
    s = Setup(build_dir, nodes=3, log_level="info,hivemind=debug")
    try:
        s.notifier.p.send_signal(signal.SIGSTOP)
        s.network.cmd("burst 0 30000 20000 0 200")
        time.sleep(3)
        check(
            "filled the push window" in s.hivemind.log(),
            "no pushes were waiting before the restart",
        )
        s.notifier.stop(sig=signal.SIGKILL)
        # Long enough for resends to find the connection gone before the new one registers.
        time.sleep(3)
        s.notifier = Proc("notifier2", [f"{FAKES}/fake_notifier", HIVEMIND_SOCK])
        check(s.notifier.readline(120) == "registered", "new notifier did not register")
        # Only what the dead notifier had taken without acknowledging is lost: under a window.
        c = s.wait_pushes(29_800, 60, settle=3)
        print(f"    {c['pushes']} of 30000 pushes reached the new notifier")
        check(
            c["pushes"] >= 29_800 and c["duplicates"] == 0,
            f"waiting pushes did not reach the new notifier: {c}",
        )
        # With its window full the hivemind sends the dead notifier nothing, so it learns of the
        # loss only when the service registers again on a new connection.
        check(
            "reconnected/reregistered" in s.hivemind.log(),
            "the hivemind did not hand the service over to the new notifier",
        )
        before = c["pushes"]
        s.network.cmd("send #7 after-the-restart-aaaaaaaaaaaaaaaaaaaaaaaaaa 0 100")
        c = s.wait_pushes(before + 1, 30)
        check(
            c["pushes"] == before + 1,
            "no push for a notification sent after the restart",
        )
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_two_notifiers(build_dir):
    """While one notifier has stopped reading, another service's pushes go out at once, and the
    stopped one's arrive once it resumes."""
    fresh_db()
    seed(0, 20_000)
    seed(20_000, 20_000, service="other")
    s = Setup(build_dir, nodes=3, log_level="info,hivemind=debug")
    other = None
    try:
        other = Proc(
            "notifier-other",
            [f"{FAKES}/fake_notifier", HIVEMIND_SOCK, "-1", "other"],
        )
        check(other.readline(120) == "registered", "second notifier did not register")
        s.notifier.p.send_signal(signal.SIGSTOP)
        s.network.cmd("burst 0 40000 40000 0 200")
        c = s.wait_pushes(20_000, 30, notifier=other, service="other", sent=20_000)
        check(
            c["pushes"] == 20_000 and c["duplicates"] == 0,
            f"the running notifier's pushes waited for the stopped one: {c}",
        )
        check(
            "filled the push window" in s.hivemind.log(),
            "the stopped notifier's window never filled",
        )
        s.notifier.p.send_signal(signal.SIGCONT)
        c = s.wait_pushes(20_000, 120, sent=20_000)
        check(
            c["pushes"] == 20_000 and c["duplicates"] == 0,
            f"expected 20000 unique pushes once resumed, got {c}",
        )
    finally:
        if other:
            other.stop()
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_backlog(build_dir):
    """While the database or the notifier stalls, the storage nodes' streams to the hivemind do
    not back up: the hivemind keeps reading and holds the notifications itself."""
    fresh_db()
    seed(0, 10_000)
    s = Setup(build_dir, nodes=3)
    try:
        # A sanitizer slows the notifier to a few hundred pushes a second, and then 2,000 a
        # second would pile up more than the hivemind holds for it (PUSH_BACKLOG_MAX, 50,000)
        # and have it drop some; half that never can, the notifier taking none at all.
        rate, seconds, stall = (1000 if SANITIZED else 2000), 14, 8

        def stall_db():
            time.sleep(2)
            with psycopg.connect(dbname=DB) as conn:
                conn.execute("LOCK TABLE service_stats IN ACCESS EXCLUSIVE MODE")
                conn.execute(f"SELECT pg_sleep({stall})")

        s.network.cmd("backlog")
        t = threading.Thread(target=stall_db)
        t.start()
        s.network.cmd(f"rate {rate} {seconds} 10000 0 200 0", timeout=seconds + 30)
        t.join()
        db_backlog = int(s.network.cmd("backlog"))

        def stall_notifier():
            time.sleep(2)
            s.notifier.p.send_signal(signal.SIGSTOP)
            time.sleep(stall)
            s.notifier.p.send_signal(signal.SIGCONT)

        t = threading.Thread(target=stall_notifier)
        t.start()
        s.network.cmd(
            f"rate {rate} {seconds} 10000 0 200 {rate * seconds}", timeout=seconds + 30
        )
        t.join()
        notifier_backlog = int(s.network.cmd("backlog"))

        # A blocked loop would leave rate * stall notifications (about 300 bytes each) per node.
        limit = 1 << 20
        print(
            f"    largest node backlog: {db_backlog} B with the database locked, "
            f"{notifier_backlog} B with the notifier stopped (limit {limit} B; a blocked loop "
            f"would leave about {rate * stall * 300} B)"
        )
        if not SANITIZED:
            check(
                db_backlog < limit,
                f"node backlog reached {db_backlog} B while the database stalled",
            )
            check(
                notifier_backlog < limit,
                f"node backlog reached {notifier_backlog} B while the notifier stalled",
            )
        c = s.wait_pushes(2 * rate * seconds, 120, sent=2 * rate * seconds)
        check(
            c["pushes"] == 2 * rate * seconds and c["duplicates"] == 0,
            f"expected {2 * rate * seconds} unique pushes, got {c}",
        )
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_churn(build_dir):
    """Subscriptions changing while notifications flow: no push lost for stable accounts, and
    afterwards pushes match what the database holds, and the status report's recount agrees with
    the hivemind's counters."""
    fresh_db()
    seed(0, 20_000)
    s = Setup(build_dir, nodes=3, config="status_report_interval = 15")
    try:
        client = s.client_proc()
        done = {}

        def flow():
            done["flow"] = s.network.cmd("rate 5000 8 20000 0 200 0", timeout=60)

        t = threading.Thread(target=flow)
        t.start()
        result = client.cmd("churn 0 200 5", timeout=300)
        t.join()
        _, subs, unsubs, failures = result.split()
        check(failures == "0", f"churn: {result}")
        c = s.wait_pushes(40_000, 120)
        check(c["pushes"] >= 40_000, f"stable accounts: expected 40000 pushes, got {c}")

        before = c["pushes"]
        for i in range(200):
            s.network.cmd(
                f"send {client.cmd(f'account {i}')} churn-final-{i:030d} 0 100"
            )
        c = s.wait_pushes(before + 100, 60, settle=2)
        check(
            c["pushes"] - before == 100,
            f"after churn: expected 100 pushes (the even clients), got {c['pushes'] - before}",
        )
        check(c["duplicates"] == 0, f"{c['duplicates']} duplicate pushes")
        n = query1("SELECT count(*) FROM subscriptions WHERE svcid LIKE 'client-%'")
        check(n == 100, f"database holds {n} client subscriptions, expected 100")
        # The hivemind keeps its own count of the rows, through every subscribe and unsubscribe.
        rows = query1("SELECT count(*) FROM subscriptions")
        counted = s.stats()["subscriptions"]["total"]
        check(counted == rows, f"the hivemind counts {counted} subscriptions; the database {rows}")
        s.wait_report()
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_shutdown(build_dir):
    """SIGTERM in the middle of a burst, with pushes held back, exits cleanly."""
    fresh_db()
    seed(0, 20_000)
    s = Setup(build_dir, nodes=3, log_level="info,hivemind=debug")
    try:
        s.notifier.p.send_signal(signal.SIGSTOP)
        s.network.cmd("burst 0 30000 20000 0 200")
        time.sleep(3)
        check(
            "filled the push window" in s.hivemind.log(), "no pushes were waiting at shutdown"
        )
        start = time.time()
        rc = s.hivemind.stop(timeout=30 * TIME_SCALE)
        print(f"    exited in {time.time() - start:.1f}s with pushes held back")
    finally:
        s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_reshuffle(build_dir):
    """A swarm split: the accounts that moved get subscribed on their new swarm's nodes, and
    nothing is sent to a node not of an account's swarm, then or after every connection is lost
    and made again (where the old per-node copies resubscribed moved accounts on their old
    nodes for good).  Then another split, with one node seconds behind oxend's view of it: the
    accounts it refuses as not its swarm's meanwhile are subscribed there once it catches up,
    within the retry backoff rather than at their renewal."""
    fresh_db()
    seed(0, 4000)
    # Monitor session support goes by the version oxend reports: with monitor sessions one node
    # reports none, and gets none; without, one reports a version with monitor sessions that it
    # lacks, and falls back.
    version = "7:none" if MODE == "monitor" else "0:2.13.0"
    # Late replies, so that the nodes see the hivemind's requests in flight together, under a cap
    # smaller than the 8 nodes.
    cap = 4
    s = Setup(
        build_dir,
        nodes=8,
        swarms=2,
        network_args=["--version", version, "--reply-delay", "10"],
        config=f"monitor_requests = {cap}\nstatus_report_interval = 15",
    )
    try:
        c = s.wait_subscribed(0, 4000, 60)
        most = s.max_in_flight()
        check(1 < most <= cap, f"{most} monitor requests in flight at once, with a cap of {cap}")
        n = s.net_counts()
        check(n["wrong_swarm"] == 0, f"subscriptions sent to the wrong swarm at startup: {n}")
        if MODE == "monitor":
            check(
                n["created"] == 7,
                f"expected monitor sessions on all but the unversioned node: {n}",
            )
        else:
            check(
                "but does not support monitor sessions" in s.hivemind.log(),
                "the node reporting a version with monitor sessions was not found to lack them",
            )

        s.network.cmd("mark")
        s.network.cmd("swarms 4")
        deadline = time.time() + 30 * TIME_SCALE
        while len(changes := re.findall(r"Swarm list changed: (\d+) accounts moved", s.hivemind.log())) < 2:
            check(time.time() < deadline, "the hivemind did not see the swarms change")
            time.sleep(0.25)
        moved = int(changes[-1])
        check(moved > 0, "no account moved swarm")
        c = s.wait_subscribed(0, 4000, 60)
        n = s.net_counts()
        check(n["wrong_swarm"] == 0, f"subscriptions sent to the wrong swarm after the move: {n}")
        print(f"    {moved} of 4000 accounts moved swarm, and are subscribed where they now belong")

        s.network.cmd("mark")
        s.network.cmd("drop")
        s.wait_conns(60)
        c = s.wait_subscribed(0, 4000, 60)
        time.sleep(2)
        n = s.net_counts()
        check(n["wrong_swarm"] == 0, f"subscriptions sent to the wrong swarm after reconnecting: {n}")
        print(
            f"    after reconnecting: {n['entries']} subscriptions sent for {c['expected']} "
            f"(account, node) pairs, {n['resumed']} monitor sessions resumed, none to the wrong "
            f"swarm"
        )
        if MODE == "legacy":
            check(n["entries"] >= c["expected"], f"the reconnections were not filled: {n}")
        else:
            check(n["resumed"] == 7, f"expected 7 monitor sessions resumed: {n}")

        s.network.cmd("lag 1 5000")
        s.network.cmd("mark")
        start = time.time()
        s.network.cmd("swarms 8")
        deadline = time.time() + 30 * TIME_SCALE
        while len(re.findall(r"Swarm list changed: \d+ accounts moved", s.hivemind.log())) < 3:
            check(time.time() < deadline, "the hivemind did not see the swarms change again")
            time.sleep(0.25)
        c = s.wait_subscribed(0, 4000, 60)
        n = s.net_counts()
        check(n["wrong_swarm"] > 0, f"the lagging node refused nothing: {n}")
        print(
            f"    with node 1 five seconds behind the next split: {n['wrong_swarm']} refused as "
            f"not its swarm's, and all subscribed {time.time() - start:.0f}s after the split"
        )
        s.wait_report()
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_restart(build_dir):
    """A hivemind restart.  With monitor sessions, the restarted hivemind restores its saved
    placements, the nodes resume their sessions without listing their monitors and replay what
    arrived while it was down, and it subscribes nothing again; when the nodes' answers to its
    resumptions are lost, with their new tokens and the replay, it forgets the tokens and its next
    connections start new sessions, every account placed again and that gap lost; after a gap in
    which the swarms
    split, the nodes that stayed resume so, and their accounts that moved are subscribed in their
    new swarm; and from saved state too old to trust, every node starts afresh.  Without monitor
    sessions, the gap is lost, and everything is subscribed again.

    The first restarted hivemind renews every minute or so, to see when it renews what it restored:
    with monitor sessions, when the first would have; without them, a renewal interval after it
    placed everything afresh, not again when the first would have."""
    accounts, gap = 2000, 100
    subscriptions = accounts + accounts // 4
    fresh_db()
    seed(0, accounts)
    # A second subscription for some accounts, with other namespaces: a node holds a monitor for
    # each, and resuming must find both held.
    seed(0, accounts // 4, namespaces="1", service="other")
    # A replay budget below the notifications some accounts get while it is down.
    budget = 2
    config = f"resume_replay = {budget}"
    s = Setup(build_dir, nodes=3, config=config)

    def all_placed():
        # A node holds the monitors of a session it was not offered again until they expire, so
        # only what is missing counts here.
        s.wait_for(lambda: s.check(0, accounts), 60, lambda c: c["missing"] == 0)

    # The restored renewals fall due within the first restarted hivemind's run: those saved by the
    # first, all acknowledged by `filled`, at most 1.1 intervals on, and are made by the next of
    # its checks every `tick`; while it places nothing afresh before it starts, `down` after
    # `filled`, and renews that no sooner than 0.9 intervals on.
    renewal, down, tick = 60, 45, 10

    try:
        s.wait_subscribed(0, accounts, 60)
        filled = time.time()
        s.network.cmd("send #1 before-the-restart-aaaaaaaaaaaaaaaaaaaaaa 0 100")
        c = s.wait_pushes(1, 30)
        check(c["pushes"] == 1, f"no push before the restart: {c}")

        steps = s.restart_hivemind(
            "hivemind2", config=f"{config}\nrenewal_interval = {renewal}"
        )
        next(steps)
        for i in range(gap):
            s.network.cmd(f"send #{i} gap-{i:036d} 0 100")
        time.sleep(max(0, filled + down - time.time()))
        next(steps, None)
        s.wait_subscribed(0, accounts, 60)
        c = s.wait_pushes(gap, 15 if MODE == "monitor" else 5)
        n = s.net_counts()
        print(
            f"    {c['pushes']} of the {gap} notifications sent while it was down reached the "
            f"notifier; {n['entries']} subscriptions sent after the restart, {n['resumed']} "
            f"monitor sessions resumed ({n['resumed_unlisted']} without their listing)"
        )
        # Said once the last restored node has settled: each node held every account.
        settled = s.wait_for(
            lambda: re.search(
                r"(?:None of the|Restored placements settled:) [^\n]*", s.hivemind.log()
            ),
            15,
            bool,
        ).group(0)
        print(f"    {settled}")
        placements = s.nodes * accounts
        if MODE == "monitor":
            want = f"Restored placements settled: {placements} of {placements} kept"
        else:
            want = (
                f"None of the {placements} restored placements was kept: {placements} on nodes "
                "without monitor sessions"
            )
        check(settled.startswith(want), f"expected '{want}...'")
        if MODE == "monitor":
            check(
                c["pushes"] == gap and c["duplicates"] == 0,
                f"the replay did not deliver the gap: {c}",
            )
            check(
                n["resumed"] == 3 and n["resumed_unlisted"] == 3 and n["listed"] == 0,
                f"monitor sessions not resumed without their listing: {n}",
            )
            check(n["entries"] == 0, f"subscriptions sent after resuming every session: {n}")
        else:
            check(c["pushes"] == 0, f"pushes for the gap without monitor sessions: {c}")
            check(
                n["entries"] >= 3 * subscriptions,
                f"only {n['entries']} subscriptions sent after the restart; expected a full fill",
            )
        before = c["pushes"]
        s.network.cmd("send #7 after-the-restart-aaaaaaaaaaaaaaaaaaaaaaa 0 100")
        c = s.wait_pushes(before + 1, 30)
        check(c["pushes"] == before + 1, "no push for a notification sent after the restart")

        restored_due = filled + renewal * 11 / 10 + tick
        fresh_due = filled + down + renewal * 9 / 10

        # A renewal keeps the monitors it renews acknowledged while it is answered.
        def renewing():
            s.check_covered("while renewing")
            return s.net_counts()

        if MODE == "monitor":
            # Every placement was restored and kept, each account scheduled once, to be renewed
            # when the first hivemind would have.
            sched = s.stats()["schedule"]
            check(sched == accounts, f"{sched} renewals scheduled for {accounts} accounts")
            s.network.cmd("mark")
            s.wait_for(
                renewing,
                restored_due + 5 - time.time(),
                lambda n: n["entries"] >= 3 * subscriptions,
            )
            renewed = time.time() - filled
            print(f"    the restored placements renewed {renewed:.0f}s after the first fill")
            check(
                time.time() < fresh_due,
                f"restored placements renewed {renewed:.0f}s after the first fill, as if placed "
                f"afresh",
            )
        else:
            # Every restored placement was dropped, and its account placed afresh: renewed a
            # renewal interval from then, and not when the first hivemind would have.
            s.network.cmd("mark")
            time.sleep(max(0, restored_due + 5 - time.time()))
            n = s.net_counts()
            print(
                f"    {n['entries']} subscriptions sent between the fill and "
                f"{time.time() - filled:.0f}s after the first fill"
            )
            check(
                n["entries"] < subscriptions // 20,
                f"placed again when the restored placements would have been renewed: {n}",
            )
            s.wait_for(
                renewing,
                fresh_due + renewal / 5 + tick + 10 - time.time(),
                lambda n: n["entries"] >= 3 * subscriptions,
            )
            print(f"    renewed {time.time() - filled:.0f}s after the first fill")

        if MODE == "monitor":
            # More notifications for each of a few accounts than the replay budget: each node
            # keeps and replays the newest of each account's, in order, and reports the rest
            # discarded.
            accts, per = 5, 5

            def replay_hash(a, k):
                return f"replay-{a}-{k}-".ljust(40, "a")

            steps = s.restart_hivemind("hivemind-replay")
            next(steps)
            for k in range(per):
                for a in range(accts):
                    s.network.cmd(f"send #{a} {replay_hash(a, k)} 0 100")
            next(steps, None)
            c = s.wait_pushes(accts * budget, 30)
            check(c["pushes"] == accts * budget, f"expected {accts * budget} pushes: {c}")
            hashes = [line.split()[1] for line in s.dump()]
            for a in range(accts):
                got = [h for h in hashes if h.startswith(f"replay-{a}-")]
                want = [replay_hash(a, k) for k in range(per - budget, per)]
                check(got == want, f"account #{a}'s replay: {got}, expected {want}")
            ms = s.stats()["monitor_sessions"]
            check(
                ms["replay_discarded"] == 3 * accts * (per - budget)
                and ms["replay_discarded_accounts"] == 3 * accts,
                f"discards beyond the replay budget: {ms}",
            )
            print(
                f"    {per} notifications for each of {accts} accounts while it was down: the "
                f"newest {budget} of each replayed in order; the nodes reported "
                f"{ms['replay_discarded']} discarded for {ms['replay_discarded_accounts']} "
                f"accounts"
            )

            # A reconnection while it runs resumes every session without its listing, the
            # hivemind's claims for each node being current, and sends nothing again.
            s.network.cmd("mark")
            s.network.cmd("drop")
            s.wait_conns(60)
            s.wait_for(s.net_counts, 30, lambda n: n["resumed"] == 3)
            time.sleep(2)
            n = s.net_counts()
            print(
                f"    after every connection dropped: {n['resumed_unlisted']} monitor sessions "
                f"resumed without their listing, {n['listed']} live monitors listed, "
                f"{n['entries']} subscriptions sent"
            )
            check(
                n["resumed_unlisted"] == 3 and n["listed"] == 0 and n["entries"] == 0,
                f"a reconnection did not resume quietly: {n}",
            )

            # Every node's answer to the restarted hivemind's resumption is lost, with the new token
            # and the replay of what arrived while it was down.  The token it offered is dead, so
            # it forgets it, and its next connections start new sessions, placing everything
            # again; the gap is lost.
            lost = 20
            steps = s.restart_hivemind("hivemind-lost-reply")
            next(steps)
            for i in range(s.nodes):
                s.network.cmd(f"lose-reply {i}")
            for i in range(lost):
                s.network.cmd(f"send #{i} lost-{i:036d} 0 100")
            next(steps, None)
            s.wait_for(
                lambda: s.hivemind.log().count("Forgot our monitor session token"),
                30,
                lambda n: n == s.nodes,
            )
            s.network.cmd("mark")
            s.network.cmd("drop")
            s.wait_conns(60)
            s.wait_for(s.net_counts, 30, lambda n: n["created"] == 3)
            all_placed()
            time.sleep(1)
            c = s.counts()
            n = s.net_counts()
            print(
                f"    after every node's answer to the resumption was lost: {n['created']} new "
                f"monitor sessions, {n['resumed']} resumed, {n['entries']} subscriptions sent; "
                f"{c['pushes']} of the {lost} notifications sent while the hivemind was down "
                f"pushed"
            )
            check(
                n["created"] == 3 and n["resumed"] == 0,
                f"expected new monitor sessions after the lost answers: {n}",
            )
            check(n["entries"] >= subscriptions, f"not everything subscribed again: {n}")
            check(c["pushes"] == 0, f"pushes for a gap whose replay was lost: {c}")

            # Nodes 0 and 2 stay in their swarm and node 1 moves to the new one, taking half the
            # accounts: the two that stayed list those as ended.
            steps = s.restart_hivemind("hivemind3")
            next(steps)
            s.network.cmd("swarms 2")
            next(steps, None)
            all_placed()
            n = s.net_counts()
            per_node = json.loads(s.network.cmd("subs"))
            print(
                f"    after a split while it was down: {n['resumed_unlisted']} monitor sessions "
                f"resumed without their listing, {n['created']} new; subscriptions sent to each "
                f"node {[p['entries'] for p in per_node]}"
            )
            check(
                n["resumed_unlisted"] == 2 and n["created"] == 1 and n["listed"] == 0,
                f"expected the nodes that stayed to resume without their listing: {n}",
            )
            check(
                per_node[0]["entries"] == 0 and per_node[2]["entries"] == 0,
                f"subscriptions sent to the nodes that stayed: {per_node}",
            )
            check(per_node[1]["entries"] > 0, f"nothing sent to the moved node: {per_node}")

            # Saved state too old to trust: new sessions everywhere, and everything subscribed.
            steps = s.restart_hivemind("hivemind4")
            next(steps)
            execute(f"UPDATE placement_state SET saved_at = saved_at - {11 * 60}")
            next(steps, None)
            all_placed()
            n = s.net_counts()
            print(
                f"    from saved state 11 minutes old: {n['created']} new monitor sessions, "
                f"{n['resumed']} resumed; {n['entries']} subscriptions sent"
            )
            check(
                n["created"] == 3 and n["resumed"] == 0,
                f"expected every node to start afresh: {n}",
            )
            check(n["entries"] >= subscriptions, f"not everything subscribed again: {n}")
            check(
                "old, more than" in s.hivemind.log(),
                "the hivemind did not say its saved state was too old",
            )
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    for hm in s.stopped:
        check_log(hm)
    check_log(s.hivemind)


def scenario_body_limit(build_dir):
    """A message over the body limit of 2500 bytes is cut to the limit: with monitor sessions by
    the node, whose sessions carry the limit, live and in the replay after a hivemind restart;
    without, by the hivemind, from the whole body the node sends.  A subscription that opted in to
    truncated bodies gets the exact first 2500 bytes with the full size; any other, the full size
    alone; and a message within the limit reaches both whole."""
    fresh_db()
    seed(0, 10)
    s = Setup(build_dir, nodes=3)
    try:
        sub = s.wait_subscribed(0, 10, 60)
        print(f"    {sub['with_b']} of {sub['monitors']} monitors have a body limit")
        # Only a monitor session can carry the limit.
        want_b = sub["monitors"] if MODE == "monitor" else 0
        check(sub["with_b"] == want_b, f"expected {want_b} monitors with a body limit: {sub}")

        # Client 3 opts in, then resubscribes without: the flag follows the latest subscription.
        client = s.client_proc()
        for cmd in ("sub 1 truncate", "sub 2", "sub 3 truncate", "sub 3"):
            check(client.cmd(cmd) == "ok", f"{cmd} failed")
        truncated = {
            i: query1(
                f"SELECT want_truncated FROM subscriptions WHERE svcid = '{client_svcid(i)}'"
            )
            for i in (1, 2, 3)
        }
        check(truncated == {1: True, 2: False, 3: False}, f"stored truncate flags: {truncated}")
        time.sleep(2 * TIME_SCALE)

        sizes = {1: 2000, 2: 2500, 3: 3000}
        for i, size in sizes.items():
            s.network.cmd(f"send #{i} limit-{size}-aaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 {size}")
        for i in (1, 2, 3):
            acct = client.cmd(f"account {i}")
            for size in (2000, 3000):
                s.network.cmd(f"send {acct} limit-c{i}-{size}-aaaaaaaaaaaaaaaaaaaaaaaaa 0 {size}")
        want_pushes = len(sizes) + 6
        c = s.wait_pushes(want_pushes, 30)
        check(c["pushes"] == want_pushes, f"expected {want_pushes} pushes, got {c}")
        got = sorted(s.dump())
        want = [
            f"{svcid(1)} limit-2000-aaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 2000 -",
            f"{svcid(2)} limit-2500-aaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 2500 -",
            f"{svcid(3)} limit-3000-aaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 0 - full=3000",
            f"{client_svcid(1)} limit-c1-2000-aaaaaaaaaaaaaaaaaaaaaaaaa 0 2000 -",
            f"{client_svcid(1)} limit-c1-3000-aaaaaaaaaaaaaaaaaaaaaaaaa 0 2500 - full=3000",
        ] + [
            line
            for i in (2, 3)
            for line in (
                f"{client_svcid(i)} limit-c{i}-2000-aaaaaaaaaaaaaaaaaaaaaaaaa 0 2000 -",
                f"{client_svcid(i)} limit-c{i}-3000-aaaaaaaaaaaaaaaaaaaaaaaaa 0 0 - full=3000",
            )
        ]
        check(got == sorted(want), f"pushes: {got}")

        if MODE == "monitor":
            # Sent while the hivemind is down, so replayed by the nodes on resuming its sessions.
            accts = {i: client.cmd(f"account {i}") for i in (1, 2)}
            steps = s.restart_hivemind("hivemind-replay")
            next(steps)
            s.network.cmd("send #3 replay-3000-aaaaaaaaaaaaaaaaaaaaaaaaaaa 0 3000")
            for i, acct in accts.items():
                for size in (2000, 3000):
                    s.network.cmd(f"send {acct} replay-c{i}-{size}-aaaaaaaaaaaaaaaaaaaaaa 0 {size}")
            next(steps, None)
            c = s.wait_pushes(5, 30)
            n = s.net_counts()
            check(n["resumed"] == 3, f"monitor sessions not resumed: {n}")
            check(c["pushes"] == 5, f"expected 5 replayed pushes, got {c}")
            got = sorted(s.dump())
            want = [
                f"{svcid(3)} replay-3000-aaaaaaaaaaaaaaaaaaaaaaaaaaa 0 0 - full=3000",
                f"{client_svcid(1)} replay-c1-2000-aaaaaaaaaaaaaaaaaaaaaa 0 2000 -",
                f"{client_svcid(1)} replay-c1-3000-aaaaaaaaaaaaaaaaaaaaaa 0 2500 - full=3000",
                f"{client_svcid(2)} replay-c2-2000-aaaaaaaaaaaaaaaaaaaaaa 0 2000 -",
                f"{client_svcid(2)} replay-c2-3000-aaaaaaaaaaaaaaaaaaaaaa 0 0 - full=3000",
            ]
            check(got == sorted(want), f"replayed pushes: {got}")
            print("    after a restart, the nodes' replay cut to the limit as live delivery is")
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    for hm in s.stopped:
        check_log(hm)
    check_log(s.hivemind)


def scenario_status_report(build_dir):
    """The periodic status report, here every 15 seconds, with no saved state, and notifiers in
    every state a service's stats can be in: one sent more pushes than the ack interval, with a
    large lifetime failure count from earlier runs; one registered and reporting its stats but
    sent no push; and one with stats left in the database from an earlier run but not registered
    now.  The hivemind logs two reports and keeps running: the busy notifier has its own line, with
    its acks' round trip and no count of unacknowledged pushes below a full window, and without the
    lifetime failures shown as if they were the interval's; the quiet one is listed as idle, and
    the unregistered one is left out."""
    fresh_db()
    seed(0, 10)
    execute(
        "INSERT INTO service_stats (service, name, val_int) VALUES ('retired', 'notifies', 5), "
        "('dummy', 'failures', 1000000)"
    )
    s = Setup(build_dir, nodes=3, config="status_report_interval = 15")
    quiet = None
    try:
        quiet = Proc("quiet", [f"{FAKES}/fake_notifier", "--stats", HIVEMIND_SOCK, "200", "quiet"])
        check(quiet.readline(120) == "registered", "the quiet notifier did not register")
        # More pushes than the ack interval (95), for an acknowledgement's round trip to be timed.
        pushes = 100
        for i in range(pushes):
            s.network.cmd(f"send #1 status-report-{i:026d} 0 100")
        c = s.wait_pushes(pushes, 30)
        check(c["pushes"] == pushes, f"not every push for the busy notifier: {c}")
        deadline = time.time() + 60 * TIME_SCALE
        while (reports := s.hivemind.log().count("Status report, over the last")) < 2:
            check(s.hivemind.p.poll() is None, "the hivemind died before its second report")
            check(time.time() < deadline, f"only {reports} status reports logged")
            time.sleep(0.5)
        log = s.hivemind.log()
        busy = re.search(r"^    dummy: .*", log, re.M)
        check(busy, "the busy notifier has no line in the report")
        check(
            re.match(
                r"    dummy: [\d.]+ pushes/s, ack latency [\d.]+m?s avg / [\d.]+m?s max",
                busy.group(0),
            ),
            f"no ack round trip on the busy notifier's line: {busy.group(0)}",
        )
        check("unacked" not in log, "a report shows unacked pushes below a full window")
        supporting = 3 if MODE == "monitor" else 0
        sessions = re.search(r"sessions: (\d+)/(\d+) nodes support them, (\d+) created", log)
        check(
            sessions and sessions.groups() == (str(supporting), "3", str(supporting)),
            f"the first report's sessions, expected {supporting}/3 supporting and created: "
            f"{sessions and sessions.group(0)}",
        )
        check(
            re.search(r"^    idle: .*\bquiet\b", log, re.M),
            "the quiet notifier is not listed as idle",
        )
        check("retired" not in log, "the unregistered notifier is in the report")
        check("failures" not in log, "lifetime failures reported as the interval's")
        print(f"    {reports} status reports logged, with the busy, quiet and retired notifiers")
        print(f"    {busy.group(0).strip()}")
    finally:
        if quiet:
            quiet.stop()
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_registration(build_dir):
    """A notifier is registered only if it speaks the hivemind's registration protocol and can
    deliver bodies as large as the hivemind's limit.  One that declares less, or speaks another
    version, is refused with a critical log line and exits on the refusal; one speaking protocol 0
    (the bare service name to register_service, a plain command) cannot be answered, and is only
    logged as using the obsolete interface."""
    fresh_db()
    seed(0, 10)
    s = Setup(build_dir, nodes=3)
    procs = []

    def refused(line):
        return re.search(rf"critical\S*\|[^\]]*\] {re.escape(line)}", s.hivemind.log())

    try:
        for name, opts, line in (
            (
                "small",
                ["--max-body", "2000"],
                "'small' notifier accepts bodies of at most 2000 B, below the hivemind's body "
                "limit of 2500 B",
            ),
            (
                "future",
                ["--protocol", "2"],
                "'future' notifier speaks protocol 2, this hivemind requires 1",
            ),
        ):
            p = Proc(name, [f"{FAKES}/fake_notifier", *opts, HIVEMIND_SOCK, "200", name])
            procs.append(p)
            try:
                rc = p.p.wait(30 * TIME_SCALE)
            except subprocess.TimeoutExpired:
                rc = None
            check(rc == 2, f"the {name} notifier did not exit on being refused (exit {rc})")
            check(refused(line), f"no critical refusal of the {name} notifier in the log")
            print(f"    {name}: refused, and exited")

        p = Proc("old", [f"{FAKES}/fake_notifier", "--protocol", "0", HIVEMIND_SOCK, "200", "old"])
        procs.append(p)
        deadline = time.time() + 30 * TIME_SCALE
        while not refused(
            "'old' notifier registered through the obsolete register_service interface "
            "(protocol 0); this hivemind requires register_notifier protocol 1"
        ):
            check(time.time() < deadline, "no critical refusal of the protocol 0 notifier")
            time.sleep(0.25)
        print("    old: refused")

        log = s.hivemind.log()
        for name in ("small", "future", "old"):
            check(
                f"'{name}' notification service registered" not in log,
                f"the {name} notifier was registered",
            )
    finally:
        for p in procs:
            p.stop()
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_redundancy(build_dir):
    """With redundancy 3 on a swarm of 6, every account ends on exactly 3 nodes, the nodes each
    holding within a request's worth of the others; when a node leaves the network, its
    accounts are back on 3 nodes well within a renewal, from the other nodes' scans."""
    accounts = 3000
    fresh_db()
    seed(0, accounts)
    s = Setup(build_dir, nodes=6, swarms=1, config="redundancy = 3")
    try:
        cov = s.wait_for(
            lambda: s.coverage(0, accounts), 60, lambda c: c["by_count"] == {"3": accounts}
        )
        loads = cov["per_node"]
        check(max(loads) - min(loads) <= 500, f"uneven node loads: {loads}")
        st = s.stats()
        check(
            st["coverage"]["covered"] == st["coverage"]["accounts"], f"coverage: {st['coverage']}"
        )
        print(f"    every account on 3 of 6 nodes; the nodes hold {loads}")

        start = time.time()
        s.network.cmd("leave 5")
        cov = s.wait_for(
            lambda: s.coverage(0, accounts), 60, lambda c: c["by_count"] == {"3": accounts}
        )
        loads = [n for n in cov["per_node"] if n is not None]
        check(max(loads) - min(loads) <= 500, f"uneven node loads after a node left: {loads}")
        print(
            f"    node 5 left: every account back on 3 nodes {time.time() - start:.1f}s later, "
            f"the 5 left holding {loads}"
        )
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_rebalance(build_dir):
    """With redundancy 3 and renewals every 10s, a node that joins a swarm whose accounts are all
    on 3 nodes already takes its share as they are renewed, the lightest nodes getting each
    renewal's placements."""
    accounts = 3000
    interval = 10
    fresh_db()
    seed(0, accounts)
    # Replies held back for long enough that a sample of the coverage catches what a renewal
    # leaves while it is answered.
    s = Setup(
        build_dir,
        nodes=6,
        swarms=1,
        network_args=["--reply-delay", "500"],
        config=f"redundancy = 3\nrenewal_interval = {interval}",
    )
    try:

        def covered(nodes):
            return (
                lambda st: st["node_load"]["nodes"] == nodes
                and st["coverage"]["covered"] == st["coverage"]["accounts"]
            )

        s.network.cmd("leave 5")
        st = s.wait_for(s.stats, 60, covered(5))
        print(f"    node 5 away: every account on 3 of 5 nodes, loads {st['node_load']}")
        start = time.time()
        moved = st["placements"]["moved"]
        s.network.cmd("join 5")
        st = s.wait_for(s.stats, 60, covered(6))
        check(st["node_load"]["min"] < 500, f"node 5 joined with accounts already: {st}")

        def balanced(st):
            # A renewal moving an account keeps the node it leaves until the new one answers.
            check(
                st["coverage"]["covered"] == st["coverage"]["accounts"],
                f"coverage dipped while renewals moved accounts: {st['coverage']}",
            )
            return covered(6)(st) and st["node_load"]["max"] - st["node_load"]["min"] <= 500

        st = s.wait_for(s.stats, 4 * interval, balanced, interval=0.2)
        print(
            f"    node 5 back: loads {st['node_load']} {time.time() - start:.0f}s later, "
            f"{st['placements']['moved'] - moved} monitors moved by renewals"
        )
        check(st["placements"]["moved"] > moved, "no renewal moved a monitor to node 5")

        # A renewal keeps the monitors it renews acknowledged while it is answered, so every
        # account stays covered through each round of them.
        samples, start = 0, time.time()
        placed = st["placements"]["placed"]
        while time.time() < start + 3 * interval:
            s.check_covered("during renewals")
            samples += 1
            time.sleep(0.2)
        st = s.stats()
        print(
            f"    {st['placements']['placed'] - placed} placements renewed over "
            f"{3 * interval}s, every account covered in each of {samples} samples"
        )
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_retry(build_dir):
    """A node that times out a monitor request, one that fails one, and one that refuses every
    subscription in one as not knowing the swarms all end up with every subscription, within a
    request timeout of startup rather than at the next renewal 45-55 minutes on."""
    accounts = 6000
    fresh_db()
    seed(0, accounts)
    start = time.time()
    # The stalled request would take the hivemind's 10 minutes to fail.
    timeout = 15
    s = Setup(
        build_dir,
        nodes=3,
        network_args=["--fail", "0:stall:1", "--fail", "1:error:1", "--fail", "2:entries:1"],
        config=f"monitor_timeout = {timeout}",
        log_level="info,snode=debug",
    )
    try:
        s.wait_subscribed(0, accounts, 120)
        took = time.time() - start
        log = s.hivemind.log()
        print(f"    every node fully subscribed {took:.0f}s after startup")
        check(
            log.count("after their failure on") >= 3, "the hivemind did not retry every failure"
        )
        check("failed: timeout" in log, "the stalled request did not time out")
        if not SANITIZED:
            check(took < timeout + 30, f"took {took:.0f}s to subscribe everything")
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_stalled_notifier(build_dir):
    """A notifier that stops reading for good costs bounded memory and little CPU: its window
    stays full, and pushes beyond 50,000 waiting are dropped with a warning."""
    fresh_db()
    seed(0, 50_000)
    s = Setup(build_dir, nodes=1)
    try:
        s.notifier.p.send_signal(signal.SIGSTOP)
        s.network.cmd("burst 0 150000 50000 0 2000", timeout=300)
        deadline = time.time() + 300 * TIME_SCALE
        while "Dropped" not in s.hivemind.log():
            check(
                time.time() < deadline,
                "nothing was dropped with 300 MB of notifications waiting",
            )
            time.sleep(1)
        rss = s.hivemind.rss_mb()
        cpu = s.hivemind.cpu_seconds()
        time.sleep(10)
        cpu = (s.hivemind.cpu_seconds() - cpu) / 10
        s.notifier.p.send_signal(signal.SIGCONT)
        c = s.wait_pushes(150_000, 120, settle=5)
        print(
            f"    while stalled: RSS {rss:.0f} MB, {cpu:.0%} of a core; {c['pushes']} of 150000 "
            f"delivered after resuming"
        )
        check(rss < 1024, f"hivemind RSS reached {rss:.0f} MB")
        if not SANITIZED:
            check(
                cpu < 0.25,
                f"hivemind used {cpu:.0%} of a core while the notifier was stopped",
            )
        check(
            0 < c["pushes"] < 150_000 and c["duplicates"] == 0,
            f"unexpected pushes: {c}",
        )
        before = c["pushes"]
        s.network.cmd("send #7 after-the-stall-aaaaaaaaaaaaaaaaaaaaaaaaaaa 0 100")
        c = s.wait_pushes(before + 1, 30)
        check(
            c["pushes"] == before + 1, "no push for a notification sent after the stall"
        )
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_sustained(build_dir, minutes=None):
    """A steady 2,000 messages a second for E2E_SUSTAINED_MINUTES (default 10) minutes, with the
    duplicate filter rotating every 30 seconds: everything arrives and memory stays flat."""
    minutes = minutes or float(os.environ.get("E2E_SUSTAINED_MINUTES", 10))
    seconds = int(minutes * 60)
    rate = 2000
    fresh_db()
    seed(0, 50_000)
    s = Setup(build_dir, nodes=5, filter_lifetime=30)
    try:
        samples = []
        stop = threading.Event()

        def sample():
            while not stop.wait(10):
                samples.append(s.hivemind.rss_mb())

        sampler = threading.Thread(target=sample)
        sampler.start()
        s.network.cmd("backlog")
        s.network.cmd(f"rate {rate} {seconds} 50000 0 500 0", timeout=seconds + 120)
        backlog = int(s.network.cmd("backlog"))
        c = s.wait_pushes(rate * seconds, 300, sent=rate * seconds)
        stop.set()
        sampler.join()
        third = max(1, len(samples) // 3)
        early, late = max(samples[third : 2 * third] or samples), max(samples[-third:])
        print(
            f"    {c['pushes']}/{rate * seconds} pushes; RSS {early:.0f} MB in the middle third, "
            f"{late:.0f} MB in the last; largest node backlog {backlog} B"
        )
        check(
            c["pushes"] == rate * seconds and c["duplicates"] == 0,
            f"expected {rate * seconds} unique pushes, got {c}",
        )
        check(
            late <= early * 1.25 + 20, f"RSS grew from {early:.0f} MB to {late:.0f} MB"
        )
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_scale(build_dir):
    """Production-like size: 1,000,000 accounts (one in ten with three devices), 50 nodes in 10
    swarms, and message bodies up to the storage server's 76,800-byte limit."""
    accounts, nodes, swarms, messages = 1_000_000, 50, 10, 20_000
    fresh_db()
    print("    seeding 1,000,000 accounts", flush=True)
    seed(0, accounts, devices="CASE WHEN i % 10 = 0 THEN 3 ELSE 1 END")
    rows = query1("SELECT count(*) FROM subscriptions")
    start = time.time()
    # Late replies, as from distant nodes, so that requests are seen in flight together.
    s = Setup(build_dir, nodes=nodes, swarms=swarms, network_args=["--reply-delay", "20"])
    try:
        # A real account's notifications come from its own swarm of about 5 nodes.
        s.network.cmd("senders 5")
        log = s.hivemind.log()
        m = re.search(r"\[\+([\d.]+)s\].*Done loading saved subscriptions", log)
        load = float(m.group(1)) if m else -1
        rss = s.hivemind.rss_mb()
        expected = sum(3 if (n % accounts) % 10 == 0 else 1 for n in range(messages))
        s.network.cmd(f"burst 0 {messages} {accounts} 0 mix", timeout=300)
        burst_start = time.time()
        c = s.wait_pushes(expected, 600)
        took = c["last_ms"] / 1000 - burst_start if c["pushes"] else 0
        print(
            f"    {rows} subscriptions loaded in {load:.1f}s, hivemind RSS {rss:.0f} MB after "
            f"startup ({time.time() - start:.0f}s to all {nodes} nodes connected); "
            f"{c['pushes']}/{expected} pushes in {took:.1f}s"
        )
        check(
            c["pushes"] == expected and c["duplicates"] == 0,
            f"expected {expected} unique pushes, got {c}",
        )
        s.wait_subscribed(0, accounts, 900, interval=5)
        most = s.max_in_flight()
        print(
            f"    every account subscribed on its swarm {time.time() - start:.0f}s after start; "
            f"at most {most} monitor requests in flight at once"
        )
        # The default [hivemind] monitor_requests, which 50 nodes cannot reach.
        check(most <= 64, f"{most} monitor requests in flight at once")
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


FAST = [
    "schema",
    "correctness",
    "burst",
    "resend",
    "notifier_restart",
    "two_notifiers",
    "backlog",
    "churn",
    "shutdown",
    "reshuffle",
    "restart",
    "body_limit",
    "retry",
    "registration",
    "redundancy",
    "rebalance",
    "status_report",
]
SLOW = ["stalled_notifier", "sustained", "scale"]


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    ap.add_argument("--slow", action="store_true", help="also run " + ", ".join(SLOW))
    ap.add_argument(
        "--build-dir",
        default=os.path.join(SRC, "build"),
        help="the project's build directory, holding SPNS, the Python module and, under "
        "tests/e2e, the fakes; the e2e build targets build them and pass this (default: "
        "%(default)s)",
    )
    ap.add_argument(
        "--sanitizer",
        choices=["thread", "address"],
        help="the build was made with this sanitizer: stretch timeouts, skip timing limits, and "
        "fail a scenario on any report",
    )
    ap.add_argument(
        "--work-dir",
        help="scratch directory for sockets, config and logs, emptied before each scenario "
        "(default: a new temporary directory)",
    )
    ap.add_argument(
        "--db",
        default="spns_e2e",
        help="existing Postgres database, emptied before each scenario, on the server the PG* "
        "environment points at (default: %(default)s)",
    )
    ap.add_argument(
        "--oxend-port", type=int, default=22029, help="fake oxend's port (default: %(default)s)"
    )
    ap.add_argument(
        "--quic-port",
        type=int,
        default=23000,
        help="first of the fake storage nodes' consecutive QUIC ports (default: %(default)s)",
    )
    ap.add_argument(
        "--mode",
        choices=["legacy", "monitor", "both"],
        default="both",
        help="run each scenario against fake storage nodes without monitor sessions (legacy), "
        "with them (monitor), or once each (default: %(default)s)",
    )
    ap.add_argument(
        "scenarios",
        nargs="*",
        metavar="SCENARIO",
        help="any of: " + ", ".join(FAST + SLOW),
    )
    args = ap.parse_args()
    unknown = set(args.scenarios) - set(FAST + SLOW)
    if unknown:
        ap.error(f"unknown scenario(s): {', '.join(sorted(unknown))}")
    names = args.scenarios or (FAST + SLOW if args.slow else FAST)

    global TIME_SCALE, SANITIZED, SANITIZER, BUILD, FAKES, WORK, DB, OXEND_PORT, FIRST_QUIC_PORT
    global MODE
    SANITIZER = args.sanitizer
    TIME_SCALE = {None: 1, "address": 3, "thread": 10}[SANITIZER]
    SANITIZED = SANITIZER is not None
    BUILD = os.path.abspath(args.build_dir)
    FAKES = os.path.join(BUILD, "tests", "e2e")
    tools = ["fake_network", "fake_notifier", "fake_client", "migrate_schema"]
    for exe in [f"{BUILD}/SPNS"] + [f"{FAKES}/{t}" for t in tools]:
        if not os.path.exists(exe):
            sys.exit(f"{exe} does not exist: run an e2e build target (make e2e), or fix --build-dir")
    WORK = os.path.abspath(args.work_dir) if args.work_dir else tempfile.mkdtemp(prefix="spns-e2e-")
    DB = args.db
    OXEND_PORT = args.oxend_port
    FIRST_QUIC_PORT = args.quic_port
    build_dir = BUILD
    wait_db()
    modes = ["legacy", "monitor"] if args.mode == "both" else [args.mode]
    results = []
    for name, MODE in ((n, m) for n in names for m in modes):
        # A scenario that failed badly can leave a child holding the ports the next one needs.
        kill_leftovers()
        shutil.rmtree(WORK, ignore_errors=True)
        os.makedirs(WORK)
        label = f"{name}[{MODE}]"
        print(f"== {label}", flush=True)
        start = time.time()
        try:
            globals()[f"scenario_{name}"](build_dir)
            results.append((label, "PASS", ""))
        except Failure as e:
            results.append((label, "FAIL", str(e)))
        except Exception:
            results.append((label, "ERROR", traceback.format_exc()))
        print(
            f"   {results[-1][1]} in {time.time() - start:.0f}s {results[-1][2]}",
            flush=True,
        )
        if results[-1][1] != "PASS":
            for log in (
                "hivemind.log",
                "hivemind2.log",
                "network.err",
                "notifier.err",
                "notifier2.err",
                "client.err",
            ):
                path = os.path.join(WORK, log)
                if os.path.exists(path):
                    with open(path, errors="replace") as f:
                        tail = f.readlines()[-25:]
                    print(f"   --- last lines of {log}")
                    print("".join("   " + l for l in tail), end="", flush=True)

    print()
    for name, status, _ in results:
        print(f"{status:5} {name}")
    sys.exit(0 if all(r[1] == "PASS" for r in results) else 1)


if __name__ == "__main__":
    main()
