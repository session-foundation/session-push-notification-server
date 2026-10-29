#!/usr/bin/env python3
"""End-to-end scenarios for the hivemind, run inside the container tests/e2e/run.sh starts.

The hivemind runs for real, against Postgres, a fake oxend and a fake swarm of storage nodes
(fake_network), a fake notifier (fake_notifier) and a fake subscribing client (fake_client).

usage: e2e.py [--slow] [--sanitize thread|address] [SCENARIO...]

With no SCENARIO, runs every fast scenario, plus the slow ones with --slow.
"""

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback

SRC = "/src"
BUILD = "/build"
WORK = "/tmp/e2e"
OXEND_PORT = 22029
FIRST_QUIC_PORT = 23000
HIVEMIND_SOCK = f"ipc://{WORK}/hivemind.sock"
# Sanitized builds run several times slower: their timeouts stretch by this much, and they skip the
# timing limits (they look for memory and threading errors; every push must still arrive).
TIME_SCALE = 1
SANITIZED = False
SANITIZER_REPORT = re.compile(
    r"WARNING: ThreadSanitizer|ERROR: AddressSanitizer|ERROR: LeakSanitizer"
)


class Failure(Exception):
    pass


def check(cond, msg):
    if not cond:
        raise Failure(msg)


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def run_quiet(cmd):
    """Runs a build step, showing its output only if it fails."""
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if r.returncode != 0:
        print(r.stdout[-20000:])
        raise subprocess.CalledProcessError(r.returncode, cmd)


def psql(sql, db="spns"):
    return run(
        ["psql", "-qtA", "-v", "ON_ERROR_STOP=1", db, "-c", sql],
        capture_output=True,
        text=True,
    ).stdout.strip()


# --- building ---------------------------------------------------------------------------------


def build(sanitize):
    variant = f"spns-{sanitize}" if sanitize else "spns"
    flags = {
        None: "-O2 -g",
        "thread": "-O1 -g -fsanitize=thread",
        "address": "-O1 -g -fsanitize=address -fno-omit-frame-pointer",
    }[sanitize]
    jobs = str(max(1, os.cpu_count() // 2))
    print(f"building {variant} and the fakes", flush=True)
    run_quiet(
        [
            "cmake",
            "-S",
            SRC,
            "-B",
            f"{BUILD}/{variant}",
            "-DCMAKE_BUILD_TYPE=None",
            f"-DCMAKE_CXX_FLAGS={flags}",
            f"-DCMAKE_EXE_LINKER_FLAGS={flags}",
            f"-DCMAKE_SHARED_LINKER_FLAGS={flags}",
            "-DCMAKE_CXX_COMPILER_LAUNCHER=ccache",
        ]
    )
    run_quiet(
        ["make", "-C", f"{BUILD}/{variant}", f"-j{jobs}", "spns", "spns_hivemind"]
    )
    run_quiet(
        [
            "cmake",
            "-S",
            f"{SRC}/tests/e2e",
            "-B",
            f"{BUILD}/fakes",
            "-DCMAKE_CXX_COMPILER_LAUNCHER=ccache",
        ]
    )
    run_quiet(["make", "-C", f"{BUILD}/fakes", f"-j{jobs}"])
    return f"{BUILD}/{variant}"


# --- database ---------------------------------------------------------------------------------


def start_postgres():
    version = sorted(os.listdir("/usr/lib/postgresql"), key=int)[-1]
    run(["pg_ctlcluster", version, "main", "start"])
    subprocess.run(
        ["su", "postgres", "-c", "psql -q -c 'CREATE ROLE root SUPERUSER LOGIN'"],
        capture_output=True,
    )


def fresh_db():
    run(
        ["su", "postgres", "-c", "dropdb --if-exists spns && createdb -O root spns"],
        capture_output=True,
    )
    run(
        [
            "psql",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "spns",
            "-f",
            f"{SRC}/spns/schema.pgsql",
        ],
        capture_output=True,
    )


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
    expression in `i` giving account #i's number of devices, whose service ids are
    "dev-<i>-<d>"."""
    sig_ts = sig_ts or int(time.time())
    psql(
        f"""
WITH s AS (
    INSERT INTO subscriptions (account, signature, signature_ts, want_data, enc_key, service, svcid, svcdata)
    SELECT {ACCOUNT.format('i')}, decode(repeat('cd', 64), 'hex'), {sig_ts}, true,
           decode(repeat('ab', 32), 'hex'), '{service}', 'dev-' || i || '-' || d, {svcdata}
    FROM generate_series({first}, {first + count - 1}) i, LATERAL generate_series(1, {devices}) d
    RETURNING id)
INSERT INTO sub_namespaces SELECT s.id, n FROM s, unnest(ARRAY[{namespaces}]::smallint[]) n"""
    )


# --- processes --------------------------------------------------------------------------------


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
    def __init__(self, build_dir, filter_lifetime=300, log_level="info"):
        self.log_path = f"{WORK}/hivemind.log"
        key = f"{WORK}/hivemind.key"
        with open(key, "wb") as f:
            f.write(os.urandom(32))
        with open(f"{WORK}/spns.ini", "w") as f:
            f.write(
                f"""[db]
url = postgresql:///spns
[log]
level = {log_level}
[hivemind]
listen = {HIVEMIND_SOCK}
oxend_rpc = tcp://127.0.0.1:{OXEND_PORT}
max_connects = 1000
filter_lifetime = {filter_lifetime}
startup_wait = 30
notifiers_expected = dummy
[keys]
hivemind = {key}
"""
            )
        env = dict(
            os.environ,
            PYTHONPATH=f"{SRC}:{build_dir}",
            # libquic, oxenmq and zmq are not instrumented: their own synchronisation is
            # invisible to TSan, so only races between instrumented accesses count.
            TSAN_OPTIONS="halt_on_error=0 second_deadlock_stack=1 "
            f"ignore_noninstrumented_modules=1 suppressions={SRC}/tests/e2e/tsan.supp",
            # Python's own allocations would drown the leak report; and the hivemind library
            # and its Python module both define libstdc++'s inline globals, which ASan's ODR
            # check counts as duplicates.
            ASAN_OPTIONS="detect_leaks=0 detect_odr_violation=0",
        )
        self.start_time = time.time()
        self.logf = open(self.log_path, "w")
        cmd = [f"{build_dir}/SPNS", f"{WORK}/spns.ini"]
        if build_dir.endswith("-thread"):
            # TSan cannot map its shadow memory under the kernel's full address randomisation.
            cmd = ["setarch", os.uname().machine, "-R"] + cmd
        self.p = subprocess.Popen(
            cmd, stdout=self.logf, stderr=subprocess.STDOUT, env=env, cwd=WORK
        )

    def wait_socket(self, timeout=600):
        path = HIVEMIND_SOCK[len("ipc://") :]
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

    def __init__(self, build_dir, nodes, swarms=1, **hivemind_args):
        os.makedirs(WORK, exist_ok=True)
        self.hivemind = self.notifier = self.client = None
        self.network = Proc(
            "network",
            [
                f"{BUILD}/fakes/fake_network",
                str(nodes),
                str(swarms),
                str(OXEND_PORT),
                str(FIRST_QUIC_PORT),
            ],
        )
        try:
            self.hivemind = Hivemind(build_dir, **hivemind_args)
            self.hivemind.wait_socket()
            self.notifier = Proc(
                "notifier", [f"{BUILD}/fakes/fake_notifier", HIVEMIND_SOCK]
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

    def client_proc(self):
        if not self.client:
            self.client = Proc("client", [f"{BUILD}/fakes/fake_client", HIVEMIND_SOCK])
        return self.client

    def counts(self, notifier=None):
        import json

        return json.loads((notifier or self.notifier).cmd("count"))

    def wait_pushes(self, expected, timeout, settle=1.5, notifier=None):
        """Waits for `expected` pushes, then `settle` more seconds to catch extras."""
        deadline = time.time() + timeout * TIME_SCALE
        while True:
            c = self.counts(notifier)
            if c["pushes"] >= expected:
                time.sleep(settle)
                return self.counts(notifier)
            if time.time() > deadline:
                return c
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
    ):
        check(bad not in log, f"hivemind log has '{bad}'")


# --- scenarios --------------------------------------------------------------------------------


def scenario_correctness(build_dir):
    """Who gets pushed what: duplicates, namespaces, devices, expiry, and the in-memory copy
    following subscribe, drop and unsubscribe at runtime."""
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
                "dev-1-1 hash-one-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 1 sd1",
                "dev-2-1 hash-three-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 0 -",
                "dev-2-2 hash-three-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 0 -",
            ]
        )
        check(got == want, f"phase 1 pushes: {got}")
        check(
            psql("SELECT count(*) FROM subscriptions WHERE svcid = 'dev-3-1'") == "0",
            "the expired subscription is still in the database",
        )

        client = s.client_proc()
        acct5 = client.cmd("account 5")
        check(client.cmd("sub 5") == "ok", "subscribe failed")
        check(client.cmd("drop dev-2-1") == "ok", "drop failed")
        time.sleep(1)
        net.cmd(f"send {acct5} hash-six-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 200")
        net.cmd("send #2 hash-eight-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 0")
        c = s.wait_pushes(5, 30)
        check(c["pushes"] == 5, f"phase 2: expected 5 pushes in all, got {c['pushes']}")
        got = sorted(s.dump())
        check(
            "client-5-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa hash-six-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 1 -"
            in got,
            f"no push for the runtime subscription: {got}",
        )
        check(
            "dev-2-2 hash-eight-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 0 -" in got
            and not any(l.startswith("dev-2-1 hash-eight") for l in got),
            f"dropped device still pushed, or the other one not: {got}",
        )

        check(client.cmd("unsub 5") == "ok", "unsubscribe failed")
        net.cmd(f"send {acct5} hash-seven-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 200")
        c = s.wait_pushes(6, 4)
        check(
            c["pushes"] == 5,
            f"phase 3: unsubscribed account still pushed ({c['pushes']})",
        )
        left = sorted(psql("SELECT svcid FROM subscriptions").split())
        check(left == ["dev-1-1", "dev-2-2"], f"subscriptions left: {left}")
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
        c = s.wait_pushes(messages, timeout)
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
    """A notifier that stops reading (SIGSTOP) loses nothing once it resumes: the pushes oxenmq
    had no room for are resent."""
    fresh_db()
    seed(0, 20_000)
    s = Setup(build_dir, nodes=3, log_level="info,hivemind=debug")
    try:
        s.notifier.p.send_signal(signal.SIGSTOP)
        s.network.cmd("burst 0 30000 20000 0 200")
        time.sleep(5)
        s.notifier.p.send_signal(signal.SIGCONT)
        c = s.wait_pushes(30_000, 120)
        check(
            c["pushes"] == 30_000 and c["duplicates"] == 0,
            f"expected 30000 unique pushes, got {c}",
        )
        check(
            "Resending" in s.hivemind.log(),
            "the notifier never filled up: nothing was resent",
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
            "Resending" in s.hivemind.log(),
            "no resends were pending before the restart",
        )
        s.notifier.stop(sig=signal.SIGKILL)
        # Long enough for resends to find the connection gone before the new one registers.
        time.sleep(3)
        s.notifier = Proc("notifier2", [f"{BUILD}/fakes/fake_notifier", HIVEMIND_SOCK])
        check(s.notifier.readline(120) == "registered", "new notifier did not register")
        # Only what zmq had already queued to the dead notifier is lost: up to its 1000-message
        # high-water mark.
        c = s.wait_pushes(29_000, 60, settle=3)
        print(f"    {c['pushes']} of 30000 pushes reached the new notifier")
        check(
            c["pushes"] >= 29_000 and c["duplicates"] == 0,
            f"waiting pushes did not reach the new notifier: {c}",
        )
        check(
            "connection lost" in s.hivemind.log(),
            "the hivemind never noticed the notifier had gone",
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
            [f"{BUILD}/fakes/fake_notifier", HIVEMIND_SOCK, "-1", "other"],
        )
        check(other.readline(120) == "registered", "second notifier did not register")
        s.notifier.p.send_signal(signal.SIGSTOP)
        s.network.cmd("burst 0 40000 40000 0 200")
        c = s.wait_pushes(20_000, 30, notifier=other)
        check(
            c["pushes"] == 20_000 and c["duplicates"] == 0,
            f"the running notifier's pushes waited for the stopped one: {c}",
        )
        check(
            "Resending" in s.hivemind.log(),
            "the stopped notifier never filled up: nothing was resent",
        )
        s.notifier.p.send_signal(signal.SIGCONT)
        c = s.wait_pushes(20_000, 120)
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
        rate, seconds, stall = 2000, 14, 8

        def stall_db():
            time.sleep(2)
            psql(
                f"BEGIN; LOCK TABLE service_stats IN ACCESS EXCLUSIVE MODE; "
                f"SELECT pg_sleep({stall}); COMMIT;"
            )

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
        c = s.wait_pushes(2 * rate * seconds, 120)
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
    afterwards pushes match what the database holds."""
    fresh_db()
    seed(0, 20_000)
    s = Setup(build_dir, nodes=3)
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
        n = psql("SELECT count(*) FROM subscriptions WHERE svcid LIKE 'client-%'")
        check(n == "100", f"database holds {n} client subscriptions, expected 100")
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_shutdown(build_dir):
    """SIGTERM in the middle of a burst, with resends pending, exits cleanly."""
    fresh_db()
    seed(0, 20_000)
    s = Setup(build_dir, nodes=3, log_level="info,hivemind=debug")
    try:
        s.notifier.p.send_signal(signal.SIGSTOP)
        s.network.cmd("burst 0 30000 20000 0 200")
        time.sleep(3)
        check("Resending" in s.hivemind.log(), "no resends were pending at shutdown")
        start = time.time()
        rc = s.hivemind.stop(timeout=30 * TIME_SCALE)
        print(f"    exited in {time.time() - start:.1f}s with resends pending")
    finally:
        s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


def scenario_stalled_notifier(build_dir):
    """A notifier that stops reading for good costs bounded memory and little CPU: pushes beyond
    100,000 waiting are dropped with a warning, and resending backs off."""
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
        c = s.wait_pushes(rate * seconds, 300)
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
    rows = int(psql("SELECT count(*) FROM subscriptions"))
    start = time.time()
    s = Setup(build_dir, nodes=nodes, swarms=swarms)
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
    finally:
        rc = s.stop()
    check(rc == 0, f"hivemind exit code {rc}")
    check_log(s.hivemind)


FAST = [
    "correctness",
    "burst",
    "resend",
    "notifier_restart",
    "two_notifiers",
    "backlog",
    "churn",
    "shutdown",
]
SLOW = ["stalled_notifier", "sustained", "scale"]


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    ap.add_argument("--slow", action="store_true", help="also run " + ", ".join(SLOW))
    ap.add_argument("--sanitize", choices=["thread", "address"])
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

    global TIME_SCALE, SANITIZED
    TIME_SCALE = {None: 1, "address": 3, "thread": 10}[args.sanitize]
    SANITIZED = args.sanitize is not None
    build_dir = build(args.sanitize)
    start_postgres()
    results = []
    for name in names:
        # A scenario that failed badly can leave a child holding the ports the next one needs.
        for child in ("SPNS", "fake_network", "fake_notifier", "fake_client"):
            subprocess.run(["pkill", "-CONT", "-x", child], capture_output=True)
            subprocess.run(["pkill", "-KILL", "-x", child], capture_output=True)
        time.sleep(0.5)
        shutil.rmtree(WORK, ignore_errors=True)
        os.makedirs(WORK)
        print(f"== {name}", flush=True)
        start = time.time()
        try:
            globals()[f"scenario_{name}"](build_dir)
            results.append((name, "PASS", ""))
        except Failure as e:
            results.append((name, "FAIL", str(e)))
        except Exception:
            results.append((name, "ERROR", traceback.format_exc()))
        print(
            f"   {results[-1][1]} in {time.time() - start:.0f}s {results[-1][2]}",
            flush=True,
        )
        if results[-1][1] != "PASS":
            for log in ("hivemind.log", "network.err", "notifier.err", "client.err"):
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
