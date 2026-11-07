# End-to-end scenarios

Runs the real hivemind against Postgres, a fake oxend and a fake swarm of storage nodes, a fake
notifier and a fake subscribing client. CI (`.woodpecker/build.star`) runs the fast scenarios on
every event and the slow ones on pushes, tags, manual and cron runs.

Every scenario runs twice: against storage nodes without monitor sessions, as today's network is
(`legacy`: `monitor_session` is an unknown endpoint, `b` is ignored), and against nodes with them
(`monitor`). `E2E_ARGS="--mode legacy"` (or `monitor`) runs one.

```
make e2e-fast                             # the fast scenarios, about 5 minutes
make e2e                                  # all of them, about 15 minutes
make e2e-burst                            # one scenario: e2e-<name> for each in the tables below
make e2e-slow                             # the three slow ones
E2E_SUSTAINED_MINUTES=2 make e2e-sustained
```

These targets of the project's build build the hivemind and the three fakes (which nothing else
builds) and run `e2e.py` against them; further `e2e.py` options go through `E2E_ARGS`, e.g.
`make e2e-fast E2E_ARGS="--db other"`. For a sanitizer run, configure a build with
`-fsanitize=thread` (or `address`) in `CMAKE_CXX_FLAGS` and the linker flags and run its e2e
targets: the harness stretches its timeouts, skips the timing limits and fails a scenario on any
report. It needs `python3-psycopg`, plus the Python modules the hivemind loads (`python3-nacl`,
`python3-coloredlogs`), and a Postgres database it may empty, reached through the usual libpq
environment (`PGHOST`, `PGUSER`, ...): `spns_e2e` unless `--db` says otherwise, created once
beforehand (`createdb spns_e2e`), and emptied before every scenario. It is Linux only, reading the
hivemind's memory and CPU use from `/proc`. Sockets, config and logs go in a temporary directory
(`--work-dir`), and the fakes listen on ports 22029 and 23000 upwards (`--oxend-port`,
`--quic-port`). The exit code is non-zero if any scenario fails, and a failing scenario prints the
end of each process's log.

## In a container

```
tests/e2e/run.sh                          # e2e-fast
E2E_TARGET=e2e-scale tests/e2e/run.sh     # another target
E2E_SANITIZER=thread tests/e2e/run.sh
```

For a machine without the dependencies or a Postgres server: builds a Debian image with both,
configures a build in the `spns-e2e-build` volume (so that a rerun only recompiles what changed;
`docker volume rm spns-e2e-build` starts from scratch) and runs the chosen e2e target.

## Scenarios

Fast:

| scenario | checks |
|---|---|
| `correctness` | one push per device per message across duplicate copies; namespaces, data, svcdata, two devices, expiry, unknown accounts; subscribe, drop and unsubscribe at runtime |
| `burst` | 50,000 subscriptions, 5 nodes each sending the same 20,000 notifications at once: all 20,000 arrive, once each |
| `resend` | the notifier stops reading (SIGSTOP) mid-burst: its window fills, and once it resumes nothing is lost |
| `notifier_restart` | the notifier is killed with pushes waiting for it, and a new one starts 3 seconds later: the waiting pushes reach the new one, less what the dead one had taken without acknowledging |
| `two_notifiers` | while one service's notifier is stopped, the other service's pushes all arrive at once; the stopped one's arrive once it resumes |
| `backlog` | while the database is locked, then while the notifier is stopped, the nodes' streams to the hivemind stay under 1 MB: the hivemind keeps reading |
| `churn` | subscriptions changing during a steady flow: no push lost for stable accounts, and pushes match the database afterwards |
| `shutdown` | SIGTERM mid-burst with pushes held back exits cleanly |
| `reshuffle` | 8 nodes go from 2 swarms to 4: the accounts that moved are subscribed on their new swarm's nodes, and nothing is sent to a node not of an account's swarm, then or after every connection is dropped and made again; then to 8, with one node 5 seconds behind: what it refuses meanwhile is subscribed once it catches up |
| `restart` | the hivemind restarts while 100 notifications arrive: with monitor sessions it restores its saved placements, the nodes resume their sessions without listing their monitors and replay the gap, and nothing is subscribed again; with more notifications for an account than the replay budget, only its newest are replayed, in order, and the rest reported discarded; a reconnection while it runs resumes every session without its listing, and sends nothing; when every node's answer to a resumption is lost, the hivemind forgets the dead tokens, its next connections start new sessions and place everything again, and the gap is lost; after a split while it is down, the nodes that stayed resume so and the moved accounts are subscribed in their new swarm; from saved state too old to trust, every node starts afresh; without monitor sessions, the gap is lost and everything is subscribed again |
| `body_limit` | monitor sessions carry the body limit `b`, and a message over it is cut to it, by the node with monitor sessions, live and in the replay after a hivemind restart, and by the hivemind without: a subscription that opted in to truncated bodies gets the exact prefix and the full size, any other the full size alone, and a message within the limit reaches both whole |
| `retry` | one node stalls a monitor request until it times out, one fails one, one refuses every entry of one: all end up fully subscribed within a timeout of startup |
| `registration` | a notifier declaring a smaller body than the hivemind's limit, or another protocol version, is refused with a critical log line and exits; a protocol 0 one (bare service name) is refused in the log |
| `redundancy` | with redundancy 3 on a swarm of 6, every account ends on exactly 3 nodes, the nodes within a request's worth of each other; a node that leaves has its accounts back on 3 nodes from the others' scans |
| `rebalance` | with redundancy 3 and 10s renewals, a node that joins a swarm already covered takes its share as the accounts are renewed |
| `status_report` | with a status report every 15 seconds and no saved state, beside a notifier sent a push (with lifetime failures from earlier runs), one registered and reporting stats but sent none, and one with stats left from an earlier run but not registered: the hivemind logs two reports and keeps running, the first listing the quiet notifier as idle, leaving out the unregistered one, and showing no lifetime counter as the interval's |

Slow (`--slow`, or by name):

| scenario | checks |
|---|---|
| `stalled_notifier` | a notifier that stops reading for good costs bounded memory and little CPU: its window stays full, and beyond 50,000 waiting pushes they are dropped with a warning |
| `sustained` | 2,000 messages a second for 10 minutes with the duplicate filter rotating every 30 seconds: everything arrives and memory stays flat |
| `scale` | 1,000,000 accounts (one in ten with three devices), 50 nodes in 10 swarms, bodies up to 76,800 bytes: load time, memory, and every push delivered |

## Sanitizers

`--sanitize thread` and `--sanitize address` build the hivemind with that sanitizer and fail a
scenario on any report. libquic, oxenmq and zmq are not instrumented, so ThreadSanitizer cannot see
their synchronisation: `tsan.supp` suppresses the hand-offs through them, each with its reason. A
suppression matches its function in any frame of either stack, so a clean run does not cover races
in the hivemind's own code whose stack passes through a `std::future`, the destructor of a
`std::function<void()>`, or oxenmq's send path. Timing limits are skipped and timeouts stretched
under a sanitizer; every push must still arrive. The ThreadSanitizer container runs without
Docker's seccomp filter, which refuses the `setarch -R` it needs.

## The fakes

- `fake_network`: the oxend that serves the service node list and announces blocks, and the
  storage nodes, which answer `monitor` (refusing accounts their swarm does not store) and, with
  `--monitor-sessions`, `monitor_session`, and send `notify` and `monitor_ended`. It can move
  nodes between swarms, drop connections, fail requests, and report what each node holds and has
  been sent; it also measures each stream's unsent bytes.
- `fake_notifier`: registers as the `dummy` notifier, accepts any `service_info.token` as the
  service id, answers `notifier.ack`, and records every push, with its `L` if it has one.
- `fake_client`: signs subscribe and unsubscribe requests for deterministic `05` accounts.

Each reads commands on stdin and answers on stdout; the comment at the top of each file lists them.
`e2e.py` seeds the database directly, with account `#i` being `03 || SHA256(big-endian i)`, the same
bytes `fake_network` sends notifications for.
