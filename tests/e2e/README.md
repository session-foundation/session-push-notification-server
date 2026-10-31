# End-to-end scenarios

Runs the real hivemind against Postgres, a fake oxend and a fake swarm of storage nodes, a fake
notifier and a fake subscribing client, all in one container. Manual only: nothing runs this in CI.

```
tests/e2e/run.sh                          # the fast scenarios, about 2 minutes
tests/e2e/run.sh --slow                   # also the slow ones, about 15 minutes
tests/e2e/run.sh burst churn              # just these
tests/e2e/run.sh --sanitize thread        # under ThreadSanitizer (or: address)
E2E_SUSTAINED_MINUTES=2 tests/e2e/run.sh sustained
```

Needs Docker. The build lives in the `spns-e2e-build` volume, so a rerun only recompiles what
changed; `docker volume rm spns-e2e-build` starts from scratch. The exit code is non-zero if any
scenario fails, and a failing scenario prints the end of each process's log.

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

- `fake_network`: the oxend that serves the service node list, and the storage nodes, which
  answer `monitor` and send `notify`. It also measures each stream's unsent bytes.
- `fake_notifier`: registers as the `dummy` notifier, accepts any `service_info.token` as the
  service id, answers `notifier.ack`, and records every push.
- `fake_client`: signs subscribe and unsubscribe requests for deterministic `05` accounts.

Each reads commands on stdin and answers on stdout; the comment at the top of each file lists them.
`e2e.py` seeds the database directly, with account `#i` being `03 || SHA256(big-endian i)`, the same
bytes `fake_network` sends notifications for.
