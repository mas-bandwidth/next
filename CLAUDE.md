# CLAUDE.md

Network Next: a network accelerator for multiplayer games. Go backend services (`cmd/`, `modules/`),
C++ SDK (`sdk/`), reference relay (`relay/reference/`), and XDP relay (`relay/xdp/`, Linux only).

## Workflow (Glenn's preferences)

- **Commit with `./commit "message"`** — commits directly to main and pushes. No branches, no PRs.
  Caveat: it uses `git commit -am`, which misses untracked files — `git add` new files first.
- **Run tests on CI with `./dist/deploy test`** — bumps the latest `test-NNN` tag and pushes it.
  The tag triggers the Build pipeline, which auto-promotes to SDK Tests, Functional Tests, and
  Happy Path. This is the preferred way to run tests: the ~155 functional test jobs run in parallel,
  much faster than locally. Wall-clock speed matters more than CI cost; never batch test jobs.
- CI triggers live in the Semaphore project config, NOT the repo: `sem get project next` shows
  `run_on: [tags, draft_pull_requests]`. Branch pushes deliberately do NOT build. Keep it that way.
- Monitor CI with the `sem` CLI (org `mas-bandwidth.semaphoreci.com`): `sem get wf -p next`,
  `sem get ppl <id>` (lowercase `state:`/`result:` fields), `sem logs <job-id>`. Per-job results
  are only in `sem get job <id>`.
- A Semaphore scheduled task `weekly-functional-tests` runs the functional tests against main
  every Monday 09:00 UTC via `.semaphore/scheduled-functional-tests.yml` (it builds relay-debug
  and libnext.so, the only two artifacts functional-tests.yml doesn't build itself).

## Build and test locally

- `make` builds everything and runs `./run test` (Go unit tests).
- On macOS, C++ targets need Homebrew paths: `export CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib`.
- The Makefile's Go-binary dependency tracking is unreliable; force with `go build -o dist/<name> ./cmd/<name>/`.
  (`go build ./cmd/<name>/` alone drops a stray binary in the cwd — avoid.)
- Run a single functional test: `cd dist && ./func_test_relay <test_name>` (needs `func_backend`,
  `relay-debug` in cwd; sdk tests also need `func_client`, `func_server`, `libnext.so`).
- `make dist/relay-debug-asan` builds the reference relay with AddressSanitizer for local runs
  (`cp` it over `dist/relay-debug`, `export ASAN_OPTIONS=detect_leaks=0`). There is deliberately
  no ASan CI job — it ran all tests sequentially and was too slow.

## Functional test conventions (hardened 2026-07-10, keep these invariants)

All func_test suites use shared helpers in `modules/common/func_test_helpers.go`:

- `common.RunTests(allTests)` — runs tests, prints `random seed = N` per test, seeds
  `common.SeedRandom`, and arms a per-test watchdog (default 120s; sdk suite passes 300s).
  Reproduce any failed test exactly: `TEST_SEED=<seed> ./func_test_<suite> <test_name>`.
  (Go 1.20+ made `rand.Seed` a no-op; `common.Random*` draw from a seedable locked source.)
- `common.Buffer` — thread-safe process output buffer (polling a plain `bytes.Buffer` mid-run
  is a data race).
- `common.WaitForOutput(buffer, marker, timeout)` — poll process output instead of `time.Sleep`.
- `common.SendPacketUntilOutput(...)` — resend a UDP packet until the relay logs processing it
  (occurrence-count aware, so repeated markers wait for a new occurrence).

Rules learned the hard way:

- Flood-loop tests (`for range 10 { for range 1000 { ... } }`) must keep fire-and-forget sends
  with ONE `WaitForOutput` after the loop. Per-packet polling is ~1000x slower.
- Per-ping relay debug lines are compiled out behind `RELAY_SPAM` — never poll for them.
- Marker strings differ per handler: "header did not verify" (route/continue response) vs
  "could not verify header" (client↔server, session ping/pong).
- Relay counters print only at shutdown, summed from `relay[j].counters` AFTER thread join
  (the periodic stats snapshots miss the final second — that was the original flake).
- relay-debug line-buffers stdout (`RELAY_LOGS` builds) so tests can poll it through a pipe.
- Route tokens that create sessions need a few seconds of validity (`time.Now().Unix() + 5`);
  a `+0` expiry races the second boundary under CI load and resends can never recover.
- Clean-shutdown timing is env-configurable in `RELAY_TEST` builds: `RELAY_SHUTDOWN_TIME` /
  `RELAY_SHUTDOWN_EXTRA_TIME` (see `test_clean_shutdown`, uses 5/1 instead of 60/30).
- Wait for every positively-asserted output marker before SIGINTing a process — asserted lines
  can print after the "terminal" one (see the sdk server_ready tests).
- Scenario-timing sleeps (session durations, mid-session kills, ping-stats warmup) are
  intentional — do not convert those to polls.

## State as of 2026-07-10

All of the above is merged to main (through `f4a3afd52`) and validated: test-226/test-227 runs
had all ~155 functional jobs green, including the historically flaky ones. Nothing in flight.
