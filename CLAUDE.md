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
- **Never run the functional test suites in bulk locally.** There are too many tests and they
  only run in parallel inside docker or a VM — locally they run sequentially and take forever.
  For work not yet on main, create a branch and trigger a CI test run against it, then wait for
  the result. Running a SINGLE func test locally to iterate on it is fine (see below).
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

## State as of 2026-07-11

All merged to main (through `97e1b2213`) and validated green on CI (test-229 through test-240):

- Fixed unbounded-allocation OOM DoS in session_cruncher/server_cruncher batch handlers
  (`97e1b2213`, test-240): `numUpdates` was read from the POST body and passed straight to
  `make()`, so a 12-byte request could drive a multi-GB allocation. Now bounded to the
  remaining body size; truncated batches rejected. (`encoding.Read*` byte helpers ARE
  bounds-checked — return false without advancing — so there was no OOB, just the OOM.)
- KNOWN CI FLAKE: the Build pipeline's "Sodium" job wgets libsodium 1.0.18 from
  download.libsodium.org, builds it, and pushes libsodium.so as a workflow artifact (consumed
  later by upload-artifacts.yml -> GCS). External-host DNS/network hiccups fail it (seen at
  test-239). Just re-run with `./dist/deploy test`. Decision (2026-07-11): leave it for now;
  if it keeps flaking, cache the sodium download/build in a Semaphore CI artifact rather than
  re-fetching from the external host. Do NOT remove the vendored sdk/sodium/ (flattened,
  Unreal-plugin-friendly) — it's what SDK Tests CI builds against (no system sodium installed
  there), the `next` tool bundles into the customer SDK example, and next.sln references. It is
  separate from this download job.

- Vendored the canonical serialize library (`a566e3cd9`, test-238): `sdk/serialize/serialize.h`
  is mas-bandwidth/serialize v1.4.3, verbatim, BSD-licensed, CANONICAL — never edit it; update
  with `sdk/serialize/update.sh` then validate on CI (see `sdk/serialize/README.md`).
  `next_bitpacker.h`/`next_stream.h`/`next_serialize.h` are now thin adapters (~1300 lines of
  forked serializer deleted); the only SDK-specific serialize helper is `serialize_address`.
  Wire compatibility verified: SDK's old uint64 encoding == canonical serialize_bits(v,64)
  (lo then hi), all standard macros byte-identical, full functional suite green.

- Routing-critical fixes (`768d3eb06`, test-237): database hot reload (`watchDatabase`) was
  validating and generating relay data from the OLD database instead of the newly loaded one
  (corrupt DBs passed validation; relay data lagged one reload behind; in-place relay sort
  raced concurrent readers) — both branches fixed, disk branch also gained the missing
  `GenerateRelaySecretKeys`. And the slice-0 "send down client relays, don't route yet"
  early-out in `MakeRouteDecision_TakeNetworkNext` only applied when buyer debug was enabled —
  buyer debug altered routing decisions; now hoisted so debug is purely observational.

- Server backend robustness (`6642c698f`, test-235): packet-handler goroutines now recover from
  panics instead of crashing the process (a validly-signed packet with an unhandled type used to
  hit `panic("unknown packet type")` — filters pass types 50-60 but only 5 are handled); unknown
  packet types now log-and-drop; fixed `serverRelayInsertBatchSize` never set (typo assigned
  `clientRelayInsertBatchSize` twice — inserter flushed every message); unknown-buyer in server
  init now returns before a nil `*Buyer` deref; fixed always-false `env == "local" && env ==
  "docker"` check. (The counter renumber shifts BigQuery counter history for indices 15-19,
  but no environments were live before this change, so there is no historical-data impact.)
- Bounded UDP packet handler concurrency (`8eaf5e17b`, test-236): `x/sync/semaphore` caps
  in-flight handlers (default 16384, `UDP_MAX_CONCURRENT_PACKETS`); read loop blocks at the cap
  so bursts are absorbed/dropped by the kernel socket buffer instead of unbounded goroutines.
  Benchmarked before committing: throughput-neutral vs unbounded; NOTE a goroutine-pool library
  (ants) was benchmarked ~12% SLOWER — pool handoff costs more than Go goroutine spawn here, so
  don't "optimize" this into a worker pool without re-measuring.

- Fixed relay gateway + relay backend bugs (`9cee7d3b6`, test-234): packet loss integer
  division in analytics (uint16 math reported 0% or 100% only), inverted error check leaking
  every forwarded connection in the gateway, `PostRelayUpdateRequest` blocking main so
  `WaitForShutdown` never ran, `/relay_counters` panic for relays that haven't reported,
  data race on relay counters. Also renumbered relay pong counters 15-18 -> 16-19 (slot 15
  collided with `RELAY_PING_PACKET_UNKNOWN_RELAY`) — BigQuery relay counter history for
  indices 15-19 changes meaning at this commit. `database.Validate()` now rejects
  > `constants.MaxRelays` relays.

- Fixed `Optimize`/`Optimize2` sorting the entire scratch buffer instead of `working[:numRoutes]`
  (route corruption bug, see assessment below — now has a regression test in core_test.go).
- Fixed SDK client advanced packet filter dropping previous-magic packets, plus a format-string
  crash in its drop log; added `NEXT_PRINTF_FORMAT` (printf format checking) to `next_printf`,
  which caught five more format bugs in next_server.cpp logs — all fixed.
- `NEXT_ADVANCED_PACKET_FILTER` is now 1 (sdk/include/next.h) and `RELAY_ADVANCED_PACKET_FILTER`
  is now 1 (relay/xdp/relay_xdp.c). Receive-side filter verification is ON everywhere.
- XDP relay advanced filter restructured to match the reference relay exactly: one
  `relay_advanced_packet_filter` helper tried for all {current,previous,next} magic x
  {public,internal} address combinations. Helper cross-validated against Go
  (`core.GeneratePittle`/`GenerateChonkle`) on 10k random vectors.
- CAVEAT: CI compiles relay_xdp.o but never loads it — the BPF verifier only runs at
  `ip link set xdp` time. Load the XDP relay on a real Linux box before the next relay
  release tag.

## Codebase assessment (Claude audit, 2026-07-11)

Honest assessment from a full read of the codebase: Go backend (~60k lines across `cmd/` and
`modules/`), C++ SDK (~21k lines source), reference relay (~7.7k), XDP relay (~13k), CI config,
terraform (~20k), and docs. Portal (Vue 3) was only skimmed.

### What is genuinely good

- **Consistency.** The entire codebase reads like one person wrote it, because one person did.
  C-style Go: flat, explicit, data-oriented, almost no interfaces or generics, goroutines +
  RWMutexes used plainly (see `modules/common/service.go`). Once you've read one module you can
  predict the shape of every other. Zero TODO/FIXME/HACK comments in the Go code. `go vet` is
  clean except unkeyed `SDKVersion` struct literals; `gofmt` is clean except 2 files
  (`modules/admin/admin.go`, `modules/crypto/crypto.go`).
- **Test culture.** 86 unit tests in core alone, ~155 parallel functional-test CI jobs, soak
  tests, load-test harnesses, seeded/reproducible functional tests with watchdogs. The
  functional-test hardening (see above) shows real maintenance discipline.
- **Crypto is boring in the right way.** libsodium / NaCl box, ed25519, chacha20poly1305 —
  no home-rolled primitives. The pittle/chonkle packet filters are DDoS chaff filters, not
  security primitives, and the code treats them as such.
- **Documentation.** 36 step-by-step guides from fork to production teardown. Very few
  projects of any size have this.
- **Ops story is coherent.** Terraform for dev/staging/prod, tag-triggered CI, artifacts to
  GCS, encrypted database blobs (`envs/*.bin`), the API JWT signing secret (`API_PRIVATE_KEY`)
  kept out of the repo, per-install keys regenerated via `next keygen`.

### Confirmed bug found during this audit (FIXED 2026-07-11, kept for the lesson)

`modules/core/core.go` — in both `Optimize` (line ~427) and `Optimize2` (line ~634), when a
relay pair had more than `MaxIndirects` (8) indirect routes, `sort.SliceStable(working, ...)`
sorted the ENTIRE scratch buffer (length numRelays), not `working[:numRoutes]`. Stale entries
from previously-processed pairs (or zeros on a goroutine's first sort) leaked into the top 8
with wrong relay indices and wrong costs, and phase 2 trusted the stored cost when it called
`AddRoute`. Verified empirically: with a seeded random 100-relay cost matrix, 61 of ~59k emitted
routes had claimed costs that didn't match the actual sum of their link costs — including
claimed-cost-0 routes through relay index 0 that actually cost 251ms and sorted as the *best*
route for their pair. In production since commit `600ebd1f4` (2023-01-31, "try this"), fixed in
`4c0672efa` with a regression test. The unit tests never caught it because no test built a
topology with >8 indirects and verified emitted route costs against the cost matrix. The SDK
client had the same class of bug (compiled-out `NEXT_ADVANCED_PACKET_FILTER` code that
bit-rotted), fixed in `7ecd565ba`. Lesson: code behind a disabled compile flag and math with
undocumented invariants are where the bugs live in this codebase.

### Structural weaknesses (honest, in rough priority order)

- **The wire protocol exists four times.** Route/continue tokens, headers, and packet filters
  are hand-implemented in Go (`modules/core`, `modules/packets`), the C++ SDK, the reference
  relay, and the XDP relay, kept in sync by convention and functional tests only. This is the
  single biggest ongoing tax and the most likely source of subtle future bugs.
- **Copy-paste divergence.** `Optimize` vs `Optimize2` are ~230 nearly-identical lines (the bug
  above exists in both); the three `isAdminAuthorized`/`isPortalAuthorized`-style middlewares in
  `cmd/api` are near-clones; the reference relay is a 6.6k-line single file. The one-author
  style makes this workable, but every duplicated block is a place where a fix lands once.
- **Sparse comments exactly where they'd pay off.** The route optimizer's invariants (what
  `working` holds, why stored cost is trusted in phase 2) are undocumented — which is precisely
  where the confirmed bug lived for 2.5 years. Mechanical code doesn't need comments; the
  clever 5% does.
- **Print-and-continue error handling.** `core.Error` is a printf. No structured logging, no
  error wrapping, and failures in hot paths increment counters at best. Fine while one person
  who knows everything operates it; hostile to anyone else on call. 45 `panic()`s in non-test
  code are mostly legitimate fail-fast, but a few sit in library-ish code paths.
- **Committed keys are a forker trap.** The same `NEXT_BUYER_PRIVATE_KEY` sits in
  `envs/dev.env`, `staging.env`, and `prod.env`, and portal JWTs are committed (including
  `portal/.env.prod`). The docs say to regenerate with `next keygen`, but nothing enforces it —
  a forker who skips that step ships with public keys. A startup check that refuses prod with
  the well-known default keys would close this.
- **API auth is thin.** Single shared HS256 secret, `admin`/`portal` booleans in claims, no
  token expiry (`iat` only), no per-buyer scoping visible. Adequate for an internal tool with
  trusted operators; not multi-tenant-grade.
- **Big-file gravity.** `core.go` (2.2k lines) mixes geo math, route optimization, tokens,
  packet filters, and pagination; `session_update.go` handler is 1.4k lines with a 90-field
  state struct. Navigable with grep, but onboarding cost is real.

### Verdict

This is a disciplined, coherent, production-hardened codebase with an unusually strong test and
docs culture, written in a deliberately simple style that trades abstraction for readability —
and that trade mostly pays off. Its two real risks are concentration (one author, one style,
four hand-synced protocol implementations) and the thin observability/error story. The one
confirmed defect (the `Optimize` sort bug) is exactly the kind of failure the style permits:
simple code, subtle invariant, no comment, no targeted test.
