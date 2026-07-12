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

Big bug-fix + hardening pass this session: commits `4c0672efa` .. `96b112a5b` on main, validated
green on CI test-229 .. test-241 (test-241 in flight at time of writing; all prior green). The
per-commit detail is in git log; below is what a future session actually needs to NOT re-break or
re-investigate.

### Deployment state (changes how you weigh severity)

Nothing is running in dev/staging/prod right now — deployed in the past, not currently. So no
config/deploy change this session had live exposure or historical-data/migration impact; they
take effect on the next deploy. See memory `next-deployment-state.md`. If it gets redeployed,
that fact is stale — reverify.

### Standing invariants — do NOT break these

- **`sdk/serialize/serialize.h` is CANONICAL and vendored verbatim** (mas-bandwidth/serialize
  v1.4.3, BSD). Never hand-edit it. Update via `sdk/serialize/update.sh` then validate on CI
  (`sdk/serialize/README.md`). `next_bitpacker.h`/`next_stream.h`/`next_serialize.h` are thin
  adapters over it; the only SDK-specific serialize helper is `serialize_address`. Any wire-format
  change here breaks every deployed relay/backend — the functional suite is the wire-compat check.
- **Do NOT remove the vendored `sdk/sodium/`** (flattened, Unreal-plugin-friendly). SDK Tests CI
  builds against it with no system sodium installed; the `next` tool bundles it into the customer
  SDK example; `sdk/visualstudio/next.sln` references it. It is SEPARATE from the Build pipeline's
  "Sodium" job that wgets+builds libsodium 1.0.18 for a GCS artifact.
- **Advanced packet filter is ON everywhere** (`NEXT_ADVANCED_PACKET_FILTER=1` in sdk/include/next.h,
  `RELAY_ADVANCED_PACKET_FILTER=1` in relay/xdp/relay_xdp.c). Magic values are now load-bearing.
  The XDP filter mirrors the reference relay exactly (all {current,previous,next} magic x
  {public,internal} address combos). Keep the Go/SDK/reference/XDP pittle+chonkle implementations
  byte-identical.
- **UDP packet-handler concurrency is bounded** by `x/sync/semaphore` (default 16384,
  `UDP_MAX_CONCURRENT_PACKETS`), same goroutine-per-packet model with a `defer recover()`. A
  goroutine-POOL library (ants) benchmarked ~12% SLOWER — do not "optimize" into a worker pool
  without re-measuring.
- **`ENABLE_DEBUG` must stay unset/false in prod** (removed from terraform/prod this session; dev
  keeps it). It registers 7 unauthenticated `/debug/*` endpoints on the public api domain that
  leak relay fleet topology.
- **`core.Optimize`/`Optimize2` invariant**: sort only `working[:numRoutes]`, never the whole
  scratch buffer (regression test in core_test.go guards it).
- **Route matrix version 5 serializes per-route `RoutePrice`** (added 2026-07-11, commit
  `4cf49e88e`). Versions < 5 dropped it, so server_backend saw price 0 on every route and
  lowest-price route selection silently no-oped. `GenerateRandomRouteMatrix` randomizes it so
  the round-trip test guards the field — keep that. Route price is the sum of relay prices
  over the route's relays (`constants.MaxRoutePrice` bounds it).
- **Session data version 8 serializes `PrevPacketsOutOfOrder*`** (same commit). Versions < 8
  dropped them, so `RealOutOfOrder` reported cumulative counts. `GenerateRandomSessionData`
  randomizes them for version >= 8 — any new session-data field must be randomized there too,
  or the round-trip test cannot catch a serialization omission (that's how both these bugs hid).
- **Relay ordering is load-bearing and subtle**: `generateRelayData` (service.go) sorts
  `database.Relays` IN PLACE by name, and `DatabaseBinFile = database.GetBinary()` re-serializes
  the sorted database. That is the only reason server_backend's `Database.Relays[relayIndex]`
  (indexed with route-matrix indices in session_update.go BuildNextTokens/BuildContinueTokens)
  lines up with the route matrix relay order. The database.bin on disk is NOT sorted (postgres
  row order, no ORDER BY). Do not reorder these steps or index `Relays` with route-matrix
  indices on a database that didn't come through this path.
- **`RedisCountersWatcher` getters require `Lock()`/`Unlock()`** around them (the watcher
  thread swaps the underlying maps every second). cmd/api and session_cruncher both do this now.
- **Session data `RouteNumRelays` serializes with bound `SDK_MaxRelaysPerRoute` (5), not
  `SDK_MaxTokens` (7)** — same bit width so not a wire change, but the larger bound indexes
  out of range of `RouteRelayIds`.

### In progress: relay consolidation (see relay/CONSOLIDATION.md)

The wire-protocol consolidation project is underway — plan, sequencing, and status live
in `relay/CONSOLIDATION.md` (keep that file current, not this section). Headline: the
feasibility spike PASSED on test-265 — the real compiled relay_xdp.o runs under
BPF_PROG_RUN in CI with maps populated from userspace, so the conformance corpus can be
fired at the actual BPF object (three-way differential: reference relay vs future
userspace core vs real kernel program). Next up: the corpus generator (step 1 proper).

### Open items (not yet done)

- **API auth is thin** (single shared HS256 secret, `admin`/`portal` booleans, no token expiry).
  Known structural item — a deliberate hardening project if wanted, not a bug. The portal audit
  below sharpens this: the portal-scope JWT is baked into the public JS bundle, so it protects
  nothing — front the portal with real auth (IAP / LB auth) and add `exp` to tokens if wanted.
- **Portal, remaining optional item from the 2026-07-12 audit**: portal JWTs never expire
  (fix is auth in front of the portal + `exp` on tokens — part of the API auth project).
  Everything else landed: quick fixes in `e219d32d3` (`yarn.lock` is COMMITTED — removed from
  both .gitignores, CI builds were fully unpinned before; regenerate it with any dep change;
  axios auth header lives in `main.js`; dead MapView/SellersView deleted), and the full stack
  modernization in `20602e6c7` (Build Portal green on test-254): vue-cli/webpack/babel/
  node-sass/core-js are GONE — the portal is Vite 8 + dart-sass + eslint 10 flat config, vue
  3.5 / vue-router 5 / axios 1.18 / bignumber 11. Env vars are `VITE_*` via `import.meta.env`,
  and the localhost env file is `.env.localhost` NOT `.env.local` (Vite loads a file named
  exactly `.env.local` into EVERY mode as an override — it would leak localhost URLs into
  prod builds). Local builds now work on Apple Silicon with plain node >= 22.18; the CI job
  pins node 24 via sem-version. Verified old-vs-new builds render char-for-char identical
  against an auth-checking mock API (948 requests, all authenticated).

### Closed 2026-07-12, third batch (optimizer merge + unit test flake hunt + govulncheck)

- **Dead code sweep done** (`1cc3f97db`, fully green on test-266): swept with
  x/tools/deadcode (-test) + staticcheck U1000 — only 11 findings in ~60k lines, all
  removed (unreachable SortedSet wrappers in both crunchers, dead test helpers, 17
  return/continue statements after panics). go vet is now clean repo-wide except the
  documented unkeyed SDKVersion literals. Kept: TestThread in both crunchers (manual
  stress knob, commented activation in main). Not swept: C++ (SDK public API is the
  product surface; relay/reference retirement is the consolidation project). Noted in
  passing: the SortedSet skiplist is copy-pasted between server_cruncher and
  session_cruncher — same fix-lands-once class as the old Optimize/Optimize2.
- **govulncheck runs in CI** (`0bb98be73`, green on test-259): a Build pipeline job (next
  to Backend unit tests, every tag) and a weekly job in scheduled-functional-tests.yml.
  Fails only on vulnerabilities REACHABLE from our code. If it fails with no code change,
  a new vuln was published — upgrade the dependency, don't revert.

- **Optimize and Optimize2 are MERGED into one function, ~2x faster at production scale**
  (`83350d8bf`, fully green on test-257). One `Optimize(..., destinationRelay []bool)`;
  nil = all pairs. Correctness pinned bit-for-bit by `TestOptimizeDifferential` against
  verbatim pre-merge reference copies in `optimize_reference_test.go` (kept in tree — any
  future optimizer change must stay identical, tie ordering included). Perf: square cost
  matrix replaces TriMatrixIndex in phase 1, stable top-8 selection replaces
  sort.SliceStable, AddRoute loop check replaces its per-call map, atomic row counter
  replaces fixed row ranges (uneven per-row work). 1000 relays 10% dest: 21.4ms -> 10.8ms.
  `BenchmarkOptimize*` in tree; benchstat before touching this function. One deliberate
  unification: old Optimize2 could emit routes with cost >= direct in the i->(x)->k->j
  case (partial-cost filter bug); merged code filters all cases on full path cost.
- **Two flaky handler unit tests fixed** (`191a5914c`, green on test-258; suite flake rate
  ~10% -> ~0.5% on a 32-thread machine). (1) RealOutOfOrder: random session data version 8
  left PrevPacketsOutOfOrder* random and unpinned -> uint64 delta wrap. Lesson: any test
  building on GenerateRandomSessionData must pin EVERY field its assertions depend on,
  including version-gated ones. (2) CreateState never set StaleDuration -> stale check was
  `CreatedAt + 0 < now`, tripping on wall-clock second ticks (the second-boundary class
  again). Unit tests now print `random seed = N` (TestMain in modules/handlers) and
  GenerateRandomSessionData draws only from the seedable common.Random* source —
  reproduce with `TEST_SEED=N go test -run <TestName> ./modules/handlers/`.
- **Known residual flake, ~1 in 200 full-suite runs, NOT understood yet**: a route token
  (always token 0, the client token) fails to decrypt in one of the MakeRouteDecision
  tests. Exonerated by targeted stress (zero failures): the AEAD/token path (640k
  concurrent round-trips), the full MakeRouteDecision+decrypt flow (64k concurrent
  iterations), 3000 isolated runs of the affected test, and `-race`. It only occurs in
  the full parallel suite (which spawns real UDP servers in SDK tests). Captured keys
  look valid (32 bytes, non-nil) and replay confirms genuine key mismatch at write vs
  read. Every token read loop now dumps index+key+token on failure — if you see it,
  grab that output; do not chase it blind (several hours already spent). No evidence of
  a production bug: relays decrypt these tokens constantly in the functional suite.
  IMPORTANT context (Glenn, 2026-07-12): heavy BURSTY unrelated CPU load (profiling in
  other contexts) was running on this machine during the hunt. With burstiness confirmed
  the evidence is fully consistent with an environmental cause and not a code bug:
  failures clustered unevenly across batches (2/60 then 0/80 — matches bursts), the
  clean targeted stress runs likely fell between bursts, CI has NEVER shown this failure
  across test-247..258 on clean VMs, and a bit flip under burst load produces exactly
  this signature (valid-looking key, genuine AEAD reject, unreproducible on replay).
  Treat as environmental unless it fires on an idle machine or CI — and if it fires,
  the token read loops dump index+key+token; note what else the machine was doing.

### Closed 2026-07-12, second batch (guard + CI cache + Makefile + middleware dedupe)

All validated fully green on test-256 (Build, SDK Tests, Functional Tests, Happy Path):

- **Default-key startup guard** (`2f8739ec1`): services REFUSE to start with `ENV=prod` on any
  of the nine key values committed to this repo (envs/*.env, docker-compose.yml, staging
  tfvars) — checked via env vars in CreateService AND buyer public keys in LoadDatabase (a
  forker's prod database contains the test buyer; that's where the trap bites). dev/staging
  warn; local is exempt (functional tests + local dev use committed keys by design). The key
  list lives in `modules/common/default_keys.go` — if a key is ever committed by mistake,
  rotate it AND add it there. Same commit fixed `next keygen`/`next config` writing stale
  `VUE_APP_*` vars to `portal/.env.local` (now `VITE_*` to `portal/.env.localhost`).
- **Sodium CI flake fixed properly** (`41bf3967c`): the built libsodium.so is in the Semaphore
  cache keyed `libsodium-1.0.18-so`; download.libsodium.org outages no longer fail builds.
  Bump the version in the cache key to force a rebuild.
- **relay/module Makefile no longer swallows insmod failures** (`a9aaf8c29`) — the
  `>/dev/null 2>&1; echo` exit-code laundering is gone; rmmod stays tolerant.
- **cmd/api auth middlewares deduped** (`ff09fe321`): isAdminAuthorized/isPortalAuthorized are
  one-line wrappers over a single isAuthorized(check, endpoint). Verified all six
  accept/reject paths against a live api (token x endpoint matrix) — identical behavior.

### Closed 2026-07-12 (session: comments + migrations + XDP CI gate + portal audit)

- **XDP verifier-load is now a permanent CI gate** (commits `114805598`..`df721afcd`, green on
  test-252). The Build XDP job builds + insmods `relay/module` (which exports the
  `bpf_relay_sha256` kfunc — without it `relay_xdp.o` cannot load AT ALL; libxdp misreports the
  unresolved ksym as attach EINVAL), then `bpftool prog load`s `relay_xdp.o` through the BPF
  verifier. The restructured advanced packet filter PASSES the verifier (50KB xlated, 6 maps).
  Attach is deliberately not tested (driver dependent; prod attaches native mode on real NICs).
  Side benefit: CI now proves the relay kernel module builds and insmods on a current kernel.
- **Major-version dependency migrations all done** (`e273fb73b`, `fc6a1d55e`, validated fully
  green on test-247 incl. functional tests): pubsub v1 -> pubsub/v2 (producer only; new
  `TestGooglePubsubProducer` in modules/common uses pstest for end-to-end coverage — the ONLY
  coverage the pubsub path has, functional tests run with `ENABLE_GOOGLE_PUBSUB=0`);
  hamba/avro -> /v2 (import path only, analytics round-trip tests cover all nine schemas);
  maxminddb-golang -> /v2 (netip.Addr Lookup().Decode() internally, net.IP signatures kept,
  not-found semantics preserved). All direct deps now current with no deprecated majors.
- **Invariant comments landed** (`770914b68`): optimizer scratch-buffer + trusted-cost
  invariants in core.go, the load-bearing relay sort in generateRelayData + pointer comments at
  the consuming sites in session_update.go, and the "randomize every serialized field" rule on
  both GenerateRandom* functions.

### Reviewed and cleared this session (don't re-audit without reason)

Route-token wire interop (Go<->SDK byte layout), the bitpacked `encoding` ReadStream and byte-level
`encoding.Read*` helpers (all bounds-checked), replay protection / ping-history / loss/jitter
trackers, SDK client/route/relay-manager receive paths, admin SQL (fully parameterized, no
injection), portal handlers (safe path-var parsing, `DoPagination_Simple` clamps), autodetect,
raspberry_backend, magic_backend. The confirmed bugs found in these areas are all fixed (see git log).

Second audit pass (2026-07-11, commit `4cf49e88e`, validated green on CI test-242) covered and
cleared: session_update.go + sdk_handlers.go handler path, sdk_packets serialization,
core.go route decision / filter / reframe / best-route functions, relay_backend, relay_gateway,
server_backend, session_cruncher, server_cruncher (batch handlers properly bounds-checked),
modules/common (service.go, relay_manager, redis time series/counters/leader election,
route_matrix, client_relays, udp_server), relay update packets, database module load/save paths.
All confirmed bugs from that pass are fixed in `4cf49e88e` (route price serialization, session
data out-of-order serialization, nil-debug panic, LongSessionUpdate defer ordering, watcher
locking, leader election race, and assorted minor items — see that commit message for the list).
Known non-bugs deliberately left alone: no-TTL time-bucketed redis keys (covered by allkeys-lru
eviction everywhere), `GeneratePingToken` IPv4-only address bytes (matches the relay side;
IPv4-only system), ping key printed via core.Debug in gateway/server_backend (debug-only,
intentional). (`sellers/` and `tools/load_test_portal` build issues were fixed in `6e60ef580`.)

Portal (Vue 3) audit pass (2026-07-12) covered all of portal/src, env files, build tooling,
nginx config, and prod terraform wiring. Clean on XSS (no v-html/innerHTML/eval anywhere, Vue
templates escape everything) and strictly read-only (zero mutating requests; AdminView is
portal-scope graphs, the bundled token has no admin power). Key structural fact: the portal has
NO user auth — the portal JWT is compiled into the public JS bundle via VUE_APP_*, so anyone
with the portal URL has permanent read access to fleet/session/buyer data for that env (tokens
have iat but no exp; revocation = rotating API_PRIVATE_KEY). The committed portal/.env.* JWTs
are therefore not a secret leak per se (the bundle publishes them anyway) — the fix, if wanted,
is auth in front of the portal, not hiding the token. Actionable defects are in Open items.

## Codebase assessment (Claude audit, 2026-07-11)

Honest assessment from a full read of the codebase: Go backend (~60k lines across `cmd/` and
`modules/`), C++ SDK (~21k lines source), reference relay (~7.7k), XDP relay (~13k), CI config,
terraform (~20k), and docs. Portal (Vue 3) was only skimmed.

### What is genuinely good

- **Consistency.** The entire codebase reads like one person wrote it, because one person did.
  C-style Go: flat, explicit, data-oriented, almost no interfaces or generics, goroutines +
  RWMutexes used plainly (see `modules/common/service.go`). Once you've read one module you can
  predict the shape of every other. Zero TODO/FIXME/HACK comments in the Go code. `go vet` is
  clean except unkeyed `SDKVersion` struct literals; `gofmt -l` is clean repo-wide as of
  2026-07-12 (`ac6fafa6b` formatted the two long-unformatted files admin.go and crypto.go —
  keep it clean).
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
- **Copy-paste divergence.** The reference relay is a 6.6k-line single file. The one-author
  style makes this workable, but every duplicated block is a place where a fix lands once.
  (The two big ones are gone: `Optimize`/`Optimize2` merged in `83350d8bf`, the `cmd/api`
  auth middleware clones deduped in `ff09fe321`.)
- **Sparse comments exactly where they'd pay off.** The route optimizer's invariants (what
  `working` holds, why stored cost is trusted in phase 2) are undocumented — which is precisely
  where the confirmed bug lived for 2.5 years. Mechanical code doesn't need comments; the
  clever 5% does. (Addressed for the known hot spots in `770914b68`.)
- **Print-and-continue error handling.** `core.Error` is a printf. No structured logging, no
  error wrapping, and failures in hot paths increment counters at best. Fine while one person
  who knows everything operates it; hostile to anyone else on call. 45 `panic()`s in non-test
  code are mostly legitimate fail-fast, but a few sit in library-ish code paths.
- **Committed keys are a forker trap.** The same `NEXT_BUYER_PRIVATE_KEY` sits in
  `envs/dev.env`, `staging.env`, and `prod.env`, and portal JWTs are committed (including
  `portal/.env.prod`). The docs say to regenerate with `next keygen`, but nothing enforced it —
  a forker who skips that step ships with public keys. (CLOSED in `2f8739ec1`: services now
  refuse to start in prod on any committed key — see modules/common/default_keys.go.)
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
