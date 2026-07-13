# Codebase Audit — 2026-07-12

A fresh full pass over the repository: Go backend (`cmd/`, `modules/`, ~61k lines), C++ SDK
(`sdk/`, ~24k lines excluding vendored serialize/sodium), the unified relay datapath
(`relay/xdp/`, ~9k lines), CI config, scripts, and a skim of terraform and the portal.
Verified empirically, not just by reading: `go build ./...` is clean, all Go module unit
tests pass locally, `go vet` is clean except the documented unkeyed `SDKVersion` literals,
`gofmt -l` is clean repo-wide, and there are zero TODO/FIXME/HACK markers in Go or C sources.

## Verdict

This is a disciplined, production-hardened codebase in unusually good shape. The style is
deliberately simple — C-flavored Go, almost no interfaces or generics, flat data-oriented
structs, explicit locking — and after reading tens of thousands of lines of it, the trade
mostly pays off: everything reads the same, nothing is clever twice, and grep works. The
test culture is the standout: 82 relay functional tests, 40 SDK functional tests, seeded and
reproducible with per-test watchdogs, backed by differential tests that pin the optimizer
bit-for-bit against a reference implementation and a conformance corpus that pins the Go and
XDP packet filters against each other on every CI tag. Very few codebases of any size have
this. The recent hardening passes show: the hot spots that used to be undocumented
(optimizer scratch-buffer invariants, the load-bearing relay sort, serialization
randomization rules) now carry precise comments explaining exactly the invariant and exactly
what breaks if you violate it — the best comments in the repo, and the right 5% to comment.

The real risks are structural, not defects: one author, three hand-synchronized wire-protocol
implementations, thin operational observability, and an API auth model that is fine for a
trusted operator and nothing more. I found no serious bugs in this pass — the defects below
are small, and it took genuine digging to find even those, which is itself a statement.

## Defects found this pass (all small)

1. **`UDP_SOCKET_WRITE_BUFFER` is silently ignored** —
   [service.go:456](modules/common/service.go#L456) reads `UDP_SOCKET_READ_BUFFER` for the
   write buffer (copy-paste). Currently harmless because terraform sets both vars to the same
   104857600 in all three envs, but the knob is dead: setting the write buffer independently
   does nothing, with no error. (FIXED 2026-07-13.)

2. **Missing printf argument** — [service.go:499](modules/common/service.go#L499):
   `core.Error("could not create redis leader election: %v")` has no argument and will print
   `%!v(MISSING)` right when you need the actual error. This is the only instance repo-wide,
   which says something good about the discipline. (FIXED 2026-07-13, plus a permanent gate.
   Correction to the original writeup: `go vet -printf.funcs` can NOT check these wrappers —
   the printf analyzer only treats registered names ending in `f` as formatting functions,
   and `core.Error`/`core.Log` don't qualify. The gate is a unit test instead:
   `modules/core/log_format_test.go` scans the tree for log calls whose format string has
   verbs but no arguments, and runs in the existing CI unit test job.)

3. **Leaked HTTP response bodies on error paths in the route matrix poll loop** —
   [service.go:559-576](modules/common/service.go#L559): on a non-200 status or a body read
   error, the loop `continue`s without closing `response.Body`. This loop runs every second
   in server_backend; a relay_backend stuck returning 500s would leak connections/fds for as
   long as the outage lasts. Same pattern in `getMagic`
   ([service.go:959](modules/common/service.go#L959)), which also never checks the status
   code — it accepts any 32-byte body as magic. (FIXED 2026-07-13: bodies read+closed on
   every path, and getMagic now checks the status code.)

4. **Ineffective sanity check** — [core.go:995](modules/core/core.go#L995):
   `len(routeRelays) == 0` in `GetCurrentRouteCost` is always false because `routeRelays` is
   a fixed-size array (`len` is the constant 5). The condition it means to catch
   (`routeNumRelays == 0`) would panic at `routeRelays[routeNumRelays-1]` below. Not
   exploitable today — the only caller path guards it at
   [session_update.go:699](modules/handlers/session_update.go#L699) — but the check documents
   an intent it doesn't implement. (FIXED 2026-07-13: checks `routeNumRelays <= 0`.)

5. **Cosmetic HTTP handler issues** — `statusHandlerFunc`, `versionHandlerFunc`, and
   `databaseHandlerFunc` in service.go set headers or status codes after writing the body
   (no-ops), and `versionHandlerFunc` takes an `allowedOrigins` parameter it never uses.
   (FIXED 2026-07-13: headers set before the body write; `/version` now actually sends
   `Content-Type: application/json`, `/database` sends its type; unused param removed.)

All five items fixed 2026-07-13.

### Terraform provider-pin defect (found 2026-07-13 while validating the MAGIC_KEY wiring)

`terraform validate` passes for dev but fails for **staging and prod**:
`google_redis_cluster.major_version = "REDIS_7_2"`
([staging main.tf:303](terraform/staging/backend/main.tf#L303), same in prod) is not a
recognized argument under the `hashicorp/google` provider pin `~> 6.0.0` (which resolves to
6.0.x — `major_version` was added to that resource much later in the 6.x line). dev has no
redis *cluster* so it validates. Because `.terraform.lock.hcl` is gitignored, a real
`terraform plan` on staging/prod resolves providers fresh against that pin and hits the same
error — so a staging/prod deploy would fail here. Pre-existing and unrelated to any change
this session; consistent with the "nothing currently deployed" state (the config was never
applied after `major_version` was added). Fix is to widen the google provider pin (e.g.
`~> 6.14`) — but that pulls the whole 6.0→6.14 range for every google resource, so it needs
a real `terraform plan` against GCP to vet, which is an operator action, not a blind edit.
Flagged, deliberately not auto-fixed.

## Honest observations (design, not defects)

- **Magic values: anti-DDoS replay defense, correctly scoped.** `magic_backend` derives
  upcoming/current/previous magic purely from wall-clock time and string constants
  ([magic_backend.go:38](cmd/magic_backend/magic_backend.go#L38)) — no key, no state, so
  every instance agrees with zero coordination. The purpose is to make historical packets
  captured from real clients and servers useless: as the magic rotates, replayed traffic
  fails the advanced packet filter, and pittle/chonkle also bind from/to addresses and
  packet length, so cross-source replay dies even within the rotation window. Against the
  attack that matters at DDoS scale — blasting recorded traffic — it works as designed.
  One residual, noted for completeness: with no secret input, someone who has read this
  source-available repo can compute current magic offline and craft packets that pass the
  filter. That pierces only the chaff layer, not any security property — everything behind
  it stays cheap until crypto-gated (ping tokens, header verification, whitelist). If that
  residual ever matters, mixing a per-install secret into `hashCounter` (generated by
  `next keygen` like every other key, delivered as an env var) would close it without
  giving up the stateless design: magic_backend is the only component that derives magic —
  everything else receives it over the wire — so all instances in an env still agree with
  zero coordination. (CLOSED 2026-07-13: `MAGIC_KEY` is now mixed into the derivation when
  set — generated per-env by `next keygen`, back-filled for existing installs by
  `next config`, and passed to magic_backend by terraform in all three envs. Empty keeps
  the constants-only derivation for local dev and functional tests.)

- **Telemetry backpressure: deep buffers, but no shed valve.** The UDP path is bounded
  (semaphore, 16384 in-flight handlers — good, and the comment explaining that a goroutine
  pool measured slower is exactly the right kind of comment). The message channels feeding
  portal/analytics sinks default to `CHANNEL_SIZE=10*1024*1024` entries
  ([server_backend.go:115](cmd/server_backend/server_backend.go#L115)) — deliberately deep:
  the system is load tested to 10M connected clients, and at those ingest rates (~100k+
  messages/sec/instance) the depth is what rides through multi-second sink jitter, so the
  size is right. What's missing is the ending for a sink outage that outlasts any buffer:
  sends are blocking, so a sustained redis/pubsub stall ends in multi-GB of queued messages
  and an OOM, or — on a box big enough to fill the slots — blocked packet handlers,
  semaphore exhaustion, and a routing stall. A `select`/`default` send with a per-stream
  drop counter (reached only when all 10M slots are full, a state healthy operation never
  hits) sheds telemetry instead, keeping the degrade-the-accessory-protect-the-core shape
  the rest of the system follows. (Fixed during this audit: all 11 producer send sites now
  use non-blocking sends with per-stream drop counters and a once-per-second warn — see
  `modules/handlers/dropped_messages.go` and its test.)

- **Print-and-continue error handling remains the weakest operational story.** `core.Error`
  is a printf. No levels, no structure, no error wrapping, counters at best in hot paths.
  One person who knows everything can operate this; nobody else could be on call for it
  without pain. This is the single highest-leverage improvement if the operator pool ever
  grows beyond one.

- **HTTP servers have no timeouts.** Every service uses bare `http.ListenAndServe` — no
  read/write/idle timeouts (slowloris-shaped exposure). Mitigated in production by the GCP
  load balancer in front, but the binaries themselves assume a friendly network.

- **API auth is exactly as thin as it looks.** Single shared HS256 secret, `admin`/`portal`
  booleans, no token expiry (`iat` only). The middleware itself is correct — algorithm is
  pinned, the dedupe into one `isAuthorized` is clean — and the portal-scope JWT baked into
  the public JS bundle means the portal effectively has no auth at all. Known, documented,
  and acceptable for a single-operator internal tool; not acceptable the day a second tenant
  or a compliance requirement shows up. The fix (auth in front of the portal, `exp` on
  tokens) is already scoped in CLAUDE.md.

- **`modules/database` (1.6k lines) and `modules/encoding` have zero unit tests.** Both are
  exercised heavily through functional suites and round-trip tests elsewhere, so this is
  coverage-by-proxy rather than a gap in practice — but database.go contains the
  load/validate/binary-serialization logic that everything trusts, and it's the largest
  untested-in-isolation surface in the Go tree.

- **The root `TODO` file is business notes, not engineering notes** — vendor contract IDs,
  cancellation plans, revenue proposals. In a source-available repo, that's commercial
  information sitting next to the code. Move it out of the tree.

- **Shelling out via `Bash(fmt.Sprintf("gcloud storage cp %s %s", ...))`** for database
  downloads ([service.go:41](modules/common/service.go#L41)) is crude but safe today (inputs
  are operator-controlled env vars). It would become a command injection the day a URL ever
  arrives from anywhere else. A comment or a switch to the storage client library would
  close that door.

## Structural assessment (unchanged in kind, improved in degree)

- **The wire protocol exists three times** — Go backend, C++ SDK, XDP datapath — kept in
  sync by convention, the functional suites, and the relaycorpus differential. This is now
  irreducible (customer SDK, backend, and kernel datapath genuinely can't share code), and
  the consolidation project that deleted the fourth copy (reference relay) was the right
  call. The corpus differential and functional suites are what make this tenable; protect
  them like production code.

- **Copy-paste gravity is much reduced** but not gone — the SortedSet skiplist is still
  duplicated between the two crunchers (same fix-lands-once class as the old
  Optimize/Optimize2 pair, which bit once already).

- **Big files remain big.** `core.go` (2.1k lines) still mixes geo math, route optimization,
  tokens, packet filters, and pagination; `session_update.go` is 1.4k lines against a
  ~40-field state struct; `api.go` is 2.7k. Navigable with grep, and the newer comments
  lower the cost, but onboarding anyone would still start with a week of archaeology.

- **Concentration risk is the real risk.** One author, one style, one person who knows where
  the bodies are buried. The codebase itself now documents its invariants far better than it
  did (CLAUDE.md is effectively an operator's handbook), which is the correct mitigation
  short of a second person.

## What's genuinely excellent

- **Test discipline**: seeded, reproducible functional tests with watchdogs; differential
  tests pinning optimizer output bit-for-bit; a wire-format golden test pinning bytes; a BPF
  verifier-load gate in CI; govulncheck reachability-gated in CI; a weekly scheduled full
  functional run against main. The "randomize every serialized field" rule, learned from two
  real bugs, is now enforced by comment at the exact place a future field would be added.
- **Crypto is boring**: libsodium, NaCl box, ed25519, XChaCha20-Poly1305, thin wrappers, no
  home-rolled primitives, sessions get fresh random keys, tokens bound to expiry and session.
  The JWT middleware pins the signing method. Session IDs come from crypto random.
- **Guard rails with teeth**: services refuse to start in prod with any of the nine
  committed keys (checked both via env and via buyer keys inside the database blob — the
  forker trap actually snaps shut). Route matrices go stale-to-nil rather than routing on
  old data. The default-direct posture on every error path means routing failures degrade to
  the player's normal internet, not to a broken experience.
- **The XDP code** is careful in the exact way BPF demands — explicit bounds checks before
  every access, counters on every drop path — and the userspace relay compiling from the
  same source file killed a whole class of "the test relay isn't the real relay" bugs.
- **Ops coherence**: 37 step-by-step docs, tag-triggered CI with parallel functional jobs,
  artifacts to GCS, encrypted database blobs, per-install keys regenerated by tooling.

## Bottom line

I went looking for the next Optimize-sort bug — the subtle invariant violation hiding in
simple-looking code — and did not find one. What I found instead were four small resource/
copy-paste slips in the service scaffolding, which is exactly where they should be: the hot
paths and the wire protocol are where the review effort has clearly gone, and it shows. The
codebase's weaknesses are the known, chosen ones — thin auth, printf observability, one
brain — and its strengths (test rigor, guard rails, documented invariants, relentless
consistency) are rarer than its weaknesses. In its current state I would trust it in
production, with the caveat that "production" currently assumes the author is the operator.
