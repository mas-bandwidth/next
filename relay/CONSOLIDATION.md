# Relay consolidation (DONE 2026-07-12)

**The project is complete.** The XDP relay compiles in a userspace socket mode
(`make dist/relay-userspace-debug`) and is the only relay in the tree: the functional
suites, soak test, happy path, local dev (`./run relay`), docker-compose relays, and
the `${tag}-debug` relay artifact upload all use it. `relay/reference` (~6.6k lines of
sync-by-convention) is DELETED -- the dual-flavor gate ran the full relay + sdk
functional suites against both relays side by side, and test-280 passed every pipeline
end to end (all relay + sdk blocks for both flavors, both soak tests, load tests,
happy path) before deletion. The retirement itself then validated fully green on
test-282 (Build, SDK Tests, Functional Tests, Happy Path with the userspace relay as
the only flavor). The plan and per-step history below are kept as the record.

Still owed before the next `relay-*` release tag: benchmark + soak the XDP build on a
real box (the per-packet session-expiry checks landed in the shipped BPF program this
session).

**Scope decision (Glenn, 2026-07-12): the userspace relay will NEVER be used in
production.** It exists so the functional suites, local dev, mac -- and Windows -- can
run the real datapath; the XDP relay is the only production relay. Consequences: the
shim maps' unbounded growth (no LRU eviction) and the synthetic frame assuming packets
arrive on the public address (no IP_PKTINFO) are permanent non-issues, not open items.
Windows support (Glenn, same day) IS wanted, for people who develop and test Network
Next related code on Windows -- build and run there, dev/test only. DONE, validated
green on test-283: `make userspace-windows` cross compiles a self-contained PE32+ exe
(mingw-w64, static libsodium, winsock2 + winhttp + win32 threads in
relay_platform_windows.c), the CI XDP job cross compiles and wine-smoke-tests it every
tag, and docs/build_the_relay_on_windows.md is the how-to. The port surfaced and fixed
a real latent bug: `(void*)(long)ctx->data` truncates pointers on win64 (LLP64), now
`relay_uptr_t` (long in the BPF build -- token-identical object; uintptr_t in
userspace).

## Why only the relay, and only this way

The wire protocol has four implementations. Three are structurally irreducible and must
stay:

- **SDK (C++)** — shipped to customers, compiled into their game. A protocol impl must live
  here by definition.
- **Go backend** — separate process, different language. Cannot share code with the relay.
- **A relay datapath** — needed to actually relay packets.

The reducible duplication is the *second relay*. Two exist for a concrete reason:

- **XDP relay** (`relay/xdp/relay_xdp.c` + userspace `relay*.c`) — production, Linux + real
  NIC only. Cannot run in Semaphore CI, cannot run on mac/windows (no XDP).
- **Reference relay** (`relay/reference/reference_relay.cpp`, 6.3k lines) — a full userspace
  reimplementation used for CI functional tests, local dev, and mac. It re-implements not
  just the datapath but the whole control plane the XDP relay's userspace already has.

**Plan:** extend the XDP relay with a non-XDP (userspace socket) mode, and use that on
mac/windows/CI. One relay codebase, two datapath backends (XDP kernel + userspace socket)
sharing one protocol core. Retires `relay/reference` (~6.3k lines of sync-by-convention).

Windows relay support does not exist today but is desirable — the userspace mode is the
natural place to add it, so keep the userspace datapath and platform layer Windows-portable
from the start (plain BSD sockets, no Linux-only syscalls in the shared/userspace paths).

## The seam

XDP and a userspace socket loop differ only OUTSIDE the protocol:

- XDP: parses ETH/IP/UDP itself, forwards via header rewrite + `XDP_TX`, state in BPF maps,
  clock in `state->current_timestamp`, sha256 via the `bpf_relay_sha256` kfunc.
- Userspace: kernel delivers UDP payload + 4-tuple, replies via `sendto`, state in hash
  tables, clock from `time()`, sha256 from libsodium/openssl.

Everything protocol-relevant is INSIDE the seam: pittle/chonkle basic + advanced packet
filters, route/continue token decrypt, header verify, replay protection, session table
transitions, the per-type handlers (`relay_xdp.c` ~line 754+, one `case` per packet type
1..14). The shared core should take *(payload bytes, 4-tuple, injected clock, map/crypto/
emit primitives)* and return *(verdict, response bytes, destination)*. It must stay in the
BPF-compatible C subset (bounded loops, no libc, verifier-friendly bounds checks) so it
compiles into both the BPF object and the userspace binary. The CI verifier gate
(`bpftool prog load`, added this session) makes "did I break the verifier" a per-commit
answer instead of a release-day surprise.

## Sequencing (each step lands independently, CI-validated)

1. **Conformance corpus + differential harness.** Generate packets across the taxonomy
   (14 types x {current,previous,next} magic x basic/advanced filter cases x session
   state), fire at each impl, assert byte-identical (verdict + output + destination).
   - reference relay: over UDP, exactly what `func_test_relay` already does (it stands up
     `func_backend`, configures the relay, sends crafted packets, checks responses +
     counters — see `test_basic_packet_filter`, `test_advanced_packet_filter`). Feasible
     by existence; the corpus is a refinement of that framework, not new risk.
   - real `relay_xdp.o`: via `BPF_PROG_RUN` in CI. **This is the risky unknown.** Spike in
     `relay/xdp/prog_test_run.c` (two crypto-free cases) proves the mechanism; if green,
     the corpus can hit the real BPF object for a three-way differential.
2. **Extract the datapath core** from `relay_xdp.c` behind primitive shims (map/crypto/
   time/emit as macros or static inlines — BPF needs static dispatch). XDP-only at this
   step; prove verifier-green + functional-suite-green. No behavior change.
3. **Userspace socket wrapper** inside the relay tree (Linux first). Run the corpus + full
   functional suite against it in parallel with the reference relay.
4. **Port the mac platform layer** (`relay/reference/relay_mac.cpp` is the donor), swap
   func tests + local dev to the userspace mode. Add Windows platform layer.
5. **Retire `relay/reference`** — DONE (deleted after the dual-flavor gate went green).

## Findings (things the corpus has already surfaced)

- **too-small drop counter attribution differs between the two relays.** The XDP relay
  has a dedicated `PACKET_TOO_SMALL` guard before the basic filter; the reference relay
  folds the `< 18` check inside `relay_basic_packet_filter`, so it attributes those drops
  to `BASIC_PACKET_FILTER_DROPPED`. Wire behavior agrees (both drop, never relay) -- this
  is a counter-accounting divergence, not a protocol one. The corpus caught it on the
  first differential run (test-268). The oracle models the XDP behavior (canonical) with a
  distinct `DropSize` verdict; a future reference-relay differential must know reference
  reports these as basic-filter drops.

## Status

- **BPF_PROG_RUN mechanism: PROVEN** (test-265). The real compiled relay_xdp.o runs under
  BPF_PROG_RUN in CI with maps populated from userspace. Environment lessons baked into the
  job + prog_test_run.c: link libbpf.a from the xdp-tools source tree; set
  BPF_PROG_TYPE_XDP explicitly (the SEC("relay_xdp") section name defeats libbpf type
  inference); libbpf_get_error is gone from current libbpf.
- **Step 1, XDP differential: COMPLETE AND GREEN** (test-269). The stateless surface (size
  guard + basic + advanced filters + type dispatch) is pinned. modules/relaycorpus
  generates 2343 packets with oracle verdicts; cmd/relaycorpus_gen emits the binary corpus;
  relay/xdp/relay_corpus_diff.c fires all of them at the real relay_xdp.o via BPF_PROG_RUN
  in the Build XDP job every tag -- 0 mismatches (2221 drop-basic, 39 drop-advanced, 27
  drop-size, 56 pass). The Go filter and the production XDP relay are proven equivalent
  here. The corpus already caught one real divergence (see Findings).
- **Datapath is ONE source, compiles both ways: PROVEN** (branch relay-userspace-mode).
  relay_xdp.c now compiles as the BPF kernel program (unchanged, byte-identical) AND as
  plain userspace C via `-DRELAY_USERSPACE` + `relay_userspace.h` -- the shim providing
  userspace stand-ins for the __uN types, eth/ip/udp structs, xdp_md over a buffer, the six
  BPF maps (as array/hash maps), the bpf_map_* helpers, the resize helpers, and the crypto
  kfuncs (STUBBED for now -- the stateless corpus never reaches them). The relay_xdp.c edits
  are only #ifdef guards around kernel-only includes/map-decls/kfunc-decls. relay_userspace_test.c
  fires the corpus at the userspace-compiled relay_xdp_filter() -> 0 mismatches, IDENTICAL
  breakdown to BPF (27 drop-size, 2221 drop-basic, 39 drop-advanced, 56 pass). Runs locally
  on mac (no BPF) AND in the CI XDP job (`make userspace-test`). THE HARD PART is done.
- **Crypto in the shim: DONE.** The two kfunc stand-ins in relay_userspace.c are real
  (libsodium): sha256 via crypto_hash_sha256, xchacha20poly1305 via
  crypto_aead_xchacha20poly1305_ietf_decrypt (in-place, NULL AD -- the exact construction
  the kernel module open-codes). Byte-exactness argument: the Go backend encrypts tokens
  with golang.org/x/crypto chacha20poly1305.NewX and both the XDP relay (kernel crypto)
  and reference relay (libsodium) already decrypt them in production/tests, so
  kernel == libsodium on this construction is proven by interop; relay_userspace_test.c
  self-tests pin the shim wiring (sha256 known answer = the kernel module's insmod vector,
  encrypt->decrypt round trip, tamper reject) before every corpus run.
- **Userspace relay binary: WORKING.** `make dist/relay-userspace-debug` builds the full
  relay (mac + linux): relay.c + relay_config.c + relay_main.c + relay_ping.c + the shim
  + relay_xdp.c as the datapath. The ping thread's socket IS the datapath: every received
  packet is wrapped in a synthetic frame and run through relay_xdp_filter() under the
  maps lock; XDP_TX -> sendto the rewritten destination, XDP_PASS -> the existing pong
  processing. main_update drives the shim maps (config/state writes, session/whitelist
  timeout sweeps via us_map_get_next_key, counters from the stats map). RELAY_TEST builds
  honor RELAY_SHUTDOWN_TIME/EXTRA_TIME, RELAY_PRINT_COUNTERS (counter dump after thread
  join, ping-thread totals folded in), RELAY_FAKE_PACKET_LOSS_*, RELAY_DISABLE_DESTROY.
  Verified locally on mac: the relay functional tests pass one-by-one against it
  (initialize, filters, pings, route/continue/forwarding, session expiry, clean shutdown,
  cost matrix, backend stats/counters spot checks) AND the SDK tests genuinely accelerate
  through it (test_accelerated: PACKET_SENT_NEXT >= 2000, zero fallbacks, repeated runs).
- **The whitelist is the big behavioral difference vs the reference relay** (production
  XDP behavior the reference never had): a valid client/server/relay ping is what admits
  a source address, and forwarding requires the DESTINATION whitelisted too. Three things
  follow, all landed:
  (1) packet-crafting relay tests prime the whitelist first (whitelistAddress helper in
  func_test_relay.go -- a valid zero-key client ping; harmless warmup on the reference);
  (2) func_backend now sends TestPingKey in relay updates (it sent a ZERO ping key
  forever -- client/server ping tokens NEVER verified; the reference relay didn't care,
  the whitelist does; ZERO_MAGIC mode keeps the zero key for the crafted-packet tests);
  (3) func_backend never answers client/server relay requests with zero relays (harness
  starts everything at once; a zero-relay answer meant the client never pinged, was never
  whitelisted, and every route request dropped -- the SDK retries for 5s, relays register
  within ~2s). RELAY_BIN env overrides the relay binary in func_test_relay, func_test_sdk
  and soak_test_relay (default ./relay-userspace-debug).
- **Datapath behavior aligned with the reference where the XDP relay had gaps** (see
  commit 'XDP datapath: per-packet session expiry checks'): per-packet session expiry
  drops in all seven session handlers + SESSION_CREATED/SESSION_CONTINUED counters --
  the counters existed and were reported but never incremented.
- **THE GATE went green, then the reference relay was deleted.** CI ran the full
  relay + sdk functional suites against BOTH relays side by side (duplicated blocks
  with RELAY_BIN=./relay-userspace-debug) and every relay and sdk block passed for
  both flavors on test-279/test-280. All 82 relay tests also passed one-by-one locally
  against the userspace relay. relay/reference is deleted; the userspace relay is the
  default in the harnesses, the only relay flavor in functional-tests.yml, the docker
  relay image, `./run relay` / happy path, and the `${tag}-debug` upload. Still owed:
  benchmark + soak the XDP build on a real box before any relay-* release tag (the
  session-expiry check touches the shipped BPF program).
- **Optional: reference-relay differential** (fire the corpus at the reference relay over
  UDP) -- nice extra confidence, but the userspace relay passing the functional suite is
  the real gate for deletion.
- **Later: stateful corpus surface** -- tokens, sessions; strengthens the differential.

## Invariants to preserve (do not regress)

- The XDP hot path must not get slower — benchmark + soak on a real box before any
  `relay-*` tag (same discipline as the optimizer merge).
- pittle/chonkle must stay byte-identical across Go/SDK/XDP (existing invariant).
- The advanced packet filter magic combinations (all {current,previous,next} x
  {public,internal}) are load-bearing — the corpus must cover every one.
