# Relay consolidation plan (in progress, started 2026-07-12)

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
5. **Retire `relay/reference`** — or freeze it one release cycle as the differential oracle.

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

- **Step 1, BPF_PROG_RUN half: PROVEN** (green on test-265, spike `396fce33f`..`dc70424ef`).
  The real compiled `relay_xdp.o` runs under `BPF_PROG_RUN` in CI: object loaded with the
  kfunc resolved from the insmodded module, `config_map` populated from userspace, synthetic
  ETH/IP/UDP frames fed in, verdicts read back (wrong port -> XDP_PASS, short payload ->
  XDP_DROP, both correct). The three-way differential is achievable. Hard-won environment
  facts baked into the job + `prog_test_run.c`: link `libbpf.a` from the xdp-tools source
  tree (install path varies, ldconfig misses it); libbpf cannot infer the program type from
  the nonstandard `SEC("relay_xdp")` section so set `BPF_PROG_TYPE_XDP` explicitly before
  load; `libbpf_get_error` is gone from current libbpf.
- Step 1, corpus generator + reference relay harness: not started (de-risked, see above).
- Steps 2-5: not started.

## Invariants to preserve (do not regress)

- The XDP hot path must not get slower — benchmark + soak on a real box before any
  `relay-*` tag (same discipline as the optimizer merge).
- pittle/chonkle must stay byte-identical across Go/SDK/reference/XDP (existing invariant).
- The advanced packet filter magic combinations (all {current,previous,next} x
  {public,internal}) are load-bearing — the corpus must cover every one.
