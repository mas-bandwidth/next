# serialize (vendored)

`serialize.h` is the canonical [serialize](https://github.com/mas-bandwidth/serialize)
bitpacking library, vendored verbatim into the SDK. The Network Next SDK's bitpacker and
stream implementation is derived from this same library, so we vendor the upstream release
directly and take advantage of its hardening rather than maintaining a divergent fork.

**Currently vendored: v1.4.3**

## Rules

- `serialize.h` is **canonical and unmodified** — do not edit it here. It keeps its own
  upstream BSD-3-Clause license header. All local changes go in the adapter headers, never
  in this file.
- The SDK adapts it in `include/next_bitpacker.h` (pulls in `serialize.h`, routes
  `serialize_assert` to `next_assert`, aliases the bitpacker classes into `namespace next`),
  `include/next_stream.h` (aliases the stream classes), and `include/next_serialize.h`
  (SDK-specific `serialize_address`; the standard `serialize_*` macros come from `serialize.h`).

## Updating to a new upstream release

```sh
./sdk/serialize/update.sh          # fetches latest serialize.h from upstream main
```

Then reconcile any edges (upstream is canonical, the SDK adapts to it):

1. Diff the new `serialize.h` against the vendored one to see what changed upstream.
2. Rebuild and run the SDK unit tests: `make dist/test && (cd dist && ./test)`.
3. Run the SDK functional tests on CI (`./dist/deploy test`) — these validate wire
   compatibility of the C++ SDK against the Go backend/relays. **This is the check that
   matters:** if a serialize change alters the wire format, the functional tests fail.
4. If macro names or the stream API changed upstream, update the adapter headers above.
   Never edit `serialize.h`.
