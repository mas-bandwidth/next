// Package relaycorpus generates a deterministic conformance corpus for the relay
// datapath -- the packet filters AND the stateful per-type handlers (ping token
// verification, route/continue token decrypt, session lookup/expiry/replay, header
// verification, whitelist admission, forwarding). This is the most security-critical
// relay code and it compiles two ways from one source (the relay_xdp.o BPF object and
// the userspace relay); the corpus is what proves the two stay byte-equivalent.
//
// The corpus is the specification. It carries a WORLD (the relay config, state, and
// map contents every entry runs against) plus entries: packet bytes, the 4-tuple they
// are sent on, and the expected outcome (XDP action + the counter that must increment).
// The same corpus is fired at the relay datapath both ways it compiles -- relay_xdp.o
// via BPF_PROG_RUN (relay/xdp/relay_corpus_diff.c) and the userspace build
// (relay/xdp/relay_userspace_test.c) -- and each must agree. The harnesses reset the
// mutable maps to the world before every entry, so entries are order-independent.
//
// Expectations are CONSTRUCTIVE, not simulated: each stateful case is crafted so its
// outcome follows from the wire protocol (a ping signed with the world's ping key must
// pong; a route token encrypted with the relay's secret key and a fresh expiry must
// create a session and forward). The corpus does not reimplement the C handlers -- it
// pins their behavior. See relay/CONSOLIDATION.md.
package relaycorpus

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"net"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/networknext/next/modules/constants"
	"github.com/networknext/next/modules/core"
)

// relay packet types (relay/xdp/relay_constants.h). the basic filter accepts type in
// [RelayPacketTypeMin, RelayPacketTypeMax]; everything else drops at the basic filter.
const (
	RelayPacketTypeMin = 1
	RelayPacketTypeMax = 14

	PacketRouteRequest     = 1
	PacketRouteResponse    = 2
	PacketClientToServer   = 3
	PacketServerToClient   = 4
	PacketSessionPing      = 5
	PacketSessionPong      = 6
	PacketContinueRequest  = 7
	PacketContinueResponse = 8
	PacketClientPing       = 9
	PacketClientPong       = 10
	PacketRelayPing        = 11
	PacketRelayPong        = 12
	PacketServerPing       = 13
	PacketServerPong       = 14
)

// wire sizes (relay/xdp/relay_constants.h + the handler size checks in relay_xdp.c)
const (
	HeaderBytes                 = 25   // seq(8) + session id(8) + version(1) + tag(8)
	PingTokenBytes              = 32   // sha256 of ping_token_data
	EncryptedRouteTokenBytes    = 111  // nonce(24) + route token(71) + poly1305 tag(16)
	EncryptedContinueTokenBytes = 57   // nonce(24) + continue token(17) + poly1305 tag(16)
	RelayMTU                    = 1200 // max c2s/s2c payload after the header
)

// XDP actions (uapi/linux/bpf.h), as stored in Expect.Action
const (
	ActionDrop = 1
	ActionPass = 2
	ActionTx   = 3
	// ActionAny means the entry does not assert the return value.
	ActionAny = 0xFF
)

// relay counters (relay/xdp/relay_constants.h -- mirrored by hand like the functional
// test counter table; a mismatch here shows up as a corpus differential failure).
// Only the counters the corpus actually asserts are mirrored.
const (
	CounterBasicFilterDropped    = 4
	CounterAdvancedFilterDropped = 5
	CounterSessionCreated        = 6
	CounterSessionContinued      = 7

	CounterRelayPingReceived     = 11
	CounterRelayPingDidNotVerify = 12
	CounterRelayPingExpired      = 13
	CounterRelayPingWrongSize    = 14
	CounterRelayPingUnknownRelay = 15

	CounterRelayPongReceived     = 17
	CounterRelayPongWrongSize    = 18
	CounterRelayPongUnknownRelay = 19

	CounterClientPingWrongSize    = 21
	CounterClientPingPonged       = 22
	CounterClientPingDidNotVerify = 23
	CounterClientPingExpired      = 24

	CounterRouteRequestWrongSize       = 31
	CounterRouteRequestCouldNotDecrypt = 32
	CounterRouteRequestTokenExpired    = 33
	CounterRouteRequestForward         = 34

	CounterRouteResponseWrongSize          = 41
	CounterRouteResponseCouldNotFind       = 42
	CounterRouteResponseSessionExpired     = 43
	CounterRouteResponseAlreadyReceived    = 44
	CounterRouteResponseHeaderDidNotVerify = 45
	CounterRouteResponseForward            = 46

	CounterContinueRequestWrongSize       = 51
	CounterContinueRequestCouldNotDecrypt = 52
	CounterContinueRequestTokenExpired    = 53
	CounterContinueRequestCouldNotFind    = 54
	CounterContinueRequestSessionExpired  = 55
	CounterContinueRequestForward         = 56

	CounterContinueResponseWrongSize          = 61
	CounterContinueResponseAlreadyReceived    = 62
	CounterContinueResponseCouldNotFind       = 63
	CounterContinueResponseSessionExpired     = 64
	CounterContinueResponseHeaderDidNotVerify = 65
	CounterContinueResponseForward            = 66

	CounterClientToServerTooSmall           = 71
	CounterClientToServerTooBig             = 72
	CounterClientToServerCouldNotFind       = 73
	CounterClientToServerSessionExpired     = 74
	CounterClientToServerAlreadyReceived    = 75
	CounterClientToServerHeaderDidNotVerify = 76
	CounterClientToServerForward            = 77

	CounterServerToClientTooSmall           = 81
	CounterServerToClientTooBig             = 82
	CounterServerToClientCouldNotFind       = 83
	CounterServerToClientSessionExpired     = 84
	CounterServerToClientAlreadyReceived    = 85
	CounterServerToClientHeaderDidNotVerify = 86
	CounterServerToClientForward            = 87

	CounterSessionPingWrongSize          = 91
	CounterSessionPingCouldNotFind       = 92
	CounterSessionPingSessionExpired     = 93
	CounterSessionPingAlreadyReceived    = 94
	CounterSessionPingHeaderDidNotVerify = 95
	CounterSessionPingForward            = 96

	CounterSessionPongWrongSize          = 101
	CounterSessionPongCouldNotFind       = 102
	CounterSessionPongSessionExpired     = 103
	CounterSessionPongAlreadyReceived    = 104
	CounterSessionPongHeaderDidNotVerify = 105
	CounterSessionPongForward            = 106

	CounterServerPingWrongSize    = 111
	CounterServerPingPonged       = 112
	CounterServerPingDidNotVerify = 113
	CounterServerPingExpired      = 114

	CounterPacketTooLarge         = 120
	CounterPacketTooSmall         = 121
	CounterRedirectNotInWhitelist = 124
	CounterDroppedPackets         = 125
	CounterNotInWhitelist         = 127

	// CounterAny: the entry does not assert a specific counter.
	CounterAny = 0xFFFF
	// CounterNotDroppedByGuards: the entry asserts only that NONE of the three
	// pre-handler guards (too-small, basic filter, advanced filter) dropped it --
	// the packet reached a type handler. Used by the randomized legacy families
	// where the handler outcome is not modeled.
	CounterNotDroppedByGuards = 0xFFFE
)

// Expect is the outcome an entry asserts: the XDP return value and one counter that
// must increment when the packet is processed against the world.
type Expect struct {
	Action  uint8
	Counter uint16
}

// Relay is a relay_map entry (a known relay the target relay pings).
type Relay struct {
	Address [4]byte
	Port    uint16
}

// WhitelistEntry is a whitelist_map entry (a source admitted by a verified ping).
type WhitelistEntry struct {
	Address         [4]byte
	Port            uint16
	ExpireTimestamp uint64
}

// Session is a session_map entry.
type Session struct {
	Id                            uint64
	Version                       uint8
	ExpireTimestamp               uint64
	PrivateKey                    [32]byte
	PayloadClientToServerSequence uint64
	PayloadServerToClientSequence uint64
	SpecialClientToServerSequence uint64
	SpecialServerToClientSequence uint64
	NextAddress                   [4]byte
	NextPort                      uint16
	PrevAddress                   [4]byte
	PrevPort                      uint16
	NextInternal                  uint8
	PrevInternal                  uint8
	FirstHop                      uint8
}

// World is everything the harnesses load into the relay's maps before each entry:
// config, state, and the three hash maps. Entries are checked against this exact
// world -- the harnesses reset to it before every packet, so entries are independent.
type World struct {
	Timestamp uint64

	CurrentMagic  [constants.MagicBytes]byte
	PreviousMagic [constants.MagicBytes]byte
	NextMagic     [constants.MagicBytes]byte

	RelayPublicAddress   [4]byte
	RelayInternalAddress [4]byte
	RelayPort            uint16

	PingKey   [32]byte
	SecretKey [32]byte

	Relays    []Relay
	Whitelist []WhitelistEntry
	Sessions  []Session
}

// headerFamily describes one of the six session-header-based handlers (route/continue
// response, client/server-to-server payloads, session ping/pong) so their identical
// check sequence -- size, session lookup, expiry, replay, header verify, forward -- is
// generated by one loop with the family's per-type counters and geometry.
type headerFamily struct {
	name       string
	packetType uint8
	extra      int  // bytes after the 25-byte header (ping sequence, or c2s/s2c payload)
	exact      bool // true: total size must equal header+extra; false (c2s/s2c): variable
	towardNext bool // forwards to the session's next hop (else previous hop)
	wrongSize  uint16
	notFound   uint16
	expired    uint16
	replay     uint16
	badHeader  uint16
	forward    uint16
}

// Entry is one corpus packet plus the context needed to reproduce and check it.
type Entry struct {
	Label       string
	Packet      []byte
	FromAddress [4]byte
	FromPort    uint16
	ToAddress   [4]byte
	ToPort      uint16
	Expect      Expect
}

// relayBasicPacketFilter mirrors core.BasicPacketFilter but with the relay packet-type
// range (1..14) instead of the SDK/backend range (0x32..0x3C). This is the only
// difference between the two -- see relay/xdp/relay_xdp.c.
func relayBasicPacketFilter(data []byte, packetLength int) bool {
	if packetLength < 18 {
		return false
	}
	if data[0] < RelayPacketTypeMin || data[0] > RelayPacketTypeMax {
		return false
	}
	if data[2] != (1 | ((255 - data[1]) ^ 113)) {
		return false
	}
	if data[3] < 0x2A || data[3] > 0x2D {
		return false
	}
	if data[4] < 0xC8 || data[4] > 0xE7 {
		return false
	}
	if data[5] < 0x05 || data[5] > 0x44 {
		return false
	}
	if data[7] < 0x4E || data[7] > 0x51 {
		return false
	}
	if data[8] < 0x60 || data[8] > 0xDF {
		return false
	}
	if data[9] < 0x64 || data[9] > 0xE3 {
		return false
	}
	if data[10] != 0x07 && data[10] != 0x4F {
		return false
	}
	if data[11] != 0x25 && data[11] != 0x53 {
		return false
	}
	if data[12] < 0x7C || data[12] > 0x83 {
		return false
	}
	if data[13] < 0xAF || data[13] > 0xB6 {
		return false
	}
	if data[14] < 0x21 || data[14] > 0x60 {
		return false
	}
	if data[15] != 0x61 && data[15] != 0x05 && data[15] != 0x2B && data[15] != 0x0D {
		return false
	}
	if data[16] < 0xD2 || data[16] > 0xF1 {
		return false
	}
	if data[17] < 0x11 || data[17] > 0x90 {
		return false
	}
	return true
}

// guardExpect computes the outcome for a packet that may not clear the pre-handler
// guards: size guard (< 18), then basic filter, then advanced filter (mirrors the drop
// order in relay_xdp.c). Packets that clear all three reached a type handler; the
// randomized legacy families do not model the handler outcome and assert only that.
func guardExpect(data []byte, magic []byte, fromAddress []byte, toAddress []byte) Expect {
	packetLength := len(data)
	if packetLength < 18 {
		return Expect{ActionDrop, CounterPacketTooSmall}
	}
	if packetLength > 1400 {
		return Expect{ActionDrop, CounterPacketTooLarge}
	}
	if !relayBasicPacketFilter(data, packetLength) {
		return Expect{ActionDrop, CounterBasicFilterDropped}
	}
	if !core.AdvancedPacketFilter(data, magic, fromAddress, toAddress, packetLength) {
		return Expect{ActionDrop, CounterAdvancedFilterDropped}
	}
	return Expect{ActionAny, CounterNotDroppedByGuards}
}

// signPacket writes the correct pittle+chonkle for the given magic and 4-tuple, so the
// packet passes the advanced filter (assuming a valid type and size). This is exactly
// what a real relay client does before sending.
func signPacket(packet []byte, magic []byte, fromAddress []byte, toAddress []byte) {
	core.GeneratePittle(packet[1:3], fromAddress, toAddress, len(packet))
	core.GenerateChonkle(packet[3:18], magic, fromAddress, toAddress, len(packet))
}

// headerTag is the 8-byte tag at the end of the 25-byte session header:
// sha256(session private key || type || sequence || session id || version)[0:8],
// exactly struct header_data in relay/xdp/relay_shared.h.
func headerTag(packetType uint8, sequence uint64, sessionId uint64, sessionVersion uint8, privateKey []byte) []byte {
	data := make([]byte, 32+1+8+8+1)
	index := 0
	copy(data[index:], privateKey)
	index += 32
	data[index] = packetType
	index += 1
	binary.LittleEndian.PutUint64(data[index:], sequence)
	index += 8
	binary.LittleEndian.PutUint64(data[index:], sessionId)
	index += 8
	data[index] = sessionVersion
	result := sha256.Sum256(data)
	return result[0:8]
}

// writeHeader writes the 25-byte session header (seq, sid, version, tag) at buf.
func writeHeader(buf []byte, packetType uint8, sequence uint64, sessionId uint64, sessionVersion uint8, privateKey []byte) {
	binary.LittleEndian.PutUint64(buf[0:], sequence)
	binary.LittleEndian.PutUint64(buf[8:], sessionId)
	buf[16] = sessionVersion
	copy(buf[17:25], headerTag(packetType, sequence, sessionId, sessionVersion, privateKey))
}

func udpAddr(a [4]byte, port uint16) net.UDPAddr {
	return net.UDPAddr{IP: net.IPv4(a[0], a[1], a[2], a[3]), Port: int(port)}
}

// encryptToken produces nonce||ciphertext||tag exactly as the relay expects (the relay
// reads the 24-byte XChaCha nonce off the front, then AEAD-opens the rest with its
// secret key). core.WriteEncrypted*Token draws the nonce from crypto/rand, which would
// make the corpus non-reproducible; here the nonce comes from the seeded rng instead.
// The relay never checks how the nonce was chosen, only that decryption succeeds.
func encryptToken(plaintext []byte, secretKey []byte, nonce []byte) []byte {
	aead, err := chacha20poly1305.NewX(secretKey)
	if err != nil {
		panic(err)
	}
	return aead.Seal(append([]byte{}, nonce...), nonce, plaintext, nil)
}

// DefaultWorld builds the self-contained world every corpus runs against. All keys and
// magics are seed-derived so the corpus is reproducible; all addresses are fixed.
func DefaultWorld(seed int64) World {
	rng := rand.New(rand.NewSource(seed))

	w := World{
		Timestamp:            1700000000,
		RelayPublicAddress:   [4]byte{127, 0, 0, 1},
		RelayInternalAddress: [4]byte{10, 1, 1, 1},
		RelayPort:            40000,
	}

	for i := range w.CurrentMagic {
		w.CurrentMagic[i] = byte(rng.Intn(256))
		w.PreviousMagic[i] = w.CurrentMagic[i] ^ 0xAA
		w.NextMagic[i] = w.CurrentMagic[i] ^ 0x55
	}
	for i := range w.PingKey {
		w.PingKey[i] = byte(rng.Intn(256))
	}
	for i := range w.SecretKey {
		w.SecretKey[i] = byte(rng.Intn(256))
	}

	// R1: a known relay (in relay_map AND whitelisted, as relay pings make it)
	w.Relays = []Relay{{Address: [4]byte{10, 2, 2, 2}, Port: 40000}}

	w.Whitelist = []WhitelistEntry{
		{Address: [4]byte{10, 0, 0, 1}, Port: 12345, ExpireTimestamp: w.Timestamp + 1000}, // W1: the client every gated entry sends from
		{Address: [4]byte{10, 3, 3, 3}, Port: 41000, ExpireTimestamp: w.Timestamp + 1000}, // W2: the next hop sessions forward to
		{Address: [4]byte{10, 4, 4, 4}, Port: 40000, ExpireTimestamp: w.Timestamp + 1000}, // W3: whitelisted but NOT a known relay
		{Address: [4]byte{10, 2, 2, 2}, Port: 40000, ExpireTimestamp: w.Timestamp + 1000}, // R1 (relay pings admit it)
		{Address: [4]byte{10, 5, 5, 5}, Port: 12345, ExpireTimestamp: w.Timestamp - 10},   // W4: whitelist entry ALREADY EXPIRED (sweep's job, datapath still admits)
	}

	key := func() (k [32]byte) {
		for i := range k {
			k[i] = byte(rng.Intn(256))
		}
		return
	}

	next := [4]byte{10, 3, 3, 3} // W2, whitelisted
	prev := [4]byte{10, 0, 0, 1} // W1, whitelisted
	bad := [4]byte{10, 8, 8, 8}  // never whitelisted

	w.Sessions = []Session{
		// S1: valid session, everything fresh
		{Id: 0x1111, Version: 1, ExpireTimestamp: w.Timestamp + 100, PrivateKey: key(),
			NextAddress: next, NextPort: 41000, PrevAddress: prev, PrevPort: 12345},
		// S2: expired session (per-packet expiry check drops + deletes)
		{Id: 0x2222, Version: 1, ExpireTimestamp: w.Timestamp - 10, PrivateKey: key(),
			NextAddress: next, NextPort: 41000, PrevAddress: prev, PrevPort: 12345},
		// S3: replay session -- every sequence preloaded to 1000
		{Id: 0x3333, Version: 1, ExpireTimestamp: w.Timestamp + 100, PrivateKey: key(),
			PayloadClientToServerSequence: 1000, PayloadServerToClientSequence: 1000,
			SpecialClientToServerSequence: 1000, SpecialServerToClientSequence: 1000,
			NextAddress: next, NextPort: 41000, PrevAddress: prev, PrevPort: 12345},
		// S4: next hop is NOT whitelisted (forwards toward next must drop at redirect)
		{Id: 0x4444, Version: 1, ExpireTimestamp: w.Timestamp + 100, PrivateKey: key(),
			NextAddress: bad, NextPort: 42000, PrevAddress: prev, PrevPort: 12345},
		// S5: prev hop is NOT whitelisted (forwards toward prev must drop at redirect)
		{Id: 0x5555, Version: 1, ExpireTimestamp: w.Timestamp + 100, PrivateKey: key(),
			NextAddress: next, NextPort: 41000, PrevAddress: bad, PrevPort: 42000},
	}

	return w
}

func (w *World) session(id uint64) *Session {
	for i := range w.Sessions {
		if w.Sessions[i].Id == id {
			return &w.Sessions[i]
		}
	}
	panic("no such session in world")
}

// Generate builds the deterministic corpus for a world. The seed drives the random
// portion; the structured portion is fixed. The legacy families exercise the filter
// guards with guardExpect-computed outcomes; the stateful families are constructed
// cases with precise (action, counter) expectations.
func Generate(seed int64, w World) []Entry {
	rng := rand.New(rand.NewSource(seed))

	from := [4]byte{10, 0, 0, 1} // W1, whitelisted
	fromPort := uint16(12345)
	to := w.RelayPublicAddress
	toPort := w.RelayPort
	magic := w.CurrentMagic

	randomBytes := func(b []byte) {
		for i := range b {
			b[i] = byte(rng.Intn(256))
		}
	}

	entries := make([]Entry, 0, 4096)

	// addGuard: legacy-style entry whose expectation is computed from the filter guards.
	addGuard := func(label string, packet []byte, m [constants.MagicBytes]byte, f, t [4]byte) {
		e := guardExpect(packet, m[:], f[:], t[:])
		entries = append(entries, Entry{Label: label, Packet: packet,
			FromAddress: f, FromPort: fromPort, ToAddress: t, ToPort: toPort, Expect: e})
	}

	// add: stateful entry, signed for the current magic and its own 4-tuple, with a
	// constructed expectation.
	add := func(label string, packet []byte, f [4]byte, fp uint16, t [4]byte, tp uint16, action uint8, counter uint16) {
		signPacket(packet, magic[:], f[:], t[:])
		entries = append(entries, Entry{Label: label, Packet: packet,
			FromAddress: f, FromPort: fp, ToAddress: t, ToPort: tp,
			Expect: Expect{Action: action, Counter: counter}})
	}

	// ------------------------------------------------------------------
	// legacy stateless families (filter guard coverage)
	// ------------------------------------------------------------------

	// 1. random garbage of random sizes -- almost all drop at the basic filter.
	for i := 0; i < 2000; i++ {
		n := rng.Intn(constants.MaxPacketBytes-1) + 1
		p := make([]byte, n)
		randomBytes(p)
		addGuard("random", p, magic, from, to)
	}

	// 2. every possible type byte 0x00..0xFF, otherwise a fully-signed minimum packet.
	//    outside 1..14 drops at the basic filter; inside, an 18-byte packet reaches the
	//    handler and every handler rejects it -- with a per-type counter pinned below.
	minPacketCounter := map[int]uint16{
		PacketRouteRequest:     CounterRouteRequestWrongSize,
		PacketRouteResponse:    CounterRouteResponseWrongSize,
		PacketClientToServer:   CounterClientToServerTooSmall,
		PacketServerToClient:   CounterServerToClientTooSmall,
		PacketSessionPing:      CounterSessionPingWrongSize,
		PacketSessionPong:      CounterSessionPongWrongSize,
		PacketContinueRequest:  CounterContinueRequestWrongSize,
		PacketContinueResponse: CounterContinueResponseWrongSize,
		PacketClientPing:       CounterClientPingWrongSize,
		PacketClientPong:       CounterDroppedPackets, // unhandled type after the whitelist gate
		PacketRelayPing:        CounterRelayPingWrongSize,
		PacketRelayPong:        CounterRelayPongWrongSize,
		PacketServerPing:       CounterServerPingWrongSize,
		PacketServerPong:       CounterDroppedPackets, // unhandled type after the whitelist gate
	}
	for typeByte := 0; typeByte <= 0xFF; typeByte++ {
		p := make([]byte, 18)
		p[0] = byte(typeByte)
		signPacket(p, magic[:], from[:], to[:])
		if typeByte >= RelayPacketTypeMin && typeByte <= RelayPacketTypeMax {
			entries = append(entries, Entry{Label: "type-sweep", Packet: p,
				FromAddress: from, FromPort: fromPort, ToAddress: to, ToPort: toPort,
				Expect: Expect{Action: ActionDrop, Counter: minPacketCounter[typeByte]}})
		} else {
			addGuard("type-sweep", p, magic, from, to)
		}
	}

	// 3. fully-signed, valid-type packets with random bodies at a few sizes. these
	//    clear the filters; the handler outcome is not modeled (random bodies), so
	//    they assert only that no pre-handler guard dropped them.
	for _, size := range []int{18, 100, constants.MaxPacketBytes} {
		for typeByte := RelayPacketTypeMin; typeByte <= RelayPacketTypeMax; typeByte++ {
			p := make([]byte, size)
			randomBytes(p[18:])
			p[0] = byte(typeByte)
			signPacket(p, magic[:], from[:], to[:])
			addGuard("filter-pass", p, magic, from, to)
		}
	}

	// 4. correctly signed for a DIFFERENT magic -> pass basic, drop advanced.
	var wrongMagic [constants.MagicBytes]byte
	for i := range wrongMagic {
		wrongMagic[i] = magic[i] ^ 0xFF
	}
	for typeByte := RelayPacketTypeMin; typeByte <= RelayPacketTypeMax; typeByte++ {
		p := make([]byte, 64)
		randomBytes(p[18:])
		p[0] = byte(typeByte)
		signPacket(p, wrongMagic[:], from[:], to[:])
		addGuard("wrong-magic", p, magic, from, to)
	}

	// 5. correctly signed but for a different 4-tuple -> pass basic, drop advanced.
	for typeByte := RelayPacketTypeMin; typeByte <= RelayPacketTypeMax; typeByte++ {
		p := make([]byte, 64)
		randomBytes(p[18:])
		p[0] = byte(typeByte)
		otherFrom := [4]byte{192, 168, 1, 1}
		signPacket(p, magic[:], otherFrom[:], to[:])
		addGuard("wrong-address", p, magic, from, to)
	}

	// 6. size boundaries: below the 18-byte header drops at the size guard.
	for _, size := range []int{1, 17} {
		p := make([]byte, size)
		p[0] = RelayPacketTypeMin
		addGuard("too-short", p, magic, from, to)
	}

	// 7. valid packet with a single flipped byte in the chonkle region -> drop advanced.
	for pos := 3; pos < 18; pos++ {
		p := make([]byte, 32)
		p[0] = RelayPacketTypeMin
		signPacket(p, magic[:], from[:], to[:])
		p[pos] ^= 0x01
		addGuard("chonkle-bitflip", p, magic, from, to)
	}

	// 8. packets signed for the PREVIOUS and NEXT magic also pass the advanced filter
	//    (magic rotation tolerance -- all three magics are load-bearing).
	for _, mc := range []struct {
		label string
		m     [constants.MagicBytes]byte
	}{{"previous-magic", w.PreviousMagic}, {"next-magic", w.NextMagic}} {
		p := make([]byte, 18)
		p[0] = PacketClientPong // unhandled after gate -> deterministic drop, no deeper parsing
		signPacket(p, mc.m[:], from[:], to[:])
		entries = append(entries, Entry{Label: mc.label, Packet: p,
			FromAddress: from, FromPort: fromPort, ToAddress: to, ToPort: toPort,
			Expect: Expect{Action: ActionDrop, Counter: CounterDroppedPackets}})
	}

	// ------------------------------------------------------------------
	// stateful families. every packet below is signed for the current magic and its
	// exact 4-tuple, so it clears the filters by construction; the expectation pins
	// the handler behavior against the world.
	// ------------------------------------------------------------------

	unlisted := [4]byte{10, 9, 9, 9} // never whitelisted, never a known relay

	// whitelist gate: every gated type from an un-whitelisted source drops with
	// NOT_IN_WHITELIST before its handler runs (pings are exempt -- they ARE the way in).
	for _, typeByte := range []int{PacketRouteRequest, PacketRouteResponse, PacketClientToServer,
		PacketServerToClient, PacketSessionPing, PacketSessionPong, PacketContinueRequest,
		PacketContinueResponse, PacketClientPong, PacketRelayPong, PacketServerPong} {
		p := make([]byte, 64)
		randomBytes(p[18:])
		p[0] = byte(typeByte)
		add("whitelist-gate", p, unlisted, 12345, to, toPort, ActionDrop, CounterNotInWhitelist)
	}

	// an EXPIRED whitelist entry still admits: the datapath only checks presence;
	// expiry enforcement is the control plane sweep's job. pin that.
	{
		s := w.session(0x1111)
		p := make([]byte, 18+HeaderBytes)
		p[0] = PacketRouteResponse
		writeHeader(p[18:], PacketRouteResponse, 1, s.Id, s.Version, s.PrivateKey[:])
		add("whitelist-expired-entry-still-admits", p, [4]byte{10, 5, 5, 5}, 12345, to, toPort,
			ActionTx, CounterRouteResponseForward)
	}

	// relay ping (type 11): exactly 18+8+8+1+32 bytes. source must be a known relay;
	// the token is sha256(ping key, expire, source addr:port, dest addr:port) and the
	// handler accepts a token computed for either the public or the internal address.
	relayPingPacket := func(src [4]byte, srcPort uint16, dst [4]byte, tokenDst [4]byte, expire uint64, flipToken bool) []byte {
		p := make([]byte, 18+8+8+1+PingTokenBytes)
		p[0] = PacketRelayPing
		binary.LittleEndian.PutUint64(p[18:], 7) // sequence
		binary.LittleEndian.PutUint64(p[26:], expire)
		p[34] = 0 // internal flag (informational; verify tries both dest addresses)
		srcAddr := udpAddr(src, srcPort)
		dstAddr := udpAddr(tokenDst, w.RelayPort)
		core.GeneratePingToken(expire, &srcAddr, &dstAddr, w.PingKey[:], p[35:35+PingTokenBytes])
		if flipToken {
			p[35] ^= 0x01
		}
		_ = dst
		return p
	}
	r1 := w.Relays[0].Address
	r1port := w.Relays[0].Port
	add("relay-ping-valid", relayPingPacket(r1, r1port, to, w.RelayPublicAddress, w.Timestamp+30, false),
		r1, r1port, to, toPort, ActionTx, CounterRelayPingReceived)
	add("relay-ping-valid-internal-dest-token", relayPingPacket(r1, r1port, to, w.RelayInternalAddress, w.Timestamp+30, false),
		r1, r1port, to, toPort, ActionTx, CounterRelayPingReceived)
	add("relay-ping-expired", relayPingPacket(r1, r1port, to, w.RelayPublicAddress, w.Timestamp-1, false),
		r1, r1port, to, toPort, ActionDrop, CounterRelayPingExpired)
	add("relay-ping-unknown-relay", relayPingPacket([4]byte{10, 9, 9, 8}, 40000, to, w.RelayPublicAddress, w.Timestamp+30, false),
		[4]byte{10, 9, 9, 8}, 40000, to, toPort, ActionDrop, CounterRelayPingUnknownRelay)
	add("relay-ping-bad-token", relayPingPacket(r1, r1port, to, w.RelayPublicAddress, w.Timestamp+30, true),
		r1, r1port, to, toPort, ActionDrop, CounterRelayPingDidNotVerify)
	for _, size := range []int{18 + 48, 18 + 50} { // one short of 49, one long
		p := make([]byte, size)
		randomBytes(p[18:])
		p[0] = PacketRelayPing
		add("relay-ping-wrong-size", p, r1, r1port, to, toPort, ActionDrop, CounterRelayPingWrongSize)
	}

	// client ping (type 9): exactly 18+8+8+8+32 bytes. the token source address has
	// PORT ZERO (NATs rewrite client ports) and the token dest is always checked
	// against the relay PUBLIC address. no whitelist needed -- a valid ping is what
	// admits the source.
	clientPingPacket := func(src [4]byte, expire uint64, flipToken bool) []byte {
		p := make([]byte, 18+8+8+8+PingTokenBytes)
		p[0] = PacketClientPing
		binary.LittleEndian.PutUint64(p[18:], 7)      // sequence
		binary.LittleEndian.PutUint64(p[26:], 0x1234) // session id
		binary.LittleEndian.PutUint64(p[34:], expire)
		srcAddr := udpAddr(src, 0) // port zero
		dstAddr := udpAddr(w.RelayPublicAddress, w.RelayPort)
		core.GeneratePingToken(expire, &srcAddr, &dstAddr, w.PingKey[:], p[42:42+PingTokenBytes])
		if flipToken {
			p[42] ^= 0x01
		}
		return p
	}
	add("client-ping-valid", clientPingPacket(from, w.Timestamp+30, false),
		from, fromPort, to, toPort, ActionTx, CounterClientPingPonged)
	add("client-ping-valid-unlisted-source", clientPingPacket(unlisted, w.Timestamp+30, false),
		unlisted, 5555, to, toPort, ActionTx, CounterClientPingPonged)
	add("client-ping-expired", clientPingPacket(from, w.Timestamp-1, false),
		from, fromPort, to, toPort, ActionDrop, CounterClientPingExpired)
	add("client-ping-bad-token", clientPingPacket(from, w.Timestamp+30, true),
		from, fromPort, to, toPort, ActionDrop, CounterClientPingDidNotVerify)
	for _, size := range []int{18 + 51, 18 + 53} {
		p := make([]byte, size)
		randomBytes(p[18:])
		p[0] = PacketClientPing
		add("client-ping-wrong-size", p, from, fromPort, to, toPort, ActionDrop, CounterClientPingWrongSize)
	}

	// server ping (type 13): exactly 18+8+8+32 bytes. token source includes the real
	// port; token dest is the relay public address.
	serverPingPacket := func(src [4]byte, srcPort uint16, expire uint64, flipToken bool) []byte {
		p := make([]byte, 18+8+8+PingTokenBytes)
		p[0] = PacketServerPing
		binary.LittleEndian.PutUint64(p[18:], 7) // sequence
		binary.LittleEndian.PutUint64(p[26:], expire)
		srcAddr := udpAddr(src, srcPort)
		dstAddr := udpAddr(w.RelayPublicAddress, w.RelayPort)
		core.GeneratePingToken(expire, &srcAddr, &dstAddr, w.PingKey[:], p[34:34+PingTokenBytes])
		if flipToken {
			p[34] ^= 0x01
		}
		return p
	}
	add("server-ping-valid", serverPingPacket(from, fromPort, w.Timestamp+30, false),
		from, fromPort, to, toPort, ActionTx, CounterServerPingPonged)
	add("server-ping-expired", serverPingPacket(from, fromPort, w.Timestamp-1, false),
		from, fromPort, to, toPort, ActionDrop, CounterServerPingExpired)
	add("server-ping-bad-token", serverPingPacket(from, fromPort, w.Timestamp+30, true),
		from, fromPort, to, toPort, ActionDrop, CounterServerPingDidNotVerify)
	for _, size := range []int{18 + 43, 18 + 45} {
		p := make([]byte, size)
		randomBytes(p[18:])
		p[0] = PacketServerPing
		add("server-ping-wrong-size", p, from, fromPort, to, toPort, ActionDrop, CounterServerPingWrongSize)
	}

	// relay pong (type 12): exactly 18+8 bytes, whitelist-gated, source must be a
	// known relay. a valid pong PASSES up to the control plane (kernel stack).
	{
		p := make([]byte, 18+8)
		binary.LittleEndian.PutUint64(p[18:], 7)
		p[0] = PacketRelayPong
		add("relay-pong-valid", p, r1, r1port, to, toPort, ActionPass, CounterRelayPongReceived)
	}
	{
		p := make([]byte, 18+8)
		binary.LittleEndian.PutUint64(p[18:], 7)
		p[0] = PacketRelayPong
		add("relay-pong-unknown-relay", p, [4]byte{10, 4, 4, 4}, 40000, to, toPort, ActionDrop, CounterRelayPongUnknownRelay)
	}
	for _, size := range []int{18 + 7, 18 + 9} {
		p := make([]byte, size)
		randomBytes(p[18:])
		p[0] = PacketRelayPong
		add("relay-pong-wrong-size", p, r1, r1port, to, toPort, ActionDrop, CounterRelayPongWrongSize)
	}

	// route request (type 1): at least 18 + 111 + 111 bytes (this relay's token plus
	// at least one more for the next hop). decrypts with the relay secret key, creates
	// the session, strips its token, and forwards the rest to the token's next hop --
	// which must be whitelisted.
	routeRequestPacket := func(sessionId uint64, expire uint64, nextAddr [4]byte, nextPort uint16, garbageToken bool) []byte {
		p := make([]byte, 18+EncryptedRouteTokenBytes*2)
		randomBytes(p[18+EncryptedRouteTokenBytes:]) // the next hop's token (opaque here)
		p[0] = PacketRouteRequest
		if garbageToken {
			randomBytes(p[18 : 18+EncryptedRouteTokenBytes])
			return p
		}
		token := core.RouteToken{}
		token.SessionId = sessionId
		token.SessionVersion = 1
		token.ExpireTimestamp = expire
		token.NextAddress = udpAddr(nextAddr, nextPort)
		token.PrevAddress = udpAddr(from, fromPort)
		var priv [32]byte
		copy(priv[:], w.session(0x1111).PrivateKey[:])
		token.SessionPrivateKey = priv
		plain := make([]byte, constants.RouteTokenBytes)
		core.WriteRouteToken(&token, plain)
		nonce := make([]byte, 24)
		randomBytes(nonce)
		copy(p[18:], encryptToken(plain, w.SecretKey[:], nonce))
		return p
	}
	next := [4]byte{10, 3, 3, 3}
	add("route-request-valid", routeRequestPacket(0x9999, w.Timestamp+15, next, 41000, false),
		from, fromPort, to, toPort, ActionTx, CounterSessionCreated)
	add("route-request-existing-session", routeRequestPacket(0x1111, w.Timestamp+15, next, 41000, false),
		from, fromPort, to, toPort, ActionTx, CounterRouteRequestForward)
	add("route-request-token-expired", routeRequestPacket(0x9999, w.Timestamp-10, next, 41000, false),
		from, fromPort, to, toPort, ActionDrop, CounterRouteRequestTokenExpired)
	add("route-request-bad-token", routeRequestPacket(0x9999, w.Timestamp+15, next, 41000, true),
		from, fromPort, to, toPort, ActionDrop, CounterRouteRequestCouldNotDecrypt)
	add("route-request-next-hop-not-whitelisted", routeRequestPacket(0x9999, w.Timestamp+15, [4]byte{10, 8, 8, 8}, 42000, false),
		from, fromPort, to, toPort, ActionDrop, CounterRedirectNotInWhitelist)
	{
		p := make([]byte, 18+EncryptedRouteTokenBytes*2-1)
		randomBytes(p[18:])
		p[0] = PacketRouteRequest
		add("route-request-wrong-size", p, from, fromPort, to, toPort, ActionDrop, CounterRouteRequestWrongSize)
	}

	// header-based handlers. each takes the 25-byte header (+ extra bytes for some
	// types), looks up the session, checks expiry, replay, and the sha256 header tag,
	// then forwards toward next (c2s, session ping) or prev (route/continue response,
	// s2c, session pong).
	families := []headerFamily{
		{"route-response", PacketRouteResponse, 0, true, false,
			CounterRouteResponseWrongSize, CounterRouteResponseCouldNotFind,
			CounterRouteResponseSessionExpired, CounterRouteResponseAlreadyReceived,
			CounterRouteResponseHeaderDidNotVerify, CounterRouteResponseForward},
		{"continue-response", PacketContinueResponse, 0, true, false,
			CounterContinueResponseWrongSize, CounterContinueResponseCouldNotFind,
			CounterContinueResponseSessionExpired, CounterContinueResponseAlreadyReceived,
			CounterContinueResponseHeaderDidNotVerify, CounterContinueResponseForward},
		{"client-to-server", PacketClientToServer, 100, false, true,
			CounterClientToServerTooSmall, CounterClientToServerCouldNotFind,
			CounterClientToServerSessionExpired, CounterClientToServerAlreadyReceived,
			CounterClientToServerHeaderDidNotVerify, CounterClientToServerForward},
		{"server-to-client", PacketServerToClient, 100, false, false,
			CounterServerToClientTooSmall, CounterServerToClientCouldNotFind,
			CounterServerToClientSessionExpired, CounterServerToClientAlreadyReceived,
			CounterServerToClientHeaderDidNotVerify, CounterServerToClientForward},
		{"session-ping", PacketSessionPing, 8, true, true,
			CounterSessionPingWrongSize, CounterSessionPingCouldNotFind,
			CounterSessionPingSessionExpired, CounterSessionPingAlreadyReceived,
			CounterSessionPingHeaderDidNotVerify, CounterSessionPingForward},
		{"session-pong", PacketSessionPong, 8, true, false,
			CounterSessionPongWrongSize, CounterSessionPongCouldNotFind,
			CounterSessionPongSessionExpired, CounterSessionPongAlreadyReceived,
			CounterSessionPongHeaderDidNotVerify, CounterSessionPongForward},
	}

	headerPacket := func(fam *headerFamily, s *Session, sequence uint64, flipTag bool) []byte {
		p := make([]byte, 18+HeaderBytes+fam.extra)
		if fam.extra > 0 {
			randomBytes(p[18+HeaderBytes:])
		}
		p[0] = fam.packetType
		writeHeader(p[18:], fam.packetType, sequence, s.Id, s.Version, s.PrivateKey[:])
		if flipTag {
			p[18+17] ^= 0x01
		}
		return p
	}

	for i := range families {
		fam := &families[i]
		s1 := w.session(0x1111)
		s2 := w.session(0x2222)
		s3 := w.session(0x3333)

		add(fam.name+"-valid", headerPacket(fam, s1, 1, false),
			from, fromPort, to, toPort, ActionTx, fam.forward)
		add(fam.name+"-session-expired", headerPacket(fam, s2, 1, false),
			from, fromPort, to, toPort, ActionDrop, fam.expired)
		add(fam.name+"-replay", headerPacket(fam, s3, 5, false),
			from, fromPort, to, toPort, ActionDrop, fam.replay)
		add(fam.name+"-bad-header", headerPacket(fam, s1, 1, true),
			from, fromPort, to, toPort, ActionDrop, fam.badHeader)
		{
			// unknown session: a header for a session id the world does not contain
			unknown := Session{Id: 0x7777, Version: 1}
			randomBytes(unknown.PrivateKey[:])
			add(fam.name+"-unknown-session", headerPacket(fam, &unknown, 1, false),
				from, fromPort, to, toPort, ActionDrop, fam.notFound)
		}
		{
			// redirect target not whitelisted (S4 next / S5 prev)
			s := w.session(0x4444)
			if !fam.towardNext {
				s = w.session(0x5555)
			}
			add(fam.name+"-redirect-not-whitelisted", headerPacket(fam, s, 1, false),
				from, fromPort, to, toPort, ActionDrop, CounterRedirectNotInWhitelist)
		}
		{
			// one byte short of the minimum. c2s/s2c accept any payload >= 0 so their
			// minimum is header-only; the exact-size families include the extra bytes.
			minExtra := 0
			if fam.exact {
				minExtra = fam.extra
			}
			p := make([]byte, 18+HeaderBytes+minExtra-1)
			randomBytes(p[18:])
			p[0] = fam.packetType
			add(fam.name+"-too-short", p, from, fromPort, to, toPort, ActionDrop, fam.wrongSize)
		}
		if fam.exact && fam.extra >= 0 {
			// one byte past the exact size
			p := make([]byte, 18+HeaderBytes+fam.extra+1)
			randomBytes(p[18:])
			p[0] = fam.packetType
			add(fam.name+"-too-long", p, from, fromPort, to, toPort, ActionDrop, fam.wrongSize)
		}
	}

	// c2s / s2c payload too big: payload after the header larger than RELAY_MTU (but
	// the whole packet still under the 1400-byte top-level guard). the handler computes
	// payload = len - 8 - 43, so the boundary is len > RELAY_MTU + 51.
	{
		p := make([]byte, 18+HeaderBytes+RelayMTU+9) // payload_bytes = RELAY_MTU+1
		randomBytes(p[18:])
		p[0] = PacketClientToServer
		s1 := w.session(0x1111)
		writeHeader(p[18:], PacketClientToServer, 1, s1.Id, s1.Version, s1.PrivateKey[:])
		add("client-to-server-too-big", p, from, fromPort, to, toPort, ActionDrop, CounterClientToServerTooBig)
	}
	{
		p := make([]byte, 18+HeaderBytes+RelayMTU+9)
		randomBytes(p[18:])
		p[0] = PacketServerToClient
		s1 := w.session(0x1111)
		writeHeader(p[18:], PacketServerToClient, 1, s1.Id, s1.Version, s1.PrivateKey[:])
		add("server-to-client-too-big", p, from, fromPort, to, toPort, ActionDrop, CounterServerToClientTooBig)
	}

	// continue request (type 7): at least 18 + 57 + 57 bytes. decrypts with the relay
	// secret key, extends the session expiry, strips its token, forwards to next.
	continueRequestPacket := func(sessionId uint64, expire uint64, garbageToken bool) []byte {
		p := make([]byte, 18+EncryptedContinueTokenBytes*2)
		randomBytes(p[18+EncryptedContinueTokenBytes:])
		p[0] = PacketContinueRequest
		if garbageToken {
			randomBytes(p[18 : 18+EncryptedContinueTokenBytes])
			return p
		}
		token := core.ContinueToken{}
		token.SessionId = sessionId
		token.SessionVersion = 1
		token.ExpireTimestamp = expire
		plain := make([]byte, constants.ContinueTokenBytes)
		core.WriteContinueToken(&token, plain)
		nonce := make([]byte, 24)
		randomBytes(nonce)
		copy(p[18:], encryptToken(plain, w.SecretKey[:], nonce))
		return p
	}
	add("continue-request-valid-extends", continueRequestPacket(0x1111, w.Timestamp+20, false),
		from, fromPort, to, toPort, ActionTx, CounterSessionContinued)
	add("continue-request-valid-same-expiry", continueRequestPacket(0x1111, w.Timestamp+100, false),
		from, fromPort, to, toPort, ActionTx, CounterContinueRequestForward)
	add("continue-request-token-expired", continueRequestPacket(0x1111, w.Timestamp-10, false),
		from, fromPort, to, toPort, ActionDrop, CounterContinueRequestTokenExpired)
	add("continue-request-bad-token", continueRequestPacket(0x1111, w.Timestamp+20, true),
		from, fromPort, to, toPort, ActionDrop, CounterContinueRequestCouldNotDecrypt)
	add("continue-request-unknown-session", continueRequestPacket(0x7777, w.Timestamp+20, false),
		from, fromPort, to, toPort, ActionDrop, CounterContinueRequestCouldNotFind)
	add("continue-request-session-expired", continueRequestPacket(0x2222, w.Timestamp+20, false),
		from, fromPort, to, toPort, ActionDrop, CounterContinueRequestSessionExpired)
	add("continue-request-next-hop-not-whitelisted", continueRequestPacket(0x4444, w.Timestamp+20, false),
		from, fromPort, to, toPort, ActionDrop, CounterRedirectNotInWhitelist)
	{
		p := make([]byte, 18+EncryptedContinueTokenBytes*2-1)
		randomBytes(p[18:])
		p[0] = PacketContinueRequest
		add("continue-request-wrong-size", p, from, fromPort, to, toPort, ActionDrop, CounterContinueRequestWrongSize)
	}

	// packets addressed to a different port pass through the relay untouched (the
	// relay is not in dedicated mode; the kernel stack owns other ports).
	{
		p := make([]byte, 18)
		p[0] = PacketClientPing
		signPacket(p, magic[:], from[:], to[:])
		entries = append(entries, Entry{Label: "other-port-passes-through", Packet: p,
			FromAddress: from, FromPort: fromPort, ToAddress: to, ToPort: 39999,
			Expect: Expect{Action: ActionPass, Counter: CounterAny}})
	}

	return entries
}

// corpus file format v2 (little endian), consumed by the C differential drivers
// (relay/xdp/relay_corpus_diff.c and relay/xdp/relay_userspace_test.c):
//
//	magic  "RLYC"
//	uint32 version = 2
//	uint32 count
//	world:
//	  uint64 timestamp
//	  uint8  current_magic[8] previous_magic[8] next_magic[8]
//	  uint8  relay_public_address[4] relay_internal_address[4]
//	  uint16 relay_port
//	  uint8  ping_key[32] secret_key[32]
//	  uint32 num_relays;    per relay:    uint8 address[4], uint16 port
//	  uint32 num_whitelist; per entry:    uint8 address[4], uint16 port, uint64 expire
//	  uint32 num_sessions;  per session:  uint64 id, uint8 version, uint64 expire,
//	         uint8 private_key[32], uint64 sequences[4] (payload c2s, payload s2c,
//	         special c2s, special s2c), uint8 next_address[4], uint16 next_port,
//	         uint8 prev_address[4], uint16 prev_port, uint8 next_internal,
//	         uint8 prev_internal, uint8 first_hop
//	per entry:
//	  uint8  label_length, label bytes (diagnostic only)
//	  uint8  expected_action  (0xFF = do not check)
//	  uint16 expected_counter (0xFFFF = do not check; 0xFFFE = assert the packet was
//	         not dropped by the size/basic/advanced guards)
//	  uint8  from[4]; uint16 from_port
//	  uint8  to[4];   uint16 to_port
//	  uint16 packet length; packet bytes
const (
	fileMagic   = "RLYC"
	fileVersion = 2
)

// Marshal serializes the world and corpus to the binary format above.
func Marshal(w World, entries []Entry) []byte {
	out := make([]byte, 0, 1<<20)
	var u16 [2]byte
	var u32 [4]byte
	var u64 [8]byte
	putU16 := func(v uint16) { binary.LittleEndian.PutUint16(u16[:], v); out = append(out, u16[:]...) }
	putU32 := func(v uint32) { binary.LittleEndian.PutUint32(u32[:], v); out = append(out, u32[:]...) }
	putU64 := func(v uint64) { binary.LittleEndian.PutUint64(u64[:], v); out = append(out, u64[:]...) }

	out = append(out, fileMagic...)
	putU32(fileVersion)
	putU32(uint32(len(entries)))

	putU64(w.Timestamp)
	out = append(out, w.CurrentMagic[:]...)
	out = append(out, w.PreviousMagic[:]...)
	out = append(out, w.NextMagic[:]...)
	out = append(out, w.RelayPublicAddress[:]...)
	out = append(out, w.RelayInternalAddress[:]...)
	putU16(w.RelayPort)
	out = append(out, w.PingKey[:]...)
	out = append(out, w.SecretKey[:]...)

	putU32(uint32(len(w.Relays)))
	for i := range w.Relays {
		out = append(out, w.Relays[i].Address[:]...)
		putU16(w.Relays[i].Port)
	}
	putU32(uint32(len(w.Whitelist)))
	for i := range w.Whitelist {
		out = append(out, w.Whitelist[i].Address[:]...)
		putU16(w.Whitelist[i].Port)
		putU64(w.Whitelist[i].ExpireTimestamp)
	}
	putU32(uint32(len(w.Sessions)))
	for i := range w.Sessions {
		s := &w.Sessions[i]
		putU64(s.Id)
		out = append(out, s.Version)
		putU64(s.ExpireTimestamp)
		out = append(out, s.PrivateKey[:]...)
		putU64(s.PayloadClientToServerSequence)
		putU64(s.PayloadServerToClientSequence)
		putU64(s.SpecialClientToServerSequence)
		putU64(s.SpecialServerToClientSequence)
		out = append(out, s.NextAddress[:]...)
		putU16(s.NextPort)
		out = append(out, s.PrevAddress[:]...)
		putU16(s.PrevPort)
		out = append(out, s.NextInternal, s.PrevInternal, s.FirstHop)
	}

	for i := range entries {
		e := &entries[i]
		label := e.Label
		if len(label) > 255 {
			label = label[:255]
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
		out = append(out, e.Expect.Action)
		putU16(e.Expect.Counter)
		out = append(out, e.FromAddress[:]...)
		putU16(e.FromPort)
		out = append(out, e.ToAddress[:]...)
		putU16(e.ToPort)
		putU16(uint16(len(e.Packet)))
		out = append(out, e.Packet...)
	}
	return out
}
