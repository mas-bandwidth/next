// Package relaycorpus generates a deterministic conformance corpus for the relay's
// stateless packet-processing surface -- the basic and advanced packet filters and the
// packet-type dispatch. This is the most security-critical relay code (DDoS chaff
// filters) and the most duplicated (pittle/chonkle exist byte-identical in the Go core,
// the C++ SDK, the reference relay, and the XDP relay).
//
// The corpus is the specification. Each entry carries the packet bytes, the 4-tuple and
// magic it was built for, and the oracle verdict (does the relay filter accept it, and
// if not, at which stage it drops). The same corpus is fired at every relay
// implementation -- the reference relay over UDP, and the compiled relay_xdp.o via
// BPF_PROG_RUN -- and each must agree with the oracle. A disagreement is a wire-protocol
// divergence between implementations, which is exactly what the four hand-synced copies
// risk. See relay/CONSOLIDATION.md.
//
// The oracle here (relayBasicPacketFilter + core.AdvancedPacketFilter) is a hypothesis
// about the C relays' behavior; the differential tests are what validate it.
package relaycorpus

import (
	"encoding/binary"
	"math/rand"

	"github.com/networknext/next/modules/constants"
	"github.com/networknext/next/modules/core"
)

// relay packet types (relay/xdp/relay_constants.h). the basic filter accepts type in
// [RelayPacketTypeMin, RelayPacketTypeMax]; everything else drops at the basic filter.
const (
	RelayPacketTypeMin = 1
	RelayPacketTypeMax = 14
)

// Verdict is the oracle's prediction for how the relay filter treats a packet.
type Verdict uint8

const (
	// DropBasic: rejected by the basic packet filter (bad type, or a pittle/chonkle
	// byte outside its allowed range). No magic needed to decide this.
	DropBasic Verdict = iota
	// DropAdvanced: passes the basic filter but the pittle/chonkle bytes do not match
	// what GeneratePittle/GenerateChonkle produce for this 4-tuple and magic.
	DropAdvanced
	// Pass: passes both filters and reaches the per-type handler.
	Pass
	// DropSize: shorter than the 18-byte header, dropped by the size guard BEFORE the
	// basic filter. This is modeled on the XDP relay (the consolidation's canonical
	// datapath), which has a dedicated PACKET_TOO_SMALL guard. NOTE: the reference relay
	// instead folds the <18 check into relay_basic_packet_filter, so it attributes these
	// drops to the basic-filter counter -- a counter-accounting divergence between the
	// two relays that this corpus surfaced (see relay/CONSOLIDATION.md). Wire behavior
	// (the packet is dropped, never relayed) agrees in both.
	DropSize
)

func (v Verdict) String() string {
	switch v {
	case DropBasic:
		return "drop-basic"
	case DropAdvanced:
		return "drop-advanced"
	case Pass:
		return "pass"
	case DropSize:
		return "drop-size"
	}
	return "?"
}

// Entry is one corpus packet plus the context needed to reproduce and check it.
type Entry struct {
	Label       string
	Packet      []byte
	FromAddress [4]byte
	ToAddress   [4]byte
	Magic       [constants.MagicBytes]byte
	Verdict     Verdict
}

// relayBasicPacketFilter mirrors core.BasicPacketFilter but with the relay packet-type
// range (1..14) instead of the SDK/backend range (0x32..0x3C). This is the only
// difference between the two -- see relay/xdp/relay_xdp.c and relay/reference.
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

// oracle computes the verdict for a fully-formed packet, modeling the XDP relay's drop
// path in order: size guard (< 18), then basic filter, then advanced filter, then the
// packet reaches a type handler (Pass).
func oracle(data []byte, magic []byte, fromAddress []byte, toAddress []byte) Verdict {
	packetLength := len(data)
	if packetLength < 18 {
		return DropSize
	}
	if !relayBasicPacketFilter(data, packetLength) {
		return DropBasic
	}
	if !core.AdvancedPacketFilter(data, magic, fromAddress, toAddress, packetLength) {
		return DropAdvanced
	}
	return Pass
}

// signPacket writes the correct pittle+chonkle for the given magic and 4-tuple, so the
// packet passes the advanced filter (assuming a valid type and size). This is exactly
// what a real relay client does before sending.
func signPacket(packet []byte, magic []byte, fromAddress []byte, toAddress []byte) {
	core.GeneratePittle(packet[1:3], fromAddress, toAddress, len(packet))
	core.GenerateChonkle(packet[3:18], magic, fromAddress, toAddress, len(packet))
}

// Config parameterizes the corpus for a specific target relay. A relay only accepts
// packets signed for ITS magic and addressed to ITS address, so to check a real relay
// the corpus must be built with that relay's configuration. From is the packet source
// IP the driver will send from; To is the relay's own IP; Magic is the relay's current
// magic. (The advanced filter uses only the 4 IP bytes, not ports.)
type Config struct {
	From  [4]byte
	To    [4]byte
	Magic [constants.MagicBytes]byte
}

// DefaultConfig is a self-contained config with a seed-derived random magic, for the Go
// unit tests where there is no real relay to match.
func DefaultConfig(seed int64) Config {
	rng := rand.New(rand.NewSource(seed))
	cfg := Config{From: [4]byte{10, 0, 0, 1}, To: [4]byte{127, 0, 0, 1}}
	for i := range cfg.Magic {
		cfg.Magic[i] = byte(rng.Intn(256))
	}
	return cfg
}

// Generate builds the deterministic corpus for a target config. The seed makes the
// random portion reproducible; the structured portion is fixed. Every entry's Verdict
// is computed by the oracle from the finished bytes, so the corpus is internally
// consistent by construction and the differential only tests the C implementations
// against it.
func Generate(seed int64, cfg Config) []Entry {
	// a local, self-contained source so the corpus is fully reproducible from the seed
	// and does not perturb (or depend on) the package-global common random source.
	rng := rand.New(rand.NewSource(seed))

	from := cfg.From
	to := cfg.To
	magic := cfg.Magic

	randomBytes := func(b []byte) {
		for i := range b {
			b[i] = byte(rng.Intn(256))
		}
	}

	entries := make([]Entry, 0, 4096)

	add := func(label string, packet []byte, m [constants.MagicBytes]byte, f, t [4]byte) {
		v := oracle(packet, m[:], f[:], t[:])
		entries = append(entries, Entry{Label: label, Packet: packet, FromAddress: f, ToAddress: t, Magic: m, Verdict: v})
	}

	// 1. random garbage of random sizes -- almost all drop at the basic filter, a
	//    vanishingly rare one might pass; the oracle labels each correctly either way.
	for i := 0; i < 2000; i++ {
		n := rng.Intn(constants.MaxPacketBytes-1) + 1
		p := make([]byte, n)
		randomBytes(p)
		add("random", p, magic, from, to)
	}

	// 2. every possible type byte 0x00..0xFF, otherwise a fully-signed minimum packet.
	//    exercises the type-range check boundary (only 1..14 survive the basic filter).
	for typeByte := 0; typeByte <= 0xFF; typeByte++ {
		p := make([]byte, 18)
		p[0] = byte(typeByte)
		signPacket(p, magic[:], from[:], to[:])
		add("type-sweep", p, magic, from, to)
	}

	// 3. fully-signed, valid-type packets that should PASS both filters, one per relay
	//    type, at a few sizes.
	for _, size := range []int{18, 100, constants.MaxPacketBytes} {
		for typeByte := RelayPacketTypeMin; typeByte <= RelayPacketTypeMax; typeByte++ {
			p := make([]byte, size)
			randomBytes(p[18:])
			p[0] = byte(typeByte)
			signPacket(p, magic[:], from[:], to[:])
			add("pass", p, magic, from, to)
		}
	}

	// 4. correctly signed for a DIFFERENT magic -> pass basic, drop advanced. this is
	//    the class the advanced filter exists to catch (magic rotation / spoofing).
	var wrongMagic [constants.MagicBytes]byte
	for i := range wrongMagic {
		wrongMagic[i] = magic[i] ^ 0xFF
	}
	for typeByte := RelayPacketTypeMin; typeByte <= RelayPacketTypeMax; typeByte++ {
		p := make([]byte, 64)
		randomBytes(p[18:])
		p[0] = byte(typeByte)
		signPacket(p, wrongMagic[:], from[:], to[:]) // signed for wrongMagic, checked against magic
		add("wrong-magic", p, magic, from, to)
	}

	// 5. correctly signed but for a different 4-tuple -> pass basic, drop advanced.
	for typeByte := RelayPacketTypeMin; typeByte <= RelayPacketTypeMax; typeByte++ {
		p := make([]byte, 64)
		randomBytes(p[18:])
		p[0] = byte(typeByte)
		otherFrom := [4]byte{192, 168, 1, 1}
		signPacket(p, magic[:], otherFrom[:], to[:]) // signed for otherFrom, checked against from
		add("wrong-address", p, magic, from, to)
	}

	// 6. size boundaries: 17 bytes (below the 18-byte header) must drop at basic.
	for _, size := range []int{1, 17} {
		p := make([]byte, size)
		if size >= 1 {
			p[0] = RelayPacketTypeMin
		}
		add("too-short", p, magic, from, to)
	}

	// 7. valid packet with a single flipped byte in the chonkle region -> drop advanced.
	for pos := 3; pos < 18; pos++ {
		p := make([]byte, 32)
		p[0] = RelayPacketTypeMin
		signPacket(p, magic[:], from[:], to[:])
		p[pos] ^= 0x01
		add("chonkle-bitflip", p, magic, from, to)
	}

	return entries
}

// corpus file format (little endian), consumed by the C differential drivers:
//
//	magic  "RLYC"
//	uint32 version = 1
//	uint32 count
//	per entry:
//	  uint8  verdict
//	  uint8  from[4], to[4]
//	  uint8  magic[8]
//	  uint16 packet length
//	  bytes  packet
const (
	fileMagic   = "RLYC"
	fileVersion = 1
)

// Marshal serializes the corpus to the binary format above.
func Marshal(entries []Entry) []byte {
	out := make([]byte, 0, 1<<16)
	out = append(out, fileMagic...)
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], fileVersion)
	out = append(out, u32[:]...)
	binary.LittleEndian.PutUint32(u32[:], uint32(len(entries)))
	out = append(out, u32[:]...)
	for i := range entries {
		e := &entries[i]
		out = append(out, byte(e.Verdict))
		out = append(out, e.FromAddress[:]...)
		out = append(out, e.ToAddress[:]...)
		out = append(out, e.Magic[:]...)
		var u16 [2]byte
		binary.LittleEndian.PutUint16(u16[:], uint16(len(e.Packet)))
		out = append(out, u16[:]...)
		out = append(out, e.Packet...)
	}
	return out
}
