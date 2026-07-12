package relaycorpus_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/networknext/next/modules/relaycorpus"

	"github.com/stretchr/testify/assert"
)

func TestCorpus_Deterministic(t *testing.T) {
	t.Parallel()
	a := relaycorpus.Generate(42, relaycorpus.DefaultWorld(42))
	b := relaycorpus.Generate(42, relaycorpus.DefaultWorld(42))
	assert.Equal(t, len(a), len(b))
	for i := range a {
		assert.Equal(t, a[i].Packet, b[i].Packet, "entry %d packet", i)
		assert.Equal(t, a[i].Expect, b[i].Expect, "entry %d expect", i)
	}
	// a different seed produces a different corpus (the random portion moves)
	c := relaycorpus.Generate(43, relaycorpus.DefaultWorld(43))
	assert.False(t, bytes.Equal(
		relaycorpus.Marshal(relaycorpus.DefaultWorld(42), a),
		relaycorpus.Marshal(relaycorpus.DefaultWorld(43), c)))
}

func TestCorpus_ExercisesEveryOutcome(t *testing.T) {
	t.Parallel()
	entries := relaycorpus.Generate(1, relaycorpus.DefaultWorld(1))

	byAction := map[uint8]int{}
	byLabel := map[string]int{}
	for i := range entries {
		byAction[entries[i].Expect.Action]++
		byLabel[entries[i].Label]++
	}

	// the corpus is worthless if it does not reach each XDP action
	assert.Greater(t, byAction[relaycorpus.ActionDrop], 100, "want many drops")
	assert.Greater(t, byAction[relaycorpus.ActionTx], 10, "want forwarded/reflected packets")
	assert.Greater(t, byAction[relaycorpus.ActionPass], 1, "want passed-to-stack packets")

	// every stateful family must be present -- a dropped family is a silent coverage hole
	for _, label := range []string{
		"whitelist-gate", "whitelist-expired-entry-still-admits",
		"relay-ping-valid", "relay-ping-bad-token", "relay-ping-unknown-relay",
		"client-ping-valid", "client-ping-bad-token", "server-ping-valid",
		"relay-pong-valid", "relay-pong-unknown-relay",
		"route-request-valid", "route-request-bad-token", "route-request-next-hop-not-whitelisted",
		"continue-request-valid-extends", "continue-request-session-expired",
		"route-response-valid", "route-response-session-expired", "route-response-replay", "route-response-bad-header",
		"session-ping-valid", "session-pong-valid",
		"client-to-server-valid", "client-to-server-too-big",
		"server-to-client-valid", "server-to-client-too-big",
	} {
		assert.Greater(t, byLabel[label], 0, "want family %q present", label)
	}

	t.Logf("corpus: %d entries (%d drop, %d tx, %d pass, %d unchecked-action)",
		len(entries), byAction[relaycorpus.ActionDrop], byAction[relaycorpus.ActionTx],
		byAction[relaycorpus.ActionPass], byAction[relaycorpus.ActionAny])
}

func TestCorpus_TypeSweepBoundary(t *testing.T) {
	t.Parallel()
	// the type-sweep entries are otherwise-valid signed 18-byte packets differing only
	// in the type byte. types outside 1..14 drop at the basic filter; inside, each
	// reaches its handler and is rejected (too small / unhandled) -- never a filter drop.
	entries := relaycorpus.Generate(7, relaycorpus.DefaultWorld(7))
	seen := map[byte]relaycorpus.Expect{}
	for i := range entries {
		if entries[i].Label == "type-sweep" {
			seen[entries[i].Packet[0]] = entries[i].Expect
		}
	}
	assert.Equal(t, 256, len(seen))
	for typeByte := 0; typeByte <= 0xFF; typeByte++ {
		e := seen[byte(typeByte)]
		if typeByte >= 1 && typeByte <= 14 {
			assert.Equal(t, uint8(relaycorpus.ActionDrop), e.Action, "type 0x%02x should drop", typeByte)
			assert.NotEqual(t, uint16(relaycorpus.CounterBasicFilterDropped), e.Counter,
				"type 0x%02x should reach a handler, not the basic filter", typeByte)
		} else {
			assert.Equal(t, uint16(relaycorpus.CounterBasicFilterDropped), e.Counter,
				"type 0x%02x should drop at the basic filter", typeByte)
		}
	}
}

func TestCorpus_MarshalRoundTrips(t *testing.T) {
	t.Parallel()
	world := relaycorpus.DefaultWorld(3)
	entries := relaycorpus.Generate(3, world)
	data := relaycorpus.Marshal(world, entries)

	// header: "RLYC", version=2, count
	assert.Equal(t, "RLYC", string(data[0:4]))
	assert.Equal(t, uint32(2), binary.LittleEndian.Uint32(data[4:8]))
	assert.Equal(t, uint32(len(entries)), binary.LittleEndian.Uint32(data[8:12]))

	off := 12

	// world: skip the fixed-size head, then the three variable-length map arrays, so we
	// land exactly on the first entry and can walk the entry framing.
	off += 8       // timestamp
	off += 8 * 3   // three magics
	off += 4 + 4   // public + internal address
	off += 2       // relay port
	off += 32 + 32 // ping key + secret key
	numRelays := int(binary.LittleEndian.Uint32(data[off : off+4]))
	off += 4
	off += numRelays * (4 + 2)
	numWhitelist := int(binary.LittleEndian.Uint32(data[off : off+4]))
	off += 4
	off += numWhitelist * (4 + 2 + 8)
	numSessions := int(binary.LittleEndian.Uint32(data[off : off+4]))
	off += 4
	off += numSessions * (8 + 1 + 8 + 32 + 8*4 + 4 + 2 + 4 + 2 + 3)

	assert.Equal(t, len(world.Relays), numRelays)
	assert.Equal(t, len(world.Whitelist), numWhitelist)
	assert.Equal(t, len(world.Sessions), numSessions)

	for i := range entries {
		labelLen := int(data[off])
		off++
		off += labelLen
		action := data[off]
		off++
		counter := binary.LittleEndian.Uint16(data[off : off+2])
		off += 2
		var from, to [4]byte
		copy(from[:], data[off:off+4])
		off += 4
		fromPort := binary.LittleEndian.Uint16(data[off : off+2])
		off += 2
		copy(to[:], data[off:off+4])
		off += 4
		toPort := binary.LittleEndian.Uint16(data[off : off+2])
		off += 2
		plen := int(binary.LittleEndian.Uint16(data[off : off+2]))
		off += 2
		packet := data[off : off+plen]
		off += plen

		assert.Equal(t, entries[i].Expect.Action, action, "entry %d action", i)
		assert.Equal(t, entries[i].Expect.Counter, counter, "entry %d counter", i)
		assert.Equal(t, entries[i].Packet, packet, "entry %d packet", i)
		assert.Equal(t, entries[i].FromAddress, from, "entry %d from", i)
		assert.Equal(t, entries[i].FromPort, fromPort, "entry %d from port", i)
		assert.Equal(t, entries[i].ToAddress, to, "entry %d to", i)
		assert.Equal(t, entries[i].ToPort, toPort, "entry %d to port", i)
	}
	assert.Equal(t, len(data), off, "consumed the whole buffer")
}
