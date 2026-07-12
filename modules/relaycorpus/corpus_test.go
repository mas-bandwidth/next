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
	a := relaycorpus.Generate(42)
	b := relaycorpus.Generate(42)
	assert.Equal(t, len(a), len(b))
	for i := range a {
		assert.Equal(t, a[i].Packet, b[i].Packet, "entry %d packet", i)
		assert.Equal(t, a[i].Verdict, b[i].Verdict, "entry %d verdict", i)
	}
	// a different seed produces a different corpus (the random portion moves)
	c := relaycorpus.Generate(43)
	assert.False(t, bytes.Equal(relaycorpus.Marshal(a), relaycorpus.Marshal(c)))
}

func TestCorpus_ExercisesEveryVerdict(t *testing.T) {
	t.Parallel()
	entries := relaycorpus.Generate(1)
	counts := map[relaycorpus.Verdict]int{}
	for i := range entries {
		counts[entries[i].Verdict]++
	}
	// the corpus is worthless if it does not contain packets that reach each outcome
	assert.Greater(t, counts[relaycorpus.DropBasic], 100, "want many basic-filter drops")
	assert.Greater(t, counts[relaycorpus.DropAdvanced], 20, "want advanced-filter drops")
	assert.Greater(t, counts[relaycorpus.Pass], 20, "want passing packets")
	t.Logf("corpus: %d entries (%d drop-basic, %d drop-advanced, %d pass)",
		len(entries), counts[relaycorpus.DropBasic], counts[relaycorpus.DropAdvanced], counts[relaycorpus.Pass])
}

func TestCorpus_TypeSweepBoundary(t *testing.T) {
	t.Parallel()
	// the type-sweep entries are otherwise-valid signed packets differing only in the
	// type byte; exactly types 1..14 must pass, all others drop at the basic filter.
	entries := relaycorpus.Generate(7)
	seen := map[byte]relaycorpus.Verdict{}
	for i := range entries {
		if entries[i].Label == "type-sweep" {
			seen[entries[i].Packet[0]] = entries[i].Verdict
		}
	}
	assert.Equal(t, 256, len(seen))
	for typeByte := 0; typeByte <= 0xFF; typeByte++ {
		v := seen[byte(typeByte)]
		if typeByte >= 1 && typeByte <= 14 {
			assert.Equal(t, relaycorpus.Pass, v, "type 0x%02x should pass", typeByte)
		} else {
			assert.Equal(t, relaycorpus.DropBasic, v, "type 0x%02x should drop at basic", typeByte)
		}
	}
}

func TestCorpus_MarshalFormat(t *testing.T) {
	t.Parallel()
	entries := relaycorpus.Generate(3)
	data := relaycorpus.Marshal(entries)

	// header: "RLYC", version=1, count
	assert.Equal(t, "RLYC", string(data[0:4]))
	assert.Equal(t, uint32(1), binary.LittleEndian.Uint32(data[4:8]))
	assert.Equal(t, uint32(len(entries)), binary.LittleEndian.Uint32(data[8:12]))

	// walk the entries and confirm the framing round-trips to the same packets/verdicts
	off := 12
	for i := range entries {
		verdict := relaycorpus.Verdict(data[off])
		off++
		var from, to [4]byte
		copy(from[:], data[off:off+4])
		off += 4
		copy(to[:], data[off:off+4])
		off += 4
		off += 8 // magic
		plen := int(binary.LittleEndian.Uint16(data[off : off+2]))
		off += 2
		packet := data[off : off+plen]
		off += plen
		assert.Equal(t, entries[i].Verdict, verdict, "entry %d verdict", i)
		assert.Equal(t, entries[i].Packet, packet, "entry %d packet", i)
		assert.Equal(t, entries[i].FromAddress, from, "entry %d from", i)
		assert.Equal(t, entries[i].ToAddress, to, "entry %d to", i)
	}
	assert.Equal(t, len(data), off, "consumed the whole buffer")
}
