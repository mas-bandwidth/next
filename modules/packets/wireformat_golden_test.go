package packets_test

// Wire-format golden test: pins the exact bytes the serializer produces for a
// deterministic corpus of every bit-packed type (route matrix, cost matrix, session
// data), so an accidental future wire-format change fails here. Run with -update to
// recapture.
//
// The golden bytes are the goserialize (== canonical C++ serialize) output. They match
// the pre-goserialize modules/encoding output exactly EXCEPT for empty strings: the old
// Go encoding skipped the byte-align after a zero-length string, which was a latent
// incompatibility with the C++ serialize lib (its SerializeBytes always aligns). The
// migration corrected this. Verified during the migration: 45 of 46 corpus messages
// were byte-identical old-vs-new; the one that differed (+1 byte) contained the single
// empty relay name in the corpus.

import (
	"bytes"
	"flag"
	"os"
	"testing"

	"github.com/networknext/next/modules/common"

	serialize "github.com/mas-bandwidth/goserialize"
	"github.com/networknext/next/modules/packets"

	"github.com/stretchr/testify/assert"
)

func writeSessionDataGolden(sessionData *packets.SDK_SessionData) []byte {
	buffer := [packets.SDK_MaxSessionDataSize]byte{}
	writeStream := serialize.NewWriteStream(buffer[:])
	if err := sessionData.Serialize(writeStream); err != nil {
		panic(err)
	}
	writeStream.Flush()
	return buffer[:int(writeStream.BytesProcessed())]
}

var updateGolden = flag.Bool("update", false, "recapture wire-format golden bytes")

// build a deterministic byte corpus exercising the full bit-packed surface
func buildWireCorpus() []byte {
	common.SeedRandom(20260712)
	var out bytes.Buffer

	// route matrices at a few sizes (exercises SerializeString for relay names,
	// SerializeAddress, ints, bits, bytes, floats, bools)
	for _, n := range []int{1, 5, 12} {
		rm := common.GenerateRandomRouteMatrix(n)
		b, err := rm.Write()
		if err != nil {
			panic(err)
		}
		out.Write(b)
	}

	// cost matrices
	for _, n := range []int{1, 5, 12} {
		cm := common.GenerateRandomCostMatrix(n)
		b, err := cm.Write()
		if err != nil {
			panic(err)
		}
		out.Write(b)
	}

	// session data across every version
	for i := 0; i < 40; i++ {
		sd := packets.GenerateRandomSessionData()
		b := writeSessionDataGolden(&sd)
		out.Write(b)
	}

	return out.Bytes()
}

func TestWireFormatGolden(t *testing.T) {
	const path = "testdata/wireformat_golden.bin"

	got := buildWireCorpus()

	if *updateGolden {
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d golden bytes to %s", len(got), path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to capture): %v", err)
	}

	if !bytes.Equal(got, want) {
		// find the first differing byte for a useful message
		n := len(got)
		if len(want) < n {
			n = len(want)
		}
		firstDiff := -1
		for i := 0; i < n; i++ {
			if got[i] != want[i] {
				firstDiff = i
				break
			}
		}
		t.Fatalf("wire format changed: golden %d bytes, got %d bytes, first diff at byte %d",
			len(want), len(got), firstDiff)
	}
	assert.Equal(t, len(want), len(got))
}
