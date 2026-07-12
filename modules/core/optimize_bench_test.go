package core_test

import (
	"math"
	"math/rand"
	"testing"

	"github.com/networknext/next/modules/core"
)

// synthetic cost matrices for benchmarking and differential testing of the optimizer.
//
// the geographic model places relays on a sphere and derives cost from great circle
// distance plus jitter, which reproduces the triangle-inequality-ish structure of real
// RTT matrices (indirect improvements exist but are not everywhere, like production).
// the uniform model is the worst case: with uniform random costs most pairs have many
// indirect improvements, so phase 1 emits far more candidates.

func generateGeographicCostMatrix(rng *rand.Rand, numRelays int) []uint8 {
	lat := make([]float64, numRelays)
	long := make([]float64, numRelays)
	for i := 0; i < numRelays; i++ {
		lat[i] = rng.Float64()*180 - 90
		long[i] = rng.Float64()*360 - 180
	}
	costs := make([]uint8, core.TriMatrixLength(numRelays))
	for i := 0; i < numRelays; i++ {
		for j := 0; j < i; j++ {
			// approximate rtt: ~1ms per 100km of great circle distance, plus jitter
			dlat := (lat[i] - lat[j]) * math.Pi / 180
			dlong := (long[i] - long[j]) * math.Pi / 180
			a := math.Sin(dlat/2)*math.Sin(dlat/2) + math.Cos(lat[i]*math.Pi/180)*math.Cos(lat[j]*math.Pi/180)*math.Sin(dlong/2)*math.Sin(dlong/2)
			km := 6371 * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
			rtt := km/100 + rng.Float64()*10
			if rtt > 254 {
				rtt = 254
			}
			if rtt < 1 {
				rtt = 1
			}
			costs[core.TriMatrixIndex(i, j)] = uint8(rtt)
		}
	}
	return costs
}

func generateUniformCostMatrix(rng *rand.Rand, numRelays int) []uint8 {
	costs := make([]uint8, core.TriMatrixLength(numRelays))
	for i := range costs {
		costs[i] = uint8(1 + rng.Intn(254))
	}
	return costs
}

func generateOptimizeInputs(seed int64, numRelays int, destFraction float64, uniform bool) (costs []uint8, relayPrice []uint8, relayDatacenter []uint64, destRelays []bool) {
	rng := rand.New(rand.NewSource(seed))
	if uniform {
		costs = generateUniformCostMatrix(rng, numRelays)
	} else {
		costs = generateGeographicCostMatrix(rng, numRelays)
	}
	relayPrice = make([]uint8, numRelays)
	relayDatacenter = make([]uint64, numRelays)
	destRelays = make([]bool, numRelays)
	numDest := 0
	for i := 0; i < numRelays; i++ {
		relayPrice[i] = uint8(rng.Intn(10))
		relayDatacenter[i] = uint64(i + 1)
		if rng.Float64() < destFraction {
			destRelays[i] = true
			numDest++
		}
	}
	if numDest == 0 {
		destRelays[0] = true
	}
	return
}

// production shape: numSegments = numRelays / 5 (relay_backend), ~10% dest relays

func benchmarkOptimizeDest(b *testing.B, numRelays int, uniform bool) {
	costs, relayPrice, relayDatacenter, destRelays := generateOptimizeInputs(42, numRelays, 0.1, uniform)
	numSegments := numRelays / 5
	if numSegments == 0 {
		numSegments = 1
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		core.Optimize(numRelays, numSegments, costs, relayPrice, relayDatacenter, destRelays)
	}
}

func benchmarkOptimizeAllPairs(b *testing.B, numRelays int, uniform bool) {
	costs, relayPrice, relayDatacenter, _ := generateOptimizeInputs(42, numRelays, 0.1, uniform)
	numSegments := numRelays / 5
	if numSegments == 0 {
		numSegments = 1
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		core.Optimize(numRelays, numSegments, costs, relayPrice, relayDatacenter, nil)
	}
}

func BenchmarkOptimizeDest_Geo_100(b *testing.B)     { benchmarkOptimizeDest(b, 100, false) }
func BenchmarkOptimizeDest_Geo_300(b *testing.B)     { benchmarkOptimizeDest(b, 300, false) }
func BenchmarkOptimizeDest_Geo_1000(b *testing.B)    { benchmarkOptimizeDest(b, 1000, false) }
func BenchmarkOptimizeDest_Uniform_300(b *testing.B) { benchmarkOptimizeDest(b, 300, true) }
func BenchmarkOptimize_Geo_300(b *testing.B)         { benchmarkOptimizeAllPairs(b, 300, false) }
func BenchmarkOptimize_Uniform_300(b *testing.B)     { benchmarkOptimizeAllPairs(b, 300, true) }
