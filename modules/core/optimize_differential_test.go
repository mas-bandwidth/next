package core_test

import (
	"fmt"
	"testing"

	"github.com/networknext/next/modules/core"

	"github.com/stretchr/testify/assert"
)

// pins the optimized Optimize against the straightforward pre-merge reference
// implementations in optimize_reference_test.go: output must be IDENTICAL, entry for
// entry, across geographic and uniform cost matrices, destination relay fractions,
// and segment counts. if an optimization changes anything -- ordering at the route
// cut boundary included -- this fails.

func routeEntriesEqual(t *testing.T, label string, a []core.RouteEntry, b []core.RouteEntry) {
	assert.Equal(t, len(a), len(b), label)
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("%s: route entry %d differs:\nreference: %+v\noptimized: %+v", label, i, a[i], b[i])
		}
	}
}

func TestOptimizeDifferential(t *testing.T) {

	t.Parallel()

	sizes := []int{3, 10, 50, 150}
	seeds := []int64{1, 2, 3}

	for _, uniform := range []bool{false, true} {
		for _, numRelays := range sizes {
			for _, seed := range seeds {

				costs, relayPrice, relayDatacenter, _ := generateOptimizeInputs(seed, numRelays, 0.1, uniform)

				numSegments := numRelays / 5
				if numSegments == 0 {
					numSegments = 1
				}

				label := fmt.Sprintf("uniform=%v numRelays=%d seed=%d", uniform, numRelays, seed)

				// nil destination relays == optimize all pairs (the old Optimize)

				expected := referenceOptimize(numRelays, numSegments, costs, relayPrice, relayDatacenter)
				actual := core.Optimize(numRelays, numSegments, costs, relayPrice, relayDatacenter, nil)
				routeEntriesEqual(t, label+" all pairs", expected, actual)

				// destination relay fractions (the old Optimize2)

				for _, destFraction := range []float64{0.1, 0.5, 1.0} {

					_, _, _, destRelays := generateOptimizeInputs(seed+1000, numRelays, destFraction, uniform)

					expected := referenceOptimize2(numRelays, numSegments, costs, relayPrice, relayDatacenter, destRelays)
					actual := core.Optimize(numRelays, numSegments, costs, relayPrice, relayDatacenter, destRelays)
					routeEntriesEqual(t, fmt.Sprintf("%s dest=%.1f", label, destFraction), expected, actual)
				}
			}
		}
	}
}

// documents the unified subdivision semantics: every emitted route must be strictly
// cheaper than the direct route for its pair (the direct route itself is the only
// entry allowed to equal it). the pre-merge Optimize2 violated this in the
// i -> (x) -> k -> j case, emitting dead routes that could never be selected.

func TestOptimizeNoRouteWorseThanDirect(t *testing.T) {

	t.Parallel()

	numRelays := 150
	costs, relayPrice, relayDatacenter, destRelays := generateOptimizeInputs(7, numRelays, 0.1, true)

	routes := core.Optimize(numRelays, numRelays/5, costs, relayPrice, relayDatacenter, destRelays)

	for i := range routes {
		entry := &routes[i]
		for u := 0; u < int(entry.NumRoutes); u++ {
			if entry.RouteNumRelays[u] == 2 {
				assert.Equal(t, entry.DirectCost, entry.RouteCost[u], "entry %d route %d is the direct route", i, u)
			} else {
				assert.Less(t, entry.RouteCost[u], entry.DirectCost, "entry %d route %d must beat direct", i, u)
			}
		}
	}
}
