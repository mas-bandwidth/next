package core_test

// Verbatim pre-merge snapshots of Optimize, Optimize2 and RouteManager.AddRoute
// (as of commit 4369a6546), kept as reference implementations for the differential
// test in optimize_differential_test.go. Any change to the production optimizer must
// produce IDENTICAL output to these (modulo the one documented unification: the
// reference Optimize2 x-subdivision filter below is corrected to filter on full path
// cost like Optimize does, see the KNOWN DIVERGENCE comment).
//
// Do not clean these up or redirect them at the production code -- they are only
// useful as an independent copy.

import (
	"sort"
	"sync"

	"github.com/networknext/next/modules/constants"
	"github.com/networknext/next/modules/core"
)

type referenceRouteManager struct {
	NumRoutes       int
	RouteCost       [constants.MaxRoutesPerEntry]int32
	RoutePrice      [constants.MaxRoutesPerEntry]int32
	RouteHash       [constants.MaxRoutesPerEntry]uint32
	RouteNumRelays  [constants.MaxRoutesPerEntry]int32
	RouteRelays     [constants.MaxRoutesPerEntry][constants.MaxRouteRelays]int32
	RelayDatacenter []uint64
}

func (manager *referenceRouteManager) AddRoute(cost int32, price int32, relays ...int32) {

	// no routes above cost 255 are allowed
	if cost >= 255 {
		return
	}

	// filter out any loops (yes, they can happen...)
	loopCheck := make(map[int32]int, len(relays))
	for i := range relays {
		if _, exists := loopCheck[relays[i]]; exists {
			return
		}
		loopCheck[relays[i]] = 1
	}

	if manager.NumRoutes == 0 {

		// no routes yet. add the route

		manager.NumRoutes = 1
		manager.RouteCost[0] = cost
		manager.RoutePrice[0] = price
		manager.RouteHash[0] = core.RouteHash(relays...)
		manager.RouteNumRelays[0] = int32(len(relays))
		for i := range relays {
			manager.RouteRelays[0][i] = relays[i]
		}

	} else if manager.NumRoutes < constants.MaxRoutesPerEntry {

		// not at max routes yet. insert according cost sort order

		hash := core.RouteHash(relays...)
		for i := 0; i < manager.NumRoutes; i++ {
			if hash == manager.RouteHash[i] {
				return
			}
		}

		if cost >= manager.RouteCost[manager.NumRoutes-1] {

			// cost is greater than existing entries. append.

			manager.RouteCost[manager.NumRoutes] = cost
			manager.RoutePrice[manager.NumRoutes] = price
			manager.RouteHash[manager.NumRoutes] = hash
			manager.RouteNumRelays[manager.NumRoutes] = int32(len(relays))
			for i := range relays {
				manager.RouteRelays[manager.NumRoutes][i] = relays[i]
			}
			manager.NumRoutes++

		} else {

			// cost is lower than at least one entry. insert.

			insertIndex := manager.NumRoutes - 1
			for {
				if insertIndex == 0 || cost > manager.RouteCost[insertIndex-1] {
					break
				}
				insertIndex--
			}
			manager.NumRoutes++
			for i := manager.NumRoutes - 1; i > insertIndex; i-- {
				manager.RouteCost[i] = manager.RouteCost[i-1]
				manager.RoutePrice[i] = manager.RoutePrice[i-1]
				manager.RouteHash[i] = manager.RouteHash[i-1]
				manager.RouteNumRelays[i] = manager.RouteNumRelays[i-1]
				for j := 0; j < int(manager.RouteNumRelays[i]); j++ {
					manager.RouteRelays[i][j] = manager.RouteRelays[i-1][j]
				}
			}
			manager.RouteCost[insertIndex] = cost
			manager.RoutePrice[insertIndex] = price
			manager.RouteHash[insertIndex] = hash
			manager.RouteNumRelays[insertIndex] = int32(len(relays))
			for i := range relays {
				manager.RouteRelays[insertIndex][i] = relays[i]
			}

		}

	} else {

		// route set is full. only insert if lower cost than at least one current route.

		if cost >= manager.RouteCost[manager.NumRoutes-1] {
			return
		}

		hash := core.RouteHash(relays...)
		for i := 0; i < manager.NumRoutes; i++ {
			if hash == manager.RouteHash[i] {
				return
			}
		}

		insertIndex := manager.NumRoutes - 1
		for {
			if insertIndex == 0 || cost > manager.RouteCost[insertIndex-1] {
				break
			}
			insertIndex--
		}

		for i := manager.NumRoutes - 1; i > insertIndex; i-- {
			manager.RouteCost[i] = manager.RouteCost[i-1]
			manager.RoutePrice[i] = manager.RoutePrice[i-1]
			manager.RouteHash[i] = manager.RouteHash[i-1]
			manager.RouteNumRelays[i] = manager.RouteNumRelays[i-1]
			for j := 0; j < int(manager.RouteNumRelays[i]); j++ {
				manager.RouteRelays[i][j] = manager.RouteRelays[i-1][j]
			}
		}

		manager.RouteCost[insertIndex] = cost
		manager.RoutePrice[insertIndex] = price
		manager.RouteHash[insertIndex] = hash
		manager.RouteNumRelays[insertIndex] = int32(len(relays))
		for i := range relays {
			manager.RouteRelays[insertIndex][i] = relays[i]
		}
	}
}

func referenceOptimize(numRelays int, numSegments int, cost []uint8, relayPrice []uint8, relayDatacenter []uint64) []core.RouteEntry {

	type Indirect struct {
		relay int32
		cost  uint32
	}

	indirect := make([][][]Indirect, numRelays)

	var wg sync.WaitGroup

	wg.Add(numSegments)

	for segment := 0; segment < numSegments; segment++ {

		startIndex := segment * numRelays / numSegments
		endIndex := (segment+1)*numRelays/numSegments - 1
		if segment == numSegments-1 {
			endIndex = numRelays - 1
		}

		go func(startIndex int, endIndex int) {

			defer wg.Done()

			working := make([]Indirect, numRelays)

			for i := startIndex; i <= endIndex; i++ {

				indirect[i] = make([][]Indirect, numRelays)

				for j := 0; j < numRelays; j++ {

					if i == j {
						continue
					}

					ijIndex := core.TriMatrixIndex(i, j)

					numRoutes := 0
					costDirect := uint32(cost[ijIndex])

					for x := 0; x < numRelays; x++ {
						if x == i || x == j {
							continue
						}
						ixIndex := core.TriMatrixIndex(i, x)
						ixCost := uint32(cost[ixIndex])
						xjIndex := core.TriMatrixIndex(x, j)
						xjCost := uint32(cost[xjIndex])
						indirectCost := uint32(ixCost) + uint32(xjCost)
						if indirectCost >= costDirect {
							continue
						}
						working[numRoutes].relay = int32(x)
						working[numRoutes].cost = indirectCost
						numRoutes++
					}

					if numRoutes > constants.MaxIndirects {
						sort.SliceStable(working[:numRoutes], func(i, j int) bool { return working[i].cost < working[j].cost })
						indirect[i][j] = make([]Indirect, constants.MaxIndirects)
						copy(indirect[i][j], working[:constants.MaxIndirects])
					} else if numRoutes > 0 {
						indirect[i][j] = make([]Indirect, numRoutes)
						copy(indirect[i][j], working)
					}
				}
			}

		}(startIndex, endIndex)
	}

	wg.Wait()

	entryCount := core.TriMatrixLength(numRelays)

	routes := make([]core.RouteEntry, entryCount)

	wg.Add(numSegments)

	for segment := 0; segment < numSegments; segment++ {

		startIndex := segment * numRelays / numSegments
		endIndex := (segment+1)*numRelays/numSegments - 1
		if segment == numSegments-1 {
			endIndex = numRelays - 1
		}

		go func(startIndex int, endIndex int) {

			defer wg.Done()

			for i := startIndex; i <= endIndex; i++ {

				for j := 0; j < i; j++ {

					var routeManager referenceRouteManager

					routeManager.RelayDatacenter = relayDatacenter

					index := core.TriMatrixIndex(i, j)

					directCost := int32(cost[index])

					if directCost < 255 {
						routeManager.AddRoute(directCost, int32(relayPrice[i])+int32(relayPrice[j]), int32(i), int32(j))
					}

					for k_index := range indirect[i][j] {

						k := int(indirect[i][j][k_index].relay)

						ik_cost := cost[core.TriMatrixIndex(i, k)]
						kj_cost := cost[core.TriMatrixIndex(k, j)]

						// i -> (k) -> j
						{
							ikj_cost := indirect[i][j][k_index].cost
							cost := int32(ikj_cost)
							if cost < directCost {
								routeManager.AddRoute(cost, int32(relayPrice[i])+int32(relayPrice[k])+int32(relayPrice[j]), int32(i), int32(k), int32(j))
							}
						}

						// i -> (x) -> k    ->     j

						for x_index := range indirect[i][k] {

							x := indirect[i][k][x_index].relay
							ixk_cost := indirect[i][k][x_index].cost
							cost := int32(ixk_cost) + int32(kj_cost)
							if cost < directCost {
								routeManager.AddRoute(cost, int32(relayPrice[i])+int32(relayPrice[x])+int32(relayPrice[k])+int32(relayPrice[j]), int32(i), int32(x), int32(k), int32(j))
							}
						}

						// i        -> k -> (y) -> j

						for y_index := range indirect[k][j] {
							kyj_cost := indirect[k][j][y_index].cost
							y := indirect[k][j][y_index].relay
							cost := int32(ik_cost) + int32(kyj_cost)
							if cost < directCost {
								routeManager.AddRoute(cost, int32(relayPrice[i])+int32(relayPrice[k])+int32(relayPrice[y])+int32(relayPrice[j]), int32(i), int32(k), int32(y), int32(j))
							}
						}

						// i -> (x) -> k -> (y) -> j

						for x_index := range indirect[i][k] {
							ixk_cost := indirect[i][k][x_index].cost
							x := int(indirect[i][k][x_index].relay)
							for y_index := range indirect[k][j] {
								kyj_cost := indirect[k][j][y_index].cost
								y := int(indirect[k][j][y_index].relay)
								cost := int32(ixk_cost) + int32(kyj_cost)
								if cost < directCost {
									routeManager.AddRoute(cost, int32(relayPrice[i])+int32(relayPrice[x])+int32(relayPrice[k])+int32(relayPrice[y])+int32(relayPrice[j]), int32(i), int32(x), int32(k), int32(y), int32(j))
								}
							}
						}
					}

					numRoutes := int(routeManager.NumRoutes)

					routes[index].DirectCost = int32(cost[index])
					routes[index].NumRoutes = int32(numRoutes)

					for u := 0; u < numRoutes; u++ {
						routes[index].RouteCost[u] = routeManager.RouteCost[u]
						routes[index].RoutePrice[u] = routeManager.RoutePrice[u]
						routes[index].RouteNumRelays[u] = routeManager.RouteNumRelays[u]
						numRelays := int(routes[index].RouteNumRelays[u])
						for v := 0; v < numRelays; v++ {
							routes[index].RouteRelays[u][v] = routeManager.RouteRelays[u][v]
						}
						routes[index].RouteHash[u] = routeManager.RouteHash[u]
					}
				}
			}

		}(startIndex, endIndex)
	}

	wg.Wait()

	return routes
}

func referenceOptimize2(numRelays int, numSegments int, cost []uint8, relayPrice []uint8, relayDatacenter []uint64, destinationRelay []bool) []core.RouteEntry {

	type Indirect struct {
		relay int32
		cost  uint32
	}

	indirect := make([][][]Indirect, numRelays)

	var wg sync.WaitGroup

	wg.Add(numSegments)

	for segment := 0; segment < numSegments; segment++ {

		startIndex := segment * numRelays / numSegments
		endIndex := (segment+1)*numRelays/numSegments - 1
		if segment == numSegments-1 {
			endIndex = numRelays - 1
		}

		go func(startIndex int, endIndex int) {

			defer wg.Done()

			working := make([]Indirect, numRelays)

			for i := startIndex; i <= endIndex; i++ {

				indirect[i] = make([][]Indirect, numRelays)

				for j := 0; j < numRelays; j++ {

					if i == j {
						continue
					}

					if !destinationRelay[i] && !destinationRelay[j] {
						continue
					}

					ijIndex := core.TriMatrixIndex(i, j)

					numRoutes := 0
					costDirect := uint32(cost[ijIndex])

					for x := 0; x < numRelays; x++ {
						if x == i || x == j {
							continue
						}
						ixIndex := core.TriMatrixIndex(i, x)
						ixCost := uint32(cost[ixIndex])
						xjIndex := core.TriMatrixIndex(x, j)
						xjCost := uint32(cost[xjIndex])
						indirectCost := uint32(ixCost) + uint32(xjCost)
						if indirectCost >= costDirect {
							continue
						}
						working[numRoutes].relay = int32(x)
						working[numRoutes].cost = indirectCost
						numRoutes++
					}

					if numRoutes > constants.MaxIndirects {
						sort.SliceStable(working[:numRoutes], func(i, j int) bool { return working[i].cost < working[j].cost })
						indirect[i][j] = make([]Indirect, constants.MaxIndirects)
						copy(indirect[i][j], working[:constants.MaxIndirects])
					} else if numRoutes > 0 {
						indirect[i][j] = make([]Indirect, numRoutes)
						copy(indirect[i][j], working)
					}
				}
			}

		}(startIndex, endIndex)
	}

	wg.Wait()

	entryCount := core.TriMatrixLength(numRelays)

	routes := make([]core.RouteEntry, entryCount)

	wg.Add(numSegments)

	for segment := 0; segment < numSegments; segment++ {

		startIndex := segment * numRelays / numSegments
		endIndex := (segment+1)*numRelays/numSegments - 1
		if segment == numSegments-1 {
			endIndex = numRelays - 1
		}

		go func(startIndex int, endIndex int) {

			defer wg.Done()

			for i := startIndex; i <= endIndex; i++ {

				for j := 0; j < i; j++ {

					var routeManager referenceRouteManager

					routeManager.RelayDatacenter = relayDatacenter

					index := core.TriMatrixIndex(i, j)

					directCost := int32(cost[index])

					if directCost < 255 {
						routeManager.AddRoute(directCost, int32(relayPrice[i])+int32(relayPrice[j]), int32(i), int32(j))
					}

					if destinationRelay[i] || destinationRelay[j] {

						for k_index := range indirect[i][j] {

							k := int(indirect[i][j][k_index].relay)

							ik_cost := cost[core.TriMatrixIndex(i, k)]
							kj_cost := cost[core.TriMatrixIndex(k, j)]

							// i -> (k) -> j
							{
								cost := int32(indirect[i][j][k_index].cost)
								if cost < directCost {
									routeManager.AddRoute(int32(cost), int32(relayPrice[i])+int32(relayPrice[k])+int32(relayPrice[j]), int32(i), int32(k), int32(j))
								}
							}

							// i -> (x) -> k    ->     j
							//
							// KNOWN DIVERGENCE, deliberately corrected here: the pre-merge
							// Optimize2 filtered this case on the PARTIAL cost (i->x->k only)
							// but added the route with the full cost i->x->k->j, so it could
							// emit routes with cost >= direct that Optimize never emits. such
							// routes are dead weight (route selection requires improvement
							// over direct) and waste route entry slots. the merged optimizer
							// filters on full path cost in all four cases, like Optimize
							// always did. this reference reflects the UNIFIED semantics.

							for x_index := range indirect[i][k] {

								x := indirect[i][k][x_index].relay
								ixk_cost := indirect[i][k][x_index].cost
								cost := int32(ixk_cost) + int32(kj_cost)
								if cost < directCost {
									routeManager.AddRoute(cost, int32(relayPrice[i])+int32(relayPrice[x])+int32(relayPrice[k])+int32(relayPrice[j]), int32(i), int32(x), int32(k), int32(j))
								}
							}

							// i        -> k -> (y) -> j

							for y_index := range indirect[k][j] {
								kyj_cost := indirect[k][j][y_index].cost
								y := indirect[k][j][y_index].relay
								cost := int32(ik_cost) + int32(kyj_cost)
								if cost < directCost {
									routeManager.AddRoute(cost, int32(relayPrice[i])+int32(relayPrice[k])+int32(relayPrice[y])+int32(relayPrice[j]), int32(i), int32(k), int32(y), int32(j))
								}
							}

							// i -> (x) -> k -> (y) -> j

							for x_index := range indirect[i][k] {
								ixk_cost := indirect[i][k][x_index].cost
								x := int(indirect[i][k][x_index].relay)
								for y_index := range indirect[k][j] {
									kyj_cost := indirect[k][j][y_index].cost
									y := int(indirect[k][j][y_index].relay)
									cost := int32(ixk_cost) + int32(kyj_cost)
									if cost < directCost {
										routeManager.AddRoute(cost, int32(relayPrice[i])+int32(relayPrice[x])+int32(relayPrice[k])+int32(relayPrice[y])+int32(relayPrice[j]), int32(i), int32(x), int32(k), int32(y), int32(j))
									}
								}
							}
						}
					}

					numRoutes := int(routeManager.NumRoutes)

					routes[index].DirectCost = int32(cost[index])
					routes[index].NumRoutes = int32(numRoutes)

					for u := 0; u < numRoutes; u++ {
						routes[index].RouteCost[u] = routeManager.RouteCost[u]
						routes[index].RoutePrice[u] = routeManager.RoutePrice[u]
						routes[index].RouteNumRelays[u] = routeManager.RouteNumRelays[u]
						numRelays := int(routes[index].RouteNumRelays[u])
						for v := 0; v < numRelays; v++ {
							routes[index].RouteRelays[u][v] = routeManager.RouteRelays[u][v]
						}
						routes[index].RouteHash[u] = routeManager.RouteHash[u]
					}
				}
			}

		}(startIndex, endIndex)
	}

	wg.Wait()

	return routes
}
