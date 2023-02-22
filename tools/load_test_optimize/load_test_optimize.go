package main

import (
	"context"
	"fmt"
	"time"

	"github.com/networknext/backend/modules/common"
	"github.com/networknext/backend/modules/constants"
	"github.com/networknext/backend/modules/core"
)

func RunOptimizeThread(ctx context.Context) {

	go func() {

		ticker := time.NewTicker(time.Second)

		iteration := uint64(0)

		for {

			select {

			case <-ctx.Done():
				return

			case <-ticker.C:

				numRelays := constants.MaxRelays

				size := core.TriMatrixLength(numRelays)

				costs := make([]uint8, size)

				for i := 0; i < numRelays; i++ {
					for j := 0; j < i; j++ {
						index := core.TriMatrixIndex(i, j)
						costs[index] = uint8(common.RandomInt(0, 255))
					}
				}

				numSegments := 256

				relayDatacenterIds := make([]uint64, numRelays)
				for i := range relayDatacenterIds {
					relayDatacenterIds[i] = uint64(i)
				}

				destRelays := make([]bool, numRelays)
				for i := range destRelays {
					destRelays[i] = true
				}

				start := time.Now()

				core.Optimize2(numRelays, numSegments, costs, relayDatacenterIds, destRelays)

				fmt.Printf("iteration %d: optimize %d relays (%dms)\n", iteration, numRelays, time.Since(start).Milliseconds())

				iteration++
			}
		}
	}()
}

func main() {

	RunOptimizeThread(context.Background())

	time.Sleep(time.Minute)
}
