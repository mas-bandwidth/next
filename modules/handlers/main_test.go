package handlers_test

// Seeds common.SeedRandom for the whole test binary and prints the seed, following the
// functional test convention: when a test fails, reproduce with
//
//   TEST_SEED=<seed> go test -run <TestName> ./modules/handlers/
//
// GenerateRandomSessionData and friends draw exclusively from the seedable common
// random source, so a single test run under a fixed seed is deterministic. NOTE:
// tests run in parallel and share the source, so a full-suite run is only
// approximately reproducible -- rerun the failing test alone with the seed.

import (
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/networknext/next/modules/common"
)

func TestMain(m *testing.M) {
	seed := time.Now().UnixNano()
	if value := os.Getenv("TEST_SEED"); value != "" {
		var err error
		seed, err = strconv.ParseInt(value, 10, 64)
		if err != nil {
			panic(fmt.Sprintf("invalid TEST_SEED '%s'", value))
		}
	}
	fmt.Printf("random seed = %d\n", seed)
	common.SeedRandom(seed)
	os.Exit(m.Run())
}
