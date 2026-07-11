package common

/*
   Helpers for functional tests: poll process output instead of sleeping fixed amounts,
   resend UDP packets until the target process logs that it processed them, and run
   tests with a per-test watchdog and a reproducible random seed.
*/

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Buffer is a thread safe bytes.Buffer, so tests can poll process output while the process is running
type Buffer struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (b *Buffer) Write(p []byte) (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.Write(p)
}

func (b *Buffer) String() string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.String()
}

func WaitForOutput(output *Buffer, substring string, timeout time.Duration) bool {
	return WaitForOutputCount(output, substring, 1, timeout)
}

func WaitForOutputCount(output *Buffer, substring string, count int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Count(output.String(), substring) >= count {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// UDP packets can be lost even on loopback when the machine is under load, so resend until the
// process logs that it processed the packet. Counts occurrences of the substring so tests that
// trigger the same output line multiple times wait for a new occurrence, not an old one.
// Best effort: if the substring never shows up, fall through and let the test checks fail
// with the full process output.
func SendPacketUntilOutput(conn *net.UDPConn, packet []byte, to *net.UDPAddr, output *Buffer, substring string) {
	count := strings.Count(output.String(), substring) + 1
	for i := 0; i < 10; i++ {
		conn.WriteToUDP(packet, to)
		if WaitForOutputCount(output, substring, count, time.Second) {
			return
		}
	}
}

const DefaultTestTimeout = 120 * time.Second

// RunTests runs all tests, or just the test named in os.Args[1]. Each test prints a random
// seed and seeds the common random source with it, so a failed test can be reproduced exactly
// by running it again with TEST_SEED=<seed>. A watchdog panics with the test name and seed
// if any single test takes longer than the timeout (default 120 seconds).
func RunTests(allTests []func(), timeoutOverride ...time.Duration) {

	timeout := DefaultTestTimeout
	if len(timeoutOverride) == 1 {
		timeout = timeoutOverride[0]
	}

	var tests []func()

	if len(os.Args) > 1 {
		funcName := os.Args[1]
		for _, test := range allTests {
			name := testName(test)
			if funcName == name {
				tests = append(tests, test)
				break
			}
		}
		if len(tests) == 0 {
			panic(fmt.Sprintf("could not find any test: '%s'", funcName))
		}
	} else {
		tests = allTests
	}

	for i := range tests {

		seed := time.Now().UnixNano()
		if value := os.Getenv("TEST_SEED"); value != "" {
			var err error
			seed, err = strconv.ParseInt(value, 10, 64)
			if err != nil {
				panic(fmt.Sprintf("invalid TEST_SEED '%s'", value))
			}
		}

		fmt.Printf("random seed = %d\n", seed)

		SeedRandom(seed)

		name := testName(tests[i])

		done := make(chan struct{})

		go func(name string, seed int64) {
			select {
			case <-done:
			case <-time.After(timeout):
				panic(fmt.Sprintf("test %s took too long! reproduce with TEST_SEED=%d ./<test binary> %s", name, seed, name))
			}
		}(name, seed)

		tests[i]()

		close(done)
	}
}

func testName(test func()) string {
	name := runtime.FuncForPC(reflect.ValueOf(test).Pointer()).Name()
	return name[strings.LastIndex(name, ".")+1:]
}
