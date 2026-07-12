package common

import (
	"bytes"
	"context"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/networknext/next/modules/core"
)

func Bash(command string) (bool, string) {
	var output bytes.Buffer
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if err != nil {
		return false, ""
	}
	return true, output.String()
}

// IMPORTANT: the global math/rand source cannot be re-seeded in go 1.20+ (rand.Seed is a no-op),
// so the Random* functions below draw from this package level source instead. Seed it with
// SeedRandom to make them deterministic, eg. to reproduce a failed functional test locally.

var randomMutex sync.Mutex
var randomSource = rand.New(rand.NewSource(time.Now().UnixNano()))

func SeedRandom(seed int64) {
	randomMutex.Lock()
	randomSource = rand.New(rand.NewSource(seed))
	randomMutex.Unlock()
}

func RandomIntn(n int) int {
	randomMutex.Lock()
	value := randomSource.Intn(n)
	randomMutex.Unlock()
	return value
}

func RandomUint64() uint64 {
	randomMutex.Lock()
	value := randomSource.Uint64()
	randomMutex.Unlock()
	return value
}

func RandomFloat32() float32 {
	randomMutex.Lock()
	value := randomSource.Float32()
	randomMutex.Unlock()
	return value
}

func RandomBool() bool {
	value := RandomIntn(2)
	if value == 1 {
		return true
	} else {
		return false
	}
}

func RandomInt(min int, max int) int {
	difference := max - min
	value := RandomIntn(difference + 1)
	return value + min
}

func RandomBytes(array []byte) {
	for i := range array {
		array[i] = byte(RandomIntn(256))
	}
}

func RandomString(length int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	length = RandomInt(0, length-1) // IMPORTANT: for compatibility with NULL terminated C-strings in the SDK
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[RandomIntn(len(letters))]
	}
	return string(b)
}

func RandomStringFixedLength(length int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[RandomIntn(len(letters))]
	}
	return string(b)
}

func RandomAddress() net.UDPAddr {
	return core.ParseAddress(fmt.Sprintf("%d.%d.%d.%d:%d", RandomIntn(256), RandomIntn(256), RandomIntn(256), RandomIntn(256), RandomIntn(65536)))
}

func HashString(s string) uint64 {
	hash := fnv.New64a()
	hash.Write([]byte(s))
	return hash.Sum64()
}

func DatacenterId(datacenterName string) uint64 {
	return HashString(datacenterName)
}

func RelayId(relayAddress string) uint64 {
	return HashString(relayAddress)
}

// ---------------------------------------------------------------

type MinuteTicker struct {
	ticker     *time.Ticker
	nextMinute time.Time
}

func NewMinuteTicker() *MinuteTicker {
	minuteTicker := MinuteTicker{}
	minuteTicker.ticker = time.NewTicker(time.Second)
	minuteTicker.nextMinute = time.Now().Truncate(time.Minute).Add(time.Minute)
	return &minuteTicker
}

func (minuteTicker *MinuteTicker) Run(ctx context.Context, tick func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-minuteTicker.ticker.C:
			if time.Now().Unix() > minuteTicker.nextMinute.Unix() {
				go tick()
				minuteTicker.nextMinute = minuteTicker.nextMinute.Add(time.Minute)
			}
		}
	}
}

// ---------------------------------------------------------------
