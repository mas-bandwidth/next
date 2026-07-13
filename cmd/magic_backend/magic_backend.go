package main

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net/http"
	"os"
	"time"

	"github.com/networknext/next/modules/common"
	"github.com/networknext/next/modules/core"
	"github.com/networknext/next/modules/envvar"
)

var magicUpdateSeconds int

var magicKey []byte

func main() {

	service := common.CreateService("magic_backend")

	magicUpdateSeconds = envvar.GetInt("MAGIC_UPDATE_SECONDS", 60)

	if magicUpdateSeconds <= 0 {
		core.Error("MAGIC_UPDATE_SECONDS must be greater than zero")
		os.Exit(1)
	}

	core.Debug("magic update seconds: %d", magicUpdateSeconds)

	// mix an optional per-install secret into the magic derivation. without it the magic
	// values are a pure function of wall clock time and constants committed to this
	// (source available) repo, so anyone who has read the source can compute them offline
	// and craft packets that pass the advanced packet filter. with it, magic stays
	// unpredictable to everyone but the operator. IMPORTANT: every magic_backend instance
	// in an env must share the same MAGIC_KEY (they already share app.env via terraform)
	// -- the stateless zero-coordination derivation depends on it. empty is deliberately
	// allowed: local dev and functional tests run without a key and fall back to the
	// constants-only derivation.

	magicKey = envvar.GetBase64("MAGIC_KEY", nil)

	if len(magicKey) > 0 {
		core.Log("magic key is set")
	} else if service.Env == "dev" || service.Env == "staging" || service.Env == "prod" {
		core.Warn("MAGIC_KEY is not set: magic values are deterministic and computable from source. run 'next config' to generate one")
	}

	service.Router.HandleFunc("/magic", magicHandler).Methods("GET")

	service.StartWebServer()

	service.WaitForShutdown()
}

func hashCounter(counter int64) []byte {
	hash := fnv.New64a()
	if len(magicKey) > 0 {
		hash.Write(magicKey)
	}
	var inputValue [8]byte
	binary.LittleEndian.PutUint64(inputValue[:], uint64(counter))
	hash.Write(inputValue[:])
	hash.Write([]byte("don't worry. be happy. :)"))
	hash.Write(fmt.Appendf(nil, "%d", counter))
	hash.Write(fmt.Appendf(nil, "%016x", counter))
	hashValue := hash.Sum64()
	var result [8]byte
	binary.LittleEndian.PutUint64(result[:], uint64(hashValue))
	return result[:]
}

func magicHandler(w http.ResponseWriter, r *http.Request) {

	timestamp := time.Now().Unix()

	counter := timestamp / int64(magicUpdateSeconds)

	var counterData [8]byte
	binary.LittleEndian.PutUint64(counterData[:], uint64(counter))

	upcomingMagic := hashCounter(counter + 2)
	currentMagic := hashCounter(counter + 1)
	previousMagic := hashCounter(counter + 0)

	core.Debug("served magic values: %x -> %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x | %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x | %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x",
		counter,
		upcomingMagic[0],
		upcomingMagic[1],
		upcomingMagic[2],
		upcomingMagic[3],
		upcomingMagic[4],
		upcomingMagic[5],
		upcomingMagic[6],
		upcomingMagic[7],
		currentMagic[0],
		currentMagic[1],
		currentMagic[2],
		currentMagic[3],
		currentMagic[4],
		currentMagic[5],
		currentMagic[6],
		currentMagic[7],
		previousMagic[0],
		previousMagic[1],
		previousMagic[2],
		previousMagic[3],
		previousMagic[4],
		previousMagic[5],
		previousMagic[6],
		previousMagic[7])

	w.Header().Set("Content-Type", "application/octet-stream")

	w.Write(counterData[:])
	w.Write(upcomingMagic[:])
	w.Write(currentMagic[:])
	w.Write(previousMagic[:])
}
