package main

import (
	"encoding/binary"
	"io"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/networknext/next/modules/common"
	"github.com/networknext/next/modules/constants"
	"github.com/networknext/next/modules/core"
	"github.com/networknext/next/modules/encoding"
	"github.com/networknext/next/modules/envvar"
)

const MaxServerAddressLength = 64 // IMPORTANT: Enough for IPv4 and IPv6 + port number

const TopServersCount = 10000

const ServerBatchVersion = uint64(1)

const TopServersVersion = uint64(1)

type ServerUpdate struct {
	serverId uint64
}

type TopServers struct {
	numTopServers int
	topServers    [TopServersCount]uint64
}

type Bucket struct {
	index               int
	mutex               sync.Mutex
	serverUpdateChannel chan []ServerUpdate
	servers             *common.SortedSet
}

var buckets []Bucket

var topServersMutex sync.Mutex
var topServersData []byte

var service *common.Service

var channelSize int

func main() {

	channelSize = envvar.GetInt("CHANNEL_SIZE", 10000)

	service = common.CreateService("server_cruncher")

	service.Router.HandleFunc("/server_batch", serverBatchHandler).Methods("POST")
	service.Router.HandleFunc("/top_servers", topServersHandler).Methods("GET")

	buckets = make([]Bucket, constants.NumBuckets)
	for i := range buckets {
		buckets[i].index = i
		buckets[i].serverUpdateChannel = make(chan []ServerUpdate, channelSize)
		buckets[i].servers = common.NewSortedSet()
		StartProcessThread(&buckets[i])
	}

	UpdateTopServers(&TopServers{})

	// go TestThread()

	go TopSessionsThread()

	service.StartWebServer()

	service.WaitForShutdown()
}

func TestThread() {
	for {
		for index := range constants.NumBuckets {
			batch := make([]ServerUpdate, 1000)
			for i := range batch {
				batch[i].serverId = rand.Uint64()
			}
			buckets[index].serverUpdateChannel <- batch
			time.Sleep(time.Millisecond)
		}
	}
}

func StartProcessThread(bucket *Bucket) {
	go func() {
		for {
			select {
			case batch := <-bucket.serverUpdateChannel:
				bucket.mutex.Lock()
				for i := range batch {
					bucket.servers.Insert(batch[i].serverId, uint32(bucket.index))
				}
				bucket.mutex.Unlock()
			}
		}
	}()
}

func UpdateTopServers(newTopServers *TopServers) {

	data := make([]byte, 8+4+newTopServers.numTopServers*MaxServerAddressLength)

	index := 0

	encoding.WriteUint64(data[:], &index, TopServersVersion)
	encoding.WriteUint32(data[:], &index, uint32(newTopServers.numTopServers))

	for i := 0; i < newTopServers.numTopServers; i++ {
		encoding.WriteUint64(data[:], &index, newTopServers.topServers[i])
	}

	topServersMutex.Lock()
	topServersData = data[:index]
	topServersMutex.Unlock()
}

func TopSessionsThread() {
	minuteTicker := common.NewMinuteTicker()
	minuteTicker.Run(service.Context, func() {

		core.Debug("-------------------------------------------------------------------")

		servers := make([]*common.SortedSet, constants.NumBuckets)

		for i := range constants.NumBuckets {
			buckets[i].mutex.Lock()
		}

		for i := range constants.NumBuckets {
			servers[i] = buckets[i].servers
			buckets[i].servers = common.NewSortedSet()
		}

		for i := range constants.NumBuckets {
			buckets[i].mutex.Unlock()
		}

		start := time.Now()

		// calculate server count and the set of top servers

		serversMap := make(map[uint64]bool, TopServersCount)

		type Server struct {
			serverId uint64
			score    uint32
		}

		topServers := make([]Server, 0, TopServersCount)

		for i := range constants.NumBuckets {
			bucketServers := servers[i].GetByRankRange(1, -1)
			for j := range bucketServers {
				if _, exists := serversMap[bucketServers[j].Key]; !exists {
					serversMap[bucketServers[j].Key] = true
					topServers = append(topServers, Server{serverId: bucketServers[j].Key, score: bucketServers[j].Score})
					if len(topServers) >= TopServersCount {
						goto done
					}
				}
			}
		}

	done:

		newTopServers := &TopServers{}
		newTopServers.numTopServers = len(topServers)
		for i := range topServers {
			newTopServers.topServers[i] = topServers[i].serverId
		}

		UpdateTopServers(newTopServers)

		duration := time.Since(start)

		core.Debug("top %d servers (%.6fms)", len(topServers), float64(duration.Nanoseconds())/1000000.0)
	})
}

func serverBatchHandler(w http.ResponseWriter, r *http.Request) {

	body, err := io.ReadAll(r.Body)
	if err != nil {
		core.Error("could not read server batch body: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer r.Body.Close()

	if len(body) < 8 {
		core.Error("server batch is too small")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	version := binary.LittleEndian.Uint64(body[0:8])

	if version != ServerBatchVersion {
		core.Error("server batch has unknown version %d, expected %d\n", version, ServerBatchVersion)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body = body[8:]

	const bytesPerUpdate = 8 // serverId

	index := 0
	for j := range constants.NumBuckets {
		var numUpdates uint32
		if !encoding.ReadUint32(body[:], &index, &numUpdates) {
			core.Error("server batch truncated reading bucket count")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// bound the allocation to what the remaining body can actually contain, so a malformed
		// count can't drive an enormous allocation (OOM)
		if int(numUpdates) > (len(body)-index)/bytesPerUpdate {
			core.Error("server batch bucket claims %d updates but body is too small", numUpdates)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if numUpdates > 0 {
			batch := make([]ServerUpdate, numUpdates)
			for i := 0; i < int(numUpdates); i++ {
				encoding.ReadUint64(body, &index, &batch[i].serverId)
			}
			buckets[j].serverUpdateChannel <- batch
		}
	}
}

func topServersHandler(w http.ResponseWriter, r *http.Request) {
	topServersMutex.Lock()
	data := topServersData
	topServersMutex.Unlock()
	w.Write(data)
}

// ---------------------------------------------------------------------------------------
