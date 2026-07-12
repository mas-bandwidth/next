package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/networknext/next/modules/common"
	"github.com/networknext/next/modules/constants"
	"github.com/networknext/next/modules/core"
	"github.com/networknext/next/modules/encoding"
	"github.com/networknext/next/modules/envvar"
)

const TopSessionsCount = 10000

const SessionBatchVersion = uint64(0)

const TopSessionsVersion = uint64(0)

const BuyerStatsVersion = uint64(0)

const MapPointsVersion = uint64(0)

type SessionUpdate struct {
	sessionId uint64
	next      uint8
	latitude  float32
	longitude float32
}

type TopSessions struct {
	numTopSessions int
	topSessions    [TopSessionsCount]uint64
}

type Bucket struct {
	index                int
	mutex                sync.Mutex
	sessionUpdateChannel chan []SessionUpdate
	totalSessions        *common.SortedSet
	mapEntries           map[uint64]MapEntry
}

var buckets []Bucket

var topSessionsMutex sync.Mutex
var topSessionsData []byte

type MapEntry struct {
	latitude  float32
	longitude float32
	next      uint8
}

type MapPoint struct {
	sessionId uint64
	next      uint8
	latitude  float32
	longitude float32
}

type MapPoints struct {
	numMapPoints int
	mapPoints    [TopSessionsCount]MapPoint
}

var mapDataMutex sync.Mutex
var mapData []byte

var channelSize int

var enableRedisTimeSeries bool
var redisTimeSeriesCluster []string
var redisTimeSeriesHostname string

var service *common.Service

func main() {

	channelSize = envvar.GetInt("CHANNEL_SIZE", 10000)

	enableRedisTimeSeries = envvar.GetBool("ENABLE_REDIS_TIME_SERIES", false)
	redisTimeSeriesCluster = envvar.GetStringArray("REDIS_TIME_SERIES_CLUSTER", []string{})
	redisTimeSeriesHostname = envvar.GetString("REDIS_TIME_SERIES_HOSTNAME", "127.0.0.1:6379")

	if enableRedisTimeSeries {
		core.Debug("redis time series cluster: %s", redisTimeSeriesCluster)
		core.Debug("redis time series hostname: %s", redisTimeSeriesHostname)
	}

	service = common.CreateService("session_cruncher")

	service.LoadDatabase(nil, nil)

	service.Router.HandleFunc("/session_batch", sessionBatchHandler).Methods("POST")
	service.Router.HandleFunc("/top_sessions", topSessionsHandler).Methods("GET")
	service.Router.HandleFunc("/map_data", mapDataHandler).Methods("GET")

	buckets = make([]Bucket, constants.NumBuckets)
	for i := range buckets {
		buckets[i].index = i
		buckets[i].sessionUpdateChannel = make(chan []SessionUpdate, channelSize)
		buckets[i].totalSessions = common.NewSortedSet()
		buckets[i].mapEntries = make(map[uint64]MapEntry, 10000)
		StartProcessThread(&buckets[i])
	}

	UpdateTopSessions(&TopSessions{})

	UpdateMapData(&MapPoints{})

	//go TestThread()

	go TopSessionsThread()

	go UpdateAcceleratedPercent(service)

	service.StartWebServer()

	service.WaitForShutdown()
}

func UpdateAcceleratedPercent(service *common.Service) {

	if !enableRedisTimeSeries {
		return
	}

	// calculate accelerated percent once per-second from counters

	countersConfig := common.RedisCountersConfig{
		RedisHostname: redisTimeSeriesHostname,
		RedisCluster:  redisTimeSeriesCluster,
	}

	countersWatcher, err := common.CreateRedisCountersWatcher(service.Context, countersConfig)
	if err != nil {
		core.Error("could not create redis counters watcher: %v", err)
		os.Exit(1)
	}

	timeSeriesConfig := common.RedisTimeSeriesConfig{
		RedisHostname: redisTimeSeriesHostname,
		RedisCluster:  redisTimeSeriesCluster,
	}

	timeSeriesPublisher, err := common.CreateRedisTimeSeriesPublisher(service.Context, timeSeriesConfig)
	if err != nil {
		core.Error("could not create redis time series publisher: %v", err)
		os.Exit(1)
	}

	go func() {

		minuteTicker := common.NewMinuteTicker()
		minuteTicker.Run(service.Context, func() {

			database := service.Database()
			if database == nil {
				core.Error("database is nil")
				return
			}

			keys := []string{
				"session_update",
				"next_session_update",
			}

			buyerIds := database.GetBuyerIds()
			for i := range buyerIds {
				keys = append(keys, fmt.Sprintf("session_update_%016x", buyerIds[i]))
				keys = append(keys, fmt.Sprintf("next_session_update_%016x", buyerIds[i]))
			}

			countersWatcher.SetKeys(keys)

			keys = []string{}
			values := []float64{}

			// IMPORTANT: the watcher getters read maps and slices that the watcher thread
			// replaces every second, so they must be called with the watcher locked
			countersWatcher.Lock()

			sessionUpdates := countersWatcher.GetFloatValue("session_update")
			nextSessionUpdates := countersWatcher.GetFloatValue("next_session_update")
			if sessionUpdates > 0 {
				acceleratedPercent := nextSessionUpdates / sessionUpdates * 100.0
				if acceleratedPercent > 100.0 {
					acceleratedPercent = 100.0
				}
				keys = append(keys, "accelerated_percent")
				values = append(values, acceleratedPercent)
			}

			for i := range buyerIds {
				sessionUpdates := countersWatcher.GetFloatValue(fmt.Sprintf("session_update_%016x", buyerIds[i]))
				nextSessionUpdates := countersWatcher.GetFloatValue(fmt.Sprintf("next_session_update_%016x", buyerIds[i]))
				if sessionUpdates > 0 {
					acceleratedPercent := nextSessionUpdates / sessionUpdates * 100.0
					if acceleratedPercent > 100.0 {
						acceleratedPercent = 100.0
					}
					keys = append(keys, fmt.Sprintf("accelerated_percent_%016x", buyerIds[i]))
					values = append(values, acceleratedPercent)
				}
			}

			countersWatcher.Unlock()

			message := common.RedisTimeSeriesMessage{}
			message.Timestamp = uint64(time.Now().UnixNano() / 1000000)
			message.Keys = keys
			message.Values = values
			timeSeriesPublisher.MessageChannel <- &message
		})
	}()
}

func TestThread() {
	for {
		for index := range constants.NumBuckets {
			batch := make([]SessionUpdate, 1000)
			for i := range batch {
				batch[i].sessionId = rand.Uint64()
				batch[i].next = uint8(i % 2)
				batch[i].latitude = rand.Float32()
				batch[i].longitude = rand.Float32()
			}
			buckets[index].sessionUpdateChannel <- batch
			time.Sleep(2 * time.Millisecond)
		}
	}
}

func StartProcessThread(bucket *Bucket) {
	go func() {
		for {
			select {
			case batch := <-bucket.sessionUpdateChannel:
				bucket.mutex.Lock()
				for i := range batch {
					bucket.totalSessions.Insert(batch[i].sessionId, uint32(bucket.index))
					bucket.mapEntries[batch[i].sessionId] = MapEntry{next: batch[i].next, latitude: batch[i].latitude, longitude: batch[i].longitude}
				}
				bucket.mutex.Unlock()
			}
		}
	}()
}

func UpdateTopSessions(newTopSessions *TopSessions) {

	data := make([]byte, 8+8*newTopSessions.numTopSessions)

	index := 0

	encoding.WriteUint64(data[:], &index, TopSessionsVersion)

	for i := 0; i < newTopSessions.numTopSessions; i++ {
		encoding.WriteUint64(data[:], &index, newTopSessions.topSessions[i])
	}

	topSessionsMutex.Lock()
	topSessionsData = data
	topSessionsMutex.Unlock()
}

func UpdateMapData(newMapPoints *MapPoints) {

	data := make([]byte, 8+4+newMapPoints.numMapPoints*(8+1+4+4))

	index := 0

	encoding.WriteUint64(data[:], &index, MapPointsVersion)
	encoding.WriteUint32(data[:], &index, uint32(newMapPoints.numMapPoints))

	for i := 0; i < newMapPoints.numMapPoints; i++ {
		encoding.WriteUint64(data[:], &index, newMapPoints.mapPoints[i].sessionId)
		encoding.WriteUint8(data[:], &index, newMapPoints.mapPoints[i].next)
		encoding.WriteFloat32(data[:], &index, newMapPoints.mapPoints[i].latitude)
		encoding.WriteFloat32(data[:], &index, newMapPoints.mapPoints[i].longitude)
	}

	mapDataMutex.Lock()
	mapData = data
	mapDataMutex.Unlock()
}

func TopSessionsThread() {
	minuteTicker := common.NewMinuteTicker()
	minuteTicker.Run(service.Context, func() {

		core.Debug("-------------------------------------------------------------------")

		totalSessions := make([]*common.SortedSet, constants.NumBuckets)
		mapEntries := make([]map[uint64]MapEntry, constants.NumBuckets)

		for i := range constants.NumBuckets {
			buckets[i].mutex.Lock()
		}

		for i := range constants.NumBuckets {
			totalSessions[i] = buckets[i].totalSessions
			mapEntries[i] = buckets[i].mapEntries
			buckets[i].totalSessions = common.NewSortedSet()
			buckets[i].mapEntries = make(map[uint64]MapEntry, TopSessionsCount)
		}

		for i := range constants.NumBuckets {
			buckets[i].mutex.Unlock()
		}

		start := time.Now()

		// build top sessions list

		totalSessionsMap := make(map[uint64]bool, TopSessionsCount)

		type Session struct {
			sessionId uint64
			score     uint32
		}

		sessions := make([]Session, 0, TopSessionsCount)

		for i := range constants.NumBuckets {
			bucketTotalSessions := totalSessions[i].GetByRankRange(1, -1)
			for j := range bucketTotalSessions {
				if _, exists := totalSessionsMap[bucketTotalSessions[j].Key]; !exists {
					totalSessionsMap[bucketTotalSessions[j].Key] = true
					sessions = append(sessions, Session{sessionId: bucketTotalSessions[j].Key, score: bucketTotalSessions[j].Score})
					if len(sessions) >= TopSessionsCount {
						goto done
					}
				}
			}
		}

	done:

		sort.SliceStable(sessions, func(i, j int) bool { return sessions[i].sessionId < sessions[j].sessionId })
		sort.SliceStable(sessions, func(i, j int) bool { return sessions[i].score < sessions[j].score })

		newTopSessions := &TopSessions{}
		newTopSessions.numTopSessions = len(sessions)
		for i := range sessions {
			newTopSessions.topSessions[i] = sessions[i].sessionId
		}

		UpdateTopSessions(newTopSessions)

		// build data for the map, derived from the top sessions list

		newMapPoints := MapPoints{}
		newMapPoints.numMapPoints = len(sessions)
		for i := range sessions {
			newMapPoints.mapPoints[i].sessionId = sessions[i].sessionId
			score := sessions[i].score
			entry := mapEntries[score][sessions[i].sessionId]
			newMapPoints.mapPoints[i].next = entry.next
			newMapPoints.mapPoints[i].latitude = entry.latitude
			newMapPoints.mapPoints[i].longitude = entry.longitude
		}

		UpdateMapData(&newMapPoints)

		duration := time.Since(start)

		core.Debug("top %d sessions (%.6fms)", len(sessions), float64(duration.Nanoseconds())/1000000.0)
	})
}

func sessionBatchHandler(w http.ResponseWriter, r *http.Request) {

	body, err := io.ReadAll(r.Body)
	if err != nil {
		core.Error("could not read session batch body: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer r.Body.Close()

	if len(body) < 8 {
		core.Error("session batch is too small")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	version := binary.LittleEndian.Uint64(body[0:8])

	if version != SessionBatchVersion {
		core.Error("session batch has unknown version %d, expected %d\n", version, SessionBatchVersion)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body = body[8:]

	const bytesPerUpdate = 8 + 1 + 4 + 4 // sessionId + next + latitude + longitude

	index := 0
	for j := range constants.NumBuckets {
		var numUpdates uint32
		if !encoding.ReadUint32(body[:], &index, &numUpdates) {
			core.Error("session batch truncated reading bucket count")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// bound the allocation to what the remaining body can actually contain, so a malformed
		// count can't drive an enormous allocation (OOM)
		if int(numUpdates) > (len(body)-index)/bytesPerUpdate {
			core.Error("session batch bucket claims %d updates but body is too small", numUpdates)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if numUpdates > 0 {
			batch := make([]SessionUpdate, numUpdates)
			for i := 0; i < int(numUpdates); i++ {
				encoding.ReadUint64(body[:], &index, &batch[i].sessionId)
				encoding.ReadUint8(body[:], &index, &batch[i].next)
				encoding.ReadFloat32(body[:], &index, &batch[i].latitude)
				encoding.ReadFloat32(body[:], &index, &batch[i].longitude)
			}
			buckets[j].sessionUpdateChannel <- batch
		}
	}
}

func topSessionsHandler(w http.ResponseWriter, r *http.Request) {
	topSessionsMutex.Lock()
	data := topSessionsData
	topSessionsMutex.Unlock()
	w.Write(data)
}

func mapDataHandler(w http.ResponseWriter, r *http.Request) {
	mapDataMutex.Lock()
	data := mapData
	mapDataMutex.Unlock()
	w.Write(data)
}

// ---------------------------------------------------------------------------------------
