package main

import (
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/networknext/backend/modules/constants"
	"github.com/networknext/backend/modules/common"
	"github.com/networknext/backend/modules/core"
	"github.com/networknext/backend/modules/crypto"
	"github.com/networknext/backend/modules/envvar"
	"github.com/networknext/backend/modules/packets"
	"github.com/networknext/backend/modules/handlers"
	db "github.com/networknext/backend/modules/database"
)

var ServerBackendAddress = core.ParseAddress("127.0.0.1:50000")
var ServerBackendPublicKey []byte
var ServerBackendPrivateKey []byte

var DatacenterId uint64

var BuyerId uint64
var BuyerPublicKey []byte
var BuyerPrivateKey []byte

type Update struct {
	from       net.UDPAddr
	packetData []byte
}

func RunSessionUpdateThreads(threadCount int, updateChannels []chan *Update) {

	for k := 0; k < threadCount; k++ {

		go func(thread int) {

			time.Sleep(time.Duration(rand.Intn(10000)) * time.Millisecond)

			const NumServers = 1000

			serverAddresses := make([]net.UDPAddr, NumServers)
			for i := range serverAddresses {
				serverAddresses[i] = core.ParseAddress(fmt.Sprintf("127.0.%d.%d:%d", i>>8, i&0xFF, 2000+thread))
			}

			for {

				for j := 0; j < NumServers; j++ {

					packet := packets.SDK5_ServerUpdateRequestPacket{
						Version:      packets.SDKVersion{5, 0, 0},
						BuyerId:      BuyerId,
						RequestId:    rand.Uint64(),
						DatacenterId: DatacenterId,
					}

					packetData, err := packets.SDK5_WritePacket(&packet, packets.SDK5_SERVER_UPDATE_REQUEST_PACKET, packets.SDK5_MaxPacketBytes, &serverAddresses[j], &ServerBackendAddress, BuyerPrivateKey[:])
					if err != nil {
						panic("failed to write server update packet")
					}

					updateChannel := updateChannels[j%len(updateChannels)]

					update := Update{}
					update.from = serverAddresses[j]
					update.packetData = packetData

					updateChannel <- &update
				}

				time.Sleep(10 * time.Second)
			}
		}(k)
	}
}

func RunHandlerThreads(threadCount int, updateChannels []chan *Update, numSessionUpdatesProcessed *uint64) {

	for k := 0; k < threadCount; k++ {

		go func(thread int) {

			updateChannel := updateChannels[thread]

			buyer := db.Buyer{}
			buyer.Id = BuyerId
			buyer.Name = "buyer"
			buyer.Live = true
			buyer.Debug = false
			buyer.PublicKey = BuyerPublicKey[:]
			buyer.RouteShader = core.NewRouteShader()

			datacenter := db.Datacenter{}
			datacenter.Id = DatacenterId
			datacenter.Name = "datacenter"
			datacenter.Latitude = 100
			datacenter.Longitude = 200

			database := db.CreateDatabase()
			database.BuyerMap[BuyerId] = &buyer
			database.DatacenterMap[DatacenterId] = &datacenter

			handler := handlers.SDK5_Handler{}
			handler.Database = database
			handler.RouteMatrix = &common.RouteMatrix{}
			handler.ServerBackendAddress = ServerBackendAddress
			handler.ServerBackendPublicKey = ServerBackendPublicKey
			handler.ServerBackendPrivateKey = ServerBackendPrivateKey
			handler.MaxPacketSize = packets.SDK5_MaxPacketBytes
			handler.GetMagicValues = func() ([constants.MagicBytes]byte, [constants.MagicBytes]byte, [constants.MagicBytes]byte) {
				return [constants.MagicBytes]byte{}, [constants.MagicBytes]byte{}, [constants.MagicBytes]byte{}
			}

			for {
				select {
				case update := <-updateChannel:
					handlers.SDK5_PacketHandler(&handler, nil, &update.from, update.packetData)
					if !handler.Events[handlers.SDK5_HandlerEvent_SentServerUpdateResponsePacket] {
						panic("failed to process server update")
					}
					atomic.AddUint64(numSessionUpdatesProcessed, 1)
				}
			}

		}(k)
	}
}

func RunWatcherThread(numSessionUpdatesProcessed *uint64) {

	go func() {

		ticker := time.NewTicker(time.Second)

		iteration := uint64(0)

		start := time.Now()

		for {
			select {
			case <-ticker.C:
				numUpdates := atomic.LoadUint64(numSessionUpdatesProcessed)
				fmt.Printf("iteration %d: %8d session updates | %7d session updates per-second\n", iteration, numUpdates, uint64(float64(numUpdates)/time.Since(start).Seconds()))
				iteration++
			}
		}
	}()
}

func main() {

	core.DebugLogs = false

	BuyerId = rand.Uint64()

	DatacenterId = rand.Uint64()

	BuyerPublicKey, BuyerPrivateKey = crypto.Sign_KeyPair()

	ServerBackendPublicKey, ServerBackendPrivateKey = crypto.Sign_KeyPair()

	numSessionUpdateThreads := envvar.GetInt("NUM_SESSION_UPDATE_THREADS", 1000)

	numHandlerThreads := envvar.GetInt("NUM_HANDLER_THREADS", runtime.NumCPU())

	updateChannels := make([]chan *Update, numHandlerThreads)
	for i := range updateChannels {
		updateChannels[i] = make(chan *Update, 1024*1024)
	}

	var numSessionUpdatesProcessed uint64

	RunSessionUpdateThreads(numSessionUpdateThreads, updateChannels)

	RunHandlerThreads(numHandlerThreads, updateChannels, &numSessionUpdatesProcessed)

	RunWatcherThread(&numSessionUpdatesProcessed)

	time.Sleep(time.Minute)
}
