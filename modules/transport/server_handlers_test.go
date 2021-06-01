package transport_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/networknext/backend/modules/billing"
	"github.com/networknext/backend/modules/core"
	"github.com/networknext/backend/modules/crypto"
	"github.com/networknext/backend/modules/metrics"
	"github.com/networknext/backend/modules/routing"
	"github.com/networknext/backend/modules/transport"
	"github.com/stretchr/testify/assert"
)

func TestGetRouteAddressesAndPublicKeys(t *testing.T) {
	clientAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:34567")
	assert.NoError(t, err)
	clientPublicKey := make([]byte, crypto.KeySize)
	core.RandomBytes(clientPublicKey)

	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:32202")
	assert.NoError(t, err)
	serverPublicKey := make([]byte, crypto.KeySize)
	core.RandomBytes(serverPublicKey)

	relayAddr1, err := net.ResolveUDPAddr("udp", "127.0.0.1:10000")
	assert.NoError(t, err)
	relayAddr2, err := net.ResolveUDPAddr("udp", "127.0.0.1:10001")
	assert.NoError(t, err)
	relayAddr3, err := net.ResolveUDPAddr("udp", "127.0.0.1:10002")
	assert.NoError(t, err)

	relayPublicKey1 := make([]byte, crypto.KeySize)
	core.RandomBytes(relayPublicKey1)
	relayPublicKey2 := make([]byte, crypto.KeySize)
	core.RandomBytes(relayPublicKey2)
	relayPublicKey3 := make([]byte, crypto.KeySize)
	core.RandomBytes(relayPublicKey3)

	seller := routing.Seller{ID: "seller"}
	datacenter := routing.Datacenter{ID: crypto.HashID("local"), Name: "local"}

	sellerMap := make(map[string]routing.Seller)
	sellerMap[seller.ID] = seller

	datacenterMap := make(map[uint64]routing.Datacenter)
	datacenterMap[datacenter.ID] = datacenter

	relayMap := make(map[uint64]routing.Relay)
	relayMap[crypto.HashID(relayAddr1.String())] = routing.Relay{ID: crypto.HashID(relayAddr1.String()), Addr: *relayAddr1, PublicKey: relayPublicKey1, Seller: seller, Datacenter: datacenter}
	relayMap[crypto.HashID(relayAddr2.String())] = routing.Relay{ID: crypto.HashID(relayAddr2.String()), Addr: *relayAddr2, PublicKey: relayPublicKey2, Seller: seller, Datacenter: datacenter}
	relayMap[crypto.HashID(relayAddr3.String())] = routing.Relay{ID: crypto.HashID(relayAddr3.String()), Addr: *relayAddr3, PublicKey: relayPublicKey3, Seller: seller, Datacenter: datacenter}

	database := routing.DatabaseBinWrapper{RelayMap: relayMap, SellerMap: sellerMap, DatacenterMap: datacenterMap}

	allRelayIDs := []uint64{crypto.HashID(relayAddr1.String()), crypto.HashID(relayAddr2.String()), crypto.HashID(relayAddr3.String())}
	routeRelays := []int32{0, 1, 2}

	routeAddresses, routePublicKeys := transport.GetRouteAddressesAndPublicKeys(clientAddr, clientPublicKey, serverAddr, serverPublicKey, 5, routeRelays, allRelayIDs, &database)

	expectedRouteAddresses := []*net.UDPAddr{clientAddr, relayAddr1, relayAddr2, relayAddr3, serverAddr}
	expectedRoutePublicKeys := [][]byte{clientPublicKey, relayPublicKey1, relayPublicKey2, relayPublicKey3, serverPublicKey}

	for i := range routeAddresses {
		assert.Equal(t, expectedRouteAddresses[i].String(), routeAddresses[i].String())
	}

	for i := range routePublicKeys {
		assert.Equal(t, expectedRoutePublicKeys[i], routePublicKeys[i])
	}
}

// todo: there should be a test here that verifies correct behavior with private relay addresses

// Server init handler tests

func TestServerInitHandlerFunc_BuyerNotFound(t *testing.T) {
	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)
	responseBuffer := bytes.NewBuffer(nil)

	requestPacket := transport.ServerInitRequestPacket{
		Version:        transport.SDKVersionMin,
		BuyerID:        buyerID,
		DatacenterID:   crypto.HashID("datacenter.name"),
		DatacenterName: "datacenter.name",
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)

	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)
	requestData = crypto.SignPacket(privateKey, requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	handler := transport.ServerInitHandlerFunc(getDatabase, metrics.ServerInitMetrics)
	handler(responseBuffer, &transport.UDPPacket{
		Data: requestData,
	})

	var responsePacket transport.ServerInitResponsePacket
	err = transport.UnmarshalPacket(&responsePacket, responseBuffer.Bytes()[1+crypto.PacketHashSize:])
	assert.NoError(t, err)

	assert.Equal(t, requestPacket.RequestID, responsePacket.RequestID)
	assert.Equal(t, uint32(transport.InitResponseUnknownBuyer), responsePacket.Response)

	assert.Equal(t, float64(1), metrics.ServerInitMetrics.BuyerNotFound.Value())
}

func TestServerInitHandlerFunc_BuyerNotLive(t *testing.T) {
	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		PublicKey: publicKey,
		Live:      false,
	}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)
	responseBuffer := bytes.NewBuffer(nil)

	requestPacket := transport.ServerInitRequestPacket{
		Version:        transport.SDKVersionMin,
		BuyerID:        buyerID,
		DatacenterID:   crypto.HashID("datacenter.name"),
		DatacenterName: "datacenter.name",
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)

	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)
	requestData = crypto.SignPacket(privateKey, requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	handler := transport.ServerInitHandlerFunc(getDatabase, metrics.ServerInitMetrics)
	handler(responseBuffer, &transport.UDPPacket{
		Data: requestData,
	})

	var responsePacket transport.ServerInitResponsePacket
	err = transport.UnmarshalPacket(&responsePacket, responseBuffer.Bytes()[1+crypto.PacketHashSize:])
	assert.NoError(t, err)

	assert.Equal(t, requestPacket.RequestID, responsePacket.RequestID)
	assert.Equal(t, uint32(transport.InitResponseBuyerNotActive), responsePacket.Response)

	assert.Equal(t, float64(1), metrics.ServerInitMetrics.BuyerNotActive.Value())
}

func TestServerInitHandlerFunc_SigCheckFail(t *testing.T) {
	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		PublicKey: publicKey,
		Live:      true,
	}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)
	responseBuffer := bytes.NewBuffer(nil)

	requestPacket := transport.ServerInitRequestPacket{
		Version:        transport.SDKVersionMin,
		BuyerID:        buyerID,
		DatacenterID:   crypto.HashID("datacenter.name"),
		DatacenterName: "datacenter.name",
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)

	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)

	// Break the crypto check by not passing in full privat key
	requestData = crypto.SignPacket(privateKey[1:], requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	handler := transport.ServerInitHandlerFunc(getDatabase, metrics.ServerInitMetrics)
	handler(responseBuffer, &transport.UDPPacket{
		Data: requestData,
	})

	var responsePacket transport.ServerInitResponsePacket
	err = transport.UnmarshalPacket(&responsePacket, responseBuffer.Bytes()[1+crypto.PacketHashSize:])
	assert.NoError(t, err)

	assert.Equal(t, requestPacket.RequestID, responsePacket.RequestID)
	assert.Equal(t, uint32(transport.InitResponseSignatureCheckFailed), responsePacket.Response)

	assert.Equal(t, float64(1), metrics.ServerInitMetrics.SignatureCheckFailed.Value())
}

func TestServerInitHandlerFunc_SDKToOld(t *testing.T) {
	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		PublicKey: publicKey,
		Live:      true,
	}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)
	responseBuffer := bytes.NewBuffer(nil)

	requestPacket := transport.ServerInitRequestPacket{
		Version:        transport.SDKVersion{3, 0, 0},
		BuyerID:        buyerID,
		DatacenterID:   crypto.HashID("datacenter.name"),
		DatacenterName: "datacenter.name",
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)

	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)
	requestData = crypto.SignPacket(privateKey, requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	handler := transport.ServerInitHandlerFunc(getDatabase, metrics.ServerInitMetrics)
	handler(responseBuffer, &transport.UDPPacket{
		Data: requestData,
	})

	var responsePacket transport.ServerInitResponsePacket
	err = transport.UnmarshalPacket(&responsePacket, responseBuffer.Bytes()[1+crypto.PacketHashSize:])
	assert.NoError(t, err)

	assert.Equal(t, requestPacket.RequestID, responsePacket.RequestID)
	assert.Equal(t, uint32(transport.InitResponseOldSDKVersion), responsePacket.Response)

	assert.Equal(t, float64(1), metrics.ServerInitMetrics.SDKTooOld.Value())
}

func TestServerInitHandlerFunc_Success_DatacenterNotFound(t *testing.T) {
	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		PublicKey: publicKey,
		Live:      true,
	}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)
	responseBuffer := bytes.NewBuffer(nil)

	requestPacket := transport.ServerInitRequestPacket{
		Version:        transport.SDKVersionMin,
		BuyerID:        buyerID,
		DatacenterID:   crypto.HashID("datacenter.name"),
		DatacenterName: "datacenter.name",
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)

	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)
	requestData = crypto.SignPacket(privateKey, requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	handler := transport.ServerInitHandlerFunc(getDatabase, metrics.ServerInitMetrics)
	handler(responseBuffer, &transport.UDPPacket{
		Data: requestData,
	})

	var responsePacket transport.ServerInitResponsePacket
	err = transport.UnmarshalPacket(&responsePacket, responseBuffer.Bytes()[1+crypto.PacketHashSize:])
	assert.NoError(t, err)

	assert.Equal(t, requestPacket.RequestID, responsePacket.RequestID)
	assert.Equal(t, uint32(transport.InitResponseOK), responsePacket.Response)

	assert.Equal(t, float64(1), metrics.ServerInitMetrics.DatacenterNotFound.Value())
}

func TestServerInitHandlerFunc_Success(t *testing.T) {
	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		PublicKey: publicKey,
		Live:      true,
	}

	datacenterID := crypto.HashID("datacenter.name")
	datacenterName := "datacenter.name"

	databaseWrapper.DatacenterMap[datacenterID] = routing.Datacenter{
		ID:   datacenterID,
		Name: datacenterName,
	}

	databaseWrapper.DatacenterMaps[buyerID] = make(map[uint64]routing.DatacenterMap, 0)
	databaseWrapper.DatacenterMaps[buyerID][datacenterID] = routing.DatacenterMap{
		BuyerID:      buyerID,
		DatacenterID: datacenterID,
		Alias:        datacenterName,
	}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)
	responseBuffer := bytes.NewBuffer(nil)

	requestPacket := transport.ServerInitRequestPacket{
		Version:        transport.SDKVersionMin,
		BuyerID:        buyerID,
		DatacenterID:   datacenterID,
		DatacenterName: datacenterName,
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)

	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)
	requestData = crypto.SignPacket(privateKey, requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	handler := transport.ServerInitHandlerFunc(getDatabase, metrics.ServerInitMetrics)
	handler(responseBuffer, &transport.UDPPacket{
		Data: requestData,
	})

	var responsePacket transport.ServerInitResponsePacket
	err = transport.UnmarshalPacket(&responsePacket, responseBuffer.Bytes()[1+crypto.PacketHashSize:])
	assert.NoError(t, err)

	assert.Equal(t, requestPacket.RequestID, responsePacket.RequestID)
	assert.Equal(t, uint32(transport.InitResponseOK), responsePacket.Response)

	assert.Equal(t, float64(0), metrics.ServerInitMetrics.DatacenterNotFound.Value())
}

// Server update handler tests

func TestServerUpdateHandlerFunc_BuyerNotFound(t *testing.T) {
	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)
	responseBuffer := bytes.NewBuffer(nil)

	requestPacket := transport.ServerUpdatePacket{}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	postSessionHandler := transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)

	handler := transport.ServerUpdateHandlerFunc(getDatabase, postSessionHandler, metrics.ServerUpdateMetrics)
	handler(responseBuffer, &transport.UDPPacket{
		Data: requestData,
	})

	assert.Equal(t, float64(1), metrics.ServerUpdateMetrics.BuyerNotFound.Value())
}

func TestServerUpdateHandlerFunc_BuyerNotLive(t *testing.T) {
	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		PublicKey: publicKey,
		Live:      false,
	}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)
	responseBuffer := bytes.NewBuffer(nil)

	requestPacket := transport.ServerUpdatePacket{
		Version: transport.SDKVersionMin,
		BuyerID: buyerID,
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	postSessionHandler := transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)

	handler := transport.ServerUpdateHandlerFunc(getDatabase, postSessionHandler, metrics.ServerUpdateMetrics)
	handler(responseBuffer, &transport.UDPPacket{
		Data: requestData,
	})

	assert.Equal(t, float64(1), metrics.ServerUpdateMetrics.BuyerNotLive.Value())
}

func TestServerUpdateHandlerFunc_SigCheckFail(t *testing.T) {
	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		PublicKey: publicKey,
		Live:      true,
	}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)
	responseBuffer := bytes.NewBuffer(nil)

	requestPacket := transport.ServerUpdatePacket{
		Version: transport.SDKVersionMin,
		BuyerID: buyerID,
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	postSessionHandler := transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)

	handler := transport.ServerUpdateHandlerFunc(getDatabase, postSessionHandler, metrics.ServerUpdateMetrics)
	handler(responseBuffer, &transport.UDPPacket{
		Data: requestData,
	})

	assert.Equal(t, float64(1), metrics.ServerUpdateMetrics.SignatureCheckFailed.Value())
}

func TestServerUpdateHandlerFunc_SDKToOld(t *testing.T) {

	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		PublicKey: publicKey,
		Live:      true,
	}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)
	responseBuffer := bytes.NewBuffer(nil)

	requestPacket := transport.ServerUpdatePacket{
		Version: transport.SDKVersion{3, 0, 0},
		BuyerID: buyerID,
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)

	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)
	requestData = crypto.SignPacket(privateKey, requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	postSessionHandler := transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)

	handler := transport.ServerUpdateHandlerFunc(getDatabase, postSessionHandler, metrics.ServerUpdateMetrics)
	handler(responseBuffer, &transport.UDPPacket{
		Data: requestData,
	})

	assert.Equal(t, float64(1), metrics.ServerUpdateMetrics.SDKTooOld.Value())
}

func TestServerUpdateHandlerFunc_DatacenterNotFound(t *testing.T) {
	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		PublicKey: publicKey,
		Live:      true,
	}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)
	responseBuffer := bytes.NewBuffer(nil)

	requestPacket := transport.ServerUpdatePacket{
		Version: transport.SDKVersionMin,
		BuyerID: buyerID,
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)

	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)
	requestData = crypto.SignPacket(privateKey, requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	postSessionHandler := transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)

	handler := transport.ServerUpdateHandlerFunc(getDatabase, postSessionHandler, metrics.ServerUpdateMetrics)
	handler(responseBuffer, &transport.UDPPacket{
		Data: requestData,
	})

	assert.Equal(t, float64(1), metrics.ServerUpdateMetrics.DatacenterNotFound.Value())
}

func TestServerUpdateHandlerFunc_Success(t *testing.T) {
	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		PublicKey: publicKey,
		Live:      true,
	}

	datacenterID := crypto.HashID("datacenter.name")
	datacenterName := "datacenter.name"

	databaseWrapper.DatacenterMap[datacenterID] = routing.Datacenter{
		ID:   datacenterID,
		Name: datacenterName,
	}

	databaseWrapper.DatacenterMaps[buyerID] = make(map[uint64]routing.DatacenterMap, 0)
	databaseWrapper.DatacenterMaps[buyerID][datacenterID] = routing.DatacenterMap{
		BuyerID:      buyerID,
		DatacenterID: datacenterID,
		Alias:        datacenterName,
	}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)
	responseBuffer := bytes.NewBuffer(nil)

	serverAddress, err := net.ResolveUDPAddr("udp", "127.0.0.1:5000")

	requestPacket := transport.ServerUpdatePacket{
		Version:       transport.SDKVersionMin,
		BuyerID:       buyerID,
		DatacenterID:  datacenterID,
		NumSessions:   uint32(10),
		ServerAddress: *serverAddress,
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)

	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)
	requestData = crypto.SignPacket(privateKey, requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	postSessionHandler := transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)

	handler := transport.ServerUpdateHandlerFunc(getDatabase, postSessionHandler, metrics.ServerUpdateMetrics)
	handler(responseBuffer, &transport.UDPPacket{
		Data: requestData,
	})

	assert.Equal(t, float64(0), metrics.ServerUpdateMetrics.DatacenterNotFound.Value())
}

// Session update handler
func TestSessionUpdateHandlerFunc_Pre_BuyerNotFound(t *testing.T) {
	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	state := transport.SessionHandlerState{}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	state.Metrics = metrics.SessionUpdateMetrics
	state.Database = getDatabase()
	state.Datacenter = routing.UnknownDatacenter
	state.IpLocator = routing.NullIsland
	state.StaleDuration = time.Second * 20
	state.PostSessionHandler = transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)
	state.Packet.BuyerID = buyerID

	assert.True(t, transport.SessionPre(&state))

	assert.True(t, state.BuyerNotFound)
	assert.Equal(t, float64(1), state.Metrics.BuyerNotFound.Value())
}

func TestSessionUpdateHandlerFunc_Pre_BuyerNotLive(t *testing.T) {
	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		ShortName: "local",
		Live:      false,
		PublicKey: publicKey,
	}

	state := transport.SessionHandlerState{}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	state.Metrics = metrics.SessionUpdateMetrics
	state.Database = getDatabase()
	state.Datacenter = routing.UnknownDatacenter
	state.IpLocator = routing.NullIsland
	state.StaleDuration = time.Second * 20
	state.PostSessionHandler = transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)
	state.Packet.BuyerID = buyerID

	assert.True(t, transport.SessionPre(&state))

	assert.True(t, state.BuyerNotLive)
	assert.Equal(t, float64(1), state.Metrics.BuyerNotLive.Value())
}

func TestSessionUpdateHandlerFunc_Pre_SigCheckFail(t *testing.T) {
	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		ShortName: "local",
		Live:      true,
		PublicKey: publicKey,
	}

	state := transport.SessionHandlerState{}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	state.Metrics = metrics.SessionUpdateMetrics
	state.Database = getDatabase()
	state.Datacenter = routing.UnknownDatacenter
	state.IpLocator = routing.NullIsland
	state.StaleDuration = time.Second * 20
	state.PostSessionHandler = transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)
	state.Packet.BuyerID = buyerID

	requestPacket := transport.SessionUpdatePacket{
		Version:              transport.SDKVersionMin,
		BuyerID:              buyerID,
		DatacenterID:         crypto.HashID("datacenter.name"),
		ClientRoutePublicKey: publicKey,
		ServerRoutePublicKey: publicKey,
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)
	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)

	// Break the crypto check by not passing in full privat key
	requestData = crypto.SignPacket(privateKey[1:], requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	state.PacketData = requestData

	assert.True(t, transport.SessionPre(&state))

	assert.True(t, state.SignatureCheckFailed)
	assert.Equal(t, float64(1), state.Metrics.SignatureCheckFailed.Value())
}

func TestSessionUpdateHandlerFunc_Pre_ClientTimedOut(t *testing.T) {
	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		ShortName: "local",
		Live:      true,
		PublicKey: publicKey,
	}

	state := transport.SessionHandlerState{}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	state.Metrics = metrics.SessionUpdateMetrics
	state.Database = getDatabase()
	state.Datacenter = routing.UnknownDatacenter
	state.IpLocator = routing.NullIsland
	state.StaleDuration = time.Second * 20
	state.PostSessionHandler = transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)
	state.Packet.BuyerID = buyerID
	state.Packet.ClientPingTimedOut = true

	requestPacket := transport.SessionUpdatePacket{
		Version:              transport.SDKVersionMin,
		BuyerID:              buyerID,
		DatacenterID:         crypto.HashID("datacenter.name"),
		ClientRoutePublicKey: publicKey,
		ServerRoutePublicKey: publicKey,
		ClientPingTimedOut:   true,
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)
	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)

	// Break the crypto check by not passing in full privat key
	requestData = crypto.SignPacket(privateKey, requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	state.PacketData = requestData

	assert.True(t, transport.SessionPre(&state))

	assert.True(t, state.Packet.ClientPingTimedOut)
	assert.Equal(t, float64(1), state.Metrics.ClientPingTimedOut.Value())
}

func TestSessionUpdateHandlerFunc_Pre_DatacenterNotFound(t *testing.T) {
	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		ShortName: "local",
		Live:      true,
		PublicKey: publicKey,
	}

	state := transport.SessionHandlerState{}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	state.Metrics = metrics.SessionUpdateMetrics
	state.Database = getDatabase()
	state.Datacenter = routing.UnknownDatacenter
	state.IpLocator = routing.NullIsland
	state.StaleDuration = time.Second * 20
	state.PostSessionHandler = transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)
	state.Packet.BuyerID = buyerID

	requestPacket := transport.SessionUpdatePacket{
		Version:              transport.SDKVersionMin,
		BuyerID:              buyerID,
		DatacenterID:         crypto.HashID("datacenter.name"),
		ClientRoutePublicKey: publicKey,
		ServerRoutePublicKey: publicKey,
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)
	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)

	// Break the crypto check by not passing in full privat key
	requestData = crypto.SignPacket(privateKey, requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	state.PacketData = requestData

	assert.True(t, transport.SessionPre(&state))

	assert.True(t, state.UnknownDatacenter)
	assert.Equal(t, float64(1), state.Metrics.DatacenterNotFound.Value())
}

func TestSessionUpdateHandlerFunc_Pre_DatacenterNotEnabled(t *testing.T) {
	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		ShortName: "local",
		Live:      true,
		PublicKey: publicKey,
	}

	datacenterName := "datacenter.name"
	datacenterID := crypto.HashID(datacenterName)
	databaseWrapper.DatacenterMap[datacenterID] = routing.Datacenter{
		ID:        datacenterID,
		Name:      datacenterName,
		AliasName: datacenterName,
	}

	state := transport.SessionHandlerState{}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	state.Metrics = metrics.SessionUpdateMetrics
	state.Database = getDatabase()
	state.Datacenter = routing.UnknownDatacenter
	state.IpLocator = routing.NullIsland
	state.StaleDuration = time.Second * 20
	state.PostSessionHandler = transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)
	state.Packet.BuyerID = buyerID
	state.Packet.DatacenterID = datacenterID

	requestPacket := transport.SessionUpdatePacket{
		Version:              transport.SDKVersionMin,
		BuyerID:              buyerID,
		DatacenterID:         crypto.HashID("datacenter.name"),
		ClientRoutePublicKey: publicKey,
		ServerRoutePublicKey: publicKey,
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)
	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)

	// Break the crypto check by not passing in full privat key
	requestData = crypto.SignPacket(privateKey, requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	state.PacketData = requestData

	assert.True(t, transport.SessionPre(&state))

	assert.True(t, state.DatacenterNotEnabled)
	assert.Equal(t, float64(1), state.Metrics.DatacenterNotEnabled.Value())
}

func TestSessionUpdateHandlerFunc_Pre_NoRelaysInDatacenter(t *testing.T) {
	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		ShortName: "local",
		Live:      true,
		PublicKey: publicKey,
	}

	datacenterName := "datacenter.name"
	datacenterID := crypto.HashID(datacenterName)
	databaseWrapper.DatacenterMap[datacenterID] = routing.Datacenter{
		ID:        datacenterID,
		Name:      datacenterName,
		AliasName: datacenterName,
	}

	databaseWrapper.DatacenterMaps[buyerID] = make(map[uint64]routing.DatacenterMap, 0)
	databaseWrapper.DatacenterMaps[buyerID][datacenterID] = routing.DatacenterMap{
		BuyerID:      buyerID,
		DatacenterID: datacenterID,
		Alias:        datacenterName,
	}

	state := transport.SessionHandlerState{}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	state.Metrics = metrics.SessionUpdateMetrics
	state.Database = getDatabase()
	state.Datacenter = routing.UnknownDatacenter
	state.IpLocator = routing.NullIsland
	state.StaleDuration = time.Second * 20
	state.PostSessionHandler = transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)
	state.Packet.BuyerID = buyerID
	state.Packet.DatacenterID = datacenterID

	state.RouteMatrix = &routing.RouteMatrix{
		RelayDatacenterIDs: []uint64{
			12345,
			123423,
			12351321,
		},
	}

	requestPacket := transport.SessionUpdatePacket{
		Version:              transport.SDKVersionMin,
		BuyerID:              buyerID,
		DatacenterID:         crypto.HashID("datacenter.name"),
		ClientRoutePublicKey: publicKey,
		ServerRoutePublicKey: publicKey,
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)
	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)

	// Break the crypto check by not passing in full privat key
	requestData = crypto.SignPacket(privateKey, requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	state.PacketData = requestData

	assert.True(t, transport.SessionPre(&state))

	assert.Equal(t, float64(1), state.Metrics.NoRelaysInDatacenter.Value())
}

func TestSessionUpdateHandlerFunc_Pre_StaleRouteMatrix(t *testing.T) {
	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		ShortName: "local",
		Live:      true,
		PublicKey: publicKey,
	}

	datacenterName := "datacenter.name"
	datacenterID := crypto.HashID(datacenterName)
	databaseWrapper.DatacenterMap[datacenterID] = routing.Datacenter{
		ID:        datacenterID,
		Name:      datacenterName,
		AliasName: datacenterName,
	}

	databaseWrapper.DatacenterMaps[buyerID] = make(map[uint64]routing.DatacenterMap, 0)
	databaseWrapper.DatacenterMaps[buyerID][datacenterID] = routing.DatacenterMap{
		BuyerID:      buyerID,
		DatacenterID: datacenterID,
		Alias:        datacenterName,
	}

	state := transport.SessionHandlerState{}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	state.Metrics = metrics.SessionUpdateMetrics
	state.Database = getDatabase()
	state.Datacenter = routing.UnknownDatacenter
	state.IpLocator = routing.NullIsland
	state.StaleDuration = time.Second * 20
	state.PostSessionHandler = transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)
	state.Packet.BuyerID = buyerID
	state.Packet.DatacenterID = datacenterID

	state.RouteMatrix = &routing.RouteMatrix{
		RelayDatacenterIDs: []uint64{
			datacenterID,
		},
		RelayIDs: []uint64{
			datacenterID,
		},
	}

	requestPacket := transport.SessionUpdatePacket{
		Version:              transport.SDKVersionMin,
		BuyerID:              buyerID,
		DatacenterID:         crypto.HashID("datacenter.name"),
		ClientRoutePublicKey: publicKey,
		ServerRoutePublicKey: publicKey,
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)
	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)

	// Break the crypto check by not passing in full privat key
	requestData = crypto.SignPacket(privateKey, requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	state.PacketData = requestData

	assert.True(t, transport.SessionPre(&state))
	assert.True(t, state.StaleRouteMatrix)
	assert.Equal(t, float64(1), state.Metrics.StaleRouteMatrix.Value())
}

func TestSessionUpdateHandlerFunc_Pre_Success(t *testing.T) {
	databaseWrapper := routing.CreateEmptyDatabaseBinWrapper()

	publicKey, privateKey, err := crypto.GenerateCustomerKeyPair()
	assert.NoError(t, err)

	publicKey = publicKey[8:]
	privateKey = privateKey[8:]

	buyerID := binary.LittleEndian.Uint64(publicKey[:8])

	databaseWrapper.BuyerMap[buyerID] = routing.Buyer{
		ID:        buyerID,
		ShortName: "local",
		Live:      true,
		PublicKey: publicKey,
	}

	datacenterName := "datacenter.name"
	datacenterID := crypto.HashID(datacenterName)
	databaseWrapper.DatacenterMap[datacenterID] = routing.Datacenter{
		ID:        datacenterID,
		Name:      datacenterName,
		AliasName: datacenterName,
	}

	databaseWrapper.DatacenterMaps[buyerID] = make(map[uint64]routing.DatacenterMap, 0)
	databaseWrapper.DatacenterMaps[buyerID][datacenterID] = routing.DatacenterMap{
		BuyerID:      buyerID,
		DatacenterID: datacenterID,
		Alias:        datacenterName,
	}

	state := transport.SessionHandlerState{}

	metricsHandler := metrics.LocalHandler{}
	metrics, err := metrics.NewServerBackendMetrics(context.Background(), &metricsHandler)
	assert.NoError(t, err)

	getDatabase := func() *routing.DatabaseBinWrapper {
		return databaseWrapper
	}

	state.Metrics = metrics.SessionUpdateMetrics
	state.Database = getDatabase()
	state.Datacenter = routing.UnknownDatacenter
	state.IpLocator = routing.NullIsland
	state.StaleDuration = time.Minute
	state.PostSessionHandler = transport.NewPostSessionHandler(4, 0, nil, 10, nil, 0, false, &billing.NoOpBiller{}, &billing.NoOpBiller{}, true, false, log.NewNopLogger(), metrics.PostSessionMetrics)
	state.Packet.BuyerID = buyerID
	state.Packet.DatacenterID = datacenterID

	state.RouteMatrix = &routing.RouteMatrix{
		CreatedAt: uint64(time.Now().Unix()),
		RelayDatacenterIDs: []uint64{
			datacenterID,
		},
		RelayIDs: []uint64{
			datacenterID,
		},
	}

	requestPacket := transport.SessionUpdatePacket{
		Version:              transport.SDKVersionMin,
		BuyerID:              buyerID,
		DatacenterID:         crypto.HashID("datacenter.name"),
		ClientRoutePublicKey: publicKey,
		ServerRoutePublicKey: publicKey,
	}
	requestData, err := transport.MarshalPacket(&requestPacket)
	assert.NoError(t, err)
	// We need to add the packet header (packet type + 8 hash bytes) in order to get the correct signature
	requestDataHeader := append([]byte{transport.PacketTypeServerInitRequest}, make([]byte, crypto.PacketHashSize)...)
	requestData = append(requestDataHeader, requestData...)

	// Break the crypto check by not passing in full privat key
	requestData = crypto.SignPacket(privateKey, requestData)

	// Once we have the signature, we need to take off the header before passing to the handler
	requestData = requestData[1+crypto.PacketHashSize:]

	state.PacketData = requestData

	assert.False(t, transport.SessionPre(&state))
}
