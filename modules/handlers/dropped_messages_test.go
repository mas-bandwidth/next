package handlers_test

import (
	"testing"
	"time"

	"github.com/networknext/next/modules/core"
	"github.com/networknext/next/modules/crypto"
	"github.com/networknext/next/modules/handlers"
	"github.com/networknext/next/modules/messages"

	"github.com/stretchr/testify/assert"
)

/*
	A full telemetry channel must shed the message and count the drop, never block:
	a blocked send holds a packet handler goroutine, and enough of them exhaust the
	UDP server semaphore and stop the whole packet path. See dropped_messages.go.

	IMPORTANT: the drop counters are package level and the suite runs parallel, so each
	counter must only be touched by one test function -- that is why the space and full
	phases live together instead of being separate tests.
*/

// run f with a watchdog: if it blocks on a full channel, fail instead of hanging the suite

func runWithTimeout(t *testing.T, description string, f func()) {
	done := make(chan bool)
	go func() {
		f()
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s blocked on a full channel", description)
	}
}

func Test_FallbackToDirect_ChannelBackpressure(t *testing.T) {

	t.Parallel()

	// with space in the channel, the message is delivered and nothing is dropped

	state := CreateState()

	state.Request.SessionId = 0x12345
	state.Request.FallbackToDirect = true

	channel := make(chan uint64, 1)
	state.FallbackToDirectChannel = channel

	numDroppedBefore := handlers.DroppedFallbackToDirect.NumDropped()

	result := handlers.SessionUpdate_Pre(state)

	assert.True(t, result)
	assert.Equal(t, uint64(0x12345), <-channel)
	assert.Equal(t, numDroppedBefore, handlers.DroppedFallbackToDirect.NumDropped())

	// with the channel full, the handler must not block and the drop must be counted

	state = CreateState()

	state.Request.FallbackToDirect = true

	channel = make(chan uint64, 1)
	channel <- 1 // fill the channel so the send cannot succeed
	state.FallbackToDirectChannel = channel

	runWithTimeout(t, "session update pre", func() {
		result := handlers.SessionUpdate_Pre(state)
		assert.True(t, result)
	})

	assert.Equal(t, numDroppedBefore+1, handlers.DroppedFallbackToDirect.NumDropped())
}

func createPostState() *handlers.SessionUpdateState {

	state := CreateState()

	serverBackendPublicKey, serverBackendPrivateKey := crypto.Sign_KeyPair()

	state.ServerBackendPublicKey = serverBackendPublicKey
	state.ServerBackendPrivateKey = serverBackendPrivateKey

	from := core.ParseAddress("127.0.0.1:40000")
	state.From = &from
	serverBackendAddress := core.ParseAddress("127.0.0.1:50000")
	state.ServerBackendAddress = &serverBackendAddress

	state.Request.SessionId = 0x12345
	state.Request.SliceNumber = 1
	state.Input.SliceNumber = 1

	return state
}

func Test_SessionUpdate_Post_ChannelBackpressure(t *testing.T) {

	t.Parallel()

	// with space in the channels, messages are delivered and nothing is dropped

	state := createPostState()

	portalChannel := make(chan *messages.PortalSessionUpdateMessage, 2)
	state.PortalSessionUpdateMessageChannel = portalChannel

	analyticsChannel := make(chan *messages.AnalyticsSessionUpdateMessage, 2)
	state.AnalyticsSessionUpdateMessageChannel = analyticsChannel

	numDroppedPortalBefore := handlers.DroppedPortalSessionUpdateMessages.NumDropped()
	numDroppedAnalyticsBefore := handlers.DroppedAnalyticsSessionUpdateMessages.NumDropped()

	handlers.SessionUpdate_Post(state)

	assert.True(t, state.SentPortalSessionUpdateMessage)
	assert.True(t, state.SentAnalyticsSessionUpdateMessage)

	portalMessage := <-portalChannel
	assert.Equal(t, uint64(0x12345), portalMessage.SessionId)

	analyticsMessage := <-analyticsChannel
	assert.Equal(t, int64(0x12345), analyticsMessage.SessionId)

	assert.Equal(t, numDroppedPortalBefore, handlers.DroppedPortalSessionUpdateMessages.NumDropped())
	assert.Equal(t, numDroppedAnalyticsBefore, handlers.DroppedAnalyticsSessionUpdateMessages.NumDropped())

	// with the channels full, the handler must not block, the sent flags must stay
	// false, and the drops must be counted

	state = createPostState()

	portalChannel = make(chan *messages.PortalSessionUpdateMessage, 1)
	portalChannel <- &messages.PortalSessionUpdateMessage{}
	state.PortalSessionUpdateMessageChannel = portalChannel

	analyticsChannel = make(chan *messages.AnalyticsSessionUpdateMessage, 1)
	analyticsChannel <- &messages.AnalyticsSessionUpdateMessage{}
	state.AnalyticsSessionUpdateMessageChannel = analyticsChannel

	runWithTimeout(t, "session update post", func() {
		handlers.SessionUpdate_Post(state)
	})

	assert.False(t, state.SentPortalSessionUpdateMessage)
	assert.False(t, state.SentAnalyticsSessionUpdateMessage)
	assert.Equal(t, numDroppedPortalBefore+1, handlers.DroppedPortalSessionUpdateMessages.NumDropped())
	assert.Equal(t, numDroppedAnalyticsBefore+1, handlers.DroppedAnalyticsSessionUpdateMessages.NumDropped())
}
