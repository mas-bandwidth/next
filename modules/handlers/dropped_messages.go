package handlers

import (
	"sync/atomic"
	"time"

	"github.com/networknext/next/modules/core"
)

/*
	The portal and analytics message channels are deliberately deep (CHANNEL_SIZE in
	server_backend, 10M entries by default): the system is load tested to 10 million
	connected clients, and at that scale the depth is what rides through multi-second
	sink jitter (redis latency spikes, batch flush stalls) without ever filling.

	A full channel therefore means the sink has been down for a long time, not that we
	are bursting. Blocking on a full channel would freeze packet handler goroutines until
	the UDP server semaphore exhausts and the service stops making route decisions, and
	waiting for the queue to grow instead ends in OOM. Telemetry must never take down
	routing, so every producer send is a non-blocking select: when the channel is full
	the message is dropped, the drop is counted per-stream, and we warn at most once per
	second per stream.
*/

type DroppedMessageCounter struct {
	name         string
	numDropped   atomic.Uint64
	lastWarnTime atomic.Int64
}

func (counter *DroppedMessageCounter) MessageDropped() {
	numDropped := counter.numDropped.Add(1)
	currentTime := time.Now().Unix()
	lastWarnTime := counter.lastWarnTime.Load()
	if currentTime != lastWarnTime && counter.lastWarnTime.CompareAndSwap(lastWarnTime, currentTime) {
		core.Warn("%s channel is full: dropped %d messages", counter.name, numDropped)
	}
}

func (counter *DroppedMessageCounter) NumDropped() uint64 {
	return counter.numDropped.Load()
}

var (
	DroppedFallbackToDirect                 = &DroppedMessageCounter{name: "fallback to direct"}
	DroppedPortalSessionUpdateMessages      = &DroppedMessageCounter{name: "portal session update message"}
	DroppedPortalClientRelayUpdateMessages  = &DroppedMessageCounter{name: "portal client relay update message"}
	DroppedPortalServerRelayUpdateMessages  = &DroppedMessageCounter{name: "portal server relay update message"}
	DroppedPortalServerUpdateMessages       = &DroppedMessageCounter{name: "portal server update message"}
	DroppedAnalyticsClientRelayPingMessages = &DroppedMessageCounter{name: "analytics client relay ping message"}
	DroppedAnalyticsServerRelayPingMessages = &DroppedMessageCounter{name: "analytics server relay ping message"}
	DroppedAnalyticsSessionUpdateMessages   = &DroppedMessageCounter{name: "analytics session update message"}
	DroppedAnalyticsSessionSummaryMessages  = &DroppedMessageCounter{name: "analytics session summary message"}
	DroppedAnalyticsServerInitMessages      = &DroppedMessageCounter{name: "analytics server init message"}
	DroppedAnalyticsServerUpdateMessages    = &DroppedMessageCounter{name: "analytics server update message"}
)
