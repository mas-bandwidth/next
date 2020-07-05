package billing

import (
	"context"
	"sync/atomic"

	"cloud.google.com/go/bigquery"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

const (
	DefaultBigQueryBatchSize   = 1000
	DefaultBigQueryChannelSize = 10000
)

type GoogleBigQueryClient struct {
	Logger        log.Logger
	TableInserter *bigquery.Inserter
	BatchSize     int

	buffer  []*BillingEntry
	entries chan *BillingEntry

	submitted uint64
	flushed   uint64
}

// Bill pushes an Entry to the channel
func (bq *GoogleBigQueryClient) Bill(ctx context.Context, entry *BillingEntry) error {
	atomic.AddUint64(&bq.submitted, 1)
	if bq.entries == nil {
		bq.entries = make(chan *BillingEntry, DefaultBigQueryChannelSize)
	}
	bq.entries <- entry
	return nil
}

func (bq *GoogleBigQueryClient) NumSubmitted() uint64 {
	return atomic.LoadUint64(&bq.submitted)
}

func (bq *GoogleBigQueryClient) NumQueued() uint64 {
	return uint64(len(bq.entries))
}

func (bq *GoogleBigQueryClient) NumFlushed() uint64 {
	return atomic.LoadUint64(&bq.flushed)
}

// WriteLoop ranges over the incoming channel of Entry types and fills an internal buffer.
// Once the buffer fills to the BatchSize it will write all entries to BigQuery. This should
// only be called from 1 goroutine to avoid using a mutex around the internal buffer slice
func (bq *GoogleBigQueryClient) WriteLoop(ctx context.Context) error {
	if bq.entries == nil {
		bq.entries = make(chan *BillingEntry, DefaultBigQueryChannelSize)
	}
	for entry := range bq.entries {
		if len(bq.buffer) >= bq.BatchSize {
			if err := bq.TableInserter.Put(ctx, bq.buffer); err != nil {
				level.Error(bq.Logger).Log("msg", "failed to write to BigQuery", "err", err)
			}
			level.Info(bq.Logger).Log("msg", "flushed entries to BigQuery", "size", bq.BatchSize, "total", len(bq.buffer))
			atomic.AddUint64(&bq.flushed, uint64(len(bq.buffer)))
			bq.buffer = bq.buffer[:0]
		}
		bq.buffer = append(bq.buffer, entry)
	}
	return nil
}

// Save implements the bigquery.ValueSaver interface for an Entry
// so it can be used in Put()
func (entry *BillingEntry) Save() (map[string]bigquery.Value, string, error) {
	
	e := make(map[string]bigquery.Value)

	e["sessionId"] = int(entry.SessionID)
	e["sliceNumber"] = int(entry.SliceNumber)
	e["buyerId"] = int(entry.BuyerID)
	e["next"] = entry.Next
	e["directRtt"] = entry.DirectRTT
	e["directJitter"] = entry.DirectJitter
	e["directPacketLoss"] = entry.DirectPacketLoss
	e["nextRtt"] = entry.NextRTT
	e["nextJitter"] = entry.NextJitter
	e["nextPacketLoss"] = entry.NextPacketLoss
	e["totalPrice"] = int(entry.TotalPrice)

	nextRelays := make([]bigquery.Value, entry.NumNextRelays)
	for i := 0; i < int(entry.NumNextRelays); i++ {
		nextRelays[i] = int(entry.NextRelays[i])
	}
	e["nextRelays"] = nextRelays

	return e, "", nil
}
