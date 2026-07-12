package common

import (
	"context"
	"sync"
	"time"

	"cloud.google.com/go/pubsub/v2"
	"github.com/networknext/next/modules/core"
	"google.golang.org/api/option"
)

type GooglePubsubConfig struct {
	ProjectId          string
	Topic              string
	Subscription       string
	ClientOptions      []option.ClientOption
	BatchSize          int
	BatchDuration      time.Duration
	MessageChannelSize int
}

type GooglePubsubProducer struct {
	MessageChannel  chan []byte
	resultChannel   chan *pubsub.PublishResult
	config          GooglePubsubConfig
	pubsubClient    *pubsub.Client
	pubsubPublisher *pubsub.Publisher
	mutex           sync.RWMutex
	numMessagesSent int
	numBatchesSent  int
}

func CreateGooglePubsubProducer(ctx context.Context, config GooglePubsubConfig) (*GooglePubsubProducer, error) {

	if config.MessageChannelSize == 0 {
		config.MessageChannelSize = 1024 * 1024
	}

	if config.BatchDuration == 0 {
		config.BatchDuration = time.Second
	}

	if config.BatchSize == 0 {
		config.BatchSize = 10000
	}

	pubsubClient, err := pubsub.NewClient(ctx, config.ProjectId, config.ClientOptions...)
	if err != nil {
		core.Error("failed to create google pubsub client: %v", err)
		return nil, err
	}

	pubsubPublisher := pubsubClient.Publisher(config.Topic)

	pubsubPublisher.PublishSettings.CountThreshold = config.BatchSize
	pubsubPublisher.PublishSettings.DelayThreshold = config.BatchDuration

	producer := &GooglePubsubProducer{}

	producer.config = config
	producer.pubsubClient = pubsubClient
	producer.pubsubPublisher = pubsubPublisher
	producer.MessageChannel = make(chan []byte, config.MessageChannelSize)
	producer.resultChannel = make(chan *pubsub.PublishResult, config.MessageChannelSize)

	go producer.monitorResults(ctx)

	go producer.updateMessageChannel(ctx)

	return producer, nil
}

func (producer *GooglePubsubProducer) monitorResults(ctx context.Context) {

	for {
		select {

		case <-ctx.Done():
			return

		case result := <-producer.resultChannel:
			_, err := result.Get(ctx)
			if err != nil {
				core.Error("failed to send message batch: %v", err)
				break
			}

			producer.mutex.Lock()
			producer.numBatchesSent++
			producer.mutex.Unlock()
		}
	}
}

func (producer *GooglePubsubProducer) updateMessageChannel(ctx context.Context) {

	for {
		select {

		case <-ctx.Done():
			return

		case message := <-producer.MessageChannel:
			producer.sendMessage(ctx, message)
		}
	}
}

func (producer *GooglePubsubProducer) sendMessage(ctx context.Context, message []byte) {

	result := producer.pubsubPublisher.Publish(ctx, &pubsub.Message{Data: message})

	producer.resultChannel <- result

	producer.mutex.Lock()
	producer.numMessagesSent++
	producer.mutex.Unlock()
}
