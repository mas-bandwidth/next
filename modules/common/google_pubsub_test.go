package common_test

import (
	"context"
	"testing"
	"time"

	"cloud.google.com/go/pubsub/v2"
	"cloud.google.com/go/pubsub/v2/apiv1/pubsubpb"
	"cloud.google.com/go/pubsub/v2/pstest"
	"github.com/networknext/next/modules/common"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// end-to-end check of the producer against an in-process fake pubsub server.
// this is the only coverage the pubsub path has (functional tests run with
// ENABLE_GOOGLE_PUBSUB=0), so keep it working when touching google_pubsub.go

func TestGooglePubsubProducer(t *testing.T) {

	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server := pstest.NewServer()
	defer server.Close()

	connection, err := grpc.NewClient(server.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	assert.NoError(t, err)
	defer connection.Close()

	clientOptions := []option.ClientOption{option.WithGRPCConn(connection)}

	// create the topic and subscription on the fake server

	adminClient, err := pubsub.NewClient(ctx, "test", clientOptions...)
	assert.NoError(t, err)
	defer adminClient.Close()

	_, err = adminClient.TopicAdminClient.CreateTopic(ctx, &pubsubpb.Topic{Name: "projects/test/topics/test_topic"})
	assert.NoError(t, err)

	_, err = adminClient.SubscriptionAdminClient.CreateSubscription(ctx, &pubsubpb.Subscription{Name: "projects/test/subscriptions/test_subscription", Topic: "projects/test/topics/test_topic"})
	assert.NoError(t, err)

	// send messages through the producer

	producer, err := common.CreateGooglePubsubProducer(ctx, common.GooglePubsubConfig{
		ProjectId:     "test",
		Topic:         "test_topic",
		ClientOptions: clientOptions,
		BatchSize:     10,
		BatchDuration: 100 * time.Millisecond,
	})
	assert.NoError(t, err)

	const NumMessages = 100

	for i := 0; i < NumMessages; i++ {
		producer.MessageChannel <- []byte{byte(i)}
	}

	// receive them back and verify nothing was lost or corrupted

	received := make(chan []byte, NumMessages)

	subscriberCtx, subscriberCancel := context.WithCancel(ctx)
	defer subscriberCancel()

	go func() {
		subscriber := adminClient.Subscriber("test_subscription")
		subscriber.Receive(subscriberCtx, func(ctx context.Context, message *pubsub.Message) {
			message.Ack()
			received <- message.Data
		})
	}()

	seen := make(map[byte]bool)
	for len(seen) < NumMessages {
		select {
		case data := <-received:
			assert.Equal(t, 1, len(data))
			seen[data[0]] = true
		case <-ctx.Done():
			t.Fatalf("timed out: received %d of %d messages", len(seen), NumMessages)
		}
	}
}
