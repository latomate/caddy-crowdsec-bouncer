package core

import (
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func TestDrainDecisionStream_empty(t *testing.T) {
	t.Parallel()

	ch := make(chan *models.DecisionsStreamResponse)
	drainDecisionStream(ch)
	// unblocked: nothing to drain
}

func TestDrainDecisionStream_drainsBufferedMessages(t *testing.T) {
	t.Parallel()

	ch := make(chan *models.DecisionsStreamResponse, 3)
	a := &models.DecisionsStreamResponse{}
	b := &models.DecisionsStreamResponse{}
	ch <- a
	ch <- b

	drainDecisionStream(ch)

	select {
	case x := <-ch:
		t.Fatalf("expected empty channel after drain, got %v", x)
	default:
	}
}

func TestDrainDecisionStream_closedChannel(t *testing.T) {
	t.Parallel()

	ch := make(chan *models.DecisionsStreamResponse)
	close(ch)

	drainDecisionStream(ch)
}

func TestDrainDecisionStream_unblocksBlockedSender(t *testing.T) {
	t.Parallel()

	// Buffered channel full so a second send blocks until we receive (same pattern as
	// shutdown when the producer is stuck on send and the consumer drains).
	ch := make(chan *models.DecisionsStreamResponse, 1)
	preload := &models.DecisionsStreamResponse{}
	ch <- preload

	payload := &models.DecisionsStreamResponse{}
	sent := make(chan struct{})
	started := make(chan struct{})
	go func() {
		close(started)
		ch <- payload
		close(sent)
	}()
	<-started

	drainDecisionStream(ch)

	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("sender did not complete after drain")
	}
}
