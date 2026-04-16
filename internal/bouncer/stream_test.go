package bouncer

import (
	"context"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestStreamSend_respectsCancelWhenNoReceiver(t *testing.T) {
	t.Parallel()

	ch := make(chan *models.DecisionsStreamResponse)
	data := &models.DecisionsStreamResponse{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := streamSend(ctx, ch, data)
	require.ErrorIs(t, err, context.Canceled)
}

func TestStreamSend_deliversWhenReceiverReady(t *testing.T) {
	t.Parallel()

	ch := make(chan *models.DecisionsStreamResponse)
	data := &models.DecisionsStreamResponse{}
	ctx := t.Context()

	go func() { <-ch }()

	err := streamSend(ctx, ch, data)
	require.NoError(t, err)
}

func TestStreamSend_bufferedChannelWithoutBlocking(t *testing.T) {
	t.Parallel()

	ch := make(chan *models.DecisionsStreamResponse, 1)
	data := &models.DecisionsStreamResponse{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := streamSend(ctx, ch, data)
	require.NoError(t, err)

	select {
	case got := <-ch:
		require.Same(t, data, got)
	case <-time.After(2 * time.Second):
		t.Fatal("expected value on channel")
	}
}
