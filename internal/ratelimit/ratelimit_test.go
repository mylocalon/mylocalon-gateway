package ratelimit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/mylocalon/mylocalon-gateway/internal/clock"
	"github.com/mylocalon/mylocalon-gateway/internal/store"
)

func TestAllow(t *testing.T) {
	c := clock.NewFake(time.Unix(0, 0))
	l := New(store.NewMemory(c), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if !l.Allow(ctx, "k", 3, time.Second) {
			t.Fatalf("call %d should pass", i)
		}
	}
	if l.Allow(ctx, "k", 3, time.Second) {
		t.Fatal("4th call should be limited")
	}
	c.Advance(time.Second)
	if !l.Allow(ctx, "k", 3, time.Second) {
		t.Fatal("new window should pass")
	}
}

type broken struct{}

func (broken) Incr(context.Context, string, time.Duration) (int64, error) {
	return 0, errors.New("redis down")
}

func TestFailOpen(t *testing.T) {
	l := New(broken{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !l.Allow(context.Background(), "k", 1, time.Second) {
		t.Fatal("must fail open when store is down")
	}
}
