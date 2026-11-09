// Package ratelimit implements fixed-window limits on top of the Store's
// counters, so limits stay correct across multiple Gateway nodes.
package ratelimit

import (
	"context"
	"log/slog"
	"time"
)

type Counter interface {
	Incr(ctx context.Context, key string, window time.Duration) (int64, error)
}

type Limiter struct {
	store Counter
	log   *slog.Logger
}

func New(store Counter, log *slog.Logger) *Limiter { return &Limiter{store: store, log: log} }

// Allow reports whether one more event fits under limit per window. A limit
// <= 0 disables the check. If the store is unavailable the limiter fails open
// (logged): a Redis outage must not turn into a total outage.
func (l *Limiter) Allow(ctx context.Context, key string, limit int, window time.Duration) bool {
	if limit <= 0 {
		return true
	}
	n, err := l.store.Incr(ctx, key, window)
	if err != nil {
		l.log.Error("ratelimit_store_error", "key", key, "err", err)
		return true
	}
	return n <= int64(limit)
}
