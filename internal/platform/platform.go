// Package platform is the Gateway's thin, optional link to mylocalon-platform
// over the private network: it pulls the reserved-subdomain list and pushes
// tunnel lifecycle events for dashboard history. Neither is on the request
// hot path, and both degrade gracefully when the Platform is down
// (ARCHITECTURE.md §8).
package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type Client struct {
	base  string
	token string
	hc    *http.Client
}

func NewClient(baseURL, internalToken string) *Client {
	return &Client{base: baseURL, token: internalToken, hc: &http.Client{Timeout: 5 * time.Second}}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: HTTP %d", method, path, res.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(out)
	}
	return nil
}

// ---------------------------------------------------------- reserved names

// Reserved caches every reserved subdomain so random allocation never hands
// out a name someone has reserved. The last good list survives outages.
type Reserved struct {
	c   *Client
	log *slog.Logger

	mu    sync.RWMutex
	names map[string]struct{}
}

func NewReserved(c *Client, log *slog.Logger) *Reserved {
	return &Reserved{c: c, log: log, names: map[string]struct{}{}}
}

func (r *Reserved) IsReserved(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.names[name]
	return ok
}

func (r *Reserved) Refresh(ctx context.Context) error {
	var body struct {
		Names []string `json:"names"`
	}
	if err := r.c.do(ctx, http.MethodGet, "/api/v1/internal/reserved-subdomains", nil, &body); err != nil {
		r.log.Warn("reserved_sync_failed", "err", err)
		return err
	}
	set := make(map[string]struct{}, len(body.Names))
	for _, n := range body.Names {
		set[n] = struct{}{}
	}
	r.mu.Lock()
	r.names = set
	r.mu.Unlock()
	r.log.Debug("reserved_synced", "count", len(set))
	return nil
}

func (r *Reserved) Run(ctx context.Context, every time.Duration) {
	_ = r.Refresh(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = r.Refresh(ctx)
		}
	}
}

// ----------------------------------------------------------------- events

type Event struct {
	TunnelID  string         `json:"tunnelId"`
	UserID    string         `json:"userId"`
	Subdomain string         `json:"subdomain"`
	Event     string         `json:"event"`
	Meta      map[string]any `json:"meta,omitempty"`
	At        int64          `json:"at"`
}

// Publisher batches lifecycle events to the Platform. It never blocks the
// tunnel: when the buffer is full or the Platform is down, events are
// dropped (they are history, not state) and counted in the logs.
type Publisher struct {
	c       *Client
	log     *slog.Logger
	ch      chan Event
	maxWait time.Duration
	dropped int64
	mu      sync.Mutex
}

func NewPublisher(c *Client, log *slog.Logger) *Publisher {
	return &Publisher{c: c, log: log, ch: make(chan Event, 4096), maxWait: time.Second}
}

// TunnelEvent implements tunnel.Lifecycle.
func (p *Publisher) TunnelEvent(tunnelID, userID, sub, event string, meta map[string]any) {
	e := Event{TunnelID: tunnelID, UserID: userID, Subdomain: sub, Event: event, Meta: meta, At: time.Now().UnixMilli()}
	select {
	case p.ch <- e:
	default:
		p.mu.Lock()
		p.dropped++
		p.mu.Unlock()
	}
}

// Run flushes batches until ctx is done, then makes a final best-effort flush.
func (p *Publisher) Run(ctx context.Context) {
	t := time.NewTicker(p.maxWait)
	defer t.Stop()
	var batch []Event
	flush := func(ctx context.Context) {
		if len(batch) == 0 {
			return
		}
		if err := p.c.do(ctx, http.MethodPost, "/api/v1/internal/tunnel-events", map[string]any{"events": batch}, nil); err != nil {
			p.log.Warn("events_publish_failed", "err", err, "dropped", len(batch))
		}
		batch = batch[:0]
	}
	for {
		select {
		case e := <-p.ch:
			batch = append(batch, e)
			if len(batch) >= 200 {
				flush(ctx)
			}
		case <-t.C:
			flush(ctx)
			p.mu.Lock()
			if p.dropped > 0 {
				p.log.Warn("events_buffer_full", "dropped", p.dropped)
				p.dropped = 0
			}
			p.mu.Unlock()
		case <-ctx.Done():
		drain:
			for {
				select {
				case e := <-p.ch:
					batch = append(batch, e)
				default:
					break drain
				}
			}
			fctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			flush(fctx)
			cancel()
			return
		}
	}
}
