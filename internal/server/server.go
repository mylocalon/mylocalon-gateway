// Package server wires the public and admin HTTP handlers.
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mylocalon/mylocalon-gateway/internal/clock"
	"github.com/mylocalon/mylocalon-gateway/internal/config"
	"github.com/mylocalon/mylocalon-gateway/internal/ingress"
	"github.com/mylocalon/mylocalon-gateway/internal/metrics"
	"github.com/mylocalon/mylocalon-gateway/internal/store"
	"github.com/mylocalon/mylocalon-gateway/internal/subdomain"
	"github.com/mylocalon/mylocalon-gateway/internal/tunnel"
)

// Version is set at build time via -ldflags.
var Version = "0.1.0-dev"

// TunnelsAdapter exposes the Hub to ingress without leaking a typed nil.
type TunnelsAdapter struct{ Hub *tunnel.Hub }

func (a TunnelsAdapter) Find(sub string) ingress.Forwarder {
	if s := a.Hub.Lookup(sub); s != nil {
		return s
	}
	return nil
}

func (a TunnelsAdapter) Held(ctx context.Context, sub string) bool { return a.Hub.Held(ctx, sub) }

// Public routes by Host: "<label>.<base>" → ingress (except the gateway's own
// "gateway" label); anything else (gateway.<base>, apex, localhost) serves
// /tunnel and /health.
func Public(cfg *config.Config, hub *tunnel.Hub, in http.Handler, c clock.Clock) http.Handler {
	control := http.NewServeMux()
	control.Handle("/tunnel", hub)
	control.HandleFunc("/health", health(c))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if label, ok := subdomain.FromHost(r.Host, cfg.BaseDomain); ok && label != "gateway" {
			in.ServeHTTP(w, r)
			return
		}
		if isTunnelHost(r.Host, cfg.BaseDomain) {
			// A subdomain-shaped host we refuse to route (nested, malformed).
			in.ServeHTTP(w, r)
			return
		}
		control.ServeHTTP(w, r)
	})
}

// isTunnelHost catches hosts under base that FromHost rejected, so they get
// a clean error page instead of the control mux.
func isTunnelHost(host, base string) bool {
	h := strings.ToLower(host)
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return strings.HasSuffix(h, "."+base) && !strings.HasPrefix(h, "gateway.")
}

// Admin serves /health, /ready and /metrics on the private address.
func Admin(st store.Store, m *metrics.Metrics, c clock.Clock) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", health(c))
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := st.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "redis": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		m.WritePrometheus(w)
	})
	return mux
}

func health(c clock.Clock) http.HandlerFunc {
	started := c.Now()
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ok", "version": Version, "uptimeSec": int64(c.Now().Sub(started).Seconds()),
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
