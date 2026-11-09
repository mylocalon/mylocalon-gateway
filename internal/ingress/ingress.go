// Package ingress turns public HTTP requests on *.{base} into HTTP_REQUEST
// messages on the owning tunnel and writes the response back.
package ingress

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/mylocalon/mylocalon-gateway/internal/clock"
	"github.com/mylocalon/mylocalon-gateway/internal/config"
	"github.com/mylocalon/mylocalon-gateway/internal/httpx"
	"github.com/mylocalon/mylocalon-gateway/internal/metrics"
	"github.com/mylocalon/mylocalon-gateway/internal/protocol"
	"github.com/mylocalon/mylocalon-gateway/internal/ratelimit"
	"github.com/mylocalon/mylocalon-gateway/internal/subdomain"
)

// Forwarder is one live tunnel (implemented by *tunnel.Session).
type Forwarder interface {
	Forward(ctx context.Context, req *protocol.HTTPRequest) (*protocol.HTTPResponse, *protocol.Error, error)
}

// Tunnels resolves subdomains to forwarders.
type Tunnels interface {
	// Find returns the local forwarder for subdomain, or nil.
	Find(sub string) Forwarder
	// Held reports whether the subdomain is mapped but not served locally
	// (e.g. reconnecting within the grace window).
	Held(ctx context.Context, sub string) bool
}

// AbuseFilter is the plugin hook for content/domain scanning (SECURITY §6).
type AbuseFilter interface {
	Allow(r *http.Request) (bool, string)
}

type allowAll struct{}

func (allowAll) Allow(*http.Request) (bool, string) { return true, "" }

type Handler struct {
	cfg     *config.Config
	tunnels Tunnels
	limiter *ratelimit.Limiter
	filter  AbuseFilter
	metrics *metrics.Metrics
	clock   clock.Clock
	log     *slog.Logger
}

func New(cfg *config.Config, t Tunnels, l *ratelimit.Limiter, m *metrics.Metrics, c clock.Clock, log *slog.Logger) *Handler {
	return &Handler{cfg: cfg, tunnels: t, limiter: l, filter: allowAll{}, metrics: m, clock: c, log: log}
}

func (h *Handler) WithFilter(f AbuseFilter) *Handler { h.filter = f; return h }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := h.clock.Now()
	reqID := httpx.NewID("rq_", 8)
	traceID := httpx.NewID("", 16)
	ip := httpx.ClientIP(r, h.cfg.TrustProxy)
	log := h.log.With("reqId", reqID, "traceId", traceID, "remoteIp", ip)

	defer func() {
		if rec := recover(); rec != nil {
			log.Error("panic_in_ingress", "panic", rec)
			errorPage(w, http.StatusInternalServerError, "Internal error", reqID)
		}
	}()

	sub, ok := subdomain.FromHost(r.Host, h.cfg.BaseDomain)
	if !ok {
		errorPage(w, http.StatusBadRequest, "Malformed host", reqID)
		return
	}
	log = log.With("subdomain", sub)
	log.Info("http_ingress", "method", r.Method, "path", r.URL.Path, "bytesIn", r.ContentLength)
	h.metrics.RequestsTotal.Add(1)

	if !h.limiter.Allow(r.Context(), "rl:ip:"+ip, h.cfg.IPReqRatePerSec, time.Second) {
		w.Header().Set("Retry-After", "1")
		errorPage(w, http.StatusTooManyRequests, "Rate limit exceeded", reqID)
		return
	}

	if ok, reason := h.filter.Allow(r); !ok {
		log.Warn("abuse_blocked", "reason", reason)
		errorPage(w, http.StatusForbidden, "Blocked", reqID)
		return
	}

	fwd := h.tunnels.Find(sub)
	if fwd == nil {
		if h.tunnels.Held(r.Context(), sub) {
			errorPage(w, http.StatusBadGateway, "Tunnel is reconnecting — try again in a moment", reqID)
			return
		}
		errorPage(w, http.StatusNotFound, "Tunnel not found", reqID)
		return
	}

	if !h.limiter.Allow(r.Context(), "rl:tun:"+sub, h.cfg.ReqRatePerSec, time.Second) {
		w.Header().Set("Retry-After", "1")
		errorPage(w, http.StatusTooManyRequests, "Rate limit exceeded", reqID)
		return
	}

	// Body limit at the edge: oversized bodies never reach the client.
	if r.ContentLength > h.cfg.MaxBodyBytes {
		errorPage(w, http.StatusRequestEntityTooLarge, "Request body too large", reqID)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, h.cfg.MaxBodyBytes+1))
	if err != nil {
		errorPage(w, http.StatusBadRequest, "Could not read request body", reqID)
		return
	}
	if int64(len(body)) > h.cfg.MaxBodyBytes {
		errorPage(w, http.StatusRequestEntityTooLarge, "Request body too large", reqID)
		return
	}

	msg := &protocol.HTTPRequest{
		ReqID:      reqID,
		Method:     r.Method,
		Path:       r.URL.RequestURI(),
		Headers:    requestHeaders(r, ip),
		BodyB64:    protocol.EncodeBody(body),
		RemoteIP:   ip,
		ReceivedAt: start.UnixMilli(),
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.RequestTimeout)
	defer cancel()
	resp, perr, err := fwd.Forward(ctx, msg)
	durationMs := h.clock.Now().Sub(start).Milliseconds()
	h.metrics.ObserveDuration(durationMs)

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		h.metrics.UpstreamErrors.Add(1)
		log.Warn("upstream_error", "code", protocol.CodeUpstreamTimeout, "message", "gateway timeout waiting for tunnel")
		errorPage(w, http.StatusGatewayTimeout, "The local app took too long to respond", reqID)
		return
	case errors.Is(err, context.Canceled):
		return // public client went away
	case err != nil:
		h.metrics.UpstreamErrors.Add(1)
		log.Warn("upstream_error", "code", "TUNNEL_GONE", "message", err.Error())
		errorPage(w, http.StatusBadGateway, "Tunnel disconnected", reqID)
		return
	case perr != nil:
		h.metrics.UpstreamErrors.Add(1)
		status := statusForCode(perr.Code)
		log.Warn("upstream_error", "code", perr.Code, "message", perr.Message)
		errorPage(w, status, messageForCode(perr.Code), reqID)
		return
	}

	out, err := protocol.DecodeBody(resp.BodyB64)
	if err != nil {
		errorPage(w, http.StatusBadGateway, "Invalid response from tunnel", reqID)
		return
	}
	conn := connectionTokens(resp.Headers)
	for _, hd := range resp.Headers {
		if httpx.IsHopByHop(hd[0], conn) || http.CanonicalHeaderKey(hd[0]) == "Content-Length" {
			continue
		}
		w.Header().Add(hd[0], hd[1])
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(out)))
	w.WriteHeader(resp.Status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(out)
	}
	log.Info("http_forwarded", "method", r.Method, "path", r.URL.Path, "status", resp.Status,
		"durationMs", durationMs, "bytesOut", len(out))
}

// requestHeaders converts headers to ordered pairs, strips hop-by-hop headers
// and adds X-Forwarded-*. Host is carried as X-Forwarded-Host; the client sets
// Host to its local target.
func requestHeaders(r *http.Request, ip string) []protocol.Header {
	conn := r.Header.Values("Connection")
	out := make([]protocol.Header, 0, len(r.Header)+3)
	for name, vals := range r.Header {
		if httpx.IsHopByHop(name, conn) {
			continue
		}
		switch http.CanonicalHeaderKey(name) {
		case "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto":
			continue // rewritten below
		}
		for _, v := range vals {
			out = append(out, protocol.Header{lower(name), v})
		}
	}
	proto := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		proto = "https"
	}
	out = append(out,
		protocol.Header{"x-forwarded-for", ip},
		protocol.Header{"x-forwarded-host", r.Host},
		protocol.Header{"x-forwarded-proto", proto},
	)
	return out
}

func connectionTokens(hs []protocol.Header) []string {
	var out []string
	for _, h := range hs {
		if http.CanonicalHeaderKey(h[0]) == "Connection" {
			out = append(out, h[1])
		}
	}
	return out
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func statusForCode(code string) int {
	switch code {
	case protocol.CodeUpstreamTimeout:
		return http.StatusGatewayTimeout
	case protocol.CodeBodyTooLarge:
		return http.StatusBadGateway
	default:
		return http.StatusBadGateway
	}
}

func messageForCode(code string) string {
	switch code {
	case protocol.CodeUpstreamTimeout:
		return "The local app took too long to respond"
	case protocol.CodeUpstreamUnreachable:
		return "The local app is not reachable — is it running?"
	case protocol.CodeBodyTooLarge:
		return "Response body too large"
	default:
		return "Bad gateway"
	}
}

func errorPage(w http.ResponseWriter, status int, msg, reqID string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Mylocalon-Error", fmt.Sprint(status))
	w.Header().Set("X-Mylocalon-Request-Id", reqID)
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>%d · mylocalon</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;color:#222}
h1{font-size:1.25rem}code{color:#666;font-size:.85rem}</style></head>
<body><h1>%d — %s</h1><p>Served by mylocalon.</p><code>request id: %s</code></body></html>`,
		status, status, html.EscapeString(msg), html.EscapeString(reqID))
}
