// Package tunnel owns the WSS tunnel endpoint: handshake, auth, subdomain
// assignment, heartbeat, resume, and the in-process session registry.
package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/mylocalon/mylocalon-gateway/internal/auth"
	"github.com/mylocalon/mylocalon-gateway/internal/clock"
	"github.com/mylocalon/mylocalon-gateway/internal/config"
	"github.com/mylocalon/mylocalon-gateway/internal/httpx"
	"github.com/mylocalon/mylocalon-gateway/internal/metrics"
	"github.com/mylocalon/mylocalon-gateway/internal/protocol"
	"github.com/mylocalon/mylocalon-gateway/internal/ratelimit"
	"github.com/mylocalon/mylocalon-gateway/internal/store"
	"github.com/mylocalon/mylocalon-gateway/internal/subdomain"
)

const storeTimeout = 2 * time.Second

// Lifecycle receives tunnel lifecycle events (e.g. for dashboard history).
// Implementations must not block.
type Lifecycle interface {
	TunnelEvent(tunnelID, userID, subdomain, event string, meta map[string]any)
}

// ReservedNames reports names reserved on the Platform, which random
// allocation must skip.
type ReservedNames interface {
	IsReserved(name string) bool
}

type noLifecycle struct{}

func (noLifecycle) TunnelEvent(string, string, string, string, map[string]any) {}

type noReserved struct{}

func (noReserved) IsReserved(string) bool { return false }

// Lifecycle event names (mirrors mylocalon-platform tunnel_audit.event).
const (
	EventConnected    = "connected"
	EventResumed      = "resumed"
	EventDisconnected = "disconnected"
	EventClosed       = "closed"
)

type Hub struct {
	lifecycle Lifecycle
	reserved  ReservedNames
	cfg       *config.Config
	store     store.Store
	verifier  auth.Verifier
	gen       subdomain.Generator
	limiter   *ratelimit.Limiter
	metrics   *metrics.Metrics
	clock     clock.Clock
	log       *slog.Logger
	reg       *registry
	sessions  sync.WaitGroup // live sessions, until their detach finishes
	upgrader  websocket.Upgrader
}

func NewHub(cfg *config.Config, st store.Store, v auth.Verifier, m *metrics.Metrics, c clock.Clock, log *slog.Logger) *Hub {
	h := &Hub{
		cfg: cfg, store: st, verifier: v, metrics: m, clock: c, log: log,
		limiter:   ratelimit.New(st, log),
		reg:       newRegistry(),
		lifecycle: noLifecycle{},
		reserved:  noReserved{},
	}
	h.upgrader = websocket.Upgrader{
		Subprotocols:    []string{protocol.Subprotocol},
		ReadBufferSize:  16 << 10,
		WriteBufferSize: 16 << 10,
		// Tunnel clients are CLIs/SDKs, not browsers; Origin is not meaningful.
		CheckOrigin: func(*http.Request) bool { return true },
	}
	return h
}

// WithLifecycle sets the lifecycle event sink.
func (h *Hub) WithLifecycle(l Lifecycle) *Hub { h.lifecycle = l; return h }

// WithReserved sets the reserved-name source used by random allocation.
func (h *Hub) WithReserved(r ReservedNames) *Hub { h.reserved = r; return h }

// liveTTL is how long runtime state survives without a heartbeat refresh.
func (h *Hub) liveTTL() time.Duration { return h.cfg.HeartbeatTimeout + h.cfg.ResumeGrace }

// Lookup returns the local session serving subdomain, or nil.
func (h *Hub) Lookup(sub string) *Session { return h.reg.bySubdomain(sub) }

// Held reports whether a subdomain is mapped in the shared store (e.g. a
// tunnel in its resume grace window, or on another node).
func (h *Hub) Held(ctx context.Context, sub string) bool {
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	id, err := h.store.LookupSubdomain(ctx, sub)
	if err != nil {
		h.log.Error("store_lookup_failed", "subdomain", sub, "err", err)
		return false
	}
	return id != ""
}

func (h *Hub) ActiveCount() int { return h.reg.count() }

// ServeHTTP is the WSS endpoint (/tunnel).
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r, h.cfg.TrustProxy)
	if !websocket.IsWebSocketUpgrade(r) {
		http.Error(w, "websocket upgrade required", http.StatusUpgradeRequired)
		return
	}
	if !offersSubprotocol(r) {
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Sec-WebSocket-Protocol", protocol.Subprotocol)
		http.Error(w, "subprotocol "+protocol.Subprotocol+" required", http.StatusUpgradeRequired)
		return
	}
	if !h.limiter.Allow(r.Context(), "rl:conn:ip:"+ip, h.cfg.ConnRatePerMin, time.Minute) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // upgrader already wrote the error
	}
	// Large enough for a max-size base64 HTTP_RESPONSE; control messages are
	// separately capped at 64KiB in readPump.
	conn.SetReadLimit(h.cfg.MaxBodyBytes*4/3 + maxControlMsgBytes)
	h.serve(conn, ip)
}

func offersSubprotocol(r *http.Request) bool {
	for _, p := range websocket.Subprotocols(r) {
		if p == protocol.Subprotocol {
			return true
		}
	}
	return false
}

// handshakeError aborts the handshake with GOAWAY.
type handshakeError struct {
	code      string
	msg       string
	reconnect bool
}

func (e *handshakeError) Error() string { return e.code + ": " + e.msg }

func fail(code, msg string, reconnect bool) *handshakeError {
	return &handshakeError{code: code, msg: msg, reconnect: reconnect}
}

func (h *Hub) serve(conn *websocket.Conn, ip string) {
	log := h.log.With("remoteIp", ip)
	defer func() {
		if rec := recover(); rec != nil {
			log.Error("panic_in_tunnel", "panic", rec)
			_ = conn.Close()
		}
	}()

	s, welcome, herr := h.handshake(conn, ip, log)
	if herr != nil {
		log.Info("handshake_rejected", "code", herr.code, "message", herr.msg)
		data, _ := protocol.Encode(&protocol.GoAway{Code: herr.code, Message: herr.msg, Reconnect: herr.reconnect})
		_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
		_ = conn.WriteMessage(websocket.TextMessage, data)
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, herr.code), time.Now().Add(time.Second))
		_ = conn.Close()
		return
	}

	if err := s.writeNow(welcome); err != nil {
		s.terminate(nil, false, "write_error")
	}
	h.sessions.Add(1)
	defer h.sessions.Done()
	h.metrics.ActiveTunnels.Add(1)
	go s.writePump()
	s.readPump()
	h.metrics.ActiveTunnels.Add(-1)
	h.detach(s)
}

func (h *Hub) handshake(conn *websocket.Conn, ip string, log *slog.Logger) (*Session, *protocol.Welcome, *handshakeError) {
	_ = conn.SetReadDeadline(h.clock.Now().Add(h.cfg.HelloTimeout))
	mt, data, err := conn.ReadMessage()
	if err != nil {
		return nil, nil, fail(protocol.CodeProtocolError, "expected HELLO", false)
	}
	if mt != websocket.TextMessage || len(data) > maxControlMsgBytes {
		return nil, nil, fail(protocol.CodeProtocolError, "HELLO must be a text frame under 64KiB", false)
	}
	msg, err := protocol.Decode(data)
	if err != nil {
		return nil, nil, fail(protocol.CodeProtocolError, err.Error(), false)
	}
	hello, ok := msg.(*protocol.Hello)
	if !ok {
		return nil, nil, fail(protocol.CodeProtocolError, "first message must be HELLO", false)
	}
	if hello.Protocol != protocol.Version {
		return nil, nil, fail(protocol.CodeVersionUnsupported, "protocol 1 required", false)
	}

	claims, err := h.verifier.Verify(hello.Token)
	if err != nil {
		return nil, nil, fail(protocol.CodeAuthFailed, "invalid or expired token", false)
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	if claims.ID != "" {
		revoked, err := h.store.IsRevoked(ctx, claims.ID)
		if err != nil {
			log.Error("denylist_check_failed", "err", err)
		} else if revoked {
			return nil, nil, fail(protocol.CodeAuthRevoked, "token revoked", false)
		}
	}
	tokKey := claims.ID
	if tokKey == "" {
		tokKey = claims.Subject
	}
	if !h.limiter.Allow(ctx, "rl:tok:"+tokKey, h.cfg.ConnRatePerMin, time.Minute) {
		return nil, nil, fail(protocol.CodeRateLimited, "too many connections", true)
	}

	log = log.With("userId", claims.Subject, "clientVersion", hello.Client.Version)

	if hello.Resume != nil {
		s, w, herr := h.resume(ctx, conn, hello, claims, log)
		if herr == nil {
			return s, w, nil
		}
		if hello.Tunnel == nil {
			return nil, nil, herr
		}
		log.Info("resume_failed_fallback_fresh", "tunnelId", hello.Resume.TunnelID, "code", herr.code)
	}
	return h.fresh(ctx, conn, hello, claims, log)
}

func (h *Hub) fresh(ctx context.Context, conn *websocket.Conn, hello *protocol.Hello, claims *auth.Claims, log *slog.Logger) (*Session, *protocol.Welcome, *handshakeError) {
	tunnelID := httpx.NewID("tnl_", 8)

	var sub string
	if hello.Tunnel != nil && hello.Tunnel.Subdomain != "" {
		sub = strings.ToLower(hello.Tunnel.Subdomain)
		if err := subdomain.Validate(sub); err != nil {
			return nil, nil, fail(protocol.CodeSubdomainForbidden, err.Error(), false)
		}
		if !claims.OwnsSubdomain(sub) {
			return nil, nil, fail(protocol.CodeSubdomainForbidden, "subdomain not reserved by this account", false)
		}
		ok, err := h.store.ClaimSubdomain(ctx, sub, tunnelID, h.liveTTL())
		if err != nil {
			log.Error("store_claim_failed", "err", err)
			return nil, nil, fail(protocol.CodeInternal, "temporarily unavailable", true)
		}
		if !ok {
			return nil, nil, fail(protocol.CodeSubdomainTaken, "subdomain is active on another tunnel", false)
		}
	} else {
		for i := 0; i < 5 && sub == ""; i++ {
			cand, err := h.gen.Next()
			if err != nil || subdomain.Validate(cand) != nil || h.reserved.IsReserved(cand) {
				continue
			}
			ok, err := h.store.ClaimSubdomain(ctx, cand, tunnelID, h.liveTTL())
			if err != nil {
				log.Error("store_claim_failed", "err", err)
				return nil, nil, fail(protocol.CodeInternal, "temporarily unavailable", true)
			}
			if ok {
				sub = cand
			}
		}
		if sub == "" {
			return nil, nil, fail(protocol.CodeInternal, "could not allocate subdomain", true)
		}
	}

	if herr := h.enforceTunnelLimit(ctx, claims, tunnelID, sub); herr != nil {
		return nil, nil, herr
	}

	s := newSession(h, conn, tunnelID, sub, claims.Subject, log.With("tunnelId", tunnelID, "subdomain", sub))
	w, herr := h.activate(ctx, s)
	if herr != nil {
		_ = h.store.ReleaseSubdomain(ctx, sub, tunnelID)
		_ = h.store.RemoveUserTunnel(ctx, claims.Subject, tunnelID)
		return nil, nil, herr
	}
	h.metrics.TunnelConnects.Add(1)
	s.log.Info("tunnel_connect", "protocol", hello.Protocol, "resumed", false)
	h.lifecycle.TunnelEvent(s.ID, s.UserID, s.Subdomain, EventConnected, map[string]any{"clientVersion": hello.Client.Version})
	return s, w, nil
}

func (h *Hub) resume(ctx context.Context, conn *websocket.Conn, hello *protocol.Hello, claims *auth.Claims, log *slog.Logger) (*Session, *protocol.Welcome, *handshakeError) {
	expired := fail(protocol.CodeResumeExpired, "resume window elapsed or unknown tunnel", true)
	id := hello.Resume.TunnelID
	rec, err := h.store.GetTunnel(ctx, id)
	if err != nil {
		log.Error("store_get_failed", "err", err)
		return nil, nil, fail(protocol.CodeInternal, "temporarily unavailable", true)
	}
	if rec == nil || rec.UserID != claims.Subject || rec.ResumeHash == "" ||
		subtle.ConstantTimeCompare([]byte(rec.ResumeHash), []byte(hashToken(hello.Resume.ResumeToken))) != 1 {
		return nil, nil, expired
	}

	// The client may notice a dead socket before we do: retire the old session.
	if old := h.reg.byID(id); old != nil {
		old.replaced.Store(true)
		old.terminate(nil, false, "superseded_by_resume")
		h.reg.remove(old)
	}

	ok, err := h.store.ClaimSubdomain(ctx, rec.Subdomain, id, h.liveTTL())
	if err != nil {
		return nil, nil, fail(protocol.CodeInternal, "temporarily unavailable", true)
	}
	if !ok {
		return nil, nil, expired
	}
	if herr := h.enforceTunnelLimit(ctx, claims, id, rec.Subdomain); herr != nil {
		return nil, nil, herr
	}
	s := newSession(h, conn, id, rec.Subdomain, claims.Subject, log.With("tunnelId", id, "subdomain", rec.Subdomain))
	w, herr := h.activate(ctx, s)
	if herr != nil {
		return nil, nil, herr
	}
	s.log.Info("tunnel_state", "from", store.StateDisconnected, "to", store.StateActive, "resumed", true)
	h.lifecycle.TunnelEvent(s.ID, s.UserID, s.Subdomain, EventResumed, nil)
	return s, w, nil
}

func (h *Hub) enforceTunnelLimit(ctx context.Context, claims *auth.Claims, tunnelID, sub string) *handshakeError {
	max := h.cfg.MaxTunnelsPerUser
	if claims.Limits != nil && claims.Limits.MaxTunnels > 0 {
		max = claims.Limits.MaxTunnels
	}
	n, err := h.store.TouchUserTunnel(ctx, claims.Subject, tunnelID, h.liveTTL())
	if err != nil {
		h.log.Error("store_touch_failed", "err", err)
		_ = h.store.ReleaseSubdomain(ctx, sub, tunnelID)
		return fail(protocol.CodeInternal, "temporarily unavailable", true)
	}
	if max > 0 && n > max {
		_ = h.store.RemoveUserTunnel(ctx, claims.Subject, tunnelID)
		_ = h.store.ReleaseSubdomain(ctx, sub, tunnelID)
		return fail(protocol.CodeTunnelLimit, "concurrent tunnel limit reached", false)
	}
	return nil
}

// activate persists the ACTIVE record with a fresh resume token, registers the
// session locally and builds WELCOME.
func (h *Hub) activate(ctx context.Context, s *Session) (*protocol.Welcome, *handshakeError) {
	resumeToken := httpx.NewID("rsm_", 24)
	rec := store.TunnelRecord{
		ID: s.ID, Subdomain: s.Subdomain, UserID: s.UserID, State: store.StateActive,
		Node: h.cfg.NodeID, LastSeen: h.clock.Now(), ResumeHash: hashToken(resumeToken),
	}
	if err := h.store.SaveTunnel(ctx, rec, h.liveTTL()); err != nil {
		h.log.Error("store_save_failed", "err", err)
		return nil, fail(protocol.CodeInternal, "temporarily unavailable", true)
	}
	h.reg.add(s)
	return &protocol.Welcome{
		TunnelID:    s.ID,
		Subdomain:   s.Subdomain,
		URL:         h.cfg.PublicURL(s.Subdomain),
		ResumeToken: resumeToken,
		Heartbeat: protocol.Heartbeat{
			IntervalMs: h.cfg.HeartbeatInterval.Milliseconds(),
			TimeoutMs:  h.cfg.HeartbeatTimeout.Milliseconds(),
		},
		Limits: protocol.Limits{MaxBodyBytes: h.cfg.MaxBodyBytes},
	}, nil
}

// refresh extends runtime-state TTLs on every heartbeat tick.
func (h *Hub) refresh(s *Session) {
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	ttl := h.liveTTL()
	if _, err := h.store.ClaimSubdomain(ctx, s.Subdomain, s.ID, ttl); err != nil {
		s.log.Error("store_refresh_failed", "err", err)
		return
	}
	_, _ = h.store.TouchUserTunnel(ctx, s.UserID, s.ID, ttl)
	if rec, err := h.store.GetTunnel(ctx, s.ID); err == nil && rec != nil {
		rec.LastSeen = h.clock.Now()
		_ = h.store.SaveTunnel(ctx, *rec, ttl)
	}
}

// detach runs once after a session's socket is gone.
func (h *Hub) detach(s *Session) {
	h.reg.remove(s)
	if s.replaced.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	durationSec := int64(h.clock.Now().Sub(s.connectedAt).Seconds())
	reason := s.closeReason()

	if s.intentional.Load() {
		h.closeTunnel(ctx, s.ID, s.Subdomain, s.UserID)
		s.log.Info("tunnel_disconnect", "reason", reason, "durationSec", durationSec)
		s.log.Info("tunnel_state", "from", store.StateActive, "to", store.StateClosed)
		h.lifecycle.TunnelEvent(s.ID, s.UserID, s.Subdomain, EventClosed, map[string]any{"reason": reason, "durationSec": durationSec})
		return
	}

	// Unexpected drop: hold the subdomain for the resume grace window.
	grace := h.cfg.ResumeGrace
	if rec, err := h.store.GetTunnel(ctx, s.ID); err == nil && rec != nil {
		rec.State = store.StateDisconnected
		rec.LastSeen = h.clock.Now()
		_ = h.store.SaveTunnel(ctx, *rec, grace)
	}
	_, _ = h.store.ClaimSubdomain(ctx, s.Subdomain, s.ID, grace)
	_, _ = h.store.TouchUserTunnel(ctx, s.UserID, s.ID, grace)
	s.log.Info("tunnel_disconnect", "reason", reason, "durationSec", durationSec)
	s.log.Info("tunnel_state", "from", store.StateActive, "to", store.StateDisconnected, "graceSec", int(grace.Seconds()))
	h.lifecycle.TunnelEvent(s.ID, s.UserID, s.Subdomain, EventDisconnected, map[string]any{"reason": reason})

	time.AfterFunc(grace, func() {
		if h.reg.byID(s.ID) != nil {
			return // resumed on this node
		}
		ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
		defer cancel()
		rec, err := h.store.GetTunnel(ctx, s.ID)
		if err != nil || (rec != nil && rec.State == store.StateActive) {
			return // resumed elsewhere, or store unavailable
		}
		h.closeTunnel(ctx, s.ID, s.Subdomain, s.UserID)
		s.log.Info("tunnel_state", "from", store.StateDisconnected, "to", store.StateClosed, "reason", "grace_expired")
		h.lifecycle.TunnelEvent(s.ID, s.UserID, s.Subdomain, EventClosed, map[string]any{"reason": "grace_expired"})
	})
}

func (h *Hub) closeTunnel(ctx context.Context, id, sub, user string) {
	_ = h.store.ReleaseSubdomain(ctx, sub, id)
	_ = h.store.DeleteTunnel(ctx, id)
	_ = h.store.RemoveUserTunnel(ctx, user, id)
}

// Shutdown sends GOAWAY{reconnect:true} to every tunnel. Their runtime state
// stays DISCONNECTED in the store so clients can resume on the next process.
func (h *Hub) Shutdown(ctx context.Context) {
	for _, s := range h.reg.all() {
		s.terminate(&protocol.GoAway{Code: protocol.CodeShutdown, Message: "gateway restarting", Reconnect: true}, false, "gateway_shutdown")
	}
	done := make(chan struct{})
	go func() { h.sessions.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}
