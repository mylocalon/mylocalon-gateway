package server_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/mylocalon/mylocalon-gateway/internal/auth"
	"github.com/mylocalon/mylocalon-gateway/internal/clock"
	"github.com/mylocalon/mylocalon-gateway/internal/config"
	"github.com/mylocalon/mylocalon-gateway/internal/ingress"
	"github.com/mylocalon/mylocalon-gateway/internal/metrics"
	"github.com/mylocalon/mylocalon-gateway/internal/protocol"
	"github.com/mylocalon/mylocalon-gateway/internal/ratelimit"
	"github.com/mylocalon/mylocalon-gateway/internal/server"
	"github.com/mylocalon/mylocalon-gateway/internal/store"
	"github.com/mylocalon/mylocalon-gateway/internal/tunnel"
)

type env struct {
	t    *testing.T
	srv  *httptest.Server
	priv ed25519.PrivateKey
	cfg  *config.Config
	in   *ingress.Handler
}

type envOpt func(*envOpts)

type envOpts struct{ st store.Store }

func withStore(s store.Store) envOpt { return func(o *envOpts) { o.st = s } }

func newEnv(t *testing.T, mut func(*config.Config)) *env { return newEnvWith(t, mut, nil) }

func newEnvWith(t *testing.T, mut func(*config.Config), hubMut func(*tunnel.Hub), opts ...envOpt) *env {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	cfg := &config.Config{
		Env: "test", BaseDomain: "localtest.me", PublicScheme: "http", PublicPort: "7002",
		NodeID: "test", JWTIssuer: "mylocalon-platform", JWTAudience: "mylocalon-gateway",
		HeartbeatInterval: 50 * time.Millisecond, HeartbeatTimeout: 300 * time.Millisecond,
		ResumeGrace: 400 * time.Millisecond, HelloTimeout: time.Second, RequestTimeout: 2 * time.Second,
		MaxBodyBytes: 1024, MaxHeaderBytes: 32 << 10, MaxTunnelsPerUser: 2,
		ConnRatePerMin: 1000, ReqRatePerSec: 1000,
	}
	if mut != nil {
		mut(cfg)
	}
	clk := clock.Real{}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	o := envOpts{st: store.NewMemory(clk)}
	for _, f := range opts {
		f(&o)
	}
	st := o.st
	m := metrics.New()
	v := auth.NewEd25519Verifier(auth.StaticKeys{"default": pub}, cfg.JWTIssuer, cfg.JWTAudience, clk)
	hub := tunnel.NewHub(cfg, st, v, m, clk, log)
	if hubMut != nil {
		hubMut(hub)
	}
	in := ingress.New(cfg, server.TunnelsAdapter{Hub: hub}, ratelimit.New(st, log), m, clk, log)
	srv := httptest.NewUnstartedServer(server.Public(cfg, hub, in, clk))
	srv.Config.MaxHeaderBytes = cfg.MaxHeaderBytes // same edge limit as main.go
	srv.Start()
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, priv: priv, cfg: cfg, in: in}
}

func (e *env) token(sub string, limits map[string]any) string {
	c := map[string]any{"sub": sub, "iss": "mylocalon-platform", "aud": "mylocalon-gateway",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	if limits != nil {
		c["limits"] = limits
	}
	s, err := auth.Sign(e.priv, "default", c)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

type client struct {
	t    *testing.T
	conn *websocket.Conn
}

func (e *env) dial() *client {
	e.t.Helper()
	url := "ws" + strings.TrimPrefix(e.srv.URL, "http") + "/tunnel"
	d := websocket.Dialer{Subprotocols: []string{protocol.Subprotocol}}
	conn, resp, err := d.Dial(url, nil)
	if err != nil {
		e.t.Fatalf("dial: %v (%v)", err, resp)
	}
	if conn.Subprotocol() != protocol.Subprotocol {
		e.t.Fatalf("subprotocol not echoed: %q", conn.Subprotocol())
	}
	e.t.Cleanup(func() { conn.Close() })
	return &client{t: e.t, conn: conn}
}

func (c *client) send(m protocol.Message) {
	c.t.Helper()
	b, _ := protocol.Encode(m)
	if err := c.conn.WriteMessage(websocket.TextMessage, b); err != nil {
		c.t.Fatal(err)
	}
}

// next returns the next non-PING message (auto-replying PONG).
func (c *client) next() protocol.Message {
	c.t.Helper()
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			c.t.Fatalf("read: %v", err)
		}
		m, err := protocol.Decode(data)
		if err != nil {
			c.t.Fatalf("decode %s: %v", data, err)
		}
		if p, ok := m.(*protocol.Ping); ok {
			c.send(&protocol.Pong{TS: p.TS})
			continue
		}
		return m
	}
}

func (e *env) open(hello *protocol.Hello) (*client, protocol.Message) {
	c := e.dial()
	hello.Protocol = protocol.Version
	if hello.Token == "" {
		hello.Token = e.token("usr_1", nil)
	}
	c.send(hello)
	return c, c.next()
}

func (e *env) welcome(hello *protocol.Hello) (*client, *protocol.Welcome) {
	e.t.Helper()
	c, m := e.open(hello)
	w, ok := m.(*protocol.Welcome)
	if !ok {
		e.t.Fatalf("want WELCOME, got %#v", m)
	}
	return c, w
}

func wantGoAway(t *testing.T, m protocol.Message, code string) {
	t.Helper()
	g, ok := m.(*protocol.GoAway)
	if !ok || g.Code != code {
		t.Fatalf("want GOAWAY %s, got %#v", code, m)
	}
}

func (e *env) public(method, sub, path string, body []byte) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	req.Host = sub + ".localtest.me"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// serveOnce answers the next HTTP_REQUEST with reply(req).
func (c *client) serveOnce(reply func(*protocol.HTTPRequest) protocol.Message) <-chan *protocol.HTTPRequest {
	got := make(chan *protocol.HTTPRequest, 1)
	go func() {
		for {
			_ = c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, data, err := c.conn.ReadMessage()
			if err != nil {
				close(got)
				return
			}
			m, _ := protocol.Decode(data)
			switch v := m.(type) {
			case *protocol.Ping:
				b, _ := protocol.Encode(&protocol.Pong{TS: v.TS})
				_ = c.conn.WriteMessage(websocket.TextMessage, b)
			case *protocol.HTTPRequest:
				if r := reply(v); r != nil {
					b, _ := protocol.Encode(r)
					_ = c.conn.WriteMessage(websocket.TextMessage, b)
				}
				got <- v
				return
			}
		}
	}()
	return got
}

// ---------------------------------------------------------------- tests

func TestHealth(t *testing.T) {
	e := newEnv(t, nil)
	resp, err := http.Get(e.srv.URL + "/health")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("health: %v %v", resp, err)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Fatalf("body %v", body)
	}
}

func TestHandshakeWelcome(t *testing.T) {
	e := newEnv(t, nil)
	_, w := e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	if !strings.HasPrefix(w.TunnelID, "tnl_") || w.Subdomain == "" || w.ResumeToken == "" {
		t.Fatalf("bad welcome %+v", w)
	}
	if w.URL != fmt.Sprintf("http://%s.localtest.me:7002", w.Subdomain) {
		t.Fatalf("url %s", w.URL)
	}
	if w.Heartbeat.IntervalMs != 50 || w.Limits.MaxBodyBytes != 1024 {
		t.Fatalf("heartbeat/limits %+v", w)
	}
}

func TestHandshakeFailures(t *testing.T) {
	e := newEnv(t, nil)
	cases := []struct {
		name  string
		hello *protocol.Hello
		code  string
	}{
		{"invalid jwt", &protocol.Hello{Token: "a.b.c"}, protocol.CodeAuthFailed},
		{"reserved not owned", &protocol.Hello{Tunnel: &protocol.TunnelRequest{Subdomain: "myapp"}}, protocol.CodeSubdomainForbidden},
		{"blocklisted", &protocol.Hello{Tunnel: &protocol.TunnelRequest{Subdomain: "admin"}}, protocol.CodeSubdomainForbidden},
		{"resume unknown", &protocol.Hello{Resume: &protocol.ResumeRequest{TunnelID: "tnl_x", ResumeToken: "rsm_x"}}, protocol.CodeResumeExpired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, m := e.open(c.hello)
			wantGoAway(t, m, c.code)
		})
	}

	t.Run("version unsupported", func(t *testing.T) {
		c := e.dial()
		b, _ := json.Marshal(map[string]any{"type": "HELLO", "protocol": 2, "token": e.token("u", nil)})
		_ = c.conn.WriteMessage(websocket.TextMessage, b)
		wantGoAway(t, c.next(), protocol.CodeVersionUnsupported)
	})
	t.Run("first message not hello", func(t *testing.T) {
		c := e.dial()
		c.send(&protocol.Ping{TS: 1})
		wantGoAway(t, c.next(), protocol.CodeProtocolError)
	})
}

func TestMissingSubprotocol426(t *testing.T) {
	e := newEnv(t, nil)
	url := "ws" + strings.TrimPrefix(e.srv.URL, "http") + "/tunnel"
	_, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("want 426, got %v %v", resp, err)
	}
}

func TestReservedSubdomain(t *testing.T) {
	e := newEnv(t, nil)
	tok := e.token("usr_1", map[string]any{"subdomains": []string{"myapp"}})
	_, w := e.welcome(&protocol.Hello{Token: tok, Tunnel: &protocol.TunnelRequest{Subdomain: "myapp"}})
	if w.Subdomain != "myapp" {
		t.Fatalf("got %s", w.Subdomain)
	}
	_, m := e.open(&protocol.Hello{Token: tok, Tunnel: &protocol.TunnelRequest{Subdomain: "myapp"}})
	wantGoAway(t, m, protocol.CodeSubdomainTaken)
}

func TestTunnelLimit(t *testing.T) {
	e := newEnv(t, nil) // MaxTunnelsPerUser = 2
	e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	_, m := e.open(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	wantGoAway(t, m, protocol.CodeTunnelLimit)
}

func TestForwarding(t *testing.T) {
	e := newEnv(t, nil)
	c, w := e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	got := c.serveOnce(func(r *protocol.HTTPRequest) protocol.Message {
		return &protocol.HTTPResponse{ReqID: r.ReqID, Status: 201,
			Headers: []protocol.Header{{"content-type", "text/plain"}, {"set-cookie", "a=1"}, {"set-cookie", "b=2"}, {"connection", "close"}},
			BodyB64: protocol.EncodeBody([]byte("created"))}
	})
	resp := e.public("POST", w.Subdomain, "/api/users?limit=10", []byte(`{"n":1}`))
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 201 || string(body) != "created" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if ck := resp.Header.Values("Set-Cookie"); len(ck) != 2 {
		t.Fatalf("set-cookie %v", ck)
	}
	req := <-got
	if req.Method != "POST" || req.Path != "/api/users?limit=10" || req.RemoteIP == "" {
		t.Fatalf("forwarded req %+v", req)
	}
	if b, _ := protocol.DecodeBody(req.BodyB64); string(b) != `{"n":1}` {
		t.Fatalf("body %q", b)
	}
	var xfh string
	for _, h := range req.Headers {
		if h[0] == "connection" || h[0] == "transfer-encoding" {
			t.Fatalf("hop-by-hop header forwarded: %v", h)
		}
		if h[0] == "x-forwarded-host" {
			xfh = h[1]
		}
	}
	if xfh != w.Subdomain+".localtest.me" {
		t.Fatalf("x-forwarded-host %q", xfh)
	}
}

func TestUnknownSubdomain404(t *testing.T) {
	e := newEnv(t, nil)
	if resp := e.public("GET", "nosuchtunnel", "/", nil); resp.StatusCode != 404 {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}

func TestUpstreamErrors(t *testing.T) {
	e := newEnv(t, nil)
	cases := map[string]int{protocol.CodeUpstreamUnreachable: 502, protocol.CodeUpstreamTimeout: 504}
	for code, status := range cases {
		t.Run(code, func(t *testing.T) {
			c, w := e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
			got := c.serveOnce(func(r *protocol.HTTPRequest) protocol.Message {
				return &protocol.Error{ReqID: r.ReqID, Code: code, Message: "x"}
			})
			if resp := e.public("GET", w.Subdomain, "/", nil); resp.StatusCode != status {
				t.Fatalf("want %d got %d", status, resp.StatusCode)
			}
			<-got                                         // serveOnce's goroutine is done writing to the socket
			c.send(&protocol.Close{TunnelID: w.TunnelID}) // free the per-user slot
			time.Sleep(50 * time.Millisecond)
		})
	}
}

func TestGatewayTimeout504(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.RequestTimeout = 200 * time.Millisecond })
	c, w := e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	c.serveOnce(func(*protocol.HTTPRequest) protocol.Message { return nil }) // never answers
	if resp := e.public("GET", w.Subdomain, "/", nil); resp.StatusCode != 504 {
		t.Fatalf("want 504 got %d", resp.StatusCode)
	}
}

func TestOversizedBody413(t *testing.T) {
	e := newEnv(t, nil) // MaxBodyBytes = 1024
	c, w := e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	got := c.serveOnce(func(r *protocol.HTTPRequest) protocol.Message {
		return &protocol.HTTPResponse{ReqID: r.ReqID, Status: 200}
	})
	if resp := e.public("POST", w.Subdomain, "/", bytes.Repeat([]byte("x"), 2048)); resp.StatusCode != 413 {
		t.Fatalf("want 413 got %d", resp.StatusCode)
	}
	select {
	case r := <-got:
		if r != nil {
			t.Fatal("oversized request reached the client")
		}
	case <-time.After(150 * time.Millisecond):
	}
}

func TestOversizedHeaders431(t *testing.T) {
	e := newEnv(t, nil)
	req, _ := http.NewRequest("GET", e.srv.URL+"/", nil)
	req.Host = "abc.localtest.me"
	req.Header.Set("X-Big", strings.Repeat("a", 40<<10))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("want 431 got %d", resp.StatusCode)
	}
}

func TestMalformedMessageProtocolError(t *testing.T) {
	e := newEnv(t, nil)
	c, _ := e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	_ = c.conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"TELEPORT"}`))
	m := c.next()
	if er, ok := m.(*protocol.Error); !ok || er.Code != protocol.CodeProtocolError {
		t.Fatalf("want ERROR PROTOCOL_ERROR, got %#v", m)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := c.conn.ReadMessage(); err == nil {
		t.Fatal("connection should be closed")
	}
}

func TestClientPingGetsPong(t *testing.T) {
	e := newEnv(t, nil)
	c, _ := e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	c.send(&protocol.Ping{TS: 42})
	if p, ok := c.next().(*protocol.Pong); !ok || p.TS != 42 {
		t.Fatal("expected PONG ts=42")
	}
}

func TestResumeWithinGraceKeepsSubdomain(t *testing.T) {
	e := newEnv(t, nil)
	c, w := e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	c.conn.Close() // simulate a dropped socket
	time.Sleep(100 * time.Millisecond)

	// During the gap the public URL reports "reconnecting", not 404.
	if resp := e.public("GET", w.Subdomain, "/", nil); resp.StatusCode != 502 {
		t.Fatalf("want 502 during grace, got %d", resp.StatusCode)
	}

	_, w2 := e.welcome(&protocol.Hello{Resume: &protocol.ResumeRequest{TunnelID: w.TunnelID, ResumeToken: w.ResumeToken}})
	if w2.TunnelID != w.TunnelID || w2.Subdomain != w.Subdomain {
		t.Fatalf("resume changed identity: %+v -> %+v", w, w2)
	}
	if w2.ResumeToken == w.ResumeToken {
		t.Fatal("resume token must rotate")
	}
	// The old resume token is now invalid.
	_, m := e.open(&protocol.Hello{Resume: &protocol.ResumeRequest{TunnelID: w.TunnelID, ResumeToken: w.ResumeToken}})
	wantGoAway(t, m, protocol.CodeResumeExpired)
}

func TestResumeAfterGraceExpires(t *testing.T) {
	e := newEnv(t, nil) // grace 400ms
	c, w := e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	c.conn.Close()
	time.Sleep(600 * time.Millisecond)

	_, m := e.open(&protocol.Hello{Resume: &protocol.ResumeRequest{TunnelID: w.TunnelID, ResumeToken: w.ResumeToken}})
	wantGoAway(t, m, protocol.CodeResumeExpired)

	// With tunnel{} set too, the Gateway falls back to a fresh tunnel.
	_, w2 := e.welcome(&protocol.Hello{
		Resume: &protocol.ResumeRequest{TunnelID: w.TunnelID, ResumeToken: w.ResumeToken},
		Tunnel: &protocol.TunnelRequest{},
	})
	if w2.TunnelID == w.TunnelID {
		t.Fatal("expected a new tunnel")
	}
	if resp := e.public("GET", w.Subdomain, "/", nil); resp.StatusCode != 404 {
		t.Fatalf("old subdomain should be gone, got %d", resp.StatusCode)
	}
}

func TestHeartbeatTimeoutDisconnects(t *testing.T) {
	e := newEnv(t, nil) // timeout 300ms
	c, w := e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	_ = c // never read or PONG: the gateway must time us out
	time.Sleep(500 * time.Millisecond)
	if resp := e.public("GET", w.Subdomain, "/", nil); resp.StatusCode != 502 {
		t.Fatalf("want 502 (disconnected, in grace), got %d", resp.StatusCode)
	}
}

func TestCloseReleasesSubdomain(t *testing.T) {
	e := newEnv(t, nil)
	c, w := e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	c.send(&protocol.Close{TunnelID: w.TunnelID})
	time.Sleep(100 * time.Millisecond)
	if resp := e.public("GET", w.Subdomain, "/", nil); resp.StatusCode != 404 {
		t.Fatalf("want 404 after CLOSE, got %d", resp.StatusCode)
	}
}

func TestRateLimited(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.ConnRatePerMin = 2 })
	e.dial()
	e.dial()
	url := "ws" + strings.TrimPrefix(e.srv.URL, "http") + "/tunnel"
	d := websocket.Dialer{Subprotocols: []string{protocol.Subprotocol}}
	_, resp, err := d.Dial(url, nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %v %v", resp, err)
	}
}

// ------------------------------------------------- platform hooks & limits

type recLifecycle struct {
	mu     sync.Mutex
	events []string
}

func (r *recLifecycle) TunnelEvent(_, _, _, event string, meta map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if reason, ok := meta["reason"].(string); ok {
		event += ":" + reason
	}
	r.events = append(r.events, event)
}

func (r *recLifecycle) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

type allReserved struct{}

func (allReserved) IsReserved(string) bool { return true }

func TestLifecycleEvents(t *testing.T) {
	rec := &recLifecycle{}
	e := newEnvWith(t, nil, func(h *tunnel.Hub) { h.WithLifecycle(rec) })
	c, w := e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	c.conn.Close()
	time.Sleep(100 * time.Millisecond)
	c2, _ := e.welcome(&protocol.Hello{Resume: &protocol.ResumeRequest{TunnelID: w.TunnelID, ResumeToken: w.ResumeToken}})
	c2.send(&protocol.Close{TunnelID: w.TunnelID})
	time.Sleep(100 * time.Millisecond)
	want := []string{"connected", "disconnected:socket_closed", "resumed", "closed:client_close"}
	if got := rec.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("events %v want %v", got, want)
	}
}

func TestGraceExpiryEmitsClosed(t *testing.T) {
	rec := &recLifecycle{}
	e := newEnvWith(t, nil, func(h *tunnel.Hub) { h.WithLifecycle(rec) })
	c, _ := e.welcome(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	c.conn.Close()
	time.Sleep(600 * time.Millisecond) // grace is 400ms
	if got := rec.snapshot(); got[len(got)-1] != "closed:grace_expired" {
		t.Fatalf("events %v", got)
	}
}

func TestRandomAllocationSkipsReservedNames(t *testing.T) {
	e := newEnvWith(t, nil, func(h *tunnel.Hub) { h.WithReserved(allReserved{}) })
	_, m := e.open(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	wantGoAway(t, m, protocol.CodeInternal) // every candidate was reserved
}

func TestPerIPRequestLimit(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.IPReqRatePerSec = 3 })
	codes := []int{}
	for i := 0; i < 5; i++ {
		codes = append(codes, e.public("GET", "nosuch", "/", nil).StatusCode)
	}
	if fmt.Sprint(codes) != "[404 404 404 429 429]" {
		t.Fatalf("codes %v", codes)
	}
}

func TestAbuseFilterBlocksTakenDownSubdomain(t *testing.T) {
	e := newEnvWith(t, nil, nil)
	e.in.WithFilter(ingress.NewBasicFilter("localtest.me", []string{"phish"}))
	if code := e.public("GET", "phish", "/", nil).StatusCode; code != 403 {
		t.Fatalf("want 403 got %d", code)
	}
}

// brokenStore simulates Redis being unavailable.
type brokenStore struct{ store.Store }

var errDown = fmt.Errorf("redis: connection refused")

func (brokenStore) ClaimSubdomain(context.Context, string, string, time.Duration) (bool, error) {
	return false, errDown
}
func (brokenStore) LookupSubdomain(context.Context, string) (string, error) { return "", errDown }
func (brokenStore) Incr(context.Context, string, time.Duration) (int64, error) {
	return 0, errDown
}
func (brokenStore) IsRevoked(context.Context, string) (bool, error) { return false, errDown }
func (brokenStore) Ping(context.Context) error                      { return errDown }

func TestRedisUnavailableDegradesGracefully(t *testing.T) {
	e := newEnvWith(t, func(c *config.Config) { c.ConnRatePerMin = 1 }, nil, withStore(brokenStore{}))
	// Handshake: rate limiter fails open, subdomain claim fails → GOAWAY INTERNAL reconnect:true.
	_, m := e.open(&protocol.Hello{Tunnel: &protocol.TunnelRequest{}})
	g, ok := m.(*protocol.GoAway)
	if !ok || g.Code != protocol.CodeInternal || !g.Reconnect {
		t.Fatalf("want GOAWAY INTERNAL reconnect, got %#v", m)
	}
	// Public ingress keeps answering (no panic): unknown tunnel → 404.
	if code := e.public("GET", "abc", "/", nil).StatusCode; code != 404 {
		t.Fatalf("want 404 got %d", code)
	}
	// Health stays up; readiness reports the outage.
	admin := httptest.NewServer(server.Admin(brokenStore{}, metrics.New(), clock.Real{}))
	defer admin.Close()
	resp, _ := http.Get(admin.URL + "/ready")
	if resp.StatusCode != 503 {
		t.Fatalf("ready = %d", resp.StatusCode)
	}
}
