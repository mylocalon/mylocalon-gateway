package platform

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestReservedSyncAndOutage(t *testing.T) {
	var mu sync.Mutex
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"names":["myapp","shop"]}`)
	}))
	defer srv.Close()

	r := NewReserved(NewClient(srv.URL, "tok"), quiet)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !r.IsReserved("myapp") || r.IsReserved("other") {
		t.Fatal("bad reserved set")
	}
	mu.Lock()
	status = 500
	mu.Unlock()
	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if !r.IsReserved("shop") {
		t.Fatal("outage must keep the last good list")
	}
	if err := NewReserved(NewClient(srv.URL, "wrong"), quiet).Refresh(context.Background()); err == nil {
		t.Fatal("wrong token must fail")
	}
}

func TestPublisherBatchesAndFlushesOnStop(t *testing.T) {
	var mu sync.Mutex
	var got []Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Events []Event }
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		got = append(got, body.Events...)
		mu.Unlock()
		w.WriteHeader(202)
	}))
	defer srv.Close()

	p := NewPublisher(NewClient(srv.URL, "tok"), quiet)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	p.TunnelEvent("tnl_1", "usr_1", "abc", "connected", nil)
	p.TunnelEvent("tnl_1", "usr_1", "abc", "closed", map[string]any{"reason": "client_close"})
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("publisher did not stop")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[1].Event != "closed" || got[1].Meta["reason"] != "client_close" || got[0].At == 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestPublisherNeverBlocks(t *testing.T) {
	p := NewPublisher(NewClient("http://127.0.0.1:1", "tok"), quiet) // not running, unreachable
	start := time.Now()
	for i := 0; i < 10_000; i++ {
		p.TunnelEvent("t", "u", "s", "connected", nil)
	}
	if time.Since(start) > time.Second {
		t.Fatal("TunnelEvent blocked")
	}
}
