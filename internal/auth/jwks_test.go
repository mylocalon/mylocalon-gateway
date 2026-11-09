package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mylocalon/mylocalon-gateway/internal/clock"
)

func jwksJSON(keys map[string]ed25519.PublicKey) string {
	s := `{"keys":[`
	i := 0
	for kid, k := range keys {
		if i > 0 {
			s += ","
		}
		s += fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"kid":%q,"alg":"EdDSA","use":"sig"}`,
			base64.RawURLEncoding.EncodeToString(k), kid)
		i++
	}
	return s + `,{"kty":"RSA","kid":"ignored"}]}`
}

func TestJWKSRotationAndOutage(t *testing.T) {
	pub1, priv1, _ := ed25519.GenerateKey(nil)
	pub2, priv2, _ := ed25519.GenerateKey(nil)

	var body atomic.Value
	body.Store(jwksJSON(map[string]ed25519.PublicKey{"k1": pub1}))
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if down.Load() {
			w.WriteHeader(503)
			return
		}
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	defer srv.Close()

	ks := NewJWKSKeys(srv.URL, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ks.minFetch = 0 // allow immediate unknown-kid refreshes in the test
	if err := ks.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ks.Len() != 1 {
		t.Fatalf("RSA key must be skipped, got %d keys", ks.Len())
	}
	now := time.Now()
	v := NewEd25519Verifier(ks, "mylocalon-platform", "mylocalon-gateway", clock.NewFake(now))
	tok := func(priv ed25519.PrivateKey, kid string) string {
		s, _ := Sign(priv, kid, map[string]any{"sub": "u", "iss": "mylocalon-platform", "aud": "mylocalon-gateway",
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
		return s
	}

	if _, err := v.Verify(tok(priv1, "k1")); err != nil {
		t.Fatalf("k1: %v", err)
	}
	// Rotation: Platform starts signing with k2 — an unknown kid triggers a refresh.
	body.Store(jwksJSON(map[string]ed25519.PublicKey{"k1": pub1, "k2": pub2}))
	if _, err := v.Verify(tok(priv2, "k2")); err != nil {
		t.Fatalf("k2 after rotation: %v", err)
	}
	// Platform outage: previously fetched keys keep working (offline verify).
	down.Store(true)
	if _, err := v.Verify(tok(priv1, "k1")); err != nil {
		t.Fatalf("k1 during outage: %v", err)
	}
	if err := ks.Refresh(context.Background()); err == nil {
		t.Fatal("refresh should fail while down")
	}
	if ks.Len() != 2 {
		t.Fatal("failed refresh must keep the last good key set")
	}
	// A key that was never published is rejected.
	_, priv3, _ := ed25519.GenerateKey(nil)
	if _, err := v.Verify(tok(priv3, "k3")); err == nil {
		t.Fatal("unknown key must fail")
	}
}

func TestParseJWKSRejectsEmpty(t *testing.T) {
	if _, err := ParseJWKS(strings.NewReader(`{"keys":[{"kty":"OKP","crv":"X25519","x":"AAAA","kid":"a"}]}`)); err == nil {
		t.Fatal("want error")
	}
}
