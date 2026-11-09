package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mylocalon/mylocalon-gateway/internal/clock"
)

var t0 = time.Unix(1_800_000_000, 0)

func setup(t *testing.T) (ed25519.PrivateKey, *Ed25519Verifier) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	v := NewEd25519Verifier(StaticKeys{"k1": pub}, "mylocalon-platform", "mylocalon-gateway", clock.NewFake(t0))
	return priv, v
}

func claims(mut func(m map[string]any)) map[string]any {
	m := map[string]any{
		"sub": "usr_1", "iss": "mylocalon-platform", "aud": "mylocalon-gateway",
		"iat": t0.Unix(), "exp": t0.Add(time.Hour).Unix(),
	}
	if mut != nil {
		mut(m)
	}
	return m
}

func TestVerify(t *testing.T) {
	priv, v := setup(t)
	_, otherPriv, _ := ed25519.GenerateKey(nil)

	cases := []struct {
		name string
		tok  func() string
		ok   bool
	}{
		{"valid", func() string { s, _ := Sign(priv, "k1", claims(nil)); return s }, true},
		{"aud array", func() string {
			s, _ := Sign(priv, "k1", claims(func(m map[string]any) { m["aud"] = []string{"x", "mylocalon-gateway"} }))
			return s
		}, true},
		{"expired", func() string {
			s, _ := Sign(priv, "k1", claims(func(m map[string]any) { m["exp"] = t0.Add(-time.Hour).Unix() }))
			return s
		}, false},
		{"wrong aud", func() string {
			s, _ := Sign(priv, "k1", claims(func(m map[string]any) { m["aud"] = "other" }))
			return s
		}, false},
		{"wrong iss", func() string {
			s, _ := Sign(priv, "k1", claims(func(m map[string]any) { m["iss"] = "evil" }))
			return s
		}, false},
		{"missing sub", func() string {
			s, _ := Sign(priv, "k1", claims(func(m map[string]any) { delete(m, "sub") }))
			return s
		}, false},
		{"wrong key", func() string { s, _ := Sign(otherPriv, "k1", claims(nil)); return s }, false},
		{"alg none", func() string {
			s, _ := Sign(priv, "k1", claims(nil))
			p := strings.Split(s, ".")
			p[0] = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
			return p[0] + "." + p[1] + "."
		}, false},
		{"garbage", func() string { return "not.a.jwt" }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := v.Verify(c.tok())
			if c.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !c.ok && !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("want ErrInvalidToken, got %v", err)
			}
		})
	}
}

func TestOwnsSubdomain(t *testing.T) {
	priv, v := setup(t)
	s, _ := Sign(priv, "k1", claims(func(m map[string]any) {
		m["limits"] = map[string]any{"subdomains": []string{"myapp"}, "maxTunnels": 3}
	}))
	c, err := v.Verify(s)
	if err != nil {
		t.Fatal(err)
	}
	if !c.OwnsSubdomain("myapp") || c.OwnsSubdomain("other") || c.Limits.MaxTunnels != 3 {
		t.Fatalf("bad claims: %+v", c.Limits)
	}
}
