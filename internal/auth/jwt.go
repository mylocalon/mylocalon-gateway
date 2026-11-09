// Package auth verifies Platform-issued Ed25519 JWTs offline
// (PROTOCOL.md §4, SECURITY.md §2). The Gateway only ever holds public keys,
// so it can verify identity but never mint tokens.
package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mylocalon/mylocalon-gateway/internal/clock"
)

var ErrInvalidToken = errors.New("invalid token")

// Limits are optional plan hints carried in the JWT.
type Limits struct {
	MaxTunnels   int      `json:"maxTunnels,omitempty"`
	MaxBodyBytes int64    `json:"maxBodyBytes,omitempty"`
	Subdomains   []string `json:"subdomains,omitempty"` // reserved subdomains the user owns
}

type Claims struct {
	Subject  string   `json:"sub"`
	Issuer   string   `json:"iss"`
	Audience audience `json:"aud"`
	Expiry   int64    `json:"exp"`
	IssuedAt int64    `json:"iat"`
	ID       string   `json:"jti,omitempty"`
	Plan     string   `json:"plan,omitempty"`
	Limits   *Limits  `json:"limits,omitempty"`
}

// OwnsSubdomain reports whether the token lists name as a reserved subdomain
// owned by the subject.
func (c *Claims) OwnsSubdomain(name string) bool {
	if c.Limits == nil {
		return false
	}
	for _, s := range c.Limits.Subdomains {
		if s == name {
			return true
		}
	}
	return false
}

// audience accepts both the string and array forms allowed by RFC 7519.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = audience{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	*a = arr
	return nil
}

type Verifier interface {
	Verify(token string) (*Claims, error)
}

// KeySource resolves a JWT "kid" to a public key.
type KeySource interface {
	Lookup(kid string) (ed25519.PublicKey, bool)
}

// StaticKeys is a fixed kid -> key map. With exactly one key, tokens without
// a matching kid are tried against it (signature is still verified).
type StaticKeys map[string]ed25519.PublicKey

func (s StaticKeys) Lookup(kid string) (ed25519.PublicKey, bool) {
	if k, ok := s[kid]; ok {
		return k, true
	}
	if len(s) == 1 {
		for _, k := range s {
			return k, true
		}
	}
	return nil, false
}

type Ed25519Verifier struct {
	keys     KeySource
	issuer   string
	audience string
	leeway   time.Duration
	clock    clock.Clock
}

func NewEd25519Verifier(keys KeySource, issuer, aud string, c clock.Clock) *Ed25519Verifier {
	return &Ed25519Verifier{keys: keys, issuer: issuer, audience: aud, leeway: 30 * time.Second, clock: c}
}

func (v *Ed25519Verifier) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: malformed", ErrInvalidToken)
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding", ErrInvalidToken)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, fmt.Errorf("%w: header json", ErrInvalidToken)
	}
	// Pin the algorithm: never trust the header to pick a weaker one.
	if hdr.Alg != "EdDSA" {
		return nil, fmt.Errorf("%w: alg %q not allowed", ErrInvalidToken, hdr.Alg)
	}
	key, ok := v.keys.Lookup(hdr.Kid)
	if !ok {
		return nil, fmt.Errorf("%w: unknown kid %q", ErrInvalidToken, hdr.Kid)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature encoding", ErrInvalidToken)
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, fmt.Errorf("%w: bad signature", ErrInvalidToken)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", ErrInvalidToken)
	}
	var c Claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, fmt.Errorf("%w: payload json", ErrInvalidToken)
	}
	now := v.clock.Now()
	switch {
	case c.Subject == "":
		return nil, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	case c.Issuer != v.issuer:
		return nil, fmt.Errorf("%w: wrong iss", ErrInvalidToken)
	case !contains(c.Audience, v.audience):
		return nil, fmt.Errorf("%w: wrong aud", ErrInvalidToken)
	case c.Expiry == 0 || now.After(time.Unix(c.Expiry, 0).Add(v.leeway)):
		return nil, fmt.Errorf("%w: expired", ErrInvalidToken)
	case c.IssuedAt != 0 && time.Unix(c.IssuedAt, 0).After(now.Add(v.leeway)):
		return nil, fmt.Errorf("%w: issued in the future", ErrInvalidToken)
	}
	return &c, nil
}

func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}

// LoadPublicKeys parses a comma-separated list of "kid=path" (or a bare path,
// which gets kid "default") into Ed25519 public keys from PEM files.
func LoadPublicKeys(spec string) (StaticKeys, error) {
	keys := StaticKeys{}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		kid, path := "default", item
		if i := strings.Index(item, "="); i > 0 {
			kid, path = item[:i], item[i+1:]
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read public key %s: %w", path, err)
		}
		k, err := ParsePublicKeyPEM(raw)
		if err != nil {
			return nil, fmt.Errorf("parse public key %s: %w", path, err)
		}
		keys[kid] = k
	}
	if len(keys) == 0 {
		return nil, errors.New("no public keys configured")
	}
	return keys, nil
}

func ParsePublicKeyPEM(raw []byte) (ed25519.PublicKey, error) {
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	k, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 key")
	}
	return k, nil
}
