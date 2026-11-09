package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// JWKSKeys fetches the Platform's published Ed25519 keys (GET /api/v1/jwks)
// and refreshes them periodically, so signing-key rotation needs no Gateway
// restart. Verification stays offline: the last good key set is kept when
// the Platform is unreachable. Static keys (PEM files) act as a fallback.
type JWKSKeys struct {
	url      string
	static   StaticKeys
	client   *http.Client
	log      *slog.Logger
	minFetch time.Duration

	mu        sync.RWMutex
	remote    map[string]ed25519.PublicKey
	fetchMu   sync.Mutex
	lastFetch time.Time
}

func NewJWKSKeys(url string, static StaticKeys, log *slog.Logger) *JWKSKeys {
	return &JWKSKeys{
		url: url, static: static, log: log,
		client:   &http.Client{Timeout: 3 * time.Second},
		minFetch: 30 * time.Second,
		remote:   map[string]ed25519.PublicKey{},
	}
}

func (j *JWKSKeys) Lookup(kid string) (ed25519.PublicKey, bool) {
	if k, ok := j.lookupRemote(kid); ok {
		return k, true
	}
	// Unknown kid: maybe a key was just rotated in. Refresh (rate-limited).
	if kid != "" && j.refreshIfStale() {
		if k, ok := j.lookupRemote(kid); ok {
			return k, true
		}
	}
	if j.static != nil {
		return j.static.Lookup(kid)
	}
	return nil, false
}

func (j *JWKSKeys) lookupRemote(kid string) (ed25519.PublicKey, bool) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	k, ok := j.remote[kid]
	return k, ok
}

func (j *JWKSKeys) Len() int {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return len(j.remote)
}

func (j *JWKSKeys) refreshIfStale() bool {
	j.fetchMu.Lock()
	stale := time.Since(j.lastFetch) >= j.minFetch
	j.fetchMu.Unlock()
	if !stale {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return j.Refresh(ctx) == nil
}

// Refresh fetches the JWKS. On any failure the previous keys are kept.
func (j *JWKSKeys) Refresh(ctx context.Context) error {
	j.fetchMu.Lock()
	j.lastFetch = time.Now()
	j.fetchMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url, nil)
	if err != nil {
		return err
	}
	res, err := j.client.Do(req)
	if err != nil {
		j.log.Warn("jwks_fetch_failed", "err", err)
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		err := fmt.Errorf("jwks: HTTP %d", res.StatusCode)
		j.log.Warn("jwks_fetch_failed", "err", err)
		return err
	}
	keys, err := ParseJWKS(http.MaxBytesReader(nil, res.Body, 64<<10))
	if err != nil {
		j.log.Warn("jwks_parse_failed", "err", err)
		return err
	}
	j.mu.Lock()
	j.remote = keys
	j.mu.Unlock()
	j.log.Info("jwks_refreshed", "keys", len(keys))
	return nil
}

// Run refreshes every interval until ctx is done.
func (j *JWKSKeys) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = j.Refresh(ctx)
		}
	}
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// ParseJWKS accepts only OKP/Ed25519 signing keys; anything else is skipped.
func ParseJWKS(r io.Reader) (map[string]ed25519.PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(r).Decode(&set); err != nil {
		return nil, fmt.Errorf("jwks json: %w", err)
	}
	out := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid == "" || (k.Alg != "" && k.Alg != "EdDSA") || (k.Use != "" && k.Use != "sig") {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			continue
		}
		out[k.Kid] = ed25519.PublicKey(x)
	}
	if len(out) == 0 {
		return nil, errors.New("jwks contains no usable Ed25519 keys")
	}
	return out, nil
}
