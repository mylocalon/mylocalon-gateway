// Package config loads Gateway configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env        string
	LogLevel   string
	ListenAddr string // public: ingress + /tunnel (behind Caddy)
	AdminAddr  string // private: /health /ready /metrics
	NodeID     string

	BaseDomain   string // e.g. mylocalon.com, or localtest.me in dev
	PublicScheme string // https in prod
	PublicPort   string // "" in prod; "7002" in dev so URLs are clickable
	TrustProxy   bool   // trust X-Forwarded-For from Caddy

	RedisURL      string // "" -> in-memory store (single node, dev only)
	JWTPublicKeys string // "kid=path,..." or a single path; optional when JWKSURL is set
	JWKSURL       string // Platform JWKS, e.g. http://127.0.0.1:3001/api/v1/jwks

	// Optional private link to the Platform (reserved names + tunnel events).
	PlatformURL   string
	InternalToken string

	BlockedSubdomains []string // operator takedowns
	JWTIssuer         string
	JWTAudience       string

	HeartbeatInterval time.Duration
	HeartbeatTimeout  time.Duration
	ResumeGrace       time.Duration
	HelloTimeout      time.Duration
	RequestTimeout    time.Duration

	MaxBodyBytes      int64
	MaxHeaderBytes    int
	MaxTunnelsPerUser int
	ConnRatePerMin    int // new tunnel connections per IP and per token
	ReqRatePerSec     int // public requests per tunnel
	IPReqRatePerSec   int // public requests per client IP
}

func Load() (*Config, error) {
	host, _ := os.Hostname()
	c := &Config{
		Env:               str("ML_ENV", "dev"),
		LogLevel:          str("ML_LOG_LEVEL", "info"),
		ListenAddr:        str("ML_LISTEN_ADDR", ":7002"),
		AdminAddr:         str("ML_ADMIN_ADDR", "127.0.0.1:7003"),
		NodeID:            str("ML_NODE_ID", host),
		BaseDomain:        str("ML_BASE_DOMAIN", "localtest.me"),
		PublicScheme:      str("ML_PUBLIC_SCHEME", "http"),
		PublicPort:        str("ML_PUBLIC_PORT", "7002"),
		RedisURL:          str("ML_REDIS_URL", ""),
		JWTPublicKeys:     str("ML_JWT_PUBLIC_KEYS", "keys/ed25519.pub"),
		JWTIssuer:         str("ML_JWT_ISSUER", "mylocalon-platform"),
		JWTAudience:       str("ML_JWT_AUDIENCE", "mylocalon-gateway"),
		JWKSURL:           str("ML_JWKS_URL", ""),
		PlatformURL:       str("ML_PLATFORM_URL", ""),
		InternalToken:     str("ML_INTERNAL_TOKEN", ""),
		BlockedSubdomains: splitList(str("ML_BLOCKED_SUBDOMAINS", "")),
		MaxHeaderBytes:    32 << 10,
	}
	var err error
	set := func(dst *time.Duration, key string, def time.Duration) {
		if err == nil {
			*dst, err = dur(key, def)
		}
	}
	set(&c.HeartbeatInterval, "ML_HEARTBEAT_INTERVAL", 15*time.Second)
	set(&c.HeartbeatTimeout, "ML_HEARTBEAT_TIMEOUT", 45*time.Second)
	set(&c.ResumeGrace, "ML_RESUME_GRACE", 30*time.Second)
	set(&c.HelloTimeout, "ML_HELLO_TIMEOUT", 10*time.Second)
	set(&c.RequestTimeout, "ML_REQUEST_TIMEOUT", 35*time.Second)
	if err != nil {
		return nil, err
	}
	if c.MaxBodyBytes, err = i64("ML_MAX_BODY_BYTES", 10<<20); err != nil {
		return nil, err
	}
	ints := []struct {
		dst *int
		key string
		def int
	}{
		{&c.MaxTunnelsPerUser, "ML_MAX_TUNNELS_PER_USER", 5},
		{&c.ConnRatePerMin, "ML_CONN_RATE_PER_MIN", 30},
		{&c.ReqRatePerSec, "ML_REQ_RATE_PER_SEC", 100},
		{&c.IPReqRatePerSec, "ML_IP_REQ_RATE_PER_SEC", 50},
	}
	for _, x := range ints {
		v, err := i64(x.key, int64(x.def))
		if err != nil {
			return nil, err
		}
		*x.dst = int(v)
	}
	if c.TrustProxy, err = strconv.ParseBool(str("ML_TRUST_PROXY", "false")); err != nil {
		return nil, fmt.Errorf("ML_TRUST_PROXY: %w", err)
	}
	if c.JWTPublicKeys == "" && c.JWKSURL == "" {
		return nil, fmt.Errorf("set ML_JWT_PUBLIC_KEYS and/or ML_JWKS_URL")
	}
	if c.PlatformURL != "" && len(c.InternalToken) < 32 {
		return nil, fmt.Errorf("ML_INTERNAL_TOKEN (>=32 chars) is required with ML_PLATFORM_URL")
	}
	if c.HeartbeatTimeout <= c.HeartbeatInterval {
		return nil, fmt.Errorf("ML_HEARTBEAT_TIMEOUT must exceed ML_HEARTBEAT_INTERVAL")
	}
	return c, nil
}

// PublicURL builds the tunnel's public URL for WELCOME.
func (c *Config) PublicURL(sub string) string {
	host := sub + "." + c.BaseDomain
	if c.PublicPort != "" {
		host += ":" + c.PublicPort
	}
	return c.PublicScheme + "://" + host
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func str(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return def
}

func dur(k string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(k)
	if !ok {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return d, nil
}

func i64(k string, def int64) (int64, error) {
	v, ok := os.LookupEnv(k)
	if !ok {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return n, nil
}
