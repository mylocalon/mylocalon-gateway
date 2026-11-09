// Package httpx holds small HTTP helpers shared by ingress and the WSS endpoint.
package httpx

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
)

// hopByHop headers are connection-scoped and must not be forwarded (RFC 9110 §7.6.1).
var hopByHop = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "proxy-connection": true, "te": true, "trailer": true,
	"transfer-encoding": true, "upgrade": true,
}

// IsHopByHop also honours headers named in the Connection header.
func IsHopByHop(name string, connection []string) bool {
	n := strings.ToLower(name)
	if hopByHop[n] {
		return true
	}
	for _, v := range connection {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), n) {
				return true
			}
		}
	}
	return false
}

// ClientIP returns the original client IP. X-Forwarded-For is only trusted
// when the Gateway sits behind Caddy (trustProxy); otherwise it is spoofable.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Caddy appends the real peer as the last hop.
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// NewID returns prefix + n random bytes as lowercase hex.
func NewID(prefix string, n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}
