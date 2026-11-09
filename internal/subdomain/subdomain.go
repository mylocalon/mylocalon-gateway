// Package subdomain generates and validates tunnel subdomain labels.
package subdomain

import (
	"crypto/rand"
	"errors"
	"io"
	"regexp"
	"strings"
)

// DNS label: lowercase alnum and hyphens, 3–63 chars, no leading/trailing hyphen.
var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])$`)

var blocklist = map[string]bool{
	"www": true, "api": true, "admin": true, "gateway": true, "app": true,
	"dashboard": true, "mail": true, "smtp": true, "status": true, "docs": true,
	"static": true, "cdn": true, "auth": true, "login": true, "billing": true,
	"support": true, "help": true, "blog": true, "root": true, "ns1": true, "ns2": true,
}

var (
	ErrInvalid = errors.New("invalid subdomain")
	ErrBlocked = errors.New("subdomain is reserved")
)

func Validate(name string) error {
	if !labelRe.MatchString(name) || strings.Contains(name, "--") {
		return ErrInvalid
	}
	if blocklist[name] {
		return ErrBlocked
	}
	return nil
}

const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// Generator produces random subdomains. Rand is injectable for deterministic
// tests; nil means crypto/rand.
type Generator struct {
	Rand   io.Reader
	Length int
}

func (g Generator) Next() (string, error) {
	n := g.Length
	if n == 0 {
		n = 8
	}
	r := g.Rand
	if r == nil {
		r = rand.Reader
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	// Start with a letter so labels never look like numbers.
	out[0] = alphabet[int(buf[0])%26]
	return string(out), nil
}

// FromHost extracts the tunnel label from a Host header for base domain
// "mylocalon.com": "abc123.mylocalon.com:443" -> "abc123", true. Only a single
// label directly under the base is accepted.
func FromHost(host, base string) (string, bool) {
	host = strings.ToLower(host)
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	host = strings.TrimSuffix(host, ".")
	suffix := "." + strings.ToLower(base)
	if !strings.HasSuffix(host, suffix) {
		return "", false
	}
	label := strings.TrimSuffix(host, suffix)
	if label == "" || strings.Contains(label, ".") || !labelRe.MatchString(label) {
		return "", false
	}
	return label, true
}
