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

// reserved names can never be claimed: mylocalon's own surfaces, infrastructure,
// environments, account/billing words and high-risk brands. Canonical source:
// docs/fixtures/policy/reserved-subdomains.json (TestReservedMatchesFixture keeps this in sync).
var reserved = toSet(
	"about", "abuse", "account", "accounts", "admin", "administrator", "admins", "airtel",
	"alpha", "amazon", "anthropic", "api", "apis", "app", "apple", "apps",
	"assets", "auth", "autoconfig", "autodiscover", "aws", "azure", "beta", "billing",
	"binance", "blog", "canary", "careers", "cdn", "changelog", "chat", "chatgpt",
	"checkout", "claude", "cluster", "coinbase", "community", "compliance", "console", "contact",
	"cookies", "dashboard", "demo", "dev", "develop", "developer", "developers", "development",
	"dns", "doc", "docs", "documentation", "download", "downloads", "edge", "email",
	"facebook", "faq", "files", "forum", "ftp", "gateway", "gdpr", "git",
	"github", "gitlab", "gmail", "google", "grafana", "hdfc", "health", "help",
	"helpdesk", "hostmaster", "icici", "icloud", "identity", "images", "imap", "img",
	"instagram", "internal", "invoice", "invoices", "jio", "jobs", "keys", "legal",
	"linkedin", "local", "localhost", "localon", "login", "logout", "logs", "mail",
	"mcp", "media", "metamask", "metrics", "microsoft", "mod", "moderator", "monitor",
	"monitoring", "my-localon", "mylocal", "mylocalon", "netflix", "news", "node", "nodes",
	"ns1", "ns2", "ns3", "ns4", "null", "oauth", "office365", "official",
	"openai", "origin", "outlook", "owner", "panel", "password", "passwords", "pay",
	"payment", "payments", "paypal", "paytm", "phonepe", "plans", "policy", "pop",
	"pop3", "portal", "postmaster", "press", "preview", "pricing", "privacy", "prod",
	"production", "prometheus", "proxy", "razorpay", "register", "registry", "relay", "report",
	"reset", "root", "sandbox", "sbi", "secure", "security", "server", "servers",
	"session", "sessions", "sftp", "shop", "signin", "signout", "signup", "smtp",
	"ssh", "sso", "staff", "stage", "staging", "static", "status", "store",
	"stripe", "superuser", "support", "sysadmin", "system", "team", "terms", "test",
	"testing", "token", "tokens", "tos", "trust", "tunnel", "tunnels", "twitter",
	"uat", "undefined", "upload", "uploads", "verification", "verify", "vpn", "webhook",
	"webhooks", "webmail", "webmaster", "whatsapp", "www", "youtube",
)

// brandTokens are also refused as any hyphen-separated part of a name
// ("paypal-login", "secure-gmail-verify") to blunt phishing on a trusted HTTPS domain.
var brandTokens = toSet(
	"airtel", "amazon", "anthropic", "apple", "aws", "azure", "binance", "chatgpt",
	"claude", "coinbase", "facebook", "github", "gitlab", "gmail", "google", "hdfc",
	"icici", "icloud", "instagram", "jio", "linkedin", "metamask", "microsoft", "mylocalon",
	"netflix", "office365", "openai", "outlook", "paypal", "paytm", "phonepe", "razorpay",
	"sbi", "stripe", "twitter", "whatsapp", "youtube",
)

func toSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

var (
	ErrInvalid = errors.New("invalid subdomain")
	ErrBlocked = errors.New("subdomain is reserved")
)

func Validate(name string) error {
	if !labelRe.MatchString(name) || strings.Contains(name, "--") {
		return ErrInvalid
	}
	if reserved[name] {
		return ErrBlocked
	}
	for _, part := range strings.Split(name, "-") {
		if brandTokens[part] {
			return ErrBlocked
		}
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
