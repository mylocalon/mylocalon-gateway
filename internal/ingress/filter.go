package ingress

import (
	"net/http"
	"strings"
)

// BasicFilter is the MVP abuse filter (SECURITY.md §6): operator takedowns
// by subdomain plus a few request shapes no dev app should need. Richer
// content/domain scanning plugs in behind the same AbuseFilter interface.
type BasicFilter struct {
	BaseDomain string
	Blocked    map[string]bool // subdomains taken down by an operator
}

var allowedMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodOptions: true,
}

func NewBasicFilter(base string, blocked []string) *BasicFilter {
	m := map[string]bool{}
	for _, b := range blocked {
		if b = strings.TrimSpace(strings.ToLower(b)); b != "" {
			m[b] = true
		}
	}
	return &BasicFilter{BaseDomain: base, Blocked: m}
}

func (f *BasicFilter) Allow(r *http.Request) (bool, string) {
	if !allowedMethods[r.Method] {
		return false, "method_not_allowed" // CONNECT, TRACE, …
	}
	host := strings.ToLower(r.Host)
	if i := strings.IndexByte(host, '.'); i > 0 && f.Blocked[host[:i]] {
		return false, "subdomain_blocked"
	}
	raw := r.URL.RawPath
	if raw == "" {
		raw = r.URL.Path
	}
	if strings.ContainsAny(raw, "\x00\r\n") || len(r.URL.RequestURI()) > 8192 {
		return false, "malformed_path"
	}
	return true, ""
}
