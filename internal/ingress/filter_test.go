package ingress

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBasicFilter(t *testing.T) {
	f := NewBasicFilter("localtest.me", []string{"Phish1", " "})
	cases := []struct {
		method, host, target string
		ok                   bool
	}{
		{"GET", "app.localtest.me", "/x?y=1", true},
		{"DELETE", "app.localtest.me", "/x", true},
		{"TRACE", "app.localtest.me", "/", false},
		{"CONNECT", "app.localtest.me", "/", false},
		{"GET", "phish1.localtest.me", "/", false},
		{"GET", "app.localtest.me", "/a%00b", false},
		{"GET", "app.localtest.me", "/" + strings.Repeat("a", 9000), false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "http://x/", nil)
		r.Method = c.method
		r.Host = c.host
		u, err := r.URL.Parse(c.target)
		if err != nil {
			t.Fatalf("bad test target: %v", err)
		}
		r.URL = u
		if ok, reason := f.Allow(r); ok != c.ok {
			t.Errorf("%s %s%q: ok=%v reason=%s", c.method, c.host, c.target[:min(len(c.target), 20)], ok, reason)
		}
	}
}
