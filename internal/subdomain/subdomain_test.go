package subdomain

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestValidate(t *testing.T) {
	cases := map[string]error{
		"myapp": nil, "my-app-2": nil, "abc": nil,
		"ab": ErrInvalid, "-ab": ErrInvalid, "ab-": ErrInvalid, "MyApp": ErrInvalid,
		"a_b": ErrInvalid, "a--b": ErrInvalid, "a.b": ErrInvalid,
		"www": ErrBlocked, "admin": ErrBlocked, "gateway": ErrBlocked,
	}
	for in, want := range cases {
		if got := Validate(in); !errors.Is(got, want) && !(got == nil && want == nil) {
			t.Errorf("Validate(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestGeneratorDeterministic(t *testing.T) {
	g := Generator{Rand: bytes.NewReader(bytes.Repeat([]byte{1, 2, 3, 4}, 4)), Length: 8}
	s, err := g.Next()
	if err != nil {
		t.Fatal(err)
	}
	if s != "bcdebcde" {
		t.Fatalf("unexpected %q", s)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("generated invalid label %q: %v", s, err)
	}
}

func TestGeneratorRandomAlwaysValid(t *testing.T) {
	g := Generator{}
	for i := 0; i < 500; i++ {
		s, _ := g.Next()
		if err := Validate(s); err != nil && !errors.Is(err, ErrBlocked) {
			t.Fatalf("invalid %q: %v", s, err)
		}
	}
}

func TestFromHost(t *testing.T) {
	cases := []struct {
		host, label string
		ok          bool
	}{
		{"abc123.mylocalon.com", "abc123", true},
		{"ABC123.mylocalon.com:443", "abc123", true},
		{"abc123.mylocalon.com.", "abc123", true},
		{"mylocalon.com", "", false},
		{"a.b.mylocalon.com", "", false},
		{"abc123.evil.in", "", false},
		{"abc123.mylocalon.com.evil.com", "", false},
		{"x_y.mylocalon.com", "", false},
	}
	for _, c := range cases {
		l, ok := FromHost(c.host, "mylocalon.com")
		if l != c.label || ok != c.ok {
			t.Errorf("FromHost(%q) = %q,%v", c.host, l, ok)
		}
	}
}

// TestReservedMatchesFixture keeps the Go copy identical to the canonical
// policy shared with mylocalon-platform.
func TestReservedMatchesFixture(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/fixtures/policy/reserved-subdomains.json")
	if err != nil {
		t.Skipf("policy fixture not found (docs repo not checked out next to the gateway): %v", err)
	}
	var fx struct {
		Reserved    []string `json:"reserved"`
		BrandTokens []string `json:"brandTokens"`
		Cases       []struct {
			Name    string `json:"name"`
			Allowed bool   `json:"allowed"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	same := func(label string, want []string, got map[string]bool) {
		if len(want) != len(got) {
			t.Errorf("%s: fixture has %d names, Go has %d", label, len(want), len(got))
		}
		for _, n := range want {
			if !got[n] {
				t.Errorf("%s: %q in fixture but not in Go", label, n)
			}
		}
	}
	same("reserved", fx.Reserved, reserved)
	same("brandTokens", fx.BrandTokens, brandTokens)
	for _, c := range fx.Cases {
		if got := Validate(c.Name) == nil; got != c.Allowed {
			t.Errorf("Validate(%q) allowed=%v, want %v", c.Name, got, c.Allowed)
		}
	}
}
