package subdomain

import (
	"bytes"
	"errors"
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
