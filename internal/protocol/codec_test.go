package protocol

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const fixturesDir = "../../../docs/fixtures"

// TestFixturesRoundTrip is the Go side of the cross-language conformance
// contract (TESTING.md §2).
func TestFixturesRoundTrip(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(fixturesDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures found in %s: %v", fixturesDir, err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, _ := os.ReadFile(f)
			m, err := Decode(raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			out, err := Encode(m)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			// Every field we know about must survive the round-trip.
			var in, got map[string]any
			_ = json.Unmarshal(raw, &in)
			_ = json.Unmarshal(out, &got)
			for k, v := range in {
				if k == "futureField" {
					continue // unknown fields are ignored, not preserved
				}
				if !reflect.DeepEqual(got[k], v) {
					t.Errorf("field %q: got %v want %v", k, got[k], v)
				}
			}
		})
	}
}

func TestFixturesInvalid(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(fixturesDir, "invalid", "*.json"))
	if len(files) == 0 {
		t.Fatal("no invalid fixtures")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, _ := os.ReadFile(f)
			if _, err := Decode(raw); !errors.Is(err, ErrProtocol) {
				t.Fatalf("want ErrProtocol, got %v", err)
			}
		})
	}
}

func TestHeaderPairsPreserveDuplicates(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join(fixturesDir, "http_response.json"))
	m, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := m.(*HTTPResponse)
	n := 0
	for _, h := range r.Headers {
		if strings.EqualFold(h[0], "set-cookie") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("want 2 set-cookie headers, got %d", n)
	}
}

func TestBodyBase64(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "", true},
		{"T0s=", "OK", true},
		{"T0s", "", false}, // must be padded
		{"!!", "", false},
	}
	for _, c := range cases {
		b, err := DecodeBody(c.in)
		if (err == nil) != c.ok || string(b) != c.want {
			t.Errorf("DecodeBody(%q) = %q, %v", c.in, b, err)
		}
	}
}
