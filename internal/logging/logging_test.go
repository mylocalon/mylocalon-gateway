package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedaction(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "gateway", "test", "debug")
	log.Info("x", "token", "eyJsecret", "Authorization", "Bearer abc", "apiKey", "mlk_live_1", "tunnelId", "tnl_1")
	out := buf.String()
	for _, leak := range []string{"eyJsecret", "Bearer abc", "mlk_live_1"} {
		if strings.Contains(out, leak) {
			t.Fatalf("secret %q leaked: %s", leak, out)
		}
	}
	for _, want := range []string{`"ts"`, `"service":"gateway"`, `"env":"test"`, `"tunnelId":"tnl_1"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in %s", want, out)
		}
	}
}
