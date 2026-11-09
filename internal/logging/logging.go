// Package logging builds the structured JSON logger (OBSERVABILITY.md §1).
// Secret-bearing attributes are redacted no matter where they are logged.
package logging

import (
	"io"
	"log/slog"
	"strings"
)

var redactedKeys = map[string]bool{
	"token":         true,
	"authorization": true,
	"apikey":        true,
	"api_key":       true,
	"secret":        true,
	"cookie":        true,
	"set-cookie":    true,
	"resumetoken":   true,
	"password":      true,
}

// IsSensitive reports whether an attribute or header name must never be logged.
func IsSensitive(key string) bool { return redactedKeys[strings.ToLower(key)] }

// New returns a JSON slog.Logger with the required base fields.
func New(w io.Writer, service, env, level string) *slog.Logger {
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(level))
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: lvl,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			switch {
			case len(groups) == 0 && a.Key == slog.TimeKey:
				a.Key = "ts"
			case IsSensitive(a.Key):
				return slog.String(a.Key, "[REDACTED]")
			}
			return a
		},
	})
	return slog.New(h).With("service", service, "env", env)
}
