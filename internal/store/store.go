// Package store holds Gateway runtime state (ARCHITECTURE.md §5). Everything
// here is ephemeral and TTL'd; PostgreSQL (Platform) is the source of truth.
package store

import (
	"context"
	"time"
)

// Tunnel states (PROTOCOL.md §11) as tracked by the Gateway.
const (
	StateActive       = "ACTIVE"
	StateDisconnected = "DISCONNECTED"
	StateClosed       = "CLOSED"
)

type TunnelRecord struct {
	ID         string
	Subdomain  string
	UserID     string
	State      string
	Node       string
	LastSeen   time.Time
	ResumeHash string // sha256 of the resume token; never the token itself
}

type Store interface {
	// ClaimSubdomain maps name -> tunnelID. It succeeds if the name is free or
	// already held by tunnelID (refreshing the TTL); false if held by another.
	ClaimSubdomain(ctx context.Context, name, tunnelID string, ttl time.Duration) (bool, error)
	// ReleaseSubdomain removes the mapping only if tunnelID still owns it.
	ReleaseSubdomain(ctx context.Context, name, tunnelID string) error
	// LookupSubdomain returns the owning tunnelID or "" if none.
	LookupSubdomain(ctx context.Context, name string) (string, error)

	SaveTunnel(ctx context.Context, rec TunnelRecord, ttl time.Duration) error
	// GetTunnel returns nil, nil when the tunnel is unknown or expired.
	GetTunnel(ctx context.Context, id string) (*TunnelRecord, error)
	DeleteTunnel(ctx context.Context, id string) error

	// TouchUserTunnel adds/refreshes tunnelID in the user's live set and
	// returns how many live tunnels the user has (including this one).
	TouchUserTunnel(ctx context.Context, userID, tunnelID string, ttl time.Duration) (int, error)
	RemoveUserTunnel(ctx context.Context, userID, tunnelID string) error

	// Incr increments a fixed-window counter, creating it with the window TTL.
	Incr(ctx context.Context, key string, window time.Duration) (int64, error)

	// IsRevoked checks the optional JWT denylist (jwt:denylist:{jti}).
	IsRevoked(ctx context.Context, jti string) (bool, error)

	Ping(ctx context.Context) error
}
