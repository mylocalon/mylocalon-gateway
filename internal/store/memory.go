package store

import (
	"context"
	"sync"
	"time"

	"github.com/mylocalon/mylocalon-gateway/internal/clock"
)

// Memory is a single-process Store for local dev and tests. It honours TTLs
// using the injected clock so expiry behaviour is testable.
type Memory struct {
	mu         sync.Mutex
	clock      clock.Clock
	subdomains map[string]entry[string]
	tunnels    map[string]entry[TunnelRecord]
	userSets   map[string]map[string]time.Time // userID -> tunnelID -> expiry
	counters   map[string]entry[int64]
	denylist   map[string]bool
}

type entry[T any] struct {
	val T
	exp time.Time
}

func (e entry[T]) live(now time.Time) bool { return e.exp.IsZero() || now.Before(e.exp) }

func NewMemory(c clock.Clock) *Memory {
	return &Memory{
		clock:      c,
		subdomains: map[string]entry[string]{},
		tunnels:    map[string]entry[TunnelRecord]{},
		userSets:   map[string]map[string]time.Time{},
		counters:   map[string]entry[int64]{},
		denylist:   map[string]bool{},
	}
}

func (m *Memory) ClaimSubdomain(_ context.Context, name, tunnelID string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	if e, ok := m.subdomains[name]; ok && e.live(now) && e.val != tunnelID {
		return false, nil
	}
	m.subdomains[name] = entry[string]{tunnelID, now.Add(ttl)}
	return true, nil
}

func (m *Memory) ReleaseSubdomain(_ context.Context, name, tunnelID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.subdomains[name]; ok && e.val == tunnelID {
		delete(m.subdomains, name)
	}
	return nil
}

func (m *Memory) LookupSubdomain(_ context.Context, name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.subdomains[name]; ok && e.live(m.clock.Now()) {
		return e.val, nil
	}
	return "", nil
}

func (m *Memory) SaveTunnel(_ context.Context, rec TunnelRecord, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnels[rec.ID] = entry[TunnelRecord]{rec, m.clock.Now().Add(ttl)}
	return nil
}

func (m *Memory) GetTunnel(_ context.Context, id string) (*TunnelRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.tunnels[id]; ok && e.live(m.clock.Now()) {
		r := e.val
		return &r, nil
	}
	return nil, nil
}

func (m *Memory) DeleteTunnel(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tunnels, id)
	return nil
}

func (m *Memory) TouchUserTunnel(_ context.Context, userID, tunnelID string, ttl time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	set := m.userSets[userID]
	if set == nil {
		set = map[string]time.Time{}
		m.userSets[userID] = set
	}
	set[tunnelID] = now.Add(ttl)
	for id, exp := range set {
		if !now.Before(exp) {
			delete(set, id)
		}
	}
	return len(set), nil
}

func (m *Memory) RemoveUserTunnel(_ context.Context, userID, tunnelID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.userSets[userID], tunnelID)
	return nil
}

func (m *Memory) Incr(_ context.Context, key string, window time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	e, ok := m.counters[key]
	if !ok || !e.live(now) {
		e = entry[int64]{0, now.Add(window)}
	}
	e.val++
	m.counters[key] = e
	return e.val, nil
}

func (m *Memory) IsRevoked(_ context.Context, jti string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.denylist[jti], nil
}

// Revoke adds a jti to the denylist (tests / dev only).
func (m *Memory) Revoke(jti string) {
	m.mu.Lock()
	m.denylist[jti] = true
	m.mu.Unlock()
}

func (m *Memory) Ping(context.Context) error { return nil }
