package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/mylocalon/mylocalon-gateway/internal/clock"
)

// contract runs the same behavioural tests against every Store implementation.
// advance moves time forward (fake clock for Memory, real sleep for Redis).
func contract(t *testing.T, s Store, advance func(time.Duration), prefix string) {
	ctx := context.Background()
	sub := prefix + "sub"

	t.Run("claim/lookup/release", func(t *testing.T) {
		ok, err := s.ClaimSubdomain(ctx, sub, "t1", time.Minute)
		if err != nil || !ok {
			t.Fatalf("claim: %v %v", ok, err)
		}
		if ok, _ := s.ClaimSubdomain(ctx, sub, "t2", time.Minute); ok {
			t.Fatal("t2 must not steal subdomain")
		}
		if ok, _ := s.ClaimSubdomain(ctx, sub, "t1", time.Minute); !ok {
			t.Fatal("owner refresh must succeed")
		}
		if id, _ := s.LookupSubdomain(ctx, sub); id != "t1" {
			t.Fatalf("lookup = %q", id)
		}
		_ = s.ReleaseSubdomain(ctx, sub, "t2") // not owner: no-op
		if id, _ := s.LookupSubdomain(ctx, sub); id != "t1" {
			t.Fatal("non-owner released mapping")
		}
		_ = s.ReleaseSubdomain(ctx, sub, "t1")
		if id, _ := s.LookupSubdomain(ctx, sub); id != "" {
			t.Fatal("release failed")
		}
	})

	t.Run("subdomain ttl", func(t *testing.T) {
		_, _ = s.ClaimSubdomain(ctx, sub+"x", "t1", 50*time.Millisecond)
		advance(120 * time.Millisecond)
		if ok, _ := s.ClaimSubdomain(ctx, sub+"x", "t2", time.Minute); !ok {
			t.Fatal("expired subdomain must be claimable")
		}
	})

	t.Run("tunnel record", func(t *testing.T) {
		rec := TunnelRecord{ID: prefix + "tnl", Subdomain: sub, UserID: "u", State: StateActive, Node: "n1",
			LastSeen: time.UnixMilli(1000), ResumeHash: "h"}
		if err := s.SaveTunnel(ctx, rec, time.Minute); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetTunnel(ctx, rec.ID)
		if err != nil || got == nil || *got != rec {
			t.Fatalf("got %+v err %v", got, err)
		}
		_ = s.DeleteTunnel(ctx, rec.ID)
		if got, _ := s.GetTunnel(ctx, rec.ID); got != nil {
			t.Fatal("delete failed")
		}
	})

	t.Run("user tunnels", func(t *testing.T) {
		u := prefix + "user"
		n1, _ := s.TouchUserTunnel(ctx, u, "a", time.Minute)
		n2, _ := s.TouchUserTunnel(ctx, u, "b", time.Minute)
		n3, _ := s.TouchUserTunnel(ctx, u, "a", time.Minute)
		if n1 != 1 || n2 != 2 || n3 != 2 {
			t.Fatalf("counts %d %d %d", n1, n2, n3)
		}
		_ = s.RemoveUserTunnel(ctx, u, "a")
		if n, _ := s.TouchUserTunnel(ctx, u, "b", time.Minute); n != 1 {
			t.Fatalf("after remove = %d", n)
		}
	})

	t.Run("incr window", func(t *testing.T) {
		k := prefix + "rl"
		for i := int64(1); i <= 3; i++ {
			if n, _ := s.Incr(ctx, k, 50*time.Millisecond); n != i {
				t.Fatalf("incr = %d want %d", n, i)
			}
		}
		advance(120 * time.Millisecond)
		if n, _ := s.Incr(ctx, k, 50*time.Millisecond); n != 1 {
			t.Fatalf("window not reset: %d", n)
		}
	})
}

func TestMemoryStore(t *testing.T) {
	c := clock.NewFake(time.Unix(0, 0))
	contract(t, NewMemory(c), c.Advance, "")
}

// TestRedisStore runs only when ML_TEST_REDIS_URL is set (CI service container
// or a local redis-server).
func TestRedisStore(t *testing.T) {
	url := os.Getenv("ML_TEST_REDIS_URL")
	if url == "" {
		t.Skip("ML_TEST_REDIS_URL not set")
	}
	r, err := NewRedis(url)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Ping(context.Background()); err != nil {
		t.Skipf("redis unreachable: %v", err)
	}
	contract(t, r, time.Sleep, fmt.Sprintf("test%d:", time.Now().UnixNano()))
}
