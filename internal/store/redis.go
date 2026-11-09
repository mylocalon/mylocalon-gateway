package store

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis implements Store with the key layout from ARCHITECTURE.md §5.
type Redis struct {
	rdb *redis.Client
}

func NewRedis(url string) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	return &Redis{rdb: redis.NewClient(opt)}, nil
}

func (r *Redis) Close() error { return r.rdb.Close() }

func keySub(name string) string  { return "subdomain:" + name }
func keyTunnel(id string) string { return "tunnel:" + id }
func keyResume(id string) string { return "resume:" + id }
func keyUser(user string) string { return "user:" + user + ":tunnels" }
func keyDeny(jti string) string  { return "jwt:denylist:" + jti }

// Claim if free or already ours; refresh TTL.
var claimScript = redis.NewScript(`
local cur = redis.call('GET', KEYS[1])
if cur == false or cur == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
  return 1
end
return 0`)

// Delete only if still ours.
var releaseScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0`)

// Sorted set scored by expiry (ms): add/refresh, drop expired, count.
var touchScript = redis.NewScript(`
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return redis.call('ZCARD', KEYS[1])`)

var incrScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return n`)

func (r *Redis) ClaimSubdomain(ctx context.Context, name, tunnelID string, ttl time.Duration) (bool, error) {
	n, err := claimScript.Run(ctx, r.rdb, []string{keySub(name)}, tunnelID, ttl.Milliseconds()).Int()
	return n == 1, err
}

func (r *Redis) ReleaseSubdomain(ctx context.Context, name, tunnelID string) error {
	return releaseScript.Run(ctx, r.rdb, []string{keySub(name)}, tunnelID).Err()
}

func (r *Redis) LookupSubdomain(ctx context.Context, name string) (string, error) {
	v, err := r.rdb.Get(ctx, keySub(name)).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	return v, err
}

func (r *Redis) SaveTunnel(ctx context.Context, rec TunnelRecord, ttl time.Duration) error {
	_, err := r.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, keyTunnel(rec.ID), map[string]any{
			"subdomain": rec.Subdomain,
			"userId":    rec.UserID,
			"state":     rec.State,
			"gwNode":    rec.Node,
			"lastSeen":  rec.LastSeen.UnixMilli(),
		})
		p.PExpire(ctx, keyTunnel(rec.ID), ttl)
		p.Set(ctx, keyResume(rec.ID), rec.ResumeHash, ttl)
		return nil
	})
	return err
}

func (r *Redis) GetTunnel(ctx context.Context, id string) (*TunnelRecord, error) {
	h, err := r.rdb.HGetAll(ctx, keyTunnel(id)).Result()
	if err != nil {
		return nil, err
	}
	if len(h) == 0 {
		return nil, nil
	}
	hash, err := r.rdb.Get(ctx, keyResume(id)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}
	ms, _ := strconv.ParseInt(h["lastSeen"], 10, 64)
	return &TunnelRecord{
		ID: id, Subdomain: h["subdomain"], UserID: h["userId"], State: h["state"],
		Node: h["gwNode"], LastSeen: time.UnixMilli(ms), ResumeHash: hash,
	}, nil
}

func (r *Redis) DeleteTunnel(ctx context.Context, id string) error {
	return r.rdb.Del(ctx, keyTunnel(id), keyResume(id)).Err()
}

func (r *Redis) TouchUserTunnel(ctx context.Context, userID, tunnelID string, ttl time.Duration) (int, error) {
	now := time.Now()
	return touchScript.Run(ctx, r.rdb, []string{keyUser(userID)},
		tunnelID, now.Add(ttl).UnixMilli(), now.UnixMilli(), ttl.Milliseconds()).Int()
}

func (r *Redis) RemoveUserTunnel(ctx context.Context, userID, tunnelID string) error {
	return r.rdb.ZRem(ctx, keyUser(userID), tunnelID).Err()
}

func (r *Redis) Incr(ctx context.Context, key string, window time.Duration) (int64, error) {
	return incrScript.Run(ctx, r.rdb, []string{key}, window.Milliseconds()).Int64()
}

func (r *Redis) IsRevoked(ctx context.Context, jti string) (bool, error) {
	n, err := r.rdb.Exists(ctx, keyDeny(jti)).Result()
	return n > 0, err
}

func (r *Redis) Ping(ctx context.Context) error { return r.rdb.Ping(ctx).Err() }
