package tunnel

import "sync"

// registry maps subdomain/tunnelId to the live Session on this process.
type registry struct {
	mu    sync.RWMutex
	bySub map[string]*Session
	byTID map[string]*Session
}

func newRegistry() *registry {
	return &registry{bySub: map[string]*Session{}, byTID: map[string]*Session{}}
}

func (r *registry) add(s *Session) {
	r.mu.Lock()
	r.bySub[s.Subdomain] = s
	r.byTID[s.ID] = s
	r.mu.Unlock()
}

// remove only deletes entries still pointing at s, so a stale session can't
// evict the session that resumed it.
func (r *registry) remove(s *Session) {
	r.mu.Lock()
	if r.bySub[s.Subdomain] == s {
		delete(r.bySub, s.Subdomain)
	}
	if r.byTID[s.ID] == s {
		delete(r.byTID, s.ID)
	}
	r.mu.Unlock()
}

func (r *registry) bySubdomain(sub string) *Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bySub[sub]
}

func (r *registry) byID(id string) *Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byTID[id]
}

func (r *registry) all() []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Session, 0, len(r.byTID))
	for _, s := range r.byTID {
		out = append(out, s)
	}
	return out
}

func (r *registry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byTID)
}
