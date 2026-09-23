package policy

import (
	"context"
	"errors"
	"sync"
)

// ErrPolicyInvalid is returned when a policy fails validation.
var ErrPolicyInvalid = errors.New("policy invalid")

// ErrVersionExists is returned when a policy version is installed twice.
var ErrVersionExists = errors.New("policy version already exists")

// ErrNoPolicy is returned before any policy has been installed.
var ErrNoPolicy = errors.New("no policy installed")

// Store holds versioned policies and serves a single snapshot per request.
// All reads return an immutable *Policy, so a request that captured the
// pointer once keeps deciding against the same version even while the store
// is hot-updated concurrently.
type Store struct {
	mu      sync.RWMutex
	current *Policy
	history map[string]*Policy
}

// NewStore constructs an empty policy store seeded with the given policy.
func NewStore(seed *Policy) *Store {
	s := &Store{history: make(map[string]*Policy)}
	if seed != nil {
		// Seed installation for construction never fails validation here;
		// callers needing validation should call Update.
		s.current = seed
		s.history[seed.Version] = seed
	}
	return s
}

// validate checks structural invariants before a version becomes visible.
func validate(p *Policy) error {
	if p == nil {
		return ErrPolicyInvalid
	}
	if p.Version == "" {
		return errors.New("policy version is empty")
	}
	seen := make(map[string]struct{}, len(p.Rules))
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.ID == "" {
			return errors.New("rule id is empty")
		}
		if _, dup := seen[r.ID]; dup {
			return errors.New("duplicate rule id: " + r.ID)
		}
		seen[r.ID] = struct{}{}
		switch r.Effect {
		case EffectDeny, EffectAllow, EffectMask:
		default:
			return errors.New("rule " + r.ID + " has unknown effect: " + string(r.Effect))
		}
		if r.Resource == "" {
			return errors.New("rule " + r.ID + " resource is empty")
		}
	}
	return nil
}

// Update atomically installs a new policy version. In-flight requests that
// already hold the previous *Policy are unaffected.
func (s *Store) Update(ctx context.Context, p *Policy) error {
	if err := validate(p); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.history[p.Version]; exists {
		return ErrVersionExists
	}
	cp := *p
	cp.Rules = append([]Rule(nil), p.Rules...)
	s.history[cp.Version] = &cp
	s.current = &cp
	return nil
}

// Current returns the latest installed policy (immutable snapshot).
func (s *Store) Current(ctx context.Context) (*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return nil, ErrNoPolicy
	}
	return s.current, nil
}

// Get returns a specific policy version (nil policy, nil error if missing).
func (s *Store) Get(ctx context.Context, version string) (*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.history[version], nil
}
