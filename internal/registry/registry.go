package registry

import (
	"sync"
	"time"
)

// Tunnel represents one active tunnel connection
type Tunnel struct {
	Name         string
	ClientAddr   string
	ConnectedAt  time.Time
	RequestCount int64
	UserID       string
	// Channel to send HTTP request bytes to the CLI client
	// The CLI reads from this, forwards to localhost, sends response back
	ReqCh  chan *PendingRequest
	Done   chan struct{}
}

// PendingRequest holds one proxied HTTP request waiting for a response
type PendingRequest struct {
	ID       string
	Data     []byte        // raw HTTP request bytes
	RespCh   chan []byte   // response bytes come back here
	ErrCh    chan error
}

// Registry holds all tunnels keyed by subdomain name
type Registry struct {
	mu      sync.RWMutex
	tunnels map[string]*Tunnel
}

func New() *Registry {
	return &Registry{
		tunnels: make(map[string]*Tunnel),
	}
}

// Register adds a new tunnel. Returns false if name is already taken.
func (r *Registry) Register(name, clientAddr, userID string) (*Tunnel, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tunnels[name]; exists {
		return nil, false
	}

	t := &Tunnel{
		Name:        name,
		ClientAddr:  clientAddr,
		ConnectedAt: time.Now(),
		UserID:      userID,
		ReqCh:       make(chan *PendingRequest, 64),
		Done:        make(chan struct{}),
	}
	r.tunnels[name] = t
	return t, true
}

// Unregister removes a tunnel
func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.tunnels[name]; ok {
		close(t.Done)
		delete(r.tunnels, name)
	}
}

// Get returns a tunnel by name
func (r *Registry) Get(name string) (*Tunnel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tunnels[name]
	return t, ok
}

// Count returns number of active tunnels
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tunnels)
}

// List returns a snapshot of all tunnels (safe copy)
type TunnelInfo struct {
	Name         string
	ClientAddr   string
	ConnectedAt  time.Time
	RequestCount int64
	UserID       string
}

func (r *Registry) List() []TunnelInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]TunnelInfo, 0, len(r.tunnels))
	for _, t := range r.tunnels {
		out = append(out, TunnelInfo{
			Name:         t.Name,
			ClientAddr:   t.ClientAddr,
			ConnectedAt:  t.ConnectedAt,
			RequestCount: t.RequestCount,
			UserID:       t.UserID,
		})
	}
	return out
}

// IsNameAvailable checks if a name is free
func (r *Registry) IsNameAvailable(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.tunnels[name]
	return !exists
}

// IncrementRequests bumps the request counter for a tunnel
func (r *Registry) IncrementRequests(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.tunnels[name]; ok {
		t.RequestCount++
	}
}
