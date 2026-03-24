package tunnel

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type Proto string

const (
	ProtoHTTP  Proto = "http"
	ProtoHTTPS Proto = "https"
	ProtoTCP   Proto = "tcp"
	ProtoUDP   Proto = "udp"
	ProtoSSH   Proto = "ssh"
)

// Tunnel is one active tunnel session.
type Tunnel struct {
	ID           string
	UserID       string
	Subdomain    string
	CustomDomain string
	Proto        Proto
	TCPPort      int
	CreatedAt    time.Time
	LastActive   time.Time

	ConnCh chan net.Conn
	done   chan struct{}

	HMACSecret    string
	IPAllowList   []string
	IPBlockList   []string
	BasicAuthUser string
	BasicAuthPass string

	BytesIn  atomic.Int64
	BytesOut atomic.Int64
	ReqCount atomic.Int64
	ErrCount atomic.Int64
	mu       sync.Mutex
}

func newTunnel() *Tunnel {
	return &Tunnel{
		ID:         uuid.New().String(),
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
		ConnCh:     make(chan net.Conn, 64),
		done:       make(chan struct{}),
	}
}

func (t *Tunnel) Close() {
	select {
	case <-t.done:
	default:
		close(t.done)
	}
}

func (t *Tunnel) Done() <-chan struct{} { return t.done }

func (t *Tunnel) Touch() {
	t.mu.Lock()
	t.LastActive = time.Now()
	t.mu.Unlock()
}

func (t *Tunnel) Stats() (in, out, reqs, errs int64) {
	return t.BytesIn.Load(), t.BytesOut.Load(), t.ReqCount.Load(), t.ErrCount.Load()
}

// RegisterRequest holds the fields needed to register a tunnel.
type RegisterRequest struct {
	UserID        string
	Subdomain     string
	CustomDomain  string
	Proto         Proto
	HMACSecret    string
	IPAllowList   []string
	IPBlockList   []string
	BasicAuthUser string
	BasicAuthPass string
}

// Registry is the in-memory store of all live tunnels.
type Registry struct {
	mu        sync.RWMutex
	byID      map[string]*Tunnel
	byHost    map[string]*Tunnel
	byUser    map[string][]*Tunnel
	byTCPPort map[int]*Tunnel
	domain    string
	bus       *EventBus
}

func NewRegistry(domain string, bus *EventBus) *Registry {
	return &Registry{
		byID:      make(map[string]*Tunnel),
		byHost:    make(map[string]*Tunnel),
		byUser:    make(map[string][]*Tunnel),
		byTCPPort: make(map[int]*Tunnel),
		domain:    domain,
		bus:       bus,
	}
}

func (r *Registry) Register(req RegisterRequest) (*Tunnel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	t := newTunnel()
	t.UserID = req.UserID
	t.Proto = req.Proto
	t.HMACSecret = req.HMACSecret
	t.IPAllowList = req.IPAllowList
	t.IPBlockList = req.IPBlockList
	t.BasicAuthUser = req.BasicAuthUser
	t.BasicAuthPass = req.BasicAuthPass

	sub := req.Subdomain
	if sub == "" {
		sub = uuid.New().String()[:8]
	}
	host := sub + "." + r.domain
	if _, exists := r.byHost[host]; exists {
		return nil, fmt.Errorf("subdomain %q is already taken — try another", sub)
	}
	t.Subdomain = sub

	if req.CustomDomain != "" {
		if _, exists := r.byHost[req.CustomDomain]; exists {
			return nil, fmt.Errorf("domain %q is already registered", req.CustomDomain)
		}
		t.CustomDomain = req.CustomDomain
		r.byHost[req.CustomDomain] = t
	}

	if req.Proto == ProtoTCP || req.Proto == ProtoSSH {
		port := r.allocTCPPort()
		if port == 0 {
			return nil, fmt.Errorf("no TCP ports available (pool exhausted)")
		}
		t.TCPPort = port
		r.byTCPPort[port] = t
	}

	r.byID[t.ID] = t
	r.byHost[host] = t
	r.byUser[req.UserID] = append(r.byUser[req.UserID], t)

	if r.bus != nil {
		r.bus.Publish(Event{Type: EventRegistered, Tunnel: t})
	}
	return t, nil
}

func (r *Registry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	t, ok := r.byID[id]
	if !ok {
		return
	}
	delete(r.byID, id)
	delete(r.byHost, t.Subdomain+"."+r.domain)
	if t.CustomDomain != "" {
		delete(r.byHost, t.CustomDomain)
	}
	if t.TCPPort != 0 {
		delete(r.byTCPPort, t.TCPPort)
	}
	list := r.byUser[t.UserID]
	for i, u := range list {
		if u.ID == id {
			r.byUser[t.UserID] = append(list[:i], list[i+1:]...)
			break
		}
	}
	t.Close()

	if r.bus != nil {
		r.bus.Publish(Event{Type: EventUnregistered, Tunnel: t})
	}
}

func (r *Registry) GetByHost(host string) (*Tunnel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.byHost[host]
	return t, ok
}

func (r *Registry) GetByID(id string) (*Tunnel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.byID[id]
	return t, ok
}

func (r *Registry) GetByTCPPort(port int) (*Tunnel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.byTCPPort[port]
	return t, ok
}

func (r *Registry) ListByUser(userID string) []*Tunnel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	src := r.byUser[userID]
	out := make([]*Tunnel, len(src))
	copy(out, src)
	return out
}

func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

func (r *Registry) IsAvailable(sub string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, taken := r.byHost[sub+"."+r.domain]
	return !taken
}

func (r *Registry) allocTCPPort() int {
	for p := 10000; p <= 20000; p++ {
		if _, used := r.byTCPPort[p]; !used {
			return p
		}
	}
	return 0
}
