package metrics

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/xtunnel/xtunnel/server/internal/tunnel"
)

type TunnelStats struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Subdomain    string    `json:"subdomain"`
	CustomDomain string    `json:"custom_domain,omitempty"`
	Proto        string    `json:"proto"`
	TCPPort      int       `json:"tcp_port,omitempty"`
	BytesIn      int64     `json:"bytes_in"`
	BytesOut     int64     `json:"bytes_out"`
	ReqCount     int64     `json:"req_count"`
	ErrCount     int64     `json:"err_count"`
	CreatedAt    time.Time `json:"created_at"`
	LastActive   time.Time `json:"last_active"`
	UptimeSec    float64   `json:"uptime_sec"`
}

type Handler struct {
	registry *tunnel.Registry
}

func NewHandler(reg *tunnel.Registry) *Handler {
	return &Handler{registry: reg}
}

func statsFrom(t *tunnel.Tunnel) TunnelStats {
	in, out, reqs, errs := t.Stats()
	return TunnelStats{
		ID: t.ID, UserID: t.UserID,
		Subdomain: t.Subdomain, CustomDomain: t.CustomDomain,
		Proto: string(t.Proto), TCPPort: t.TCPPort,
		BytesIn: in, BytesOut: out, ReqCount: reqs, ErrCount: errs,
		CreatedAt: t.CreatedAt, LastActive: t.LastActive,
		UptimeSec: time.Since(t.CreatedAt).Seconds(),
	}
}

// GET /api/tunnels - list tunnels for a user
func (h *Handler) ListTunnels(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user")
	var list []TunnelStats
	for _, t := range h.registry.ListByUser(userID) {
		list = append(list, statsFrom(t))
	}
	if list == nil {
		list = []TunnelStats{}
	}
	writeJSON(w, map[string]any{"tunnels": list, "total": h.registry.Count()})
}

// GET /api/tunnels/{id}/stats
func (h *Handler) TunnelStats(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, ok := h.registry.GetByID(id)
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	writeJSON(w, statsFrom(t))
}

// DELETE /api/tunnels/{id}
func (h *Handler) CloseTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h.registry.Unregister(id)
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/health
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"status":  "ok",
		"tunnels": h.registry.Count(),
		"time":    time.Now().UTC(),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
