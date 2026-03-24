package ctrl

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtunnel/xtunnel/server/internal/auth"
	"github.com/xtunnel/xtunnel/server/internal/tunnel"
)

const (
	MsgRegister   = "register"
	MsgRegistered = "registered"
	MsgError      = "error"
)

type Msg struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type RegisterPayload struct {
	Subdomain     string   `json:"subdomain"`
	CustomDomain  string   `json:"custom_domain,omitempty"`
	Proto         string   `json:"proto"`
	HMACSecret    string   `json:"hmac_secret,omitempty"`
	IPAllowList   []string `json:"ip_allow_list,omitempty"`
	IPBlockList   []string `json:"ip_block_list,omitempty"`
	BasicAuthUser string   `json:"basic_auth_user,omitempty"`
	BasicAuthPass string   `json:"basic_auth_pass,omitempty"`
}

type RegisteredPayload struct {
	TunnelID  string `json:"tunnel_id"`
	PublicURL string `json:"public_url"`
	TCPPort   int    `json:"tcp_port,omitempty"`
}

type ErrorPayload struct {
	Code string `json:"code"`
	Msg  string `json:"message"`
}

var upgrader = websocket.Upgrader{
	HandshakeTimeout: 15 * time.Second,
	CheckOrigin:      func(*http.Request) bool { return true },
}

type Handler struct {
	registry  *tunnel.Registry
	auth      *auth.Service
	domain    string
	anonymous bool
}

func NewHandler(reg *tunnel.Registry, a *auth.Service, domain string, allowAnon bool) *Handler {
	return &Handler{registry: reg, auth: a, domain: domain, anonymous: allowAnon}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var userID string
	tokenStr := auth.ExtractBearer(r)
	if tokenStr != "" {
		claims, err := h.auth.Verify(tokenStr)
		if err != nil {
			http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		userID = claims.UserID
	} else if h.anonymous {
		userID = "anon-" + r.RemoteAddr
	} else {
		http.Error(w, "authorization required", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("ws upgrade failed", "err", err)
		return
	}
	defer conn.Close()

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	slog.Info("agent connected", "user", userID, "ip", clientIP)

	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	var msg Msg
	if err := conn.ReadJSON(&msg); err != nil {
		slog.Error("failed to read register", "err", err)
		return
	}
	if msg.Type != MsgRegister {
		sendErr(conn, "BAD_MSG", "expected 'register' as first message")
		return
	}

	var reg RegisterPayload
	if err := json.Unmarshal(msg.Payload, &reg); err != nil {
		sendErr(conn, "BAD_PAYLOAD", err.Error())
		return
	}
	if reg.Proto == "" {
		reg.Proto = "http"
	}

	t, err := h.registry.Register(tunnel.RegisterRequest{
		UserID:        userID,
		Subdomain:     reg.Subdomain,
		CustomDomain:  reg.CustomDomain,
		Proto:         tunnel.Proto(reg.Proto),
		HMACSecret:    reg.HMACSecret,
		IPAllowList:   reg.IPAllowList,
		IPBlockList:   reg.IPBlockList,
		BasicAuthUser: reg.BasicAuthUser,
		BasicAuthPass: reg.BasicAuthPass,
	})
	if err != nil {
		sendErr(conn, "REGISTER_FAILED", err.Error())
		return
	}
	defer h.registry.Unregister(t.ID)

	publicURL := buildURL(t, h.domain)
	rp, _ := json.Marshal(RegisteredPayload{TunnelID: t.ID, PublicURL: publicURL, TCPPort: t.TCPPort})
	conn.WriteJSON(Msg{Type: MsgRegistered, Payload: rp})
	slog.Info("tunnel active", "id", t.ID, "url", publicURL, "proto", t.Proto)

	conn.SetReadDeadline(time.Time{})
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		return nil
	})

	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-t.Done():
			return
		case <-tick.C:
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				slog.Info("agent disconnected", "tunnel", t.ID)
				return
			}
		}
	}
}

func buildURL(t *tunnel.Tunnel, domain string) string {
	if t.CustomDomain != "" {
		return "https://" + t.CustomDomain
	}
	switch t.Proto {
	case tunnel.ProtoTCP:
		return fmt.Sprintf("tcp://%s:%d", domain, t.TCPPort)
	case tunnel.ProtoSSH:
		return fmt.Sprintf("ssh://%s:%d", domain, t.TCPPort)
	default:
		return fmt.Sprintf("https://%s.%s", t.Subdomain, domain)
	}
}

func sendErr(conn *websocket.Conn, code, msg string) {
	p, _ := json.Marshal(ErrorPayload{Code: code, Msg: msg})
	conn.WriteJSON(Msg{Type: MsgError, Payload: p})
}
