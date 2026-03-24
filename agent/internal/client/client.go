// Package client implements the XTunnel agent — the program that runs on the
// developer's machine and connects to the XTunnel server.
package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtunnel/xtunnel/shared/config"
)

// RegisteredInfo is returned after successful registration.
type RegisteredInfo struct {
	TunnelID  string `json:"tunnel_id"`
	PublicURL string `json:"public_url"`
	TCPPort   int    `json:"tcp_port,omitempty"`
}

// Agent manages a single tunnel connection to the XTunnel server.
type Agent struct {
	cfg      *config.AgentConfig
	info     RegisteredInfo
	cancelFn context.CancelFunc
}

func New(cfg *config.AgentConfig) *Agent {
	return &Agent{cfg: cfg}
}

// Start connects to the server and begins forwarding traffic.
func (a *Agent) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	a.cancelFn = cancel
	defer cancel()

	backoff := 2 * time.Second
	for {
		slog.Info("Connecting to XTunnel server", "addr", a.cfg.ServerAddr)
		err := a.run(ctx)
		if err != nil {
			slog.Error("Tunnel error", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			if backoff < 60*time.Second {
				backoff *= 2
			}
			slog.Info("Reconnecting...", "wait", backoff)
		}
	}
}

func (a *Agent) Stop() {
	if a.cancelFn != nil {
		a.cancelFn()
	}
}

func (a *Agent) Info() RegisteredInfo { return a.info }

func (a *Agent) run(ctx context.Context) error {
	// Build WebSocket URL
	scheme := "wss"
	u := url.URL{
		Scheme: scheme,
		Host:   a.cfg.ServerAddr,
		Path:   "/tunnel",
	}
	if a.cfg.AuthToken != "" {
		u.RawQuery = "token=" + url.QueryEscape(a.cfg.AuthToken)
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
	}

	headers := http.Header{}
	if a.cfg.AuthToken != "" {
		headers.Set("Authorization", "Bearer "+a.cfg.AuthToken)
	}

	conn, _, err := dialer.DialContext(ctx, u.String(), headers)
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}
	defer conn.Close()
	slog.Info("Control connection established")

	// Send register message
	reg := map[string]any{
		"subdomain":      a.cfg.Subdomain,
		"custom_domain":  a.cfg.CustomDomain,
		"proto":          a.cfg.Proto,
		"hmac_secret":    a.cfg.HMACSecret,
		"ip_allow_list":  a.cfg.IPAllowList,
		"ip_block_list":  a.cfg.IPBlockList,
		"basic_auth_user": a.cfg.BasicUser,
		"basic_auth_pass": a.cfg.BasicPass,
	}
	payload, _ := json.Marshal(reg)
	if err := conn.WriteJSON(map[string]any{"type": "register", "payload": payload}); err != nil {
		return fmt.Errorf("send register: %w", err)
	}

	// Wait for registered response
	var resp struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err := conn.ReadJSON(&resp); err != nil {
		return fmt.Errorf("read registered: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	switch resp.Type {
	case "registered":
		if err := json.Unmarshal(resp.Payload, &a.info); err != nil {
			return fmt.Errorf("parse registered: %w", err)
		}
		printBanner(a.cfg, a.info)
	case "error":
		var ep struct{ Code, Message string }
		json.Unmarshal(resp.Payload, &ep)
		return fmt.Errorf("server error %s: %s", ep.Code, ep.Message)
	default:
		return fmt.Errorf("unexpected message type: %s", resp.Type)
	}

	// For TCP/SSH tunnels, start a direct TCP listener that forwards to local
	if a.cfg.Proto == "tcp" || a.cfg.Proto == "ssh" {
		go a.tcpForwardLoop(ctx)
	}

	// Keepalive loop — stay connected and handle pings
	conn.SetPingHandler(func(data string) error {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		return conn.WriteMessage(websocket.PongMessage, []byte(data))
	})

	for {
		select {
		case <-ctx.Done():
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			return nil
		default:
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			_, _, err := conn.ReadMessage()
			if err != nil {
				return fmt.Errorf("control connection lost: %w", err)
			}
		}
	}
}

// tcpForwardLoop listens on a local port and connects to the server TCP port.
func (a *Agent) tcpForwardLoop(ctx context.Context) {
	serverHost, _, _ := net.SplitHostPort(a.cfg.ServerAddr)
	serverAddr := fmt.Sprintf("%s:%d", serverHost, a.info.TCPPort)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Connect to server's public TCP port
		srvConn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		// Connect to local service
		localConn, err := net.DialTimeout("tcp", a.cfg.LocalAddr, 5*time.Second)
		if err != nil {
			slog.Error("failed to dial local service", "addr", a.cfg.LocalAddr, "err", err)
			srvConn.Close()
			time.Sleep(time.Second)
			continue
		}

		go pipe(srvConn, localConn)
	}
}

// HTTPForwardLoop forwards HTTP connections: server sends conn → agent connects local → pipes.
// This is used for HTTP tunnels where the server dials back to the agent.
func (a *Agent) HTTPForwardLoop(ctx context.Context, serverAddr, localAddr string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		srvConn, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}

		localConn, err := net.DialTimeout("tcp", localAddr, 5*time.Second)
		if err != nil {
			slog.Error("failed to dial local", "addr", localAddr, "err", err)
			srvConn.Close()
			time.Sleep(time.Second)
			continue
		}
		go pipe(srvConn, localConn)
	}
}

func pipe(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	errc := make(chan error, 2)
	go func() { _, err := io.Copy(a, b); errc <- err }()
	go func() { _, err := io.Copy(b, a); errc <- err }()
	<-errc
}

func printBanner(cfg *config.AgentConfig, info RegisteredInfo) {
	fmt.Printf("\n")
	fmt.Printf("  ╔══════════════════════════════════════════════════════╗\n")
	fmt.Printf("  ║            XTunnel — Tunnel Active                  ║\n")
	fmt.Printf("  ╠══════════════════════════════════════════════════════╣\n")
	fmt.Printf("  ║  Public URL  : %-37s║\n", info.PublicURL)
	fmt.Printf("  ║  Local addr  : %-37s║\n", cfg.LocalAddr)
	fmt.Printf("  ║  Protocol    : %-37s║\n", cfg.Proto)
	fmt.Printf("  ║  Tunnel ID   : %-37s║\n", info.TunnelID)
	if info.TCPPort != 0 {
		fmt.Printf("  ║  TCP Port    : %-37d║\n", info.TCPPort)
	}
	fmt.Printf("  ╚══════════════════════════════════════════════════════╝\n\n")
}

// InspectedRequest holds a captured HTTP request for the inspector.
type InspectedRequest struct {
	ID        string
	Timestamp time.Time
	Method    string
	Path      string
	Headers   http.Header
	Body      []byte
	Status    int
	Duration  time.Duration
}

// InspectingProxy is an HTTP proxy that captures and logs all requests.
type InspectingProxy struct {
	localAddr string
	ch        chan InspectedRequest
}

func NewInspectingProxy(localAddr string) *InspectingProxy {
	return &InspectingProxy{
		localAddr: localAddr,
		ch:        make(chan InspectedRequest, 512),
	}
}

func (p *InspectingProxy) Requests() <-chan InspectedRequest { return p.ch }

func (p *InspectingProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body = io.NopCloser(bufio.NewReader(io.MultiReader(
		io.NewSectionReader(bytesReader(body), 0, int64(len(body))),
	)))

	// Forward to local
	localURL := "http://" + p.localAddr + r.RequestURI
	req, _ := http.NewRequestWithContext(r.Context(), r.Method, localURL, io.NopCloser(io.Reader(bytesReader(body))))
	req.Header = r.Header.Clone()

	resp, err := http.DefaultTransport.RoundTrip(req)
	status := 502
	if err == nil {
		status = resp.StatusCode
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		resp.Body.Close()
	} else {
		http.Error(w, "upstream error: "+err.Error(), 502)
	}

	dur := time.Since(start)
	slog.Info("→",
		"method", r.Method,
		"path", r.URL.Path,
		"status", status,
		"duration", dur.Round(time.Millisecond),
	)

	select {
	case p.ch <- InspectedRequest{
		Timestamp: start,
		Method:    r.Method,
		Path:      r.URL.Path,
		Headers:   r.Header,
		Body:      body,
		Status:    status,
		Duration:  dur,
	}:
	default:
	}
}

type bytesReaderType []byte

func bytesReader(b []byte) *bytesReaderType {
	r := bytesReaderType(b)
	return &r
}

func (b *bytesReaderType) Read(p []byte) (int, error) {
	if len(*b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, *b)
	*b = (*b)[n:]
	return n, nil
}

func (b *bytesReaderType) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(*b)) {
		return 0, io.EOF
	}
	n := copy(p, (*b)[off:])
	return n, nil
}
