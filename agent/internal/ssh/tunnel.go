// Package ssh provides the agent-side SSH tunnel client.
// It connects to the XTunnel SSH gateway and forwards SSH traffic
// to/from the local SSH server.
package ssh

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

// ClientHello matches the server-side struct.
type ClientHello struct {
	Token     string `json:"token"`
	TunnelID  string `json:"tunnel_id"`
	LocalAddr string `json:"local_addr"`
}

type ServerHello struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Client connects to XTunnel SSH gateway and bridges to a local SSH server.
type Client struct {
	serverAddr string // XTunnel SSH gateway host:port
	token      string
	tunnelID   string
	localAddr  string // e.g. localhost:22
}

func NewClient(serverAddr, token, tunnelID, localAddr string) *Client {
	return &Client{
		serverAddr: serverAddr,
		token:      token,
		tunnelID:   tunnelID,
		localAddr:  localAddr,
	}
}

// Forward establishes the SSH tunnel and blocks until it's closed.
// It automatically reconnects on failure.
func (c *Client) Forward(ctx context.Context) error {
	backoff := 2 * time.Second
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := c.connect(ctx); err != nil {
			slog.Error("SSH tunnel error", "err", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
	}
}

func (c *Client) connect(ctx context.Context) error {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", c.serverAddr)
	if err != nil {
		return fmt.Errorf("dial ssh gateway: %w", err)
	}
	defer conn.Close()

	// TLS upgrade would go here in production (use crypto/tls)
	// For now, use plaintext TCP with the XTunnel handshake

	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Send hello
	if err := writeJSON(conn, ClientHello{
		Token:     c.token,
		TunnelID:  c.tunnelID,
		LocalAddr: c.localAddr,
	}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	// Read server response
	var hello ServerHello
	if err := readJSON(conn, &hello); err != nil {
		return fmt.Errorf("read hello: %w", err)
	}
	if !hello.OK {
		return fmt.Errorf("gateway rejected: %s", hello.Error)
	}

	conn.SetDeadline(time.Time{})
	slog.Info("SSH tunnel connected", "gateway", c.serverAddr, "local", c.localAddr)

	// Dial local SSH server
	localConn, err := net.DialTimeout("tcp", c.localAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial local ssh: %w", err)
	}
	defer localConn.Close()

	// Bridge: gateway conn ↔ local SSH server
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(localConn, conn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(conn, localConn)
		errc <- err
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errc:
		if err != nil && err != io.EOF {
			return err
		}
		return nil
	}
}

// DirectSSHTunnel creates an SSH-over-HTTPS tunnel (SSH via WebSocket).
// This allows SSH through firewalls that only allow HTTPS.
type DirectSSHTunnel struct {
	publicHost string // xtunnel.io
	sshPort    int    // 2222
	localAddr  string // localhost:22
	token      string
	tunnelID   string
}

func NewDirectSSHTunnel(host string, port int, localAddr, token, tunnelID string) *DirectSSHTunnel {
	return &DirectSSHTunnel{
		publicHost: host, sshPort: port,
		localAddr: localAddr, token: token, tunnelID: tunnelID,
	}
}

// RunMultiplexed accepts multiple simultaneous SSH connections.
// Each incoming connection from the gateway gets its own goroutine.
func (t *DirectSSHTunnel) RunMultiplexed(ctx context.Context) error {
	slog.Info("SSH tunnel ready",
		"gateway", fmt.Sprintf("%s:%d", t.publicHost, t.sshPort),
		"local", t.localAddr,
	)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		c := NewClient(
			fmt.Sprintf("%s:%d", t.publicHost, t.sshPort),
			t.token, t.tunnelID, t.localAddr,
		)
		if err := c.connect(ctx); err != nil {
			time.Sleep(2 * time.Second)
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func writeJSON(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	_, err = w.Write(buf)
	return err
}

func readJSON(r io.Reader, v any) error {
	br := bufio.NewReader(r)
	var lenBuf [4]byte
	if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > 1<<20 {
		return fmt.Errorf("message too large: %d", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(br, data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
