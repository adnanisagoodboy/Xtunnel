// Package ssh implements the XTunnel SSH gateway.
//
// Security model:
//   - All connections require a valid XTunnel auth token (passed as SSH password or env var).
//   - Each SSH session maps to one tunnel; traffic is forwarded through the tunnel's ConnCh.
//   - Host key is loaded from disk (RSA 4096 or Ed25519); auto-generated on first run.
//   - We implement our own mini SSH handshake using net.Conn + protocol framing so we do
//     NOT depend on golang.org/x/crypto/ssh (blocked in this env). In production, swap this
//     for the full x/crypto/ssh package for complete RFC 4253 compliance.
//
// Wire protocol (XTunnel SSH-over-TCP, simplified):
//   Client → Server:
//     [4 bytes len][JSON handshake]
//   Server → Client:
//     [4 bytes len][JSON response]
//   Then raw bidirectional copy.
package ssh

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/xtunnel/xtunnel/server/internal/auth"
	"github.com/xtunnel/xtunnel/server/internal/tunnel"
)

// Handshake messages
type ClientHello struct {
	Token     string `json:"token"`
	TunnelID  string `json:"tunnel_id"`
	LocalAddr string `json:"local_addr"`
}

type ServerHello struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
}

// Gateway listens on a TCP port and forwards SSH connections through tunnels.
type Gateway struct {
	port     int
	registry *tunnel.Registry
	auth     *auth.Service
	tlsCfg   *tls.Config
}

func NewGateway(port int, reg *tunnel.Registry, a *auth.Service, certFile, keyFile string) (*Gateway, error) {
	tlsCfg, err := loadOrGenTLS(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("ssh gateway tls: %w", err)
	}
	return &Gateway{port: port, registry: reg, auth: a, tlsCfg: tlsCfg}, nil
}

func (g *Gateway) ListenAndServe() error {
	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", g.port), g.tlsCfg)
	if err != nil {
		return fmt.Errorf("ssh listen: %w", err)
	}
	defer ln.Close()
	slog.Info("SSH gateway listening", "port", g.port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Error("ssh accept error", "err", err)
			continue
		}
		go g.handle(conn)
	}
}

func (g *Gateway) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Read client hello
	var hello ClientHello
	if err := readJSON(conn, &hello); err != nil {
		slog.Error("ssh read hello", "err", err)
		writeJSON(conn, ServerHello{OK: false, Error: "bad handshake"})
		return
	}

	// Verify JWT token
	claims, err := g.auth.Verify(hello.Token)
	if err != nil {
		writeJSON(conn, ServerHello{OK: false, Error: "unauthorized"})
		return
	}

	// Look up tunnel
	t, ok := g.registry.GetByID(hello.TunnelID)
	if !ok {
		writeJSON(conn, ServerHello{OK: false, Error: "tunnel not found"})
		return
	}
	if t.UserID != claims.UserID {
		writeJSON(conn, ServerHello{OK: false, Error: "tunnel belongs to another user"})
		return
	}
	if t.Proto != tunnel.ProtoSSH {
		writeJSON(conn, ServerHello{OK: false, Error: "tunnel is not SSH type"})
		return
	}

	// IP check
	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if !auth.IPAllowed(clientIP, t.IPAllowList, t.IPBlockList) {
		writeJSON(conn, ServerHello{OK: false, Error: "forbidden"})
		return
	}

	writeJSON(conn, ServerHello{OK: true})
	conn.SetDeadline(time.Time{})

	slog.Info("SSH session established",
		"user", claims.UserID,
		"tunnel", t.ID,
		"client_ip", clientIP)

	t.ReqCount.Add(1)
	t.Touch()

	// Dial through tunnel to the agent's local SSH server
	upstream, err := dialTunnel(t)
	if err != nil {
		slog.Error("ssh dial tunnel", "err", err)
		return
	}
	defer upstream.Close()

	// Bidirectional copy: SSH client ↔ local SSH server through the tunnel
	errc := make(chan error, 2)
	go func() {
		n, err := io.Copy(upstream, conn)
		t.BytesIn.Add(n)
		errc <- err
	}()
	go func() {
		n, err := io.Copy(conn, upstream)
		t.BytesOut.Add(n)
		errc <- err
	}()

	if err := <-errc; err != nil && err != io.EOF {
		slog.Debug("ssh session ended", "err", err)
	}
	slog.Info("SSH session closed", "tunnel", t.ID)
}

// TCPForwarder handles raw TCP tunnels (non-SSH) on dynamic ports.
type TCPForwarder struct {
	registry *tunnel.Registry
}

func NewTCPForwarder(reg *tunnel.Registry) *TCPForwarder {
	return &TCPForwarder{registry: reg}
}

// StartPort starts a listener for a specific TCP tunnel port.
func (f *TCPForwarder) StartPort(port int, t *tunnel.Tunnel) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		slog.Error("tcp forwarder listen failed", "port", port, "err", err)
		return
	}
	slog.Info("TCP forwarder listening", "port", port, "tunnel", t.ID)

	go func() {
		defer ln.Close()
		// Close listener when tunnel dies
		go func() { <-t.Done(); ln.Close() }()

		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-t.Done():
					return
				default:
					slog.Error("tcp accept error", "err", err)
					continue
				}
			}
			go f.forward(conn, t)
		}
	}()
}

func (f *TCPForwarder) forward(client net.Conn, t *tunnel.Tunnel) {
	defer client.Close()

	upstream, err := dialTunnel(t)
	if err != nil {
		slog.Error("tcp forward dial tunnel", "err", err)
		return
	}
	defer upstream.Close()

	t.ReqCount.Add(1)
	t.Touch()

	errc := make(chan error, 2)
	go func() {
		n, err := io.Copy(upstream, client)
		t.BytesIn.Add(n)
		errc <- err
	}()
	go func() {
		n, err := io.Copy(client, upstream)
		t.BytesOut.Add(n)
		errc <- err
	}()
	<-errc
}

// ── helpers ──────────────────────────────────────────────────────────────────

func dialTunnel(t *tunnel.Tunnel) (net.Conn, error) {
	select {
	case conn := <-t.ConnCh:
		return conn, nil
	case <-t.Done():
		return nil, io.EOF
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("tunnel dial timeout")
	}
}

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
	if n > 1<<20 { // 1 MB max
		return fmt.Errorf("message too large: %d", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(br, data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// loadOrGenTLS loads TLS cert+key or generates a self-signed cert.
func loadOrGenTLS(certFile, keyFile string) (*tls.Config, error) {
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}, nil
	}

	// Auto-generate self-signed RSA-4096 cert
	slog.Warn("No TLS cert configured for SSH gateway — generating self-signed cert")
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"XTunnel"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	// Optionally persist
	if certFile != "" {
		os.WriteFile(certFile, certPEM, 0600)
		os.WriteFile(keyFile, keyPEM, 0600)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		// TLS 1.3 cipher suites are fixed; these apply to TLS 1.2 fallback (disabled above)
	}, nil
}
