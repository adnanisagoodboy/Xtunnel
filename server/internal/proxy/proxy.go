// Package proxy routes public HTTP(S) traffic to the right tunnel agent.
package proxy

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"fmt"
	"strings"
	"time"

	"github.com/xtunnel/xtunnel/server/internal/auth"
	"github.com/xtunnel/xtunnel/server/internal/tunnel"
)

type Handler struct {
	registry *tunnel.Registry
}

func NewHandler(reg *tunnel.Registry) *Handler {
	return &Handler{registry: reg}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := stripPort(r.Host)

	t, ok := h.registry.GetByHost(host)
	if !ok {
		http.Error(w, "no tunnel for "+host, http.StatusNotFound)
		return
	}

	// IP filter
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !auth.IPAllowed(clientIP, t.IPAllowList, t.IPBlockList) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Basic auth gate
	if t.BasicAuthUser != "" {
		u, p, ok := r.BasicAuth()
		if !ok || u != t.BasicAuthUser || p != t.BasicAuthPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="XTunnel"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	t.ReqCount.Add(1)
	t.Touch()

	// WebSocket passthrough
	if isWSUpgrade(r) {
		h.proxyWS(w, r, t)
		return
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = t.ID
			req.Header.Set("X-Forwarded-Host", r.Host)
			req.Header.Set("X-Forwarded-For", clientIP)
			req.Header.Set("X-Real-IP", clientIP)
			req.Header.Set("X-XTunnel-ID", t.ID)
			if t.HMACSecret != "" {
				req.Header.Set("X-XTunnel-Signature",
					auth.SignHMAC([]byte(t.HMACSecret), []byte(req.URL.RequestURI())))
			}
		},
		Transport: &tunnelTransport{t: t},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("proxy error", "tunnel", t.ID, "err", err)
			t.ErrCount.Add(1)
			http.Error(w, "tunnel upstream error", http.StatusBadGateway)
		},
		ModifyResponse: func(resp *http.Response) error {
			t.BytesOut.Add(resp.ContentLength)
			return nil
		},
	}
	rp.ServeHTTP(w, r)
}

// tunnelTransport dials a conn from the tunnel's connection pool.
type tunnelTransport struct{ t *tunnel.Tunnel }

func (tr *tunnelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	conn, err := dialTunnel(tr.t)
	if err != nil {
		return nil, err
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return resp, nil
}

func (h *Handler) proxyWS(w http.ResponseWriter, r *http.Request, t *tunnel.Tunnel) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", 500)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	upstream, err := dialTunnel(t)
	if err != nil {
		slog.Error("ws dial tunnel failed", "err", err)
		return
	}
	defer upstream.Close()

	// Forward the original HTTP upgrade request
	r.Write(upstream)

	// Bidirectional pipe
	errc := make(chan error, 2)
	cp := func(dst, src net.Conn) {
		n, err := io.Copy(dst, src)
		t.BytesOut.Add(n)
		errc <- err
	}
	go cp(upstream, clientConn)
	go cp(clientConn, upstream)
	<-errc
}

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

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func isWSUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}
