package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"xtunnel-server/internal/registry"
	"xtunnel-server/internal/tunnel"
)

// Handler proxies incoming HTTP requests to the correct tunnel
type Handler struct {
	reg    *registry.Registry
	domain string
}

func NewHandler(reg *registry.Registry, domain string) *Handler {
	return &Handler{reg: reg, domain: domain}
}

func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
	// Extract subdomain from Host header
	// e.g. "myapp.xtunnel.io" → "myapp"
	// For local dev: "myapp.localhost:8080" → "myapp"
	name := extractSubdomain(r.Host, h.domain)
	if name == "" {
		// No subdomain — this is a request to the root domain
		http.Redirect(w, r, "/dashboard", 302)
		return
	}

	tun, ok := h.reg.Get(name)
	if !ok {
		w.WriteHeader(404)
		fmt.Fprintf(w, notFoundHTML(name), name)
		return
	}

	start := time.Now()

	// Read the request body
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB limit
	}

	// Flatten headers
	headers := make(map[string]string)
	for k, vals := range r.Header {
		headers[k] = strings.Join(vals, ", ")
	}
	headers["X-Forwarded-For"] = r.RemoteAddr
	headers["X-Forwarded-Host"] = r.Host
	headers["X-Forwarded-Proto"] = scheme(r)

	reqID := newID()

	pr := &registry.PendingRequest{
		ID: reqID,
		Data: mustJSON(tunnel.ProxyRequest{
			Type:      "request",
			ID:        reqID,
			Method:    r.Method,
			Path:      r.RequestURI,
			Headers:   headers,
			Body:      bodyBytes,
			Timestamp: time.Now(),
		}),
		RespCh: make(chan []byte, 1),
		ErrCh:  make(chan error, 1),
	}

	// Send request to tunnel goroutine
	select {
	case tun.ReqCh <- pr:
	case <-time.After(5 * time.Second):
		http.Error(w, "tunnel queue full or timeout", 503)
		return
	}

	// Wait for response (30s timeout)
	select {
	case respRaw := <-pr.RespCh:
		var resp tunnel.ProxyResponse
		if err := json.Unmarshal(respRaw, &resp); err != nil {
			http.Error(w, "bad response from tunnel", 502)
			return
		}

		// Write response back to browser
		for k, v := range resp.Headers {
			// skip hop-by-hop headers
			switch strings.ToLower(k) {
			case "transfer-encoding", "connection", "keep-alive", "upgrade", "te", "trailer":
				continue
			}
			w.Header().Set(k, v)
		}
		w.Header().Set("X-Tunneled-By", "xtunnel")
		w.WriteHeader(resp.StatusCode)
		w.Write(resp.Body)

		duration := time.Since(start)
		h.reg.IncrementRequests(name)

		log.Printf("[proxy] %s %s%s → %d (%dms) [tunnel=%s]",
			r.Method, name, r.RequestURI, resp.StatusCode,
			duration.Milliseconds(), name)

	case err := <-pr.ErrCh:
		log.Printf("[proxy] tunnel error for %s: %v", name, err)
		http.Error(w, "tunnel error: "+err.Error(), 502)

	case <-time.After(30 * time.Second):
		log.Printf("[proxy] timeout waiting for %s to respond", name)
		http.Error(w, "tunnel response timeout (30s)", 504)
	}
}

func extractSubdomain(host, domain string) string {
	// Strip port from domain for comparison
	baseDomain := domain
	if idx := strings.LastIndex(baseDomain, ":"); idx != -1 {
		baseDomain = baseDomain[:idx]
	}

	// Strip port from host
	h := host
	if idx := strings.LastIndex(h, ":"); idx != -1 {
		h = h[:idx]
	}

	// Check if host ends with .baseDomain
	suffix := "." + baseDomain
	if strings.HasSuffix(h, suffix) {
		sub := h[:len(h)-len(suffix)]
		if sub != "" && !strings.Contains(sub, ".") {
			return sub
		}
	}
	return ""
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func newID() string {
	b := make([]byte, 8)
	chars := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func notFoundHTML(name string) string {
	return `<!DOCTYPE html>
<html>
<head><title>Tunnel not found – Xtunnel</title>
<style>
body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f9f9f9}
.box{text-align:center;padding:40px;background:#fff;border-radius:12px;border:1px solid #e5e7eb;max-width:420px}
h1{color:#4f46e5;font-size:48px;margin:0}
h2{color:#111;margin:16px 0 8px}
p{color:#666;line-height:1.6}
code{background:#f3f4f6;padding:2px 8px;border-radius:4px;font-family:monospace}
.hint{margin-top:24px;font-size:13px;color:#999}
</style></head>
<body>
<div class="box">
<h1>⚡</h1>
<h2>Tunnel not found</h2>
<p>No active tunnel named <code>` + name + `</code>.</p>
<p>Start it with:<br><code>xtunnel 3000 ` + name + `</code></p>
<p class="hint">Xtunnel — open source tunneling</p>
</div>
</body></html>`
}

// Ensure bytes import is used
var _ = bytes.NewReader
