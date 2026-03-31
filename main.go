package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"xtunnel-server/internal/auth"
	"xtunnel-server/internal/proxy"
	"xtunnel-server/internal/registry"
	"xtunnel-server/internal/tunnel"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	domain := os.Getenv("XTUNNEL_DOMAIN")
	if domain == "" {
		domain = "localhost:" + port
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "change-me-in-production-please"
		log.Println("[warn] JWT_SECRET not set, using default (insecure)")
	}

	reg := registry.New()
	authSvc := auth.New(jwtSecret)
	tunnelHandler := tunnel.NewHandler(reg, authSvc, domain)
	proxyHandler := proxy.NewHandler(reg, domain)

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/register", authSvc.RegisterHandler)
	mux.HandleFunc("/api/login", authSvc.LoginHandler)
	mux.HandleFunc("/api/status", authSvc.StatusHandler)

	// WebSocket tunnel endpoint (CLI connects here)
	mux.HandleFunc("/tunnel", tunnelHandler.Handle)

	// Health check (Railway/Render use this)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		active := reg.Count()
		fmt.Fprintf(w, `{"status":"ok","tunnels":%d,"time":"%s"}`, active, time.Now().UTC().Format(time.RFC3339))
	})

	// Dashboard (simple HTML status page)
	mux.HandleFunc("/dashboard", dashboardHandler(reg, domain))

	// Everything else → reverse proxy to tunnel
	mux.HandleFunc("/", proxyHandler.Handle)

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // disabled — tunnels are long-lived
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("[xtunnel] Server starting on :%s", port)
	log.Printf("[xtunnel] Domain: %s", domain)
	log.Printf("[xtunnel] Tunnel WS endpoint: ws://%s/tunnel", domain)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[xtunnel] Server error: %v", err)
	}
}

func dashboardHandler(reg *registry.Registry, domain string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		tunnels := reg.List()
		rows := ""
		for _, t := range tunnels {
			rows += fmt.Sprintf(`<tr>
				<td>%s</td>
				<td><a href="http://%s.%s" target="_blank">%s.%s</a></td>
				<td>%s</td>
				<td>%d</td>
				<td>%s ago</td>
			</tr>`, t.Name, t.Name, domain, t.Name, domain,
				t.ClientAddr, t.RequestCount, time.Since(t.ConnectedAt).Round(time.Second))
		}
		fmt.Fprintf(w, dashboardHTML, len(tunnels), rows)
	}
}

const dashboardHTML = `<!DOCTYPE html>
<html>
<head>
<title>Xtunnel Dashboard</title>
<meta charset="utf-8">
<meta http-equiv="refresh" content="10">
<style>
  body { font-family: system-ui, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; background: #f9f9f9; color: #222; }
  h1 { color: #4f46e5; margin-bottom: 4px; }
  .subtitle { color: #666; margin-bottom: 28px; font-size: 14px; }
  .stat { display: inline-block; background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px 24px; margin-right: 12px; }
  .stat-num { font-size: 28px; font-weight: 600; color: #4f46e5; }
  .stat-label { font-size: 13px; color: #666; }
  table { width: 100%%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; border: 1px solid #e5e7eb; margin-top: 24px; }
  th { background: #f3f4f6; text-align: left; padding: 10px 14px; font-size: 13px; color: #555; }
  td { padding: 10px 14px; border-top: 1px solid #f0f0f0; font-size: 14px; }
  tr:hover td { background: #fafafa; }
  a { color: #4f46e5; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .empty { text-align: center; color: #aaa; padding: 40px; }
  .badge { background: #ecfdf5; color: #065f46; padding: 2px 8px; border-radius: 12px; font-size: 12px; }
</style>
</head>
<body>
<h1>⚡ Xtunnel</h1>
<p class="subtitle">Active tunnels — auto-refreshes every 10 seconds</p>
<div class="stat"><div class="stat-num">%d</div><div class="stat-label">Active tunnels</div></div>
<table>
<thead><tr><th>Name</th><th>Public URL</th><th>Client IP</th><th>Requests</th><th>Connected</th></tr></thead>
<tbody>
%s
</tbody>
</table>
%s
</body></html>`
