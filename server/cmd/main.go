package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xtunnel/xtunnel/server/internal/auth"
	"github.com/xtunnel/xtunnel/server/internal/ctrl"
	"github.com/xtunnel/xtunnel/server/internal/metrics"
	"github.com/xtunnel/xtunnel/server/internal/proxy"
	"github.com/xtunnel/xtunnel/server/internal/ratelimit"
	"github.com/xtunnel/xtunnel/server/internal/ssh"
	"github.com/xtunnel/xtunnel/server/internal/tunnel"
	"github.com/xtunnel/xtunnel/shared/config"
)

const banner = `
 ██╗  ██╗████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗     
 ╚██╗██╔╝╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║     
  ╚███╔╝    ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║     
  ██╔██╗    ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║     
 ██╔╝ ██╗   ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
 ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
 Secure Tunnel Platform — v1.0.0
`

func main() {
	cfgPath := flag.String("config", "", "path to server config JSON")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		slog.Error("config load failed", "err", err)
		os.Exit(1)
	}

	fmt.Print(banner)
	slog.Info("Starting XTunnel server",
		"domain", cfg.Domain,
		"http", cfg.HTTPPort,
		"ctrl", cfg.CtrlPort,
		"ssh", cfg.SSHPort,
		"api", cfg.APIPort,
	)

	// ── Core services ──────────────────────────────────────────────────────
	bus := tunnel.NewEventBus()
	reg := tunnel.NewRegistry(cfg.Domain, bus)
	authSvc := auth.NewService(cfg.JWTSecret, cfg.TokenExpiry.Duration)
	limiter := ratelimit.New(cfg.RateLimitRPS, cfg.RateLimitRPS*3)
	tcpFwd := ssh.NewTCPForwarder(reg)

	// Watch for new TCP/SSH tunnels via event bus → start port listeners
	go func() {
		events := bus.Subscribe()
		for e := range events {
			if e.Type == tunnel.EventRegistered &&
				(e.Tunnel.Proto == tunnel.ProtoTCP || e.Tunnel.Proto == tunnel.ProtoSSH) {
				slog.Info("Starting TCP listener", "port", e.Tunnel.TCPPort, "proto", e.Tunnel.Proto)
				tcpFwd.StartPort(e.Tunnel.TCPPort, e.Tunnel)
			}
		}
	}()

	// ── Control plane (WebSocket) ──────────────────────────────────────────
	ctrlMux := http.NewServeMux()
	ctrlHandler := ctrl.NewHandler(reg, authSvc, cfg.Domain, cfg.AllowAnonymous)
	ctrlMux.Handle("/tunnel", ctrlHandler)
	ctrlMux.HandleFunc("POST /auth/token", func(w http.ResponseWriter, r *http.Request) {
		userID := r.FormValue("user_id")
		if userID == "" {
			userID = "user-" + auth.GenerateToken(4)
		}
		tok, err := authSvc.Issue(userID, userID+"@xtunnel.io", "free")
		if err != nil {
			http.Error(w, "token error: "+err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":%q,"user_id":%q}`, tok, userID)
	})
	// Subdomain availability check
	ctrlMux.HandleFunc("GET /check/{subdomain}", func(w http.ResponseWriter, r *http.Request) {
		sub := r.PathValue("subdomain")
		available := reg.IsAvailable(sub)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"subdomain":%q,"available":%v}`, sub, available)
	})

	ctrlServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.CtrlPort),
		Handler:      limiter.Middleware(ctrlMux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// ── HTTP proxy ─────────────────────────────────────────────────────────
	proxyHandler := proxy.NewHandler(reg)
	proxyServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:      limiter.Middleware(proxyHandler),
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// ── REST API / Metrics ─────────────────────────────────────────────────
	metricsHandler := metrics.NewHandler(reg)
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("GET /api/health", metricsHandler.Health)
	apiMux.HandleFunc("GET /api/tunnels", metricsHandler.ListTunnels)
	apiMux.HandleFunc("GET /api/tunnels/{id}/stats", metricsHandler.TunnelStats)
	apiMux.HandleFunc("DELETE /api/tunnels/{id}", metricsHandler.CloseTunnel)

	// CORS wrapper for dashboard
	apiServer := &http.Server{
		Addr: fmt.Sprintf(":%d", cfg.APIPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
			if r.Method == http.MethodOptions {
				w.WriteHeader(204)
				return
			}
			apiMux.ServeHTTP(w, r)
		}),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	// ── SSH Gateway ─────────────────────────────────────────────────────────
	sshGateway, err := ssh.NewGateway(cfg.SSHPort, reg, authSvc, cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		slog.Error("ssh gateway init failed", "err", err)
		os.Exit(1)
	}

	// ── Launch all servers ─────────────────────────────────────────────────
	errCh := make(chan error, 4)
	go func() { errCh <- ctrlServer.ListenAndServe() }()
	go func() { errCh <- proxyServer.ListenAndServe() }()
	go func() { errCh <- apiServer.ListenAndServe() }()
	go func() { errCh <- sshGateway.ListenAndServe() }()

	slog.Info("XTunnel ready",
		"ctrl", fmt.Sprintf("ws://localhost:%d/tunnel", cfg.CtrlPort),
		"proxy", fmt.Sprintf("http://localhost:%d", cfg.HTTPPort),
		"api", fmt.Sprintf("http://localhost:%d/api/health", cfg.APIPort),
		"ssh", fmt.Sprintf("tls://localhost:%d", cfg.SSHPort),
	)

	// ── Graceful shutdown ──────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		slog.Error("server error", "err", err)
	case sig := <-sigCh:
		slog.Info("shutting down", "signal", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctrlServer.Shutdown(ctx)
	proxyServer.Shutdown(ctx)
	apiServer.Shutdown(ctx)
	slog.Info("XTunnel stopped cleanly")
}
