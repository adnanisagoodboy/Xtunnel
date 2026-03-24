package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

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

	// ── Environment overrides (Railway / Render / Fly inject these) ────────
	// JWT secret
	if v := envOr("JWT_SECRET", ""); v != "" {
		cfg.JWTSecret = v
	}
	// Domain (Railway sets RAILWAY_PUBLIC_DOMAIN automatically)
	if v := envOr("RAILWAY_PUBLIC_DOMAIN", ""); v != "" {
		cfg.Domain = v
	}
	if v := envOr("DOMAIN", ""); v != "" {
		cfg.Domain = v
	}
	// Allow anonymous tunnels
	if v := envOr("ALLOW_ANONYMOUS", ""); v != "" {
		cfg.AllowAnonymous = v == "true"
	}
	// Railway injects PORT — we use it as our single public port
	railwayPort := envOr("PORT", "")

	fmt.Print(banner)

	// ── Core services ──────────────────────────────────────────────────────
	bus := tunnel.NewEventBus()
	reg := tunnel.NewRegistry(cfg.Domain, bus)
	authSvc := auth.NewService(cfg.JWTSecret, cfg.TokenExpiry.Duration)
	limiter := ratelimit.New(cfg.RateLimitRPS, cfg.RateLimitRPS*3)
	tcpFwd := ssh.NewTCPForwarder(reg)

	// Watch for TCP/SSH tunnels and start dynamic port listeners
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

	// ── Handlers ───────────────────────────────────────────────────────────
	ctrlHandler := ctrl.NewHandler(reg, authSvc, cfg.Domain, cfg.AllowAnonymous)
	proxyHandler := proxy.NewHandler(reg)
	metricsHandler := metrics.NewHandler(reg)

	tokenHandler := func(w http.ResponseWriter, r *http.Request) {
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
	}

	checkHandler := func(w http.ResponseWriter, r *http.Request) {
		sub := r.PathValue("subdomain")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"subdomain":%q,"available":%v}`, sub, reg.IsAvailable(sub))
	}

	errCh := make(chan error, 4)

	// ── Railway / single-port mode ─────────────────────────────────────────
	// When PORT env var is set (Railway, Render, Fly), everything runs on
	// that one port. The proxy still routes by Host header.
	if railwayPort != "" {
		slog.Info("Railway mode — single port", "port", railwayPort)

		mainMux := http.NewServeMux()

		// Control plane WebSocket
		mainMux.Handle("/tunnel", ctrlHandler)

		// Auth + utility
		mainMux.HandleFunc("POST /auth/token", tokenHandler)
		mainMux.HandleFunc("GET /check/{subdomain}", checkHandler)

		// API
		mainMux.HandleFunc("GET /api/health", metricsHandler.Health)
		mainMux.HandleFunc("GET /api/tunnels", metricsHandler.ListTunnels)
		mainMux.HandleFunc("GET /api/tunnels/{id}/stats", metricsHandler.TunnelStats)
		mainMux.HandleFunc("DELETE /api/tunnels/{id}", metricsHandler.CloseTunnel)

		// Everything else → proxy (routes by Host header)
		mainMux.Handle("/", proxyHandler)

		single := &http.Server{
			Addr: ":" + railwayPort,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
				if r.Method == http.MethodOptions {
					w.WriteHeader(204)
					return
				}
				limiter.Middleware(mainMux).ServeHTTP(w, r)
			}),
			ReadTimeout:  60 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		}

		go func() { errCh <- single.ListenAndServe() }()

		slog.Info("XTunnel ready (Railway mode)",
			"port", railwayPort,
			"domain", cfg.Domain,
			"url", "https://"+cfg.Domain,
		)

	} else {
		// ── Local / self-hosted mode — each service on its own port ───────
		ctrlMux := http.NewServeMux()
		ctrlMux.Handle("/tunnel", ctrlHandler)
		ctrlMux.HandleFunc("POST /auth/token", tokenHandler)
		ctrlMux.HandleFunc("GET /check/{subdomain}", checkHandler)

		apiMux := http.NewServeMux()
		apiMux.HandleFunc("GET /api/health", metricsHandler.Health)
		apiMux.HandleFunc("GET /api/tunnels", metricsHandler.ListTunnels)
		apiMux.HandleFunc("GET /api/tunnels/{id}/stats", metricsHandler.TunnelStats)
		apiMux.HandleFunc("DELETE /api/tunnels/{id}", metricsHandler.CloseTunnel)

		ctrlServer := &http.Server{
			Addr:         ":" + strconv.Itoa(cfg.CtrlPort),
			Handler:      limiter.Middleware(ctrlMux),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
		proxyServer := &http.Server{
			Addr:         ":" + strconv.Itoa(cfg.HTTPPort),
			Handler:      limiter.Middleware(proxyHandler),
			ReadTimeout:  60 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
		apiServer := &http.Server{
			Addr: ":" + strconv.Itoa(cfg.APIPort),
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

		sshGateway, err := ssh.NewGateway(cfg.SSHPort, reg, authSvc, cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			slog.Error("ssh gateway init failed", "err", err)
			os.Exit(1)
		}

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
	}

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
	slog.Info("XTunnel stopped cleanly")
	_ = ctx
}
