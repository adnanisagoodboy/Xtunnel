// XTunnel agent — developer-side CLI
// Usage:
//   xtunnel http 3000                     # expose localhost:3000 via HTTP
//   xtunnel http 3000 --subdomain myapp   # custom subdomain
//   xtunnel tcp 5432                      # expose PostgreSQL
//   xtunnel ssh 22                        # expose local SSH server
//   xtunnel ssh 22 --tunnel-id <id>       # reconnect existing SSH tunnel
//   xtunnel token --user-id alice         # get an auth token
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	agentssh "github.com/xtunnel/xtunnel/agent/internal/ssh"
	"github.com/xtunnel/xtunnel/agent/internal/client"
	"time"

	"github.com/xtunnel/xtunnel/shared/config"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "http", "https":
		runHTTP(cmd, args)
	case "tcp":
		runTCP(args)
	case "ssh":
		runSSH(args)
	case "token":
		runToken(args)
	case "version", "--version", "-v":
		fmt.Printf("xtunnel v%s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func runHTTP(proto string, args []string) {
	if len(args) == 0 {
		die("usage: xtunnel http <port> [--subdomain <sub>] [--server <addr>]")
	}

	port := args[0]
	cfg := baseConfig()
	cfg.Proto = proto
	cfg.LocalAddr = "localhost:" + port

	// Parse flags
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--subdomain", "-s":
			i++
			if i < len(args) {
				cfg.Subdomain = args[i]
			}
		case "--server":
			i++
			if i < len(args) {
				cfg.ServerAddr = args[i]
			}
		case "--token":
			i++
			if i < len(args) {
				cfg.AuthToken = args[i]
			}
		case "--hmac-secret":
			i++
			if i < len(args) {
				cfg.HMACSecret = args[i]
			}
		case "--basic-auth":
			i++
			if i < len(args) {
				// format: user:pass
				cfg.BasicUser = args[i]
			}
		case "--inspect":
			// TODO: enable request inspector
		}
	}

	runAgent(cfg)
}

func runTCP(args []string) {
	if len(args) == 0 {
		die("usage: xtunnel tcp <port> [--server <addr>]")
	}
	port := args[0]
	cfg := baseConfig()
	cfg.Proto = "tcp"
	cfg.LocalAddr = "localhost:" + port
	parseCommonFlags(cfg, args[1:])
	runAgent(cfg)
}

func runSSH(args []string) {
	if len(args) == 0 {
		die("usage: xtunnel ssh <port> [--tunnel-id <id>]")
	}
	port := args[0]
	if _, err := strconv.Atoi(port); err != nil {
		die("invalid port: " + port)
	}

	cfg := baseConfig()
	cfg.Proto = "ssh"
	cfg.LocalAddr = "localhost:" + port
	var tunnelID string

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--tunnel-id":
			i++
			if i < len(args) {
				tunnelID = args[i]
			}
		case "--server":
			i++
			if i < len(args) {
				cfg.ServerAddr = args[i]
			}
		case "--token":
			i++
			if i < len(args) {
				cfg.AuthToken = args[i]
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// First register the tunnel, then start the SSH forwarder
	ag := client.New(cfg)

	go func() {
		if err := ag.Start(ctx); err != nil {
			slog.Error("agent error", "err", err)
			cancel()
		}
	}()

	// Wait for registration
	var info client.RegisteredInfo
	for i := 0; i < 20; i++ {
		info = ag.Info()
		if info.TunnelID != "" {
			break
		}
		waitMs(500)
	}

	if info.TunnelID == "" && tunnelID == "" {
		die("failed to register SSH tunnel")
	}
	if tunnelID == "" {
		tunnelID = info.TunnelID
	}

	serverHost := cfg.ServerAddr
	if serverHost == "" {
		serverHost = "localhost:2222"
	}

	sshClient := agentssh.NewDirectSSHTunnel(
		serverHost, 2222, cfg.LocalAddr, cfg.AuthToken, tunnelID,
	)

	fmt.Printf("\n  SSH Tunnel active:\n")
	fmt.Printf("  Connect: ssh -p %d user@%s\n\n", info.TCPPort, cfg.ServerAddr)

	go func() {
		if err := sshClient.RunMultiplexed(ctx); err != nil && err != context.Canceled {
			slog.Error("ssh tunnel error", "err", err)
		}
	}()

	<-sigCh
	cancel()
	fmt.Println("\nXTunnel SSH stopped.")
}

func runToken(args []string) {
	server := envOrDefault("XTUNNEL_SERVER", "localhost:7000")
	userID := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			i++
			if i < len(args) {
				server = args[i]
			}
		case "--user-id":
			i++
			if i < len(args) {
				userID = args[i]
			}
		}
	}

	resp, err := http.PostForm("http://"+server+"/auth/token",
		map[string][]string{"user_id": {userID}})
	if err != nil {
		die("failed to get token: " + err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]string
	json.Unmarshal(body, &result)
	fmt.Printf("Token : %s\n", result["token"])
	fmt.Printf("UserID: %s\n", result["user_id"])
	fmt.Printf("\nAdd to env: export XTUNNEL_TOKEN=%s\n", result["token"])
}

func runAgent(cfg *config.AgentConfig) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ag := client.New(cfg)

	go func() {
		if err := ag.Start(ctx); err != nil && err != context.Canceled {
			slog.Error("agent stopped", "err", err)
		}
		cancel()
	}()

	<-sigCh
	cancel()
	fmt.Println("\nXTunnel stopped.")
}

func baseConfig() *config.AgentConfig {
	cfg := &config.AgentConfig{}
	cfg.ServerAddr = envOrDefault("XTUNNEL_SERVER", "xtunnel.io:7000")
	cfg.AuthToken = envOrDefault("XTUNNEL_TOKEN", "")
	cfg.Proto = "http"
	return cfg
}

func parseCommonFlags(cfg *config.AgentConfig, args []string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			i++
			if i < len(args) {
				cfg.ServerAddr = args[i]
			}
		case "--token":
			i++
			if i < len(args) {
				cfg.AuthToken = args[i]
			}
		case "--subdomain", "-s":
			i++
			if i < len(args) {
				cfg.Subdomain = args[i]
			}
		}
	}
}

func printUsage() {
	fmt.Printf(`
XTunnel v%s — Secure Tunnel Platform

USAGE:
  xtunnel <command> [options]

COMMANDS:
  http <port>       Tunnel HTTP traffic to localhost:<port>
  tcp  <port>       Tunnel raw TCP traffic to localhost:<port>
  ssh  <port>       Tunnel SSH traffic to localhost:<port> (default 22)
  token             Get an auth token from the server
  version           Print version

OPTIONS:
  --server  <addr>     XTunnel server address (default: $XTUNNEL_SERVER)
  --token   <jwt>      Auth token (default: $XTUNNEL_TOKEN)
  --subdomain <sub>    Request a specific subdomain
  --hmac-secret <key>  Enable HMAC request signing

EXAMPLES:
  xtunnel http 3000
  xtunnel http 3000 --subdomain myapp
  xtunnel tcp 5432
  xtunnel ssh 22
  xtunnel token --user-id alice

ENVIRONMENT:
  XTUNNEL_SERVER   Server address (default: xtunnel.io:7000)
  XTUNNEL_TOKEN    Auth token

`, version)
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, "error: "+msg)
	os.Exit(1)
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func waitMs(ms int) {
	time.Sleep(time.Duration(ms) * time.Millisecond)
}
