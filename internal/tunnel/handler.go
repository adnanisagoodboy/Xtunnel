package tunnel

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"xtunnel-server/internal/auth"
	"xtunnel-server/internal/registry"
	"xtunnel-server/internal/ws"
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$`)

// Protocol messages (JSON over WebSocket)
type clientHello struct {
	Type    string `json:"type"`    // "hello"
	Token   string `json:"token"`   // auth token
	Name    string `json:"name"`    // requested subdomain (optional)
	Version string `json:"version"` // CLI version
}

type serverHello struct {
	Type   string `json:"type"`   // "hello_ack"
	Name   string `json:"name"`   // assigned subdomain
	URL    string `json:"url"`    // full public URL
	UserID string `json:"user_id"`
}

type serverError struct {
	Type    string `json:"type"` // "error"
	Message string `json:"message"`
	Code    string `json:"code"`
}

// ProxyRequest is sent from server → client (forward an incoming HTTP request)
type ProxyRequest struct {
	Type      string            `json:"type"` // "request"
	ID        string            `json:"id"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Body      []byte            `json:"body"`
	Timestamp time.Time         `json:"timestamp"`
}

// ProxyResponse is sent from client → server (response from localhost)
type ProxyResponse struct {
	Type       string            `json:"type"` // "response"
	ID         string            `json:"id"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body"`
}

// LogEntry is sent server → client (request log line)
type LogEntry struct {
	Type       string        `json:"type"` // "log"
	Method     string        `json:"method"`
	Path       string        `json:"path"`
	StatusCode int           `json:"status_code"`
	Duration   time.Duration `json:"duration_ms"`
	RemoteAddr string        `json:"remote_addr"`
	Timestamp  time.Time     `json:"timestamp"`
}

// Handler manages incoming WebSocket tunnel connections
type Handler struct {
	reg    *registry.Registry
	auth   *auth.Service
	domain string
}

func NewHandler(reg *registry.Registry, auth *auth.Service, domain string) *Handler {
	return &Handler{reg: reg, auth: auth, domain: domain}
}

func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
	// Upgrade to WebSocket
	conn, err := ws.Upgrade(w, r)
	if err != nil {
		http.Error(w, "websocket upgrade failed: "+err.Error(), 400)
		return
	}
	defer conn.Close()

	clientAddr := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		clientAddr = strings.Split(fwd, ",")[0]
	}

	log.Printf("[tunnel] new WS connection from %s", clientAddr)

	// Step 1: wait for hello message
	msg, err := conn.ReadMessage()
	if err != nil || msg.Op == ws.OpClose {
		log.Printf("[tunnel] client %s disconnected before hello", clientAddr)
		return
	}

	var hello clientHello
	if err := json.Unmarshal(msg.Data, &hello); err != nil || hello.Type != "hello" {
		sendError(conn, "expected hello message", "bad_handshake")
		return
	}

	// Step 2: authenticate
	var userID string
	if hello.Token != "" {
		claims, err := h.auth.ValidateToken(hello.Token)
		if err != nil {
			sendError(conn, "invalid auth token: "+err.Error(), "auth_failed")
			return
		}
		userID = claims.UserID
		log.Printf("[tunnel] authenticated user %s from %s", claims.Email, clientAddr)
	} else {
		// Allow anonymous with random name for dev/testing
		userID = "anon-" + randomWords(1)
		log.Printf("[tunnel] anonymous client from %s", clientAddr)
	}

	// Step 3: assign a name
	name, conflict := h.assignName(hello.Name)
	if conflict {
		alts := h.suggestAlternatives(hello.Name, 3)
		sendError(conn, fmt.Sprintf("name '%s' is already in use. Suggestions: %s",
			hello.Name, strings.Join(alts, ", ")), "name_taken")
		return
	}

	// Step 4: register tunnel
	tun, ok := h.reg.Register(name, clientAddr, userID)
	if !ok {
		sendError(conn, "name taken (race condition), try again", "name_taken")
		return
	}
	defer func() {
		h.reg.Unregister(name)
		log.Printf("[tunnel] tunnel '%s' closed", name)
	}()

	publicURL := fmt.Sprintf("https://%s.%s", name, h.domain)
	// local dev uses http
	if strings.HasPrefix(h.domain, "localhost") {
		publicURL = fmt.Sprintf("http://%s.%s", name, h.domain)
	}

	// Step 5: send hello_ack
	ack, _ := json.Marshal(serverHello{
		Type:   "hello_ack",
		Name:   name,
		URL:    publicURL,
		UserID: userID,
	})
	if err := conn.WriteMessage(ws.OpText, ack); err != nil {
		return
	}

	log.Printf("[tunnel] tunnel '%s' active → %s (user=%s)", name, publicURL, userID)

	// Step 6: event loop - multiplex requests and responses
	// We use two goroutines: one reading from WS (responses from CLI),
	// one writing to WS (forwarding incoming HTTP requests)
	pendingReqs := make(map[string]*registry.PendingRequest)

	// Goroutine: read responses and logs from CLI
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			m, err := conn.ReadMessage()
			if err != nil || m.Op == ws.OpClose {
				return
			}

			var env map[string]json.RawMessage
			if err := json.Unmarshal(m.Data, &env); err != nil {
				continue
			}
			var msgType string
			json.Unmarshal(env["type"], &msgType)

			switch msgType {
			case "response":
				var resp ProxyResponse
				json.Unmarshal(m.Data, &resp)
				if pr, ok := pendingReqs[resp.ID]; ok {
					delete(pendingReqs, resp.ID)
					raw, _ := json.Marshal(resp)
					pr.RespCh <- raw
				}

			case "ping":
				pong, _ := json.Marshal(map[string]string{"type": "pong"})
				conn.WriteMessage(ws.OpText, pong)
			}
		}
	}()

	// Main loop: receive proxy requests from the registry channel and forward to CLI
	for {
		select {
		case <-tun.Done:
			return
		case <-readDone:
			return
		case pr := <-tun.ReqCh:
			pendingReqs[pr.ID] = pr
			raw, _ := json.Marshal(pr)
			if err := conn.WriteMessage(ws.OpText, raw); err != nil {
				// Connection died; fail pending requests
				pr.ErrCh <- fmt.Errorf("websocket write failed")
				return
			}
		}
	}
}

// assignName returns (name, conflict)
func (h *Handler) assignName(requested string) (string, bool) {
	if requested == "" {
		// Generate random name
		for i := 0; i < 10; i++ {
			name := randomWords(2)
			if h.reg.IsNameAvailable(name) {
				return name, false
			}
		}
		return randomWords(2) + "-" + fmt.Sprintf("%d", rand.Intn(9999)), false
	}

	// Validate requested name
	clean := strings.ToLower(strings.TrimSpace(requested))
	if !nameRe.MatchString(clean) {
		// Invalid chars — sanitize and use random
		return randomWords(2), false
	}

	if h.reg.IsNameAvailable(clean) {
		return clean, false
	}
	return clean, true // conflict
}

func (h *Handler) suggestAlternatives(base string, n int) []string {
	var alts []string
	adjectives := []string{"happy", "swift", "brave", "cool", "bright", "fast", "wild"}
	for i := 0; i < n*5 && len(alts) < n; i++ {
		var candidate string
		if i < 3 {
			candidate = fmt.Sprintf("%s-%d", base, rand.Intn(9000)+1000)
		} else {
			candidate = fmt.Sprintf("%s-%s", adjectives[rand.Intn(len(adjectives))], base)
		}
		if h.reg.IsNameAvailable(candidate) {
			alts = append(alts, candidate)
		}
	}
	return alts
}

func sendError(conn *ws.Conn, msg, code string) {
	data, _ := json.Marshal(serverError{Type: "error", Message: msg, Code: code})
	conn.WriteMessage(ws.OpText, data)
}

var adjectives = []string{
	"autumn", "hidden", "bitter", "misty", "silent", "empty", "dry", "dark",
	"summer", "icy", "delicate", "quiet", "white", "cool", "spring", "winter",
	"patient", "twilight", "crimson", "wispy", "weathered", "ancient", "wild",
	"fragile", "snowy", "proud", "floral", "restless", "divine", "polished",
}

var nouns = []string{
	"waterfall", "river", "breeze", "moon", "rain", "wind", "sea", "morning",
	"snow", "lake", "sunset", "pine", "shadow", "leaf", "dawn", "glitter",
	"forest", "hill", "cloud", "meadow", "sun", "glade", "bird", "brook",
	"butterfly", "bush", "dew", "dust", "field", "fire", "flower", "firefly",
}

func randomWords(n int) string {
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		if i == 0 {
			parts[i] = adjectives[rand.Intn(len(adjectives))]
		} else {
			parts[i] = nouns[rand.Intn(len(nouns))]
		}
	}
	return strings.Join(parts, "-")
}
