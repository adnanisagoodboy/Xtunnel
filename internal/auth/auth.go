package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	Tier      string    `json:"tier"`
}

type Service struct {
	secret   string
	mu       sync.RWMutex
	users    map[string]*storedUser
	dataFile string
}

type storedUser struct {
	User
	PasswordHash string `json:"password_hash"`
}

type Claims struct {
	UserID string
	Email  string
	Exp    int64
}

func New(secret string) *Service {
	s := &Service{
		secret:   secret,
		users:    make(map[string]*storedUser),
		dataFile: dataFilePath(),
	}
	s.load()
	return s
}

// --- Persistence ---

func dataFilePath() string {
	dir := os.Getenv("DATA_DIR")
	if dir == "" {
		dir = "/tmp"
	}
	return filepath.Join(dir, "xtunnel-users.json")
}

func (s *Service) load() {
	data, err := os.ReadFile(s.dataFile)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Printf("[auth] could not load users file: %v", err)
		return
	}
	var users map[string]*storedUser
	if err := json.Unmarshal(data, &users); err != nil {
		log.Printf("[auth] could not parse users file: %v", err)
		return
	}
	s.users = users
	log.Printf("[auth] loaded %d users from disk", len(users))
}

func (s *Service) persist() {
	data, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		log.Printf("[auth] marshal error: %v", err)
		return
	}
	if err := os.WriteFile(s.dataFile, data, 0600); err != nil {
		log.Printf("[auth] could not save users: %v", err)
	}
}

// --- HTTP Handlers ---

func (s *Service) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		jsonError(w, "email and password required", 400)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[req.Email]; exists {
		jsonError(w, "email already registered", 409)
		return
	}

	id := randomID(8)
	hash := hashPassword(req.Password, s.secret)
	u := &storedUser{
		User: User{
			ID:        id,
			Email:     req.Email,
			CreatedAt: time.Now(),
			Tier:      "free",
		},
		PasswordHash: hash,
	}
	s.users[req.Email] = u
	s.persist()

	token, _ := s.makeToken(u.ID, u.Email)
	log.Printf("[auth] new user: %s (id=%s)", req.Email, id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token": token,
		"user":  u.User,
	})
}

func (s *Service) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", 400)
		return
	}

	s.mu.RLock()
	u, ok := s.users[req.Email]
	s.mu.RUnlock()

	if !ok || u.PasswordHash != hashPassword(req.Password, s.secret) {
		jsonError(w, "invalid email or password", 401)
		return
	}

	token, _ := s.makeToken(u.ID, u.Email)
	log.Printf("[auth] login: %s", req.Email)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token": token,
		"user":  u.User,
	})
}

func (s *Service) StatusHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := s.ValidateRequest(r)
	if err != nil {
		jsonError(w, "unauthorized", 401)
		return
	}

	s.mu.RLock()
	// Look up by email (faster) since claims has email
	u, ok := s.users[claims.Email]
	s.mu.RUnlock()

	if !ok {
		jsonError(w, "user not found", 404)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user": u.User,
	})
}

// --- Token logic ---

func (s *Service) makeToken(userID, email string) (string, error) {
	exp := time.Now().Add(30 * 24 * time.Hour).Unix()
	payload := fmt.Sprintf("%s|%s|%d", userID, email, exp)
	sig := s.sign(payload)
	raw := payload + "." + sig
	return base64.RawURLEncoding.EncodeToString([]byte(raw)), nil
}

func (s *Service) ValidateToken(token string) (*Claims, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token encoding")
	}
	parts := strings.SplitN(string(raw), ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed token")
	}
	payload, sig := parts[0], parts[1]
	if s.sign(payload) != sig {
		return nil, fmt.Errorf("invalid token signature")
	}
	fields := strings.Split(payload, "|")
	if len(fields) != 3 {
		return nil, fmt.Errorf("bad token payload")
	}
	var exp int64
	fmt.Sscan(fields[2], &exp)
	if time.Now().Unix() > exp {
		return nil, fmt.Errorf("token expired")
	}
	return &Claims{UserID: fields[0], Email: fields[1], Exp: exp}, nil
}

func (s *Service) ValidateRequest(r *http.Request) (*Claims, error) {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return s.ValidateToken(strings.TrimPrefix(auth, "Bearer "))
	}
	token := r.URL.Query().Get("token")
	if token != "" {
		return s.ValidateToken(token)
	}
	return nil, fmt.Errorf("no token provided")
}

func (s *Service) sign(payload string) string {
	mac := hmac.New(sha256.New, []byte(s.secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func hashPassword(password, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(password))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func randomID(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
