package config

import (
	"encoding/json"
	"os"
	"time"
)

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil { return err }
	dur, err := time.ParseDuration(s)
	if err != nil { return err }
	d.Duration = dur
	return nil
}

type ServerConfig struct {
	Domain    string `json:"domain"`
	HTTPPort  int    `json:"http_port"`
	HTTPSPort int    `json:"https_port"`
	CtrlPort  int    `json:"ctrl_port"`
	SSHPort   int    `json:"ssh_port"`
	APIPort   int    `json:"api_port"`
	TLSCert   string `json:"tls_cert"`
	TLSKey    string `json:"tls_key"`
	JWTSecret string `json:"jwt_secret"`
	SSHHostKey string `json:"ssh_host_key"`
	TokenExpiry Duration `json:"token_expiry"`
	MaxTunnelsPerUser int `json:"max_tunnels_per_user"`
	RateLimitRPS      int `json:"rate_limit_rps"`
	AllowAnonymous    bool `json:"allow_anonymous"`
}

type AgentConfig struct {
	ServerAddr   string `json:"server_addr"`
	AuthToken    string `json:"auth_token"`
	LocalAddr    string `json:"local_addr"`
	Proto        string `json:"proto"`       // http, tcp, udp, ssh
	Subdomain    string `json:"subdomain"`
	CustomDomain string `json:"custom_domain"`
	HMACSecret   string `json:"hmac_secret"`
	BasicUser    string `json:"basic_user"`
	BasicPass    string `json:"basic_pass"`
	IPAllowList  []string `json:"ip_allow_list"`
	IPBlockList  []string `json:"ip_block_list"`
	TLSSkipVerify bool `json:"tls_skip_verify"`
	TLSCACert    string `json:"tls_ca_cert"`
	ClientCert   string `json:"client_cert"`
	ClientKey    string `json:"client_key"`
}

func LoadServer(path string) (*ServerConfig, error) {
	cfg := DefaultServer()
	if path == "" { return cfg, nil }
	data, err := os.ReadFile(path)
	if err != nil { return cfg, nil }
	if err := json.Unmarshal(data, cfg); err != nil { return nil, err }
	return cfg, nil
}

func LoadAgent(path string) (*AgentConfig, error) {
	cfg := &AgentConfig{}
	if path == "" { return cfg, nil }
	data, err := os.ReadFile(path)
	if err != nil { return cfg, nil }
	return cfg, json.Unmarshal(data, cfg)
}

func DefaultServer() *ServerConfig {
	return &ServerConfig{
		Domain:            "xtunnel.io",
		HTTPPort:          8080,
		HTTPSPort:         8443,
		CtrlPort:          7000,
		SSHPort:           2222,
		APIPort:           7001,
		JWTSecret:         "change-me-in-production",
		TokenExpiry:       Duration{24 * time.Hour},
		MaxTunnelsPerUser: 10,
		RateLimitRPS:      100,
		AllowAnonymous:    true,
	}
}
