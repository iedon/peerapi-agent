package config

import (
	"encoding/json"
	"fmt"
	"os"
	"text/template"
)

// Config holds all application configuration
type Config struct {
	Server    Server    `json:"server"`
	PeerAPI   PeerAPI   `json:"peerApiCenter"`
	IP        IP        `json:"ipConfig"`
	Bird      Bird      `json:"bird"`
	Sysctl    Sysctl    `json:"sysctl"`
	Metric    Metric    `json:"metric"`
	WireGuard WireGuard `json:"wireGuard"`
	GRE       GRE       `json:"gre"`
	Logger    Logger    `json:"logger"`
	PeerProbe PeerProbe `json:"peerProbe"`
}

// Server holds HTTP server configuration
type Server struct {
	Debug           bool     `json:"debug"`
	ListenerType    string   `json:"listenerType"`
	Listen          string   `json:"listen"`
	BodyLimit       int      `json:"bodyLimit"`
	ReadTimeout     int      `json:"readTimeout"`
	WriteTimeout    int      `json:"writeTimeout"`
	IdleTimeout     int      `json:"idleTimeout"`
	ReadBufferSize  int      `json:"readBufferSize"`
	WriteBufferSize int      `json:"writeBufferSize"`
	TrustedProxies  []string `json:"trustedProxies"`
}

// PeerAPI holds PeerAPI center configuration
type PeerAPI struct {
	APIURL                      string   `json:"apiUrl"`
	ProbeServerIPv4             string   `json:"probeServerIPv4"`
	ProbeServerIPv6             string   `json:"probeServerIPv6"`
	ProbeServerIPv6Prefix       string   `json:"probeServerIPv6Prefix"`
	ProbeServerIPv6Interface    string   `json:"probeServerIPv6Interface"`
	ProbeServerPort             int      `json:"probeServerPort"`
	Secret                      string   `json:"secret"`
	RequestTimeout              int      `json:"requestTimeout"`
	RouterUUID                  string   `json:"routerUuid"`
	AgentSecret                 string   `json:"agentSecret"`
	HeartbeatInterval           int      `json:"heartbeatInterval"`
	SyncInterval                int      `json:"syncInterval"`
	MetricInterval              int      `json:"metricInterval"`
	WanInterfaces               []string `json:"wanInterfaces"`
	SessionPassthroughJwtSecert string   `json:"sessionPassthroughJwtSecert"`
	InterfaceIpAllowPublic      bool     `json:"interfaceIpAllowPublic"`
	InterfaceIpBlacklist        []string `json:"interfaceIpBlacklist"`
}

// IP holds local IP configuration
type IP struct {
	IPv4          string `json:"ipv4"`
	IPv6          string `json:"ipv6"`
	IPv6LinkLocal string `json:"ipv6LinkLocal"`
}

// Bird holds BIRD routing daemon configuration
type Bird struct {
	ControlSocket           string             `json:"controlSocket"`
	PoolSize                int                `json:"poolSize"`
	PoolSizeMax             int                `json:"poolSizeMax"`
	ConnectionMaxRetries    int                `json:"connectionMaxRetries"`
	ConnectionRetryDelayMs  int                `json:"connectionRetryDelayMs"`
	BGPPeerConfDir          string             `json:"bgpPeerConfDir"`
	BGPPeerConfTemplateFile string             `json:"bgpPeerConfTemplateFile"`
	BGPPeerConfTemplate     *template.Template `json:"-"`
	IPCommandPath           string             `json:"ipCommandPath"`
}

// Sysctl holds system control configuration
type Sysctl struct {
	CommandPath        string `json:"commandPath"`
	IfaceIPForwarding  bool   `json:"ifaceIpForwarding"`
	IfaceIP6Forwarding bool   `json:"ifaceIp6Forwarding"`
	IfaceIP6AcceptRA   bool   `json:"ifaceIp6AcceptRa"`
	IfaceIP6AutoConfig bool   `json:"ifaceIp6AutoConfig"`
	IfaceRPFilter      int    `json:"ifaceRpFilter"`
	IfaceAcceptLocal   bool   `json:"ifaceAcceptLocal"`
}

// Metric holds metrics collection configuration
type Metric struct {
	AutoTeardown                  bool     `json:"autoTeardown"`
	MaxMindGeoLiteCountryMmdbPath string   `json:"maxMindGeoLiteCountryMmdbPath"`
	GeoIPCountryMode              string   `json:"geoIpCountryMode"`
	BlacklistGeoCountries         []string `json:"blacklistGeoCountries"`
	WhitelistGeoCountries         []string `json:"whitelistGeoCountries"`
	PingCommandPath               string   `json:"pingCommandPath"`
	PingTimeout                   int      `json:"pingTimeout"`
	PingCount                     int      `json:"pingCount"`
	PingCountOnFail               int      `json:"pingCountOnFail"`
	PingWorkerCount               int      `json:"pingWorkerCount"`
	SessionWorkerCount            int      `json:"sessionWorkerCount"`
	MaxRTTMetricsHistroy          int      `json:"maxRTTMetricsHistroy"`
	GeoCheckInterval              int      `json:"geoCheckInterval"`
	FilterParamsUpdateInterval    int      `json:"filterParamsUpdateInterval"`
}

// WireGuard holds WireGuard configuration
type WireGuard struct {
	WGCommandPath                  string `json:"wgCommandPath"`
	LocalEndpointHost              string `json:"localEndpointHost"`
	PrivateKeyPath                 string `json:"privateKeyPath"`
	PublicKeyPath                  string `json:"publicKeyPath"`
	PrivateKey                     string `json:"-"`
	PublicKey                      string `json:"-"`
	PersistentKeepaliveInterval    int    `json:"persistentKeepaliveInterval"`
	AllowedIPs                     string `json:"allowedIps"`
	DNSUpdateInterval              int    `json:"dnsUpdateInterval"`
	DN42BandwidthCommunity         int    `json:"dn42BandwidthCommunity"`
	DN42InterfaceSecurityCommunity int    `json:"dn42InterfaceSecurityCommunity"`
}

// GRE holds GRE tunnel configuration
type GRE struct {
	LocalEndpointHost4             string `json:"localEndpointHost4"`
	LocalEndpointHost6             string `json:"localEndpointHost6"`
	LocalEndpointDesc4             string `json:"localEndpointDesc4"`
	LocalEndpointDesc6             string `json:"localEndpointDesc6"`
	DN42BandwidthCommunity         int    `json:"dn42BandwidthCommunity"`
	DN42InterfaceSecurityCommunity int    `json:"dn42InterfaceSecurityCommunity"`
}

// Logger holds logger configuration
type Logger struct {
	File           string `json:"file"`
	MaxSize        int    `json:"maxSize"`
	MaxBackups     int    `json:"maxBackups"`
	MaxAge         int    `json:"maxAge"`
	Compress       bool   `json:"compress"`
	ConsoleLogging bool   `json:"consoleLogging"`
	Level          string `json:"level"`
}

// PeerProbe holds peer probe configuration
type PeerProbe struct {
	Enabled                     bool   `json:"enabled"`
	IntervalSeconds             int    `json:"intervalSeconds"`
	ProbePacketCount            int    `json:"probePacketCount"`
	ProbePacketIntervalMs       int    `json:"probePacketIntervalMs"`
	ProbePacketEncryptionKey    string `json:"probePacketEncryptionKey"`
	SessionWorkerCount          int    `json:"sessionWorkerCount"`
	ProbePacketBanner           string `json:"probePacketBanner"`
	ProbeSummaryCooldownSeconds int    `json:"probeSummaryCooldownSeconds"`
}

// Load reads and parses configuration from a file
func Load(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	cfg := &Config{}
	if err := json.NewDecoder(file).Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	// Load WireGuard keys
	if cfg.WireGuard.PrivateKeyPath != "" {
		key, err := os.ReadFile(cfg.WireGuard.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read WireGuard private key: %w", err)
		}
		cfg.WireGuard.PrivateKey = string(key)
	}

	if cfg.WireGuard.PublicKeyPath != "" {
		key, err := os.ReadFile(cfg.WireGuard.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read WireGuard public key: %w", err)
		}
		cfg.WireGuard.PublicKey = string(key)
	}

	// Load BIRD template
	if cfg.Bird.BGPPeerConfTemplateFile != "" {
		tmpl, err := template.ParseFiles(cfg.Bird.BGPPeerConfTemplateFile)
		if err != nil {
			return nil, fmt.Errorf("failed to parse BIRD template: %w", err)
		}
		cfg.Bird.BGPPeerConfTemplate = tmpl
	}

	// Validate configuration
	if err := Validate(cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}
