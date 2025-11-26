package main

import (
	"encoding/json"
	"os"
	"text/template"
)

type serverConfig struct {
	Debug           bool     `json:"debug"`        // Will print detail access log for debug
	ListenerType    string   `json:"listenerType"` // "tcp" or "unix" - type of listener to use
	Listen          string   `json:"listen"`       // For TCP: host:port, For Unix: socket file path
	BodyLimit       int      `json:"bodyLimit"`
	ReadTimeout     int      `json:"readTimeout"`
	WriteTimeout    int      `json:"writeTimeout"`
	IdleTimeout     int      `json:"idleTimeout"`
	ReadBufferSize  int      `json:"readBufferSize"`
	WriteBufferSize int      `json:"writeBufferSize"`
	TrustedProxies  []string `json:"trustedProxies"` // String array of IP or CIDR. X-Forwarded headers from these networks will be trusted.
}

type peerApiCenterConfig struct { // Legacy property to maintain backward compatibility
	APIURL                      string   `json:"apiUrl"`                // URL of the PeerAPI center server
	ProbeServerIPv4             string   `json:"probeServerIPv4"`       // IPv4 address of probe server endpoint
	ProbeServerIPv6             string   `json:"probeServerIPv6"`       // IPv6 address of probe server endpoint
	ProbeServerIPv6Prefix       string   `json:"probeServerIPv6Prefix"` // IPv6 prefix for probe server endpoint, used with IPv6ProbingNextHopRouteMetric, with greater metric value having lower priority, to ensure proper IPv6 probe packets routing
	ProbeServerPort             int      `json:"probeServerPort"`       // UDP port for probe server
	Secret                      string   `json:"secret"`                // Secret key for PeerAPI center authentication
	RequestTimeout              int      `json:"requestTimeout"`        // Timeout for requests to the PeerAPI center
	RouterUUID                  string   `json:"routerUuid"`            // UUID of this router from PeerAPI center server
	AgentSecret                 string   `json:"agentSecret"`           // Secret key for agent authentication
	HeartbeatInterval           int      `json:"heartbeatInterval"`     // Heartbeat interval in seconds
	SyncInterval                int      `json:"syncInterval"`          // Session sync interval in seconds
	MetricInterval              int      `json:"metricInterval"`
	WanInterfaces               []string `json:"wanInterfaces"` // List of WAN interfaces to monitor their traffic
	SessionPassthroughJwtSecert string   `json:"sessionPassthroughJwtSecert"`
	InterfaceIpAllowPublic      bool     `json:"interfaceIpAllowPublic"` // Whether to allow public IP addresses on interfaces
	InterfaceIpBlacklist        []string `json:"interfaceIpBlacklist"`   // List of IP/CIDR ranges to blacklist from interface assignment
}

type birdConfig struct {
	ControlSocket           string             `json:"controlSocket"`
	PoolSize                int                `json:"poolSize"`                // Number of connections to the BIRD control socket
	PoolSizeMax             int                `json:"poolSizeMax"`             // Maximum size of the connection pool
	ConnectionMaxRetries    int                `json:"connectionMaxRetries"`    // Maximum number of retries for connection attempts
	ConnectionRetryDelayMs  int                `json:"connectionRetryDelayMs"`  // Delay in milliseconds between connection retries
	BGPPeerConfDir          string             `json:"bgpPeerConfDir"`          // Directory for BGP peer configuration files
	BGPPeerConfTemplateFile string             `json:"bgpPeerConfTemplateFile"` // Template for BGP peer configuration files
	BGPPeerConfTemplate     *template.Template `json:"-"`
	IPCommandPath           string             `json:"ipCommandPath"`
}

type wireGuardConfig struct {
	WGCommandPath                  string `json:"wgCommandPath"`     // Path to the WireGuard command
	LocalEndpointHost              string `json:"localEndpointHost"` // Local endpoint for WireGuard interface
	PrivateKeyPath                 string `json:"privateKeyPath"`    // Private key for WireGuard interface
	PublicKeyPath                  string `json:"publicKeyPath"`     // Public key for WireGuard interface
	PrivateKey                     string `json:"-"`
	PublicKey                      string `json:"-"`
	PersistentKeepaliveInterval    int    `json:"persistentKeepaliveInterval"` // Persistent keepalive interval in seconds
	AllowedIPs                     string `json:"allowedIps"`                  // Allowed IPs for WireGuard peers
	DNSUpdateInterval              int    `json:"dnsUpdateInterval"`           // Interval for WireGuard DNS endpoint updates in seconds
	DN42BandwidthCommunity         int    `json:"dn42BandwidthCommunity"`
	DN42InterfaceSecurityCommunity int    `json:"dn42InterfaceSecurityCommunity"`
}

type greConfig struct {
	LocalEndpointHost4             string `json:"localEndpointHost4"` // Local IPv4 endpoint for GRE tunnel
	LocalEndpointHost6             string `json:"localEndpointHost6"` // Local IPv6 endpoint for GRE tunnel
	LocalEndpointDesc4             string `json:"localEndpointDesc4"` // Description for local IPv4 endpoint
	LocalEndpointDesc6             string `json:"localEndpointDesc6"` // Description for local IPv6 endpoint
	DN42BandwidthCommunity         int    `json:"dn42BandwidthCommunity"`
	DN42InterfaceSecurityCommunity int    `json:"dn42InterfaceSecurityCommunity"`
}

type loggerConfig struct {
	File           string `json:"file"`           // Log file path
	MaxSize        int    `json:"maxSize"`        // Maximum log file size in MB before rotation (default: 10MB)
	MaxBackups     int    `json:"maxBackups"`     // Maximum number of log backups to keep (default: 10)
	MaxAge         int    `json:"maxAge"`         // Maximum days to keep old log files (default: 30 days)
	Compress       bool   `json:"compress"`       // Whether to compress old log files with gzip (default: true)
	ConsoleLogging bool   `json:"consoleLogging"` // Whether to output logs to console (default: true)
}

type metricConfig struct {
	AutoTeardown                  bool     `json:"autoTeardown"`                  // Automatically teardown sessions based on metrics
	MaxMindGeoLiteCountryMmdbPath string   `json:"maxMindGeoLiteCountryMmdbPath"` // Path to MaxMind GeoLite2 Country database
	GeoIPCountryMode              string   `json:"geoIpCountryMode"`              // Mode for GeoIP country filtering (blacklist/whitelist)
	BlacklistGeoCountries         []string `json:"blacklistGeoCountries"`         // List of countries to blacklist
	WhitelistGeoCountries         []string `json:"whitelistGeoCountries"`         // List of countries to whitelist
	PingCommandPath               string   `json:"pingCommandPath"`               // Path to the ping command
	PingTimeout                   int      `json:"pingTimeout"`                   // Timeout for ping requests in seconds
	PingCount                     int      `json:"pingCount"`                     // Number of ping attempts
	PingCountOnFail               int      `json:"pingCountOnFail"`               // If ping fails, retry with only pingCountOnFail times to avoid blocking the system
	PingWorkerCount               int      `json:"pingWorkerCount"`               // Number of workers for parallel pinging, don't create too many or we might overwhelm the system
	SessionWorkerCount            int      `json:"sessionWorkerCount"`            // Number of workers for parallel session metric collection (default: 8)
	MaxRTTMetricsHistroy          int      `json:"maxRTTMetricsHistroy"`          // Maximum number of RTT historical metrics to keep for each metric type of each session, used for calculating average RTT / Loss rate and bgp latency community
	GeoCheckInterval              int      `json:"geoCheckInterval"`              // Interval for geo check task in seconds
	FilterParamsUpdateInterval    int      `json:"filterParamsUpdateInterval"`    // Interval for DN42 BGP community update task in seconds
}

type sysctlConfig struct {
	CommandPath        string `json:"commandPath"`        // Path to the sysctl command
	IfaceIPForwarding  bool   `json:"ifaceIpForwarding"`  // Enable IPv4 forwarding on interfaces
	IfaceIP6Forwarding bool   `json:"ifaceIp6Forwarding"` // Enable IPv6 forwarding on interfaces
	IfaceIP6AcceptRA   bool   `json:"ifaceIp6AcceptRa"`   // Accept Router Advertisements on interfaces
	IfaceIP6AutoConfig bool   `json:"ifaceIp6AutoConfig"` // Enable IPv6 autoconfiguration on interfaces
	IfaceRPFilter      int    `json:"ifaceRpFilter"`      // Reverse Path Filter setting (0=disabled, 1=strict, 2=loose)
	IfaceAcceptLocal   bool   `json:"ifaceAcceptLocal"`   // Accept local traffic on interfaces(must be on for anycasting, eg. DN42 Anycast DNS)
}

type peerProbeConfig struct {
	Enabled                       bool   `json:"enabled"`
	IntervalSeconds               int    `json:"intervalSeconds"`
	ProbePacketCount              int    `json:"probePacketCount"`
	ProbePacketIntervalMs         int    `json:"probePacketIntervalMs"`
	ProbePacketEncryptionKey      string `json:"probePacketEncryptionKey"`
	SessionWorkerCount            int    `json:"sessionWorkerCount"`
	ProbePacketBanner             string `json:"probePacketBanner"`
	ProbeSummaryCooldownSeconds   int    `json:"probeSummaryCooldownSeconds"`
	IPv6ProbingNextHopRouteMetric int    `json:"ipv6ProbingNextHopRouteMetric"`
}

type ipConfig struct {
	IPv4          string `json:"ipv4"`
	IPv6          string `json:"ipv6"`
	IPv6LinkLocal string `json:"ipv6LinkLocal"`
}

type config struct {
	Server    serverConfig        `json:"server"`
	PeerAPI   peerApiCenterConfig `json:"peerApiCenter"`
	IP        ipConfig            `json:"ipConfig"`
	Bird      birdConfig          `json:"bird"`
	Sysctl    sysctlConfig        `json:"sysctl"`
	Metric    metricConfig        `json:"metric"`
	WireGuard wireGuardConfig     `json:"wireGuard"`
	GRE       greConfig           `json:"gre"`
	Logger    loggerConfig        `json:"logger"`
	PeerProbe peerProbeConfig     `json:"peerProbe"`
}

func loadConfig(filename string) (*config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &config{}

	err = json.NewDecoder(file).Decode(cfg)
	if err != nil {
		return nil, err
	}

	if cfg.WireGuard.PrivateKeyPath != "" {
		key, err := os.ReadFile(cfg.WireGuard.PrivateKeyPath)
		if err != nil {
			return cfg, err
		}
		cfg.WireGuard.PrivateKey = string(key)
	}

	if cfg.WireGuard.PublicKeyPath != "" {
		key, err := os.ReadFile(cfg.WireGuard.PublicKeyPath)
		if err != nil {
			return cfg, err
		}
		cfg.WireGuard.PublicKey = string(key)
	}

	if cfg.Bird.BGPPeerConfTemplateFile != "" {
		tmpl, err := template.ParseFiles(cfg.Bird.BGPPeerConfTemplateFile)
		if err != nil {
			return cfg, err
		}
		cfg.Bird.BGPPeerConfTemplate = tmpl
	}

	return cfg, nil
}
