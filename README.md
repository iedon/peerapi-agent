# iEdon PeerAPI Agent

[![Go Version](https://img.shields.io/badge/Go-1.25%2B-blue.svg)](https://golang.org)

A comprehensive Go application for automated BGP peering session management on `iEdon-Net` infrastructure nodes. This agent communicates with a central PeerAPI server to orchestrate BGP session lifecycle, interface configuration, network monitoring, and real-time performance metrics collection.

## Features

### Core BGP Session Management
- **Automated Session Lifecycle**: Complete setup, configuration, monitoring, and teardown of BGP peering sessions
- **Multi-Protocol Support**: Traditional BGP and MP-BGP with IPv4/IPv6 route filtering
- **Dynamic Interface Management**: Automated WireGuard and GRE tunnel configuration with IP addressing
- **Status Synchronization**: Real-time session state sync with central PeerAPI server
- **JWT Session Authentication**: Secure session passthrough with JWT token validation

### Advanced BIRD Integration
- **Connection Pool Management**: Efficient BIRD control socket connection pooling (configurable pool size)
- **Template-Based Configuration**: Dynamic BIRD configuration generation using Go templates
- **Real-Time Statistics**: Route import/export statistics collection and reporting
- **Configuration Validation**: Automatic BIRD configuration reload and validation
- **Protocol State Monitoring**: BGP session state tracking and problem detection

### Intelligent Performance Monitoring
- **Multi-Protocol RTT Measurement**: Adaptive ping testing with protocol preference (IPv4/IPv6/IPv6-LL)
- **Interface Traffic Monitoring**: Real-time bandwidth usage tracking for WAN interfaces
- **System Resource Metrics**: CPU usage, memory consumption, and network connection statistics
- **Geographic Validation**: MaxMind GeoIP-based session validation with country filtering

### DN42 Network Optimization
- **Dynamic BGP Communities**: Automatic latency-based community assignment (64511:X) 
- **Real-Time Community Updates**: RTT-based community adjustments for optimal routing
- **Bandwidth Classification**: Interface bandwidth and security community propagation
- **Route Filtering**: Advanced import/export filtering with community-based policies

### Enterprise-Grade Infrastructure
- **Graceful Shutdown**: Context-based shutdown with configurable timeout and resource cleanup
- **Concurrent Task Management**: Six independent background tasks with proper synchronization
- **Thread-Safe Operations**: Dedicated mutexes for session, metric, and traffic data structures
- **Resource Leak Prevention**: Comprehensive cleanup of connections, files, and memory structures
- **Structured Logging**: Configurable file and console logging with rotation support

## Installation

### Prerequisites

- **Go 1.24 or higher** - Required for building from source
- **BIRD routing daemon 2.0+** - For BGP session management and routing
- **Linux operating system** - The agent uses Linux-specific features (`/proc` filesystem, `ip` command)
- **Root/administrative privileges** - Required for network interface management
- **MaxMind GeoLite2 Country database** - Optional, enables geographic session validation

### Binary Installation

1. Download the latest release:

```bash
curl -L -o peerapi-agent https://github.com/iedon/peerapi-agent/releases/latest/download/peerapi-agent-linux-amd64
chmod +x peerapi-agent
```

2. Create configuration directory and download GeoIP database (optional):

```bash
mkdir -p /data/peerapi-agent/logs
wget -O /data/peerapi-agent/GeoLite2-Country.mmdb <Your mmdb file source>
```

3. Create a configuration file (see Configuration section below)

4. Run the agent:

```bash
./peerapi-agent -c config.json
```

### Building from Source

```bash
git clone https://github.com/iedon/peerapi-agent.git
cd peerapi-agent/src
go get
go build -o peerapi-agent" .
```

### Running as a System Service

A systemd service file is included in the repository:

1. Install the binary and configuration:

```bash
mkdir -p /data/peerapi-agent
cp peerapi-agent /data/peerapi-agent/
cp config.json /data/peerapi-agent/
```

2. Install and enable the systemd service:

```bash
cp peerapi-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable peerapi-agent
systemctl start peerapi-agent
```

3. Monitor service status:

```bash
systemctl status peerapi-agent
journalctl -u peerapi-agent -f
```

## Usage

### Command Line Options

```bash
Usage: ./peerapi-agent [-c config_file] [-h]
  -c string
        Path to the JSON configuration file (default "config.json")
  -h    Print help message and exit
```

### API Endpoints

The agent exposes a REST API for management and monitoring:

- **GET /status** - Returns current session and metric data
- **GET /sync** - Triggers manual session synchronization
- **POST /info** - Node passthrough information endpoint (authenticated)

All endpoints require JWT authentication using the configured `agentSecret`.

### Background Tasks

The agent runs **6 concurrent background tasks**:

1. **Heartbeat Task** (`heartbeatTask`) - Sends periodic health reports to PeerAPI server
2. **Session Sync Task** (`mainSessionTask`) - Synchronizes BGP session configurations
3. **Metric Collection Task** (`metricTask`) - Collects and reports performance metrics
4. **Bandwidth Monitor Task** (`bandwidthMonitorTask`) - Monitors interface traffic rates
5. **DN42 BGP Community Task** (`dn42BGPCommunityTask`) - Updates BGP communities based on RTT
6. **GeoIP Check Task** (`geoCheckTask`) - Validates sessions against geographic policies

## Graceful Shutdown

The peerapi-agent implements comprehensive graceful shutdown handling to ensure data consistency and resource cleanup:

### Shutdown Process

1. **Signal Reception**: Captures SIGINT, SIGTERM, and SIGKILL signals
2. **Context Cancellation**: Immediately cancels the root context to notify all background tasks
3. **HTTP Server Shutdown**: Gracefully stops the HTTP server with context timeout
4. **Task Completion**: Waits for all 6 background tasks to complete within timeout (default: 30 seconds)
5. **Resource Cleanup**: Performs comprehensive cleanup of all resources:
   - Closes GeoIP database connections
   - Shuts down BIRD connection pool
   - Clears global data structures (sessions, metrics, traffic data)
   - Closes log file handles

### Shutdown Configuration

- **Default timeout**: 30 seconds for all operations
- **Task-specific shutdown**: Each background task performs its own cleanup
- **Resource leak prevention**: All mutexes, connections, and memory structures are properly cleaned up
- **Logging**: Detailed shutdown progress logging with timing information

This ensures that the agent can be safely restarted without leaving behind stale connections, configuration files, or memory leaks.

## Configuration

The agent is configured through a JSON file with the following structure. All configuration sections are required unless explicitly marked as optional.

### Complete Configuration Example

```json
{
  "server": {
    "debug": false,
    "listenerType": "tcp",
    "listen": ":8080",
    "readTimeout": 30,
    "writeTimeout": 30,
    "idleTimeout": 120,
    "writeBufferSize": 8192,
    "readBufferSize": 8192,
    "bodyLimit": 1048576,
    "trustedProxies": ["127.0.0.1", "::1"]
  },

  "logger": {
    "file": "./logs/peerapi-agent.log",
    "maxSize": 10,
    "maxBackups": 10,
    "maxAge": 30,
    "compress": true,
    "consoleLogging": true
  },

  "peerApiCenter": {
    "url": "https://peerapi.example.org",
    "secret": "shared-secret-key",
    "requestTimeout": 15,
    "routerUuid": "40ca6d20-048d-4cb2-89be-e94f99af6781",
    "agentSecret": "agent-authentication-secret",
    "heartbeatInterval": 30,
    "syncInterval": 300,
    "metricInterval": 60,
    "wanInterfaces": ["eth0", "ens3"],
    "sessionPassthroughJwtSecret": "jwt-secret-for-passthrough"
  },

  "bird": {
    "controlSocket": "/var/run/bird/bird.ctl",
    "poolSize": 5,
    "poolSizeMax": 128,
    "bgpPeerConfDir": "/etc/bird/peers",
    "bgpPeerConfTemplateFile": "./templates/bird_peer.conf",
    "ipCommandPath": "/usr/sbin/ip"
  },

  "metric": {
    "autoTeardown": true,
    "maxMindGeoLiteCountryMmdbPath": "./GeoLite2-Country.mmdb",
    "geoIPCountryMode": "blacklist",
    "blacklistGeoCountries": ["CN"],
    "whitelistGeoCountries": ["US", "DE", "FR", "GB", "NL", "JP", "CA", "AU"],
    "pingTimeout": 5,
    "pingCount": 4,
    "geoCheckInterval": 900,
    "filterParamsUpdateInterval": 3600
  },

  "wireguard": {
    "wgCommandPath": "/usr/bin/wg",
    "ipv4": "172.23.91.132",
    "ipv6": "fd42:4242:2189:118::1",
    "ipv6LinkLocal": "fe80::118",
    "privateKeyPath": "/etc/wireguard/privatekey",
    "publicKeyPath": "/etc/wireguard/publickey",
    "persistentKeepaliveInterval": 25,
    "localEndpointHost": "jp-118.dn42.iedon.net",
    "dn42BandwidthCommunity": 24,
    "dn42InterfaceSecurityCommunity": 34
  },

  "gre": {
    "ipv4": "172.23.91.132",
    "ipv6": "fd42:4242:2189:118::1",
    "ipv6LinkLocal": "fe80::118",
    "localEndpointHost4": "203.0.113.1",
    "localEndpointHost6": "2001:db8::1",
    "dn42BandwidthCommunity": 24,
    "dn42InterfaceSecurityCommunity": 31
  }
}
```

### Configuration Reference

#### Server Configuration (`server`)

HTTP server settings for the agent's API endpoints. The server supports both TCP and Unix socket listeners.

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `debug` | boolean | Enable debug mode with detailed access logging | `false` |
| `listenerType` | string | Type of listener: `tcp` or `unix` | `tcp` |
| `listen` | string | Address and port for TCP (`host:port`) or socket file path for Unix | `:8080` |
| `readTimeout` | integer | Read timeout in seconds | `30` |
| `writeTimeout` | integer | Write timeout in seconds | `30` |
| `idleTimeout` | integer | Idle connection timeout in seconds | `120` |
| `writeBufferSize` | integer | Write buffer size in bytes (TCP only) | `8192` |
| `readBufferSize` | integer | Read buffer size in bytes (TCP only) | `8192` |
| `bodyLimit` | integer | Maximum request body size in bytes | `1048576` |
| `trustedProxies` | string[] | List of trusted proxy IP addresses or CIDR blocks | `["127.0.0.1", "::1"]` |

**Listener Types:**
- **TCP**: Standard network listener for external access (e.g., `:8080`, `127.0.0.1:8080`)
- **Unix Socket**: Local domain socket for same-machine communication (e.g., `/tmp/peerapi-agent.sock`, `/var/run/peerapi-agent.sock`)

**Examples:**
```json
// TCP listener (default)
{
  "server": {
    "listenerType": "tcp",
    "listen": ":8080"
  }
}

// Unix socket listener
{
  "server": {
    "listenerType": "unix", 
    "listen": "/tmp/peerapi-agent.sock"
  }
}
```

#### Logger Configuration (`logger`)

Structured logging configuration with file rotation support.

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `file` | string | Log file path | `"./logs/peerapi-agent.log"` |
| `maxSize` | integer | Maximum log file size in MB before rotation | `10` |
| `maxBackups` | integer | Maximum number of rotated log files to retain | `10` |
| `maxAge` | integer | Maximum days to keep old log files | `30` |
| `compress` | boolean | Compress rotated log files with gzip | `true` |
| `consoleLogging` | boolean | Enable console output in addition to file logging | `true` |

#### PeerAPI Center Configuration (`peerApiCenter`)

Central server communication and authentication settings.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `url` | string | Base URL of the central PeerAPI server | Yes |
| `secret` | string | Shared secret for PeerAPI server authentication | Yes |
| `requestTimeout` | integer | HTTP request timeout in seconds | Yes |
| `routerUuid` | string | UUID identifier for this router in PeerAPI system | Yes |
| `agentSecret` | string | Secret key for JWT authentication of API requests | Yes |
| `heartbeatInterval` | integer | Heartbeat report interval in seconds | Yes |
| `syncInterval` | integer | BGP session sync interval in seconds | Yes |
| `metricInterval` | integer | Performance metric collection interval in seconds | Yes |
| `wanInterfaces` | string[] | Network interfaces to monitor for traffic statistics | Yes |
| `sessionPassthroughJwtSecret` | string | JWT secret for session passthrough token validation | Yes |

#### BIRD Configuration (`bird`)

BIRD routing daemon integration settings.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `controlSocket` | string | Path to BIRD control socket | Yes |
| `poolSize` | integer | Initial BIRD connection pool size | Yes |
| `poolSizeMax` | integer | Maximum BIRD connection pool size | Yes |
| `bgpPeerConfDir` | string | Directory for generated BGP peer configuration files | Yes |
| `bgpPeerConfTemplateFile` | string | Path to BIRD configuration template file | Yes |
| `ipCommandPath` | string | Path to `ip` command binary | Yes |

#### Metric Configuration (`metric`)

Performance monitoring and geographic validation settings.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `autoTeardown` | boolean | Automatically teardown problematic sessions | Yes |
| `maxMindGeoLiteCountryMmdbPath` | string | Path to MaxMind GeoLite2 Country database | No |
| `geoIPCountryMode` | string | Geographic filtering mode: `"blacklist"` or `"whitelist"` | No |
| `blacklistGeoCountries` | string[] | Country codes to block (ISO 3166-1 alpha-2) | No |
| `whitelistGeoCountries` | string[] | Country codes to allow (ISO 3166-1 alpha-2) | No |
| `pingTimeout` | integer | Ping request timeout in seconds | Yes |
| `pingCount` | integer | Number of ping attempts for RTT measurement | Yes |
| `geoCheckInterval` | integer | Geographic validation check interval in seconds | No |
| `filterParamsUpdateInterval` | integer | DN42 BGP community and filter params update interval in seconds | No |

#### WireGuard Configuration (`wireguard`)

WireGuard tunnel interface settings.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `wgCommandPath` | string | Path to `wg` command binary | Yes |
| `ipv4` | string | IPv4 address for WireGuard interfaces | Yes |
| `ipv6` | string | IPv6 address for WireGuard interfaces | Yes |
| `ipv6LinkLocal` | string | IPv6 link-local address for WireGuard interfaces | Yes |
| `privateKeyPath` | string | Path to WireGuard private key file | Yes |
| `publicKeyPath` | string | Path to WireGuard public key file | Yes |
| `persistentKeepaliveInterval` | integer | WireGuard keepalive interval in seconds | Yes |
| `localEndpointHost` | string | Hostname/IP for local WireGuard endpoint | Yes |
| `dn42BandwidthCommunity` | integer | BGP community value for bandwidth classification | Yes |
| `dn42InterfaceSecurityCommunity` | integer | BGP community value for security level | Yes |

#### GRE Configuration (`gre`)

GRE tunnel interface settings.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `ipv4` | string | IPv4 address for GRE tunnel interfaces | Yes |
| `ipv6` | string | IPv6 address for GRE tunnel interfaces | Yes |
| `ipv6LinkLocal` | string | IPv6 link-local address for GRE interfaces | Yes |
| `localEndpointHost4` | string | IPv4 address for local GRE endpoint | Yes |
| `localEndpointHost6` | string | IPv6 address for local GRE endpoint | Yes |
| `dn42BandwidthCommunity` | integer | BGP community value for bandwidth classification | Yes |
| `dn42InterfaceSecurityCommunity` | integer | BGP community value for security level | Yes |

## Architecture

The peerapi-agent is built with a modern concurrent architecture featuring **6 independent background tasks** that communicate through thread-safe shared data structures:

### Background Task System

| Task | Function | Interval | Purpose |
|------|----------|----------|---------|
| **Heartbeat Task** | `heartbeatTask()` | 30s (configurable) | Reports node health, system metrics, and uptime to PeerAPI server |
| **Session Sync Task** | `mainSessionTask()` | 300s (configurable) | Synchronizes BGP session configurations and status with central server |
| **Metric Collection Task** | `metricTask()` | 60s (configurable) | Collects BGP statistics, RTT measurements, and interface metrics |
| **Bandwidth Monitor Task** | `bandwidthMonitorTask()` | 1s (fixed) | Real-time monitoring of interface traffic rates and bandwidth usage |
| **DN42 BGP Community Task** | `dn42BGPCommunityTask()` | 3600s (configurable) | Updates BGP communities based on RTT and performance metrics |
| **GeoIP Check Task** | `geoCheckTask()` | 900s (configurable) | Validates active sessions against geographic filtering policies |

### Data Structure Management

The application uses **dedicated mutex protection** for different data categories to minimize contention:

```go
// Global data structures with dedicated mutexes
var localSessions = make(map[string]BgpSession)     // sessionMutex (RWMutex)
var localMetrics = make(map[string]SessionMetric)   // metricMutex (RWMutex)
var localTrafficRate = make(map[string]TrafficRate) // trafficMutex (RWMutex)
var rttTrackers = make(map[string]*RTTTracker)      // rttMutex (RWMutex)
```

### BIRD Integration Architecture

- **Connection Pool**: Configurable pool of BIRD control socket connections (5-128 connections)
- **Pool Maintenance**: Automatic cleanup of stale connections every 30 seconds
- **Template System**: Go template-based BGP configuration generation
- **Configuration Validation**: Automatic BIRD configuration reload and validation

### Session Lifecycle Management

1. **Discovery**: Sessions fetched from central PeerAPI server
2. **Configuration**: Automatic interface creation (WireGuard/GRE) and IP addressing
3. **BIRD Setup**: Dynamic BGP configuration generation and deployment
4. **Monitoring**: Continuous RTT measurement and performance tracking
5. **Optimization**: DN42 community updates based on real-time metrics
6. **Teardown**: Clean removal of interfaces and configurations when needed

### Network Interface Management

- **WireGuard Support**: Full lifecycle management of WireGuard tunnels
- **GRE Support**: IPv4 and IPv6 GRE tunnel configuration
- **IP Management**: Automatic IP address assignment and routing setup
- **Interface Cleanup**: Proper teardown and resource cleanup

## Development

### Project Structure

```
peerapi-agent/
├── src/                          # Go source code
│   ├── main.go                   # Application entry point and lifecycle management
│   ├── config.go                 # Configuration loading and validation
│   ├── types.go                  # Data structure definitions and API types
│   ├── functions.go              # Utility functions and system metrics
│   ├── handler.go                # HTTP API endpoint handlers
│   ├── auth.go                   # JWT authentication and token validation
│   ├── logger.go                 # Structured logging with rotation support
│   ├── session.go                # BGP session management and interface configuration
│   ├── task_monitoring.go        # Heartbeat and bandwidth monitoring tasks
│   ├── task_session_sync.go      # BGP session synchronization with PeerAPI server
│   ├── task_metric.go            # Performance metrics collection and reporting
│   ├── task_dn42_bgp_community.go # DN42 BGP community management
│   ├── task_geoip.go            # Geographic validation and filtering
│   ├── go.mod                    # Go module dependencies
│   ├── go.sum                    # Dependency checksums
│   └── bird/                     # BIRD routing daemon integration
│       ├── bird.go               # BIRD control interface and connection pooling
│       └── conn.go               # Low-level BIRD socket communication
├── templates/                    # Configuration templates
│   └── bird_peer.conf           # BIRD BGP peer configuration template
├── config.json                  # Main configuration file
├── peerapi-agent.service        # Systemd service definition
├── GeoLite2-Country.mmdb        # MaxMind GeoIP database (optional)
└── logs/                        # Log file directory
    └── peerapi-agent.log        # Application logs with rotation
```

### Key Components

#### Session Management (`session.go`)
- **Interface Configuration**: WireGuard and GRE tunnel setup
- **JWT Validation**: Session passthrough token parsing and validation
- **BIRD Configuration**: Template-based BGP configuration generation
- **Resource Management**: Interface cleanup and teardown

#### Background Tasks (`task_*.go`)
- **Concurrent Design**: Context-based cancellation and graceful shutdown
- **Error Handling**: Robust error handling with retry mechanisms
- **Resource Cleanup**: Proper cleanup of connections and temporary resources
- **Performance Optimization**: Efficient data collection and processing

#### BIRD Integration (`bird/`)
- **Connection Pooling**: Thread-safe connection pool with automatic maintenance
- **Protocol Parsing**: BGP statistics extraction and route counting
- **Configuration Management**: Dynamic configuration updates and validation

### Dependencies

#### Core Dependencies
- **net/http** - Standard Go HTTP server and client
- **jwt/v5** - JWT authentication and token validation
- **geoip2-golang** - MaxMind GeoIP database integration
- **lumberjack.v2** - Log file rotation and management

#### System Dependencies
- **BIRD 2.0+** - BGP routing daemon
- **Linux kernel** - Network interface management
- **iproute2** - Network configuration utilities
- **WireGuard tools** - WireGuard interface management

### Building and Testing

```bash
#!/bin/sh
set -e
echo "Building peerapi-agent for Linux AMD64..."

export GOOS=linux
export GOARCH=amd64

rm -rf dist || true
mkdir dist

cd src
go mod tidy
go build -o ../dist/peerapi-agent -ldflags="-X main.GIT_COMMIT=$(git rev-parse --short HEAD)"

cd ..
cp config.json ./dist/config.json

echo "Build completed."
```

### Contributing

1. **Code Style**: Follow Go standard formatting (`gofmt`, `golint`)
2. **Error Handling**: Use structured error handling with context
3. **Logging**: Use structured logging with appropriate log levels
4. **Concurrency**: Use context-based cancellation for background tasks
5. **Resource Management**: Ensure proper cleanup of all resources
6. **Documentation**: Update README.md for any configuration changes

## Technologies and Dependencies

### Core Technologies
- **[Go 1.25+](https://golang.org)** - Modern systems programming language with excellent concurrency support
- **[BIRD 2.0+](https://bird.network.cz/)** - Internet routing daemon for BGP, OSPF, and other protocols
- **[Linux](https://kernel.org)** - Required for network interface management and system metrics

### Go Dependencies

#### HTTP and Web Framework
- **[net/http](https://pkg.go.dev/net/http)** - Go's standard HTTP package for server and client functionality

#### Authentication and Security
- **[jwt/v5](https://github.com/golang-jwt/jwt)** - JSON Web Token implementation for Go
- **[crypto](https://golang.org/x/crypto)** - Extended cryptography packages

#### Network and Geographic Services
- **[geoip2-golang](https://github.com/oschwald/geoip2-golang)** - MaxMind GeoIP2 database reader
- **[maxminddb-golang](https://github.com/oschwald/maxminddb-golang)** - MaxMind database format reader

#### Logging and Utilities
- **[lumberjack.v2](https://gopkg.in/natefinch/lumberjack.v2)** - Rolling logger with size-based rotation
- **[goInfo](https://github.com/matishsiao/goInfo)** - System information gathering

### External Services

#### Required Services
- **MaxMind GeoLite2** - Geographic IP database for session validation
- **PeerAPI Center** - Central coordination server for BGP session management
- **BIRD Control Socket** - Unix socket communication with BIRD daemon

#### System Requirements
- **iproute2** - Network interface configuration (`ip` command)
- **WireGuard Tools** - WireGuard VPN tunnel management (`wg` command)
- **procfs** - Linux process and system information (`/proc` filesystem)

### Network Protocols and Standards
- **BGP-4** (RFC 4271) - Border Gateway Protocol version 4
- **MP-BGP** (RFC 4760) - Multiprotocol extensions for BGP-4
- **WireGuard** (RFC 9105) - Modern VPN protocol
- **GRE** (RFC 2784, RFC 2890) - Generic Routing Encapsulation
- **JWT** (RFC 7519) - JSON Web Token standard
- **DN42 Communities** - DN42 network BGP community standards

This architecture ensures robust, scalable, and maintainable BGP session management with modern Go practices and industry-standard networking protocols.

## Performance Tuning

### BIRD Pool Optimization
```json
{
  "bird": {
    "poolSize": 10,        // Increase for high session counts
    "poolSizeMax": 256     // Maximum concurrent BIRD operations
  }
}
```

### Metric Collection Intervals
```json
{
  "peerApiCenter": {
    "heartbeatInterval": 30,    // Reduce for faster health updates
    "syncInterval": 300,        // Increase for lower CPU usage
    "metricInterval": 60        // Balance between accuracy and performance
  }
}
```

### Buffer Sizes
```json
{
  "server": {
    "readBufferSize": 8192,     // Increase for high-throughput environments  
    "writeBufferSize": 8192,    // Match your network MTU characteristics
    "bodyLimit": 2097152        // Increase for large metric payloads
  }
}
```

## License

This project is licensed under the GPL3 License - see the [LICENSE](LICENSE) file for details.
