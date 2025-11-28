package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/iedon/peerapi-agent/api"
	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/network"
)

// SendJSONResponse sends a JSON response
func SendJSONResponse(w http.ResponseWriter, statusCode int, message string, data any) {
	w.Header().Set("Content-Type", "application/json")

	httpStatusCode := statusCode
	if statusCode == 0 {
		httpStatusCode = http.StatusOK
	}

	response := api.AgentApiResponse{
		Code:    statusCode,
		Message: message,
		Data:    nil,
	}

	if data != nil {
		response.Data = data
	}

	w.WriteHeader(httpStatusCode)
	json.NewEncoder(w).Encode(response)
}

// NodePassthroughRequest represents the request for node passthrough info
type NodePassthroughRequest struct {
	ASN  uint `json:"asn"`
	Data struct {
		LinkType      string   `json:"linkType"`
		BGPExtensions []string `json:"bgpExtensions"`
	} `json:"data"`
}

// Handlers holds dependencies for HTTP handlers
type Handlers struct {
	cfg    *config.Config
	logger *logger.Logger
	// Add callback functions for handlers that need to interact with app state
	GetStatusData func() (sessions, metrics any)
	TriggerSync   func()
}

// NewHandlers creates a new Handlers instance
func NewHandlers(cfg *config.Config, log *logger.Logger) *Handlers {
	return &Handlers{
		cfg:    cfg,
		logger: log,
	}
}

// StatusHandler returns session and metrics status
func (h *Handlers) StatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		SendJSONResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	if h.GetStatusData == nil {
		SendJSONResponse(w, http.StatusInternalServerError, "Status data unavailable", nil)
		return
	}

	sessions, metrics := h.GetStatusData()
	SendJSONResponse(w, 0, "OK", map[string]any{
		"sessions": sessions,
		"metrics":  metrics,
	})
}

// SyncHandler triggers manual session sync
func (h *Handlers) SyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		SendJSONResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	if h.TriggerSync != nil {
		go h.TriggerSync()
	}
	SendJSONResponse(w, 0, "Sync initiated", nil)
}

// InfoHandler provides node passthrough information
func (h *Handlers) InfoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		SendJSONResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	// Parse the request body
	var req NodePassthroughRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendJSONResponse(w, http.StatusBadRequest, "Invalid request format", nil)
		return
	}

	switch req.Data.LinkType {
	case "wireguard":
		h.getWireGuardPassthroughInfo(w, &req)
	case "gre":
		h.getGREPassthroughInfo(w, &req, false)
	case "ip6gre":
		h.getGREPassthroughInfo(w, &req, true)
	default:
		SendJSONResponse(w, http.StatusBadRequest, "Link(Interface) type not supported", nil)
	}
}

func (h *Handlers) getWireGuardPassthroughInfo(w http.ResponseWriter, req *NodePassthroughRequest) {
	port, err := network.GetRandomUnusedPort("udp")
	if err != nil {
		SendJSONResponse(w, http.StatusInternalServerError, "Failed to get random unused port", nil)
		return
	}

	// Create the passthrough data
	data := map[string]any{
		"asn":  req.ASN,
		"port": port,
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(data))
	tokenString, err := token.SignedString([]byte(h.cfg.PeerAPI.SessionPassthroughJwtSecert))
	if err != nil {
		SendJSONResponse(w, http.StatusInternalServerError, "Failed to create token", nil)
		return
	}

	// Create response with endpoint and WireGuard public key
	endpoint := h.cfg.WireGuard.LocalEndpointHost
	if strings.Contains(endpoint, ":") {
		endpoint = fmt.Sprintf("[%s]", endpoint)
	}

	SendJSONResponse(w, 0, "OK", map[string]string{
		"passthrough": tokenString,
		"info": fmt.Sprintf(
			"**Endpoint**: ```%s:%d```\n\n**WireGuard** Public Key: ```%s```",
			endpoint,
			port,
			strings.TrimSpace(h.cfg.WireGuard.PublicKey),
		),
	})
}

func (h *Handlers) getGREPassthroughInfo(w http.ResponseWriter, req *NodePassthroughRequest, isIPv6 bool) {
	// Create the passthrough data (no port required for GRE tunnels)
	data := map[string]any{
		"asn": req.ASN,
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(data))
	tokenString, err := token.SignedString([]byte(h.cfg.PeerAPI.SessionPassthroughJwtSecert))
	if err != nil {
		SendJSONResponse(w, http.StatusInternalServerError, "Failed to create token", nil)
		return
	}

	// Select the appropriate endpoint based on GRE type (IPv4 or IPv6)
	var endpoint string
	var tunnelType string
	if isIPv6 {
		endpoint = h.cfg.GRE.LocalEndpointDesc6
		tunnelType = "GRE over IPv6(ip6gre)"
	} else {
		endpoint = h.cfg.GRE.LocalEndpointDesc4
		tunnelType = "GRE over IPv4(gre)"
	}

	endpoint = strings.TrimSpace(endpoint)

	SendJSONResponse(w, 0, "OK", map[string]string{
		"passthrough": tokenString,
		"info": fmt.Sprintf(
			"- Keep in mind that GRE Tunnels are not safe, as traffic is not going to be encrypted\n- You can create only 1 session with the same endpoint\n- You must use IP instead of hostname for endpoint\n\n**Endpoint**: ```%s```\n\n**Tunnel Type**: ```%s``` , **TTL**: ```255```",
			endpoint,
			tunnelType,
		),
	})
}
