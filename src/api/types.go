package api

import (
	"encoding/json"

	"github.com/iedon/peerapi-agent/session"
)

// Response formats
type AgentApiResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type PeerApiResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// SessionsResponse from PeerAPI
type SessionsResponse struct {
	BgpSessions []SessionData `json:"bgpSessions"`
}

// SessionData from PeerAPI (matches BgpSession in old code)
type SessionData struct {
	UUID          string          `json:"uuid"`
	ASN           uint            `json:"asn"`
	Status        int             `json:"status"`
	IPv4          string          `json:"ipv4"`
	IPv6          string          `json:"ipv6"`
	IPv6LinkLocal string          `json:"ipv6LinkLocal"`
	Type          string          `json:"type"`
	Extensions    []string        `json:"extensions"`
	Interface     string          `json:"interface"`
	Endpoint      string          `json:"endpoint"`
	Credential    string          `json:"credential"`
	Data          json.RawMessage `json:"data"`
	MTU           int             `json:"mtu"`
	Policy        int             `json:"policy"`
}

// SessionModifyRequest for reporting session status changes
type SessionModifyRequest struct {
	Status    int    `json:"status"`
	Session   string `json:"session"`
	LastError string `json:"lastError,omitempty"`
}

// ProbeHealthStatus represents the health status of a probe endpoint
type ProbeHealthStatus int

const (
	ProbeHealthStatusHealthy      ProbeHealthStatus = 0
	ProbeHealthStatusUnhealthy    ProbeHealthStatus = 1
	ProbeHealthStatusNotAvailable ProbeHealthStatus = 2
)

// ProbeEndpointSnapshot represents probe status for one address family
type ProbeEndpointSnapshot struct {
	Timestamp *int64             `json:"timestamp"`
	Status    *ProbeHealthStatus `json:"status"`
	NAT       *bool              `json:"nat"`
}

// ProbeSummarySnapshot represents the probe summary for one session
type ProbeSummarySnapshot struct {
	UUID string                `json:"uuid"`
	IPv4 ProbeEndpointSnapshot `json:"ipv4"`
	IPv6 ProbeEndpointSnapshot `json:"ipv6"`
}

// ToSession converts API SessionData to internal session.Session
func (s *SessionData) ToSession() *session.Session {
	return &session.Session{
		UUID:          s.UUID,
		ASN:           s.ASN,
		Status:        s.Status,
		IPv4:          s.IPv4,
		IPv6:          s.IPv6,
		IPv6LinkLocal: s.IPv6LinkLocal,
		Type:          s.Type,
		Extensions:    s.Extensions,
		Interface:     s.Interface,
		Endpoint:      s.Endpoint,
		Credential:    s.Credential,
		Data:          s.Data,
		MTU:           s.MTU,
		Policy:        s.Policy,
	}
}
