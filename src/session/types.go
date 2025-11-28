package session

import "encoding/json"

// Session status constants
const (
	StatusDeleted         = 0
	StatusDisabled        = 1
	StatusEnabled         = 2
	StatusPendingApproval = 3
	StatusQueuedForSetup  = 4
	StatusQueuedForDelete = 5
	StatusProblem         = 6
	StatusTeardown        = 7
)

// Legacy names for backward compatibility
const (
	PEERING_STATUS_DELETED           = StatusDeleted
	PEERING_STATUS_DISABLED          = StatusDisabled
	PEERING_STATUS_ENABLED           = StatusEnabled
	PEERING_STATUS_PENDING_APPROVAL  = StatusPendingApproval
	PEERING_STATUS_QUEUED_FOR_SETUP  = StatusQueuedForSetup
	PEERING_STATUS_QUEUED_FOR_DELETE = StatusQueuedForDelete
	PEERING_STATUS_PROBLEM           = StatusProblem
	PEERING_STATUS_TEARDOWN          = StatusTeardown
)

// Session types
const (
	BGP_SESSION_TYPE_IPV4  = "ipv4"
	BGP_SESSION_TYPE_IPV6  = "ipv6"
	BGP_SESSION_TYPE_MPBGP = "mpbgp"
)

// Session represents a BGP peering session
type Session struct {
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

// SessionData holds parsed JSON from session.Data field
type SessionData struct {
	Passthrough string `json:"passthrough"`
	Info        string `json:"info"`
}

// BirdTemplateData holds data for BIRD configuration template
type BirdTemplateData struct {
	SessionName       string
	InterfaceAddr     string
	ASN               uint
	IPv4ShouldImport  bool
	IPv4ShouldExport  bool
	IPv6ShouldImport  bool
	IPv6ShouldExport  bool
	ExtendedNextHopOn bool
	FilterParamsIPv4  string
	FilterParamsIPv6  string
}
