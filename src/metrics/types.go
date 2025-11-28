package metrics

// SessionMetric represents metrics for a single BGP session
type SessionMetric struct {
	UUID      string          `json:"uuid"`
	ASN       uint            `json:"asn"`
	Timestamp int64           `json:"timestamp"`
	BGP       []BGPMetric     `json:"bgp"`
	Interface InterfaceMetric `json:"interface"`
	RTT       RTT             `json:"rtt"`
}

// BGPMetric holds BGP protocol metrics
type BGPMetric struct {
	Name   string          `json:"name"`
	State  string          `json:"state"`
	Info   string          `json:"info"`
	Type   string          `json:"type"` // BGP_SESSION_TYPE_IPV4, BGP_SESSION_TYPE_IPV6, or BGP_SESSION_TYPE_MPBGP
	Since  string          `json:"since"`
	Routes BGPRoutesMetric `json:"routes"`
}

// BGPRoutesMetric holds route counts for IPv4 and IPv6
type BGPRoutesMetric struct {
	IPv4 RouteMetricStruct `json:"ipv4"`
	IPv6 RouteMetricStruct `json:"ipv6"`
}

// RouteMetricStruct holds imported and exported route counts
type RouteMetricStruct struct {
	Imported RouteMetrics `json:"imported"`
	Exported RouteMetrics `json:"exported"`
}

// RouteMetrics holds current route count
type RouteMetrics struct {
	Current int `json:"current"`
}

// InterfaceMetric holds interface-level metrics
type InterfaceMetric struct {
	IPv4          string                 `json:"ipv4"`
	IPv6          string                 `json:"ipv6"`
	IPv6LinkLocal string                 `json:"ipv6LinkLocal"`
	MAC           string                 `json:"mac"`
	MTU           int                    `json:"mtu"`
	Status        string                 `json:"status"`
	Traffic       InterfaceTrafficMetric `json:"traffic"`
}

// InterfaceTrafficMetric holds traffic statistics
type InterfaceTrafficMetric struct {
	Total   []int64 `json:"total"`   // [Tx, Rx]
	Current []int64 `json:"current"` // [Tx, Rx]
}

// RTT represents round-trip time metrics
type RTT struct {
	Current int     `json:"current"`
	Loss    float64 `json:"loss"` // Average packet loss rate (0.0 = no loss, 1.0 = 100% loss)
}

// RTTTracker holds information about the best protocol to use for RTT measurements
type RTTTracker struct {
	PreferredProtocol string    // "ipv4", "ipv6", or "ipv6ll"
	LastRTT           int       // Last measured RTT value
	LastLoss          float64   // Last measured packet loss rate
	Metric            []int     // RTT records (each time LastRTT is archived here)
	LossMetric        []float64 // Packet loss records (each time LastLoss is archived here)
	AvgLoss           float64   // Average loss rate of RTT measurements
}

// SessionReportRequest is sent to PeerAPI to report metrics
type SessionReportRequest struct {
	Metrics []SessionMetric `json:"metrics"`
}
