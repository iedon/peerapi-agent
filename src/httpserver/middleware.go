package httpserver

import (
	"net"
	"net/http"
	"strings"

	"github.com/iedon/peerapi-agent/api"
	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
)

// BodyLimitMiddleware limits request body size
func BodyLimitMiddleware(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if maxBytes > 0 {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TrustedProxyMiddleware validates IPs and handles trusted proxies
func TrustedProxyMiddleware(trustedProxies []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the real IP address considering trusted proxies
			clientIP := getRealIP(r, trustedProxies)

			// Enhanced IP validation
			if clientIP != "" {
				parsedIP := net.ParseIP(clientIP)
				if parsedIP == nil {
					SendJSONResponse(w, http.StatusBadRequest, "Invalid IP address format", nil)
					return
				}

				// Additional IP validation - reject unspecified IPs
				if parsedIP.IsUnspecified() {
					SendJSONResponse(w, http.StatusBadRequest, "Unspecified IP address not allowed", nil)
					return
				}
			}

			// Store the real IP in request header for later use
			r.Header.Set("X-Real-IP", clientIP)
			next.ServeHTTP(w, r)
		})
	}
}

// getRealIP gets real IP address considering trusted proxies
func getRealIP(r *http.Request, trustedProxies []string) string {
	remoteAddr := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteAddr = host
	}

	// Check if the request comes from a trusted proxy
	if isTrustedProxy(remoteAddr, trustedProxies) {
		// Check X-Forwarded-For header
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ips := strings.Split(forwarded, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}

		// Check X-Real-IP header
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			return strings.TrimSpace(realIP)
		}
	}

	return remoteAddr
}

// isTrustedProxy checks if IP is in trusted proxy list
func isTrustedProxy(ip string, trustedProxies []string) bool {
	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}

	for _, trusted := range trustedProxies {
		if strings.Contains(trusted, "/") {
			// CIDR notation
			_, network, err := net.ParseCIDR(trusted)
			if err == nil && network.Contains(clientIP) {
				return true
			}
		} else {
			// Direct IP match
			if ip == trusted {
				return true
			}
		}
	}

	return false
}

// ServerHeaderMiddleware adds server header
func ServerHeaderMiddleware(serverHeader string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", serverHeader)
			next.ServeHTTP(w, r)
		})
	}
}

// DebugLoggingMiddleware logs requests in debug mode
func DebugLoggingMiddleware(log *logger.Logger, debug bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if debug {
				clientIP := r.Header.Get("X-Real-IP")
				if clientIP == "" {
					clientIP = r.RemoteAddr
				}
				log.Debug("%s %s %s from %s", r.Method, r.URL.Path, r.Proto, clientIP)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AuthMiddleware wraps handlers with bearer token authentication
func AuthMiddleware(cfg *config.Config) func(http.HandlerFunc) http.HandlerFunc {
	return func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !api.VerifyBearerToken(r, cfg) {
				SendJSONResponse(w, http.StatusUnauthorized, "Unauthorized", nil)
				return
			}
			handler(w, r)
		}
	}
}
