package api

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/iedon/peerapi-agent/config"
	"golang.org/x/crypto/bcrypt"
)

const (
	bearerScheme = "Bearer\x20"
)

// GenerateToken generates a bcrypt token for outbound requests
func GenerateToken(cfg *config.Config) (string, error) {
	if cfg.PeerAPI.Secret == "" || cfg.PeerAPI.RouterUUID == "" {
		return "", errors.New("missing PeerAPI secret or router UUID in config")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.PeerAPI.Secret+cfg.PeerAPI.RouterUUID), 10)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// VerifyBearerToken verifies if the request has a valid bearer token
func VerifyBearerToken(r *http.Request, cfg *config.Config) bool {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, bearerScheme) {
		return false
	}

	tokenStr := authHeader[len(bearerScheme):]

	// Check if it's our own token going outbound
	if subtle.ConstantTimeCompare([]byte(tokenStr), []byte(cfg.PeerAPI.Secret)) == 1 {
		return true
	}

	// Otherwise verify the inbound bcrypt hash
	err := bcrypt.CompareHashAndPassword([]byte(tokenStr), []byte(cfg.PeerAPI.AgentSecret+cfg.PeerAPI.RouterUUID))
	return err == nil
}
