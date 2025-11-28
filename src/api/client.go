package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/metrics"
	"github.com/iedon/peerapi-agent/version"
)

// Client handles communication with PeerAPI server
type Client struct {
	cfg        *config.Config
	logger     *logger.Logger
	httpClient *http.Client
}

// NewClient creates a new PeerAPI client
func NewClient(cfg *config.Config, log *logger.Logger) *Client {
	return &Client{
		cfg:    cfg,
		logger: log,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.PeerAPI.RequestTimeout) * time.Second,
		},
	}
}

// GetSessions fetches BGP session information from the PeerAPI server
func (c *Client) GetSessions(ctx context.Context) ([]SessionData, error) {
	url := fmt.Sprintf("%s/agent/%s/sessions", c.cfg.PeerAPI.APIURL, c.cfg.PeerAPI.RouterUUID)

	token, err := GenerateToken(c.cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	SetHTTPClientHeader(req, token, false)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get sessions, status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var response PeerApiResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if response.Code != 0 {
		return nil, fmt.Errorf("got an error response from PeerAPI: %s", response.Message)
	}

	var data SessionsResponse
	if err := json.Unmarshal(response.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse BGP sessions data: %w", err)
	}

	return data.BgpSessions, nil
}

// ReportSessionStatus reports a session status change to the PeerAPI server
func (c *Client) ReportSessionStatus(ctx context.Context, sessionUUID string, status int, lastError string) error {
	url := fmt.Sprintf("%s/agent/%s/modify", c.cfg.PeerAPI.APIURL, c.cfg.PeerAPI.RouterUUID)

	token, err := GenerateToken(c.cfg)
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	requestBody := map[string]any{
		"status":    status,
		"session":   sessionUUID,
		"lastError": lastError,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	SetHTTPClientHeader(req, token, true)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to notify: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to notify, status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var response PeerApiResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if response.Code != 0 {
		return fmt.Errorf("got an error response from PeerAPI: %s", response.Message)
	}

	return nil
}

// SendHeartbeat sends a heartbeat message to the PeerAPI server
func (c *Client) SendHeartbeat(ctx context.Context, version, kernel, loadAvg string, uptime float64, rs string, tx, rx uint64, tcp, udp int) error {
	url := fmt.Sprintf("%s/agent/%s/heartbeat", c.cfg.PeerAPI.APIURL, c.cfg.PeerAPI.RouterUUID)

	token, err := GenerateToken(c.cfg)
	if err != nil {
		c.logger.Error("Failed to generate token for heartbeat: %v", err)
		return err
	}

	requestBody := map[string]any{
		"version":   version,
		"kernel":    kernel,
		"loadAvg":   loadAvg,
		"uptime":    uptime,
		"rs":        rs,
		"tx":        tx,
		"rx":        rx,
		"tcp":       tcp,
		"udp":       udp,
		"timestamp": time.Now().UnixMilli(),
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		c.logger.Error("Failed to marshal heartbeat request body: %v", err)
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		c.logger.Error("Failed to create heartbeat request: %v", err)
		return err
	}

	SetHTTPClientHeader(req, token, true)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("Failed to send heartbeat: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		c.logger.Error("Heartbeat server returned status code: %d", resp.StatusCode)
		return fmt.Errorf("heartbeat failed with status: %d", resp.StatusCode)
	}

	return nil
}

// ReportMetrics sends metrics to the PeerAPI server
func (c *Client) ReportMetrics(ctx context.Context, sessionMetrics []metrics.SessionMetric) error {
	url := fmt.Sprintf("%s/agent/%s/report", c.cfg.PeerAPI.APIURL, c.cfg.PeerAPI.RouterUUID)

	token, err := GenerateToken(c.cfg)
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	requestBody := metrics.SessionReportRequest{
		Metrics: sessionMetrics,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	SetHTTPClientHeader(req, token, true)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send metrics: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("metrics report failed, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var response PeerApiResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if response.Code != 0 {
		return fmt.Errorf("got an error response from PeerAPI: %s", response.Message)
	}

	return nil
}

// GetProbeSummaries fetches probe summaries from the PeerAPI server
func (c *Client) GetProbeSummaries(ctx context.Context) ([]ProbeSummarySnapshot, error) {
	url := fmt.Sprintf("%s/agent/%s/probe", c.cfg.PeerAPI.APIURL, c.cfg.PeerAPI.RouterUUID)

	token, err := GenerateToken(c.cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	SetHTTPClientHeader(req, token, false)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get probe summaries: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("probe summaries request failed, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var response PeerApiResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if response.Code != 0 {
		return nil, fmt.Errorf("got an error response from PeerAPI: %s", response.Message)
	}

	var summaries []ProbeSummarySnapshot
	if err := json.Unmarshal(response.Data, &summaries); err != nil {
		return nil, fmt.Errorf("failed to parse probe summaries data: %w", err)
	}

	return summaries, nil
}

// SetHTTPClientHeader sets common headers for API requests
func SetHTTPClientHeader(req *http.Request, token string, jsonContent bool) {
	req.Header.Set("Authorization", bearerScheme+token)
	req.Header.Set("User-Agent", version.SERVER_SIGNATURE)
	if jsonContent {
		req.Header.Set("Content-Type", "application/json")
	}
}
