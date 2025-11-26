package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const defaultProbeSummaryCooldownSeconds = 30

type probeEndpointSnapshot struct {
	Seen    bool  `json:"seen"`
	Healthy *bool `json:"healthy"`
	NAT     *bool `json:"nat"`
}

type probeSummarySnapshot struct {
	UUID string                `json:"uuid"`
	IPv4 probeEndpointSnapshot `json:"ipv4"`
	IPv6 probeEndpointSnapshot `json:"ipv6"`
}

type probeFamily int

const (
	probeFamilyIPv4 probeFamily = iota
	probeFamilyIPv6
	probeFamilyAny
)

var (
	probeSummaryMu   sync.RWMutex
	probeSummaryData = make(map[string]probeSummarySnapshot)
)

func refreshProbeSummariesWithCooldown(ctx context.Context) (int, error) {
	cooldown := cfg.PeerProbe.ProbeSummaryCooldownSeconds
	if cooldown <= 0 {
		cooldown = defaultProbeSummaryCooldownSeconds
	}

	timer := time.NewTimer(time.Duration(cooldown) * time.Second)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-timer.C:
	}

	summaries, err := fetchProbeSummaries(ctx)
	if err != nil {
		return 0, err
	}

	storeProbeSummaries(summaries)
	return len(summaries), nil
}

func fetchProbeSummaries(ctx context.Context) ([]probeSummarySnapshot, error) {
	client := &http.Client{
		Timeout: time.Duration(cfg.PeerAPI.RequestTimeout) * time.Second,
	}

	url := fmt.Sprintf("%s/agent/%s/probe", cfg.PeerAPI.APIURL, cfg.PeerAPI.RouterUUID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	setHTTPClientHeader(req, token, false)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("probe summary request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var peerResp PeerApiResponse
	if err := json.Unmarshal(body, &peerResp); err != nil {
		return nil, err
	}

	if peerResp.Code != 0 {
		return nil, fmt.Errorf("probe summary error response: %s", peerResp.Message)
	}

	var summaries []probeSummarySnapshot
	if err := json.Unmarshal(peerResp.Data, &summaries); err != nil {
		return nil, err
	}

	return summaries, nil
}

func storeProbeSummaries(summaries []probeSummarySnapshot) {
	probeSummaryMu.Lock()
	defer probeSummaryMu.Unlock()

	updated := make(map[string]probeSummarySnapshot, len(summaries))
	for _, summary := range summaries {
		updated[summary.UUID] = summary
	}
	probeSummaryData = updated
}

func probeStatusFlag(uuid string, family probeFamily) int {
	probeSummaryMu.RLock()
	snapshot, ok := probeSummaryData[uuid]
	probeSummaryMu.RUnlock()
	if !ok {
		return 0
	}

	switch family {
	case probeFamilyIPv4:
		return evaluateProbeEndpoint(snapshot.IPv4)
	case probeFamilyIPv6:
		return evaluateProbeEndpoint(snapshot.IPv6)
	case probeFamilyAny:
		if evaluateProbeEndpoint(snapshot.IPv4) == 1 || evaluateProbeEndpoint(snapshot.IPv6) == 1 {
			return 1
		}
	}

	return 0
}

func evaluateProbeEndpoint(endpoint probeEndpointSnapshot) int {
	if !endpoint.Seen {
		return 0
	}

	if boolPtrValue(endpoint.Healthy) || boolPtrValue(endpoint.NAT) {
		return 1
	}

	return 0
}

func boolPtrValue(val *bool) bool {
	return val != nil && *val
}
