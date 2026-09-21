package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// Each request has its own configured context deadline.
var httpClient = &http.Client{}

type decisionRequest struct {
	Kind      string            `json:"kind"`
	Source    string            `json:"source"`
	Content   decisionContent   `json:"content"`
	Policy    decisionPolicy    `json:"policy"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

type decisionContent struct {
	Raw       string            `json:"raw"`
	Formatted string            `json:"formatted"`
	Parsed    map[string]string `json:"parsed,omitempty"`
}

type decisionPolicy struct {
	Action string `json:"action"`
}

type decisionResponse struct {
	Decision    string  `json:"decision"`
	Confidence  float64 `json:"confidence"`
	Reason      string  `json:"reason"`
	Summary     string  `json:"summary"`
	TTLSeconds  int     `json:"ttl_seconds,omitempty"`
	Fingerprint string  `json:"fingerprint,omitempty"`
}

type alertDecision struct {
	Send          bool
	TTLSeconds    int
	ServiceFailed bool
	Outcome       string
	Fingerprint   string
}

type decisionCache struct {
	mu       sync.Mutex
	inflight map[string]*decisionFlight
}

type decisionFlight struct {
	done     chan struct{}
	decision alertDecision
}

// GetOrEvaluate shares a request among concurrent identical candidates.
func (c *decisionCache) GetOrEvaluate(key string, evaluate func() alertDecision) (alertDecision, bool) {
	c.mu.Lock()
	if flight := c.inflight[key]; flight != nil {
		c.mu.Unlock()
		<-flight.done
		return flight.decision, true
	}
	if c.inflight == nil {
		c.inflight = make(map[string]*decisionFlight)
	}
	flight := &decisionFlight{done: make(chan struct{})}
	c.inflight[key] = flight
	c.mu.Unlock()
	decision := evaluate()
	c.mu.Lock()
	flight.decision = decision
	delete(c.inflight, key)
	close(flight.done)
	c.mu.Unlock()
	return decision, false
}

type decisionHTTPError struct{ status int }

func (e *decisionHTTPError) Error() string {
	return fmt.Sprintf("decision service returned %d %s", e.status, http.StatusText(e.status))
}

func newDecisionCache() *decisionCache {
	return &decisionCache{inflight: make(map[string]*decisionFlight)}
}

func decisionFailOpen(cfg DecisionServiceConfig) bool {
	if cfg.FailOpen == nil {
		return true
	}
	return *cfg.FailOpen
}

func decisionTimeout(cfg DecisionServiceConfig) time.Duration {
	if cfg.TimeoutSeconds <= 0 {
		return 3 * time.Second
	}
	return time.Duration(cfg.TimeoutSeconds) * time.Second
}

func decisionMinConfidence(cfg DecisionServiceConfig) float64 {
	if cfg.MinConfidence <= 0 {
		return 0.75
	}
	return cfg.MinConfidence
}

func decisionLogHost(parsedLine map[string]string) string {
	if parsedLine == nil || parsedLine["host"] == "" {
		return "<unknown>"
	}
	return parsedLine["host"]
}

func shouldSendByDecisionService(cfg DecisionServiceConfig, rawLine string, parsedLine map[string]string, formattedMessage string) alertDecision {
	if !cfg.Enabled {
		return alertDecision{Send: true, Outcome: "disabled"}
	}
	if cfg.URL == "" {
		log.Println("decision service enabled but no URL configured")
		return alertDecision{Send: decisionFailOpen(cfg), ServiceFailed: true, Outcome: "configuration_error"}
	}

	reqBody := decisionRequest{
		Kind:   "log_alert",
		Source: "clattermark",
		Content: decisionContent{
			Raw:       rawLine,
			Formatted: formattedMessage,
			Parsed:    parsedLine,
		},
		Policy: decisionPolicy{Action: "send_alert"},
		Metadata: map[string]string{
			"component": "clattermark",
		},
		Timestamp: time.Now().UTC(),
	}

	decision, err := requestDecision(cfg, reqBody)
	if err != nil {
		log.Printf("decision service error: %v", err)
		outcome := "request_error"
		var statusError *decisionHTTPError
		if errors.Is(err, context.DeadlineExceeded) {
			outcome = "timeout"
		} else if errors.As(err, &statusError) {
			outcome = "http_error"
			if statusError.status == http.StatusTooManyRequests {
				outcome = "rate_limited"
			}
		}
		return alertDecision{Send: decisionFailOpen(cfg), ServiceFailed: true, Outcome: outcome}
	}

	minConfidence := decisionMinConfidence(cfg)
	host := decisionLogHost(parsedLine)
	if decision.Decision != "allow" {
		log.Printf("decision service suppressed alert: host=%q line=%q decision=%s confidence=%.2f reason=%q summary=%q", host, rawLine, decision.Decision, decision.Confidence, decision.Reason, decision.Summary)
		return alertDecision{Outcome: "deny"}
	}
	if decision.Confidence < minConfidence {
		log.Printf("decision service suppressed low-confidence alert: host=%q line=%q confidence=%.2f min=%.2f reason=%q summary=%q", host, rawLine, decision.Confidence, minConfidence, decision.Reason, decision.Summary)
		return alertDecision{Outcome: "low_confidence"}
	}
	log.Printf("decision service allowed alert: host=%q line=%q confidence=%.2f reason=%q summary=%q", host, rawLine, decision.Confidence, decision.Reason, decision.Summary)
	return alertDecision{Send: true, TTLSeconds: decision.TTLSeconds, Outcome: "allow", Fingerprint: decision.Fingerprint}
}

func requestDecision(cfg DecisionServiceConfig, reqBody decisionRequest) (decisionResponse, error) {
	jsonPayload, err := json.Marshal(reqBody)
	if err != nil {
		return decisionResponse{}, fmt.Errorf("marshal decision request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), decisionTimeout(cfg))
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return decisionResponse{}, fmt.Errorf("create decision request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return decisionResponse{}, fmt.Errorf("send decision request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decisionResponse{}, &decisionHTTPError{status: resp.StatusCode}
	}

	var decision decisionResponse
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return decisionResponse{}, fmt.Errorf("decode decision response: %w", err)
	}
	if decision.Decision != "allow" && decision.Decision != "deny" {
		return decisionResponse{}, fmt.Errorf("invalid decision %q", decision.Decision)
	}
	return decision, nil
}
