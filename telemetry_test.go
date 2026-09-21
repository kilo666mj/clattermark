package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthReflectsLifecycle(t *testing.T) {
	t.Parallel()
	metrics := newTelemetry()

	assertHealth := func(want int) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		resp := httptest.NewRecorder()
		metrics.healthHandler(resp, req)
		if resp.Code != want {
			t.Fatalf("status = %d, want %d; body=%s", resp.Code, want, resp.Body.String())
		}
	}

	assertHealth(http.StatusServiceUnavailable)
	metrics.ready.Store(true)
	assertHealth(http.StatusOK)
	metrics.shuttingDown.Store(true)
	assertHealth(http.StatusServiceUnavailable)
}

func TestMetricsExposePipelineAndOutboxState(t *testing.T) {
	t.Parallel()
	metrics := newTelemetry()
	metrics.ready.Store(true)
	metrics.linesRead.Store(7)
	metrics.queueDepth.Store(3)
	metrics.incidentOutboxDepth.Store(2)
	metrics.decisionFailures.Store(3)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	resp := httptest.NewRecorder()
	metrics.metricsHandler(resp, req)
	body := resp.Body.String()
	for _, want := range []string{
		"clattermark_ready 1",
		"clattermark_lines_read_total 7",
		"clattermark_pipeline_queue_depth 3",
		"clattermark_incident_outbox_depth 2",
		"clattermark_decision_failures_total 3",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
}

func TestDecisionHistogramAndOutcomes(t *testing.T) {
	m := newTelemetry()
	m.observeDecision("allow", 0.2)
	m.observeDecision("timeout", 40)
	r := httptest.NewRecorder()
	m.metricsHandler(r, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, want := range []string{
		`clattermark_decision_requests_total{outcome="allow"} 1`,
		`clattermark_decision_requests_total{outcome="timeout"} 1`,
		`clattermark_decision_request_duration_seconds_bucket{le="0.1"} 0`,
		`clattermark_decision_request_duration_seconds_bucket{le="0.25"} 1`,
		`clattermark_decision_request_duration_seconds_bucket{le="40"} 2`,
		`clattermark_decision_request_duration_seconds_bucket{le="+Inf"} 2`,
		`clattermark_decision_request_duration_seconds_count 2`,
		`clattermark_decision_request_duration_seconds_sum 40.2`,
	} {
		if !strings.Contains(r.Body.String(), want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestWebServerExposesOperationalEndpointsWithoutAPITokens(t *testing.T) {
	t.Parallel()
	metrics := newTelemetry()
	metrics.ready.Store(true)
	server := newWebServer("127.0.0.1:0", newDynamicExcludesStore(nil), nil, nil, nil, metrics)

	for _, path := range []string{"/healthz", "/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		resp := httptest.NewRecorder()
		server.Handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want %d", path, resp.Code, http.StatusOK)
		}
	}
}

func TestSleepContextStopsOnCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepContext(ctx, time.Hour) {
		t.Fatal("sleep completed after cancellation")
	}
}
