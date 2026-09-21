package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDecisionRequestUsesConfiguredSource(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
		want   string
	}{
		{name: "default", want: "clattermark"},
		{name: "configured", source: "log_watcher", want: "log_watcher"},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := httpClient
			defer func() { httpClient = original }()
			var got decisionRequest
			httpClient = &http.Client{Transport: decisionTestTransport(func(r *http.Request) (*http.Response, error) {
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Fatal(err)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"decision":"allow","confidence":1}`)),
					Header:     make(http.Header),
				}, nil
			})}

			decision := shouldSendByDecisionService(DecisionServiceConfig{Enabled: true, URL: "http://example.test", Source: test.source}, "raw", nil, "formatted")
			if !decision.Send {
				t.Fatalf("decision = %+v", decision)
			}
			if got.Source != test.want || got.Metadata["component"] != test.want {
				t.Fatalf("source = %q, component = %q, want %q", got.Source, got.Metadata["component"], test.want)
			}
		})
	}
}

func TestDecisionCacheSharesOnlyConcurrentRequests(t *testing.T) {
	cache := newDecisionCache()
	var calls atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, _ := cache.GetOrEvaluate("same", func() alertDecision {
				calls.Add(1)
				time.Sleep(20 * time.Millisecond)
				return alertDecision{Outcome: "deny", TTLSeconds: 10}
			})
			if got.Outcome != "deny" {
				t.Errorf("wrong shared result: %+v", got)
			}
		}()
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("made %d calls for concurrent duplicates", calls.Load())
	}
	_, cached := cache.GetOrEvaluate("same", func() alertDecision { calls.Add(1); return alertDecision{Outcome: "allow", Send: true} })
	if cached || calls.Load() != 2 {
		t.Fatal("completed result was cached")
	}
}

type decisionTestTransport func(*http.Request) (*http.Response, error)

func (f decisionTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDecisionRequestUsesConfiguredDeadline(t *testing.T) {
	original := httpClient
	if original.Timeout != 0 {
		t.Fatal("HTTP client cap overrides the per-request timeout")
	}
	defer func() { httpClient = original }()
	httpClient = &http.Client{Transport: decisionTestTransport(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) < 39*time.Second || time.Until(deadline) > 40*time.Second {
			t.Errorf("unexpected request deadline: %v", deadline)
		}
		return nil, context.DeadlineExceeded
	})}
	got := shouldSendByDecisionService(DecisionServiceConfig{Enabled: true, URL: "http://example.test", TimeoutSeconds: 40}, "", nil, "")
	if got.Outcome != "timeout" || !got.ServiceFailed || !got.Send {
		t.Fatalf("timeout fallback: %+v", got)
	}
}

func TestDecisionRateLimitOutcome(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }))
	defer s.Close()
	got := shouldSendByDecisionService(DecisionServiceConfig{Enabled: true, URL: s.URL}, "", nil, "")
	if got.Outcome != "rate_limited" || !got.ServiceFailed {
		t.Fatalf("rate limit classified as %+v", got)
	}
}

func TestDecisionFailureMetricCountsCompletedRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	failOpen := false
	metrics := newTelemetry()
	engine := &alertEngine{
		monitors:        []monitor{{search: regexp.MustCompile("failed")}},
		dynamicExcludes: newDynamicExcludesStore(nil),
		decisionCfg:     DecisionServiceConfig{Enabled: true, URL: server.URL, FailOpen: &failOpen},
		decisionCache:   newDecisionCache(),
		metrics:         metrics,
	}
	line := "2026-09-08T12:00:00+02:00 host service[123]: operation failed"
	engine.checkLine(line)
	engine.checkLine(line)
	if got := metrics.decisionFailures.Load(); got != 2 {
		t.Fatalf("decision failures = %d, want two failed requests", got)
	}
	if metrics.decisionCacheHits.Load() != 0 {
		t.Fatal("completed fallback was cached")
	}
}

func TestDecisionResponseCarriesFeedbackFingerprint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"allow","confidence":0.9,"ttl_seconds":900,"fingerprint":"abc123"}`))
	}))
	defer server.Close()
	got := shouldSendByDecisionService(DecisionServiceConfig{Enabled: true, URL: server.URL}, "", nil, "")
	if !got.Send || got.Fingerprint != "abc123" {
		t.Fatalf("decision = %+v", got)
	}
}

func TestDecisionFailurePreservesFallbackPolicy(t *testing.T) {
	for _, failOpen := range []bool{true, false} {
		got := shouldSendByDecisionService(DecisionServiceConfig{Enabled: true, FailOpen: &failOpen}, "", nil, "")
		if !got.ServiceFailed || got.Send != failOpen {
			t.Fatalf("fallback policy %v: got %+v", failOpen, got)
		}
	}
	if got := shouldSendByDecisionService(DecisionServiceConfig{}, "", nil, ""); got.ServiceFailed {
		t.Fatal("disabled decision service counted as a failure")
	}
}
