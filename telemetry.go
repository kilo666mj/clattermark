package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type telemetry struct {
	decisionMu              sync.Mutex
	decisionOutcomes        map[string]uint64
	decisionDurationBuckets [13]uint64
	decisionDurationSum     float64
	decisionDurationCount   uint64
	startedAt               time.Time
	ready                   atomic.Bool
	shuttingDown            atomic.Bool
	linesRead               atomic.Uint64
	jobsStarted             atomic.Uint64
	jobsCompleted           atomic.Uint64
	queueDepth              atomic.Int64
	queueSaturations        atomic.Uint64
	tailRestarts            atomic.Uint64
	decisionCacheHits       atomic.Uint64
	decisionCacheMisses     atomic.Uint64
	decisionFailures        atomic.Uint64
	notificationFailures    atomic.Uint64
	keyDBFailures           atomic.Uint64
	outboxPublishFailures   atomic.Uint64
	incidentOutboxDepth     atomic.Int64
	lastLineUnix            atomic.Int64
}

var decisionDurationBounds = [...]float64{0.1, 0.25, 0.5, 1, 2, 4, 8, 10, 15, 20, 30, 40, 60}
var decisionOutcomes = [...]string{"allow", "deny", "low_confidence", "timeout", "rate_limited", "http_error", "request_error", "configuration_error"}

func (m *telemetry) observeDecision(outcome string, seconds float64) {
	m.decisionMu.Lock()
	defer m.decisionMu.Unlock()
	if m.decisionOutcomes == nil {
		m.decisionOutcomes = make(map[string]uint64)
	}
	m.decisionOutcomes[outcome]++
	m.decisionDurationCount++
	m.decisionDurationSum += seconds
	for i, bound := range decisionDurationBounds {
		if seconds <= bound {
			m.decisionDurationBuckets[i]++
		}
	}
}

func (m *telemetry) writeDecisionMetrics(w http.ResponseWriter) {
	m.decisionMu.Lock()
	counts := make(map[string]uint64, len(m.decisionOutcomes))
	for k, v := range m.decisionOutcomes {
		counts[k] = v
	}
	buckets, sum, count := m.decisionDurationBuckets, m.decisionDurationSum, m.decisionDurationCount
	m.decisionMu.Unlock()
	fmt.Fprintln(w, "# TYPE clattermark_decision_requests_total counter")
	for _, outcome := range decisionOutcomes {
		fmt.Fprintf(w, "clattermark_decision_requests_total{outcome=%q} %d\n", outcome, counts[outcome])
	}
	fmt.Fprintln(w, "# TYPE clattermark_decision_request_duration_seconds histogram")
	for i, bound := range decisionDurationBounds {
		fmt.Fprintf(w, "clattermark_decision_request_duration_seconds_bucket{le=%q} %d\n", fmt.Sprint(bound), buckets[i])
	}
	fmt.Fprintf(w, "clattermark_decision_request_duration_seconds_bucket{le=\"+Inf\"} %d\nclattermark_decision_request_duration_seconds_sum %g\nclattermark_decision_request_duration_seconds_count %d\n", count, sum, count)
}

func newTelemetry() *telemetry {
	return &telemetry{startedAt: time.Now()}
}

func (m *telemetry) healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	status := "ok"
	code := http.StatusOK
	if !m.ready.Load() || m.shuttingDown.Load() {
		status = "unavailable"
		code = http.StatusServiceUnavailable
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":         status,
		"ready":          m.ready.Load(),
		"shutting_down":  m.shuttingDown.Load(),
		"uptime_seconds": int64(time.Since(m.startedAt).Seconds()),
	})
}

func (m *telemetry) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	ready := 0
	if m.ready.Load() && !m.shuttingDown.Load() {
		ready = 1
	}
	_, _ = fmt.Fprintf(w, `# TYPE clattermark_ready gauge
clattermark_ready %d
# TYPE clattermark_uptime_seconds gauge
clattermark_uptime_seconds %.0f
# TYPE clattermark_lines_read_total counter
clattermark_lines_read_total %d
# TYPE clattermark_pipeline_jobs_started_total counter
clattermark_pipeline_jobs_started_total %d
# TYPE clattermark_pipeline_jobs_completed_total counter
clattermark_pipeline_jobs_completed_total %d
# TYPE clattermark_pipeline_queue_depth gauge
clattermark_pipeline_queue_depth %d
# TYPE clattermark_pipeline_queue_saturations_total counter
clattermark_pipeline_queue_saturations_total %d
# TYPE clattermark_tail_restarts_total counter
clattermark_tail_restarts_total %d
# TYPE clattermark_decision_cache_hits_total counter
clattermark_decision_cache_hits_total %d
# TYPE clattermark_decision_cache_misses_total counter
clattermark_decision_cache_misses_total %d
# TYPE clattermark_decision_failures_total counter
clattermark_decision_failures_total %d
# TYPE clattermark_notification_failures_total counter
clattermark_notification_failures_total %d
# TYPE clattermark_keydb_failures_total counter
clattermark_keydb_failures_total %d
# TYPE clattermark_outbox_publish_failures_total counter
clattermark_outbox_publish_failures_total %d
# TYPE clattermark_incident_outbox_depth gauge
clattermark_incident_outbox_depth %d
# TYPE clattermark_last_line_timestamp_seconds gauge
clattermark_last_line_timestamp_seconds %d
`, ready, time.Since(m.startedAt).Seconds(), m.linesRead.Load(), m.jobsStarted.Load(),
		m.jobsCompleted.Load(), m.queueDepth.Load(), m.queueSaturations.Load(), m.tailRestarts.Load(),
		m.decisionCacheHits.Load(), m.decisionCacheMisses.Load(), m.decisionFailures.Load(), m.notificationFailures.Load(),
		m.keyDBFailures.Load(), m.outboxPublishFailures.Load(), m.incidentOutboxDepth.Load(),
		m.lastLineUnix.Load())
	m.writeDecisionMetrics(w)
}
