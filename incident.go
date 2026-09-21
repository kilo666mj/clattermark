package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kilo666mj/clattermark/keydb"
)

const incidentRecoveryOutboxKey = "incident:v1:recovery-outbox"

type IncidentAggregationConfig struct {
	Enabled           bool           `json:"enabled"`
	QuietSeconds      int            `json:"quiet_seconds"`
	ReminderEvery     int            `json:"reminder_every"`
	SweepSeconds      int            `json:"sweep_seconds"`
	RecoveryOutboxMax int64          `json:"recovery_outbox_max"`
	Rules             []IncidentRule `json:"rules"`
}

type IncidentRule struct {
	Name     string   `json:"name"`
	Title    string   `json:"title"`
	Patterns []string `json:"patterns"`
}

type compiledIncidentRule struct {
	IncidentRule
	patterns []*regexp.Regexp
}

type incidentRecovery struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	FirstSeenMS string   `json:"first_seen_ms"`
	LastSeenMS  string   `json:"last_seen_ms"`
	Count       string   `json:"count"`
	Sample      string   `json:"sample"`
	Hosts       []string `json:"hosts"`
	Processes   []string `json:"processes"`
}

type incidentAggregator struct {
	cfg      IncidentAggregationConfig
	store    *keydb.Keydb
	rules    []compiledIncidentRule
	notifier *notificationClient
	iconURL  string
	isActive func() bool
	metrics  *telemetry
}

func newIncidentAggregator(cfg IncidentAggregationConfig, store *keydb.Keydb, notifier *notificationClient, iconURL string, isActive func() bool) (*incidentAggregator, error) {
	a := &incidentAggregator{cfg: cfg, store: store, notifier: notifier, iconURL: iconURL, isActive: isActive}
	if !cfg.Enabled {
		return a, nil
	}
	if store == nil || notifier == nil {
		return nil, fmt.Errorf("incident aggregation requires KeyDB and notifier")
	}
	if cfg.QuietSeconds <= 0 || cfg.ReminderEvery <= 0 {
		return nil, fmt.Errorf("incident aggregation quiet_seconds and reminder_every must be positive")
	}
	seen := map[string]bool{}
	for _, rule := range cfg.Rules {
		if strings.TrimSpace(rule.Name) == "" || strings.TrimSpace(rule.Title) == "" || len(rule.Patterns) == 0 {
			return nil, fmt.Errorf("incident aggregation rules require name, title, and patterns")
		}
		if seen[rule.Name] {
			return nil, fmt.Errorf("duplicate incident aggregation rule %q", rule.Name)
		}
		seen[rule.Name] = true
		compiled := compiledIncidentRule{IncidentRule: rule}
		for _, pattern := range rule.Patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("incident aggregation rule %q pattern %q: %w", rule.Name, pattern, err)
			}
			compiled.patterns = append(compiled.patterns, re)
		}
		a.rules = append(a.rules, compiled)
	}
	return a, nil
}

func (a *incidentAggregator) Match(line string, parsed map[string]string) *compiledIncidentRule {
	if a == nil || !a.cfg.Enabled {
		return nil
	}
	text := line
	if parsed != nil && parsed["text"] != "" {
		text = parsed["text"]
	}
	for i := range a.rules {
		for _, pattern := range a.rules[i].patterns {
			if pattern.MatchString(text) {
				return &a.rules[i]
			}
		}
	}
	return nil
}

func (a *incidentAggregator) Record(rule *compiledIncidentRule, parsed map[string]string, sample string) (keydb.IncidentUpdate, error) {
	host, process := "", ""
	if parsed != nil {
		host, process = parsed["host"], parsed["process"]
	}
	return a.store.RecordIncident(rule.Name, rule.Title, truncateUTF8(sample, 500), host, process,
		time.Now().UTC(), time.Duration(a.cfg.QuietSeconds)*time.Second, a.cfg.ReminderEvery)
}

func incidentNotification(rule *compiledIncidentRule, update keydb.IncidentUpdate, parsed map[string]string, sample string) (tintwireCard, string) {
	first := time.UnixMilli(update.FirstSeenMS).UTC()
	title := rule.Title
	summary := truncateUTF8(sample, 500)
	if update.Count > 1 {
		title += " update"
		summary = fmt.Sprintf("%d related events since %s. Latest: %s", update.Count, first.Format(time.RFC3339), truncateUTF8(sample, 350))
	}
	fields := []tintwireField{{Label: "Events", Value: strconv.Itoa(update.Count)}, {Label: "First seen", Value: first.Format(time.RFC3339)}}
	if parsed != nil && parsed["host"] != "" {
		fields = append(fields, tintwireField{Label: "Latest host", Value: parsed["host"]})
	}
	card := tintwireCard{Version: 1, Title: title, Summary: summary, Severity: "warning", Source: "clattermark", Fields: fields}
	return card, fmt.Sprintf("**%s** — %s", title, summary)
}

func (a *incidentAggregator) Release(rule *compiledIncidentRule, count int) {
	if err := a.store.ReleaseIncidentNotification(rule.Name, count); err != nil {
		log.Printf("incident notification release name=%q count=%d err=%v", rule.Name, count, err)
	}
}

func (a *incidentAggregator) Start(ctx context.Context) {
	if a == nil || !a.cfg.Enabled {
		return
	}
	interval := time.Duration(a.cfg.SweepSeconds) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if a.isActive != nil && !a.isActive() {
					continue
				}
				a.closeQuiet()
				a.publishRecoveries()
			}
		}
	}()
}

func (a *incidentAggregator) closeQuiet() {
	cutoff := time.Now().UTC().Add(-time.Duration(a.cfg.QuietSeconds) * time.Second)
	names, err := a.store.DueIncidents(cutoff, 100)
	if err != nil {
		if a.metrics != nil {
			a.metrics.keyDBFailures.Add(1)
		}
		log.Printf("incident due scan: %v", err)
		return
	}
	max := a.cfg.RecoveryOutboxMax
	if max <= 0 {
		max = 1000
	}
	for _, name := range names {
		if _, err := a.store.CloseIncidentToOutbox(name, cutoff, max); err != nil {
			if a.metrics != nil {
				a.metrics.keyDBFailures.Add(1)
			}
			log.Printf("incident close name=%q: %v", name, err)
		}
	}
}

func (a *incidentAggregator) publishRecoveries() {
	raw, err := a.store.PeekQueue(incidentRecoveryOutboxKey, 20)
	if err != nil || len(raw) == 0 {
		if err != nil {
			if a.metrics != nil {
				a.metrics.keyDBFailures.Add(1)
			}
			log.Printf("incident recovery outbox read: %v", err)
		}
		return
	}
	delivered := int64(0)
	for _, item := range raw {
		var recovery incidentRecovery
		if err := json.Unmarshal([]byte(item), &recovery); err != nil {
			log.Printf("incident recovery outbox decode; dropping item: %v", err)
			delivered++
			continue
		}
		sort.Strings(recovery.Hosts)
		sort.Strings(recovery.Processes)
		count, _ := strconv.Atoi(recovery.Count)
		firstMS, _ := strconv.ParseInt(recovery.FirstSeenMS, 10, 64)
		lastMS, _ := strconv.ParseInt(recovery.LastSeenMS, 10, 64)
		duration := time.Duration(lastMS-firstMS) * time.Millisecond
		summary := fmt.Sprintf("No related events for %d seconds after %d event(s) over %s.", a.cfg.QuietSeconds, count, duration.Round(time.Second))
		fields := []tintwireField{{Label: "Events", Value: strconv.Itoa(count)}}
		if len(recovery.Hosts) > 0 {
			fields = append(fields, tintwireField{Label: "Hosts", Value: strings.Join(recovery.Hosts, ", ")})
		}
		if len(recovery.Processes) > 0 {
			fields = append(fields, tintwireField{Label: "Processes", Value: strings.Join(recovery.Processes, ", ")})
		}
		card := tintwireCard{Version: 1, Title: recovery.Title + " quiet", Summary: summary, Severity: "info", Source: "clattermark", Fields: fields}
		if err := a.notifier.Send(card, "clattermark", "", fmt.Sprintf("**%s quiet** — %s", recovery.Title, summary), a.iconURL); err != nil {
			if a.metrics != nil {
				a.metrics.outboxPublishFailures.Add(1)
			}
			log.Printf("incident recovery notification name=%q: %v", recovery.Name, err)
			break
		}
		delivered++
	}
	if delivered > 0 {
		if err := a.store.DropQueue(incidentRecoveryOutboxKey, delivered); err != nil {
			if a.metrics != nil {
				a.metrics.keyDBFailures.Add(1)
			}
			log.Printf("incident recovery outbox drop: %v", err)
		}
	}
}
