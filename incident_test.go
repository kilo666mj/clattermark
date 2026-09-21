package main

import (
	"regexp"
	"testing"
)

func TestIncidentAggregatorRequiresDependencies(t *testing.T) {
	cfg := IncidentAggregationConfig{
		Enabled: true, QuietSeconds: 900, ReminderEvery: 25,
		Rules: []IncidentRule{{Name: "dns", Title: "DNS incident", Patterns: []string{`timeout`}}},
	}
	aggregator, err := newIncidentAggregator(cfg, nil, nil, "", nil)
	if err == nil || aggregator != nil {
		t.Fatal("enabled aggregator accepted missing dependencies")
	}
	cfg.Enabled = false
	aggregator, err = newIncidentAggregator(cfg, nil, nil, "", nil)
	if err != nil || aggregator == nil {
		t.Fatalf("disabled aggregator: %v", err)
	}
}

func TestIncidentRulesMatchOnlyConfiguredSymptoms(t *testing.T) {
	cfg := IncidentAggregationConfig{
		Enabled: true, QuietSeconds: 900, ReminderEvery: 25,
		Rules: []IncidentRule{{Name: "dns", Title: "DNS incident", Patterns: []string{`(?i)temporary failure in name resolution`, `(?i)lookup .*: i/o timeout`}}},
	}
	aggregator := &incidentAggregator{cfg: cfg}
	for _, rule := range cfg.Rules {
		compiled := compiledIncidentRule{IncidentRule: rule}
		for _, pattern := range rule.Patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				t.Fatal(err)
			}
			compiled.patterns = append(compiled.patterns, re)
		}
		aggregator.rules = append(aggregator.rules, compiled)
	}
	tests := []struct {
		text string
		want bool
	}{
		{`policy sync: lookup api.example.com on 127.0.0.1:53: i/o timeout`, true},
		{`Failed to connect (getaddrinfo: Temporary failure in name resolution)`, true},
		{`container startup failed`, false},
		{`authentication failure`, false},
	}
	for _, tt := range tests {
		matched := aggregator.Match("", map[string]string{"text": tt.text}) != nil
		if matched != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.text, matched, tt.want)
		}
	}
}
