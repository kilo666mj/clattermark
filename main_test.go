package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplySecretsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	data := []byte(`{
		"keydb":{"password":"redis-secret"},
		"decision_service":{"token":"decision-secret"},
		"notifications":{"primary_url":"https://primary.example/hooks/token","secondary_url":"https://secondary.example/hooks/token"},
		"web":{"tokens":["slash-secret"],"api_tokens":["api-secret"]}
	}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := applySecretsFile(&cfg, path); err != nil {
		t.Fatal(err)
	}
	if cfg.KeyDB.Password != "redis-secret" || cfg.DecisionService.Token != "decision-secret" ||
		cfg.Notifications.PrimaryURL == "" || cfg.Notifications.SecondaryURL == "" ||
		len(cfg.Web.Tokens) != 1 || len(cfg.Web.APITokens) != 1 {
		t.Fatalf("secrets not applied: %#v", cfg)
	}
}

func TestApplySecretsFileAllowsPartialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(path, []byte(`{"keydb":{"password":"only-one-secret"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := applySecretsFile(&cfg, path); err != nil {
		t.Fatal(err)
	}
	if cfg.KeyDB.Password != "only-one-secret" {
		t.Fatalf("keydb password was not applied: %#v", cfg)
	}
}

func TestReadConfigAllowsMissingSecretsFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"keydb":{"host":"127.0.0.1:6379"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLATTERMARK_SECRETS_FILE", filepath.Join(dir, "missing-secrets.json"))
	cfg, err := readConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KeyDB.Host != "127.0.0.1:6379" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestParseLineFormats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, line, process, pid, text string
	}{
		{"nginx", `2026-08-28T12:00:00+02:00 web nginx 2026/08/28 12:00:00 [error] 123#456: upstream failed`, "nginx", "error", "upstream failed"},
		{"standard", `2026-08-28T12:00:00.123+02:00 mx postfix/smtpd[1234]: connection refused`, "postfix/smtpd", "1234", "connection refused"},
		{"level-pid", `2026-08-28T12:00:00+02:00 vpn stunnel LOG5[4321]: service failed`, "stunnel", "4321", "service failed"},
		{"no-pid", `2026-08-28T12:00:00+02:00 host kernel disk error`, "kernel", "", "disk error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLine(tt.line)
			if err != nil {
				t.Fatalf("parseLine: %v", err)
			}
			if got["process"] != tt.process || got["pid"] != tt.pid || got["text"] != tt.text {
				t.Fatalf("parsed = %#v", got)
			}
		})
	}
}

func TestMatchesProcessExclude(t *testing.T) {
	excludes := compileProcessExcludes([]string{"^ansible-", "^kernel$"})

	cases := map[string]bool{
		"ansible-ansible.legacy.apt": true,
		"kernel":                     true,
		"my-ansible-thing":           false, // anchored prefix only
		"kernel-watchdog":            false, // anchored exact only
		"postfix":                    false,
		"":                           false,
	}
	for process, want := range cases {
		if got := matchesProcessExclude(process, excludes); got != want {
			t.Errorf("matchesProcessExclude(%q) = %v, want %v", process, got, want)
		}
	}
}

func TestCompileProcessExcludesSkipsInvalid(t *testing.T) {
	excludes := compileProcessExcludes([]string{"^ansible-", "(", "^kernel$"})
	if len(excludes) != 2 {
		t.Fatalf("expected 2 valid patterns, got %d", len(excludes))
	}
}

func TestIsNonActionableStructuredLine(t *testing.T) {
	tests := []struct {
		name   string
		parsed map[string]string
		want   bool
	}{
		{"nginx access record", map[string]string{"process": "nginx_example", "pid": "000", "text": `GET /error HTTP/1.1`}, false},
		{"nginx error log", map[string]string{"process": "nginx_example", "pid": "error", "text": "upstream failed"}, false},
		{"ansible invocation", map[string]string{"process": "python3.13", "text": "ansible-ansible.builtin.apt Invoked with fail_on_autoremove=False"}, true},
		{"ansible result", map[string]string{"process": "python3.13", "text": "ansible task failed"}, false},
		{"snapd startup estimate", map[string]string{"process": "snapd", "text": "daemon.go:302: adjusting startup timeout by 50s (pessimistic estimate of 30s plus 5s per snap)"}, true},
		{"snapd real timeout", map[string]string{"process": "snapd", "text": "startup failed: timed out waiting for service"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNonActionableStructuredLine(tt.parsed, nil); got != tt.want {
				t.Fatalf("isNonActionableStructuredLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJSONExcludes(t *testing.T) {
	excludes := compileJSONExcludes([]JSONExcludeConfig{{
		Process:          `^agent-relay$`,
		BooleanFields:    map[string]bool{"complete": true},
		EmptyArrayFields: []string{"failures"},
	}})
	for _, test := range []struct {
		name    string
		process string
		text    string
		want    bool
	}{
		{name: "successful summary", process: "agent-relay", text: `{"complete":true,"failures":[]}`, want: true},
		{name: "whitespace and key order", process: "agent-relay", text: `{ "failures": [ ], "complete": true }`, want: true},
		{name: "incomplete", process: "agent-relay", text: `{"complete":false,"failures":[]}`},
		{name: "failure present", process: "agent-relay", text: `{"complete":true,"failures":["host1"]}`},
		{name: "null failures", process: "agent-relay", text: `{"complete":true,"failures":null}`},
		{name: "missing failures", process: "agent-relay", text: `{"complete":true}`},
		{name: "malformed JSON", process: "agent-relay", text: `{"complete":true`},
		{name: "wrong process", process: "other", text: `{"complete":true,"failures":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := matchesJSONExclude(map[string]string{"process": test.process, "text": test.text}, excludes)
			if got != test.want {
				t.Fatalf("matchesJSONExclude() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCompileJSONExcludesSkipsInvalid(t *testing.T) {
	excludes := compileJSONExcludes([]JSONExcludeConfig{
		{Process: "(", BooleanFields: map[string]bool{"complete": true}},
		{Process: "^agent-relay$"},
		{BooleanFields: map[string]bool{"complete": true}},
		{Process: "^valid$", EmptyArrayFields: []string{"failures"}},
	})
	if len(excludes) != 1 || !excludes[0].process.MatchString("valid") {
		t.Fatalf("compiled excludes = %#v", excludes)
	}
}

func TestCompileMonitors(t *testing.T) {
	monitors, err := compileMonitors(map[string]MonitorConfig{
		"warnings": {Search: `(?i)warning`, Excludes: []string{"expected warning"}},
		"errors":   {Search: `(?i)error`},
	})
	if err != nil {
		t.Fatalf("compileMonitors: %v", err)
	}
	if len(monitors) != 2 {
		t.Fatalf("monitor count = %d, want 2", len(monitors))
	}
	if monitors[0].name != "errors" || !monitors[0].search.MatchString("ERROR") {
		t.Fatalf("unexpected first monitor: %#v", monitors[0])
	}
}

func TestCompileMonitorsRejectsMissingSearch(t *testing.T) {
	_, err := compileMonitors(map[string]MonitorConfig{"broken": {Excludes: []string{"noise"}}})
	if err == nil {
		t.Fatal("missing search accepted")
	}
}

func TestCompileMonitorsRejectsInvalidRegex(t *testing.T) {
	_, err := compileMonitors(map[string]MonitorConfig{"broken": {Search: "("}})
	if err == nil {
		t.Fatal("invalid regex accepted")
	}
}

func TestAlertEngineStaticExcludeDoesNotNotify(t *testing.T) {
	monitors, err := compileMonitors(map[string]MonitorConfig{
		"errors": {Search: `error`, Excludes: []string{"expected error"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	deduper := newAlertDeduper(AlertDedupConfig{Enabled: true}, nil)
	engine := &alertEngine{
		monitors: monitors, dynamicExcludes: newDynamicExcludesStore(nil),
		deduper: deduper, dedupCfg: AlertDedupConfig{Enabled: true}, decisionCache: newDecisionCache(),
	}

	// A nil notifier makes an unexpected notification attempt fail the test by panic.
	engine.checkLine(`2026-08-28T12:00:00+02:00 host app[1]: expected error`)
}

func TestAlertEngineStructuredJSONExcludeDoesNotNotify(t *testing.T) {
	monitors, err := compileMonitors(map[string]MonitorConfig{
		"failures": {Search: `failure`},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine := &alertEngine{
		monitors:        monitors,
		dynamicExcludes: newDynamicExcludesStore(nil),
		jsonExcludes: compileJSONExcludes([]JSONExcludeConfig{{
			Process:          `^agent-relay$`,
			BooleanFields:    map[string]bool{"complete": true},
			EmptyArrayFields: []string{"failures"},
		}}),
		deduper:       newAlertDeduper(AlertDedupConfig{Enabled: true}, nil),
		dedupCfg:      AlertDedupConfig{Enabled: true},
		decisionCache: newDecisionCache(),
	}

	// A nil notifier makes an unexpected notification attempt fail by panic.
	engine.checkLine(`2026-09-21T12:00:00+02:00 host agent-relay[1]: {"complete":true,"failures":[]}`)
}

func TestPipelineConfigValues(t *testing.T) {
	workers, queueSize := PipelineConfig{}.values()
	if workers != 4 || queueSize != 1000 {
		t.Fatalf("defaults = %d workers, %d queue; want 4, 1000", workers, queueSize)
	}
	workers, queueSize = PipelineConfig{Workers: 2, QueueSize: 50}.values()
	if workers != 2 || queueSize != 50 {
		t.Fatalf("configured = %d workers, %d queue; want 2, 50", workers, queueSize)
	}
}
