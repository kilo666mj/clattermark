package main

import (
	"testing"
	"time"
)

func TestAlertFingerprintNormalizesVolatileValues(t *testing.T) {
	a := map[string]string{"host": "web01", "process": "nginx", "text": "connect to 192.0.2.10:8080 failed for request 12345"}
	b := map[string]string{"host": "web01", "process": "nginx", "text": "connect to 192.0.2.11:9090 failed for request 67890"}
	if alertFingerprint("", a) != alertFingerprint("", b) {
		t.Fatal("volatile values produced different fingerprints")
	}
	b["host"] = "web02"
	if alertFingerprint("", a) == alertFingerprint("", b) {
		t.Fatal("different hosts produced the same fingerprint")
	}
	b = map[string]string{"host": "web01", "process": "nginx", "text": "upstream returned status 500"}
	c := map[string]string{"host": "web01", "process": "nginx", "text": "upstream returned status 404"}
	if alertFingerprint("", b) == alertFingerprint("", c) {
		t.Fatal("meaningful short numbers were normalized")
	}
}

func TestFingerprintIgnoresStructuredLogTimestampOnly(t *testing.T) {
	a := map[string]string{"host": "dns", "process": "rill-api", "text": `{"time":"2026-09-07T17:58:01.123+02:00","level":"ERROR","msg":"read API token","error":"no such file"}`}
	b := map[string]string{"host": "dns", "process": "rill-api", "text": `{"time":"2026-09-07T18:05:59.456+02:00","level":"ERROR","msg":"read API token","error":"no such file"}`}
	if alertFingerprint("", a) != alertFingerprint("", b) {
		t.Fatal("embedded timestamps bypassed cache")
	}
	b["text"] = `{"time":"2026-09-07T18:05:59.456+02:00","level":"ERROR","msg":"read API token","error":"permission denied"}`
	if alertFingerprint("", a) == alertFingerprint("", b) {
		t.Fatal("different failure causes collapsed")
	}
	if normalizeAlertText("certificate expires 2026-09-07T17:58:01Z") == normalizeAlertText("certificate expires 2026-09-08T18:05:59Z") {
		t.Fatal("meaningful dates outside timestamp fields collapsed")
	}
}

func TestAlertFingerprintNormalizesBracketedIPv6Endpoints(t *testing.T) {
	a := map[string]string{"host": "mailtag", "process": "mailtag-viewer", "text": "read tcp [2a02:3102:a64c:1500::1]:43878->[2a00:1450:400c:c02::6d]:993: i/o timeout"}
	b := map[string]string{"host": "mailtag", "process": "mailtag-viewer", "text": "read tcp [2a02:3102:a64c:1500::2]:39326->[2a01:4f8:c17:28b::1]:993: i/o timeout"}
	if alertFingerprint("", a) != alertFingerprint("", b) {
		t.Fatal("volatile IPv6 endpoints produced different fingerprints")
	}
}

func TestAlertDeduperUsesDecisionTTL(t *testing.T) {
	d := newAlertDeduper(AlertDedupConfig{DefaultTTLSeconds: 900}, nil)
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	if !d.Allow("fingerprint", 60) {
		t.Fatal("first alert was suppressed")
	}
	if d.Allow("fingerprint", 60) {
		t.Fatal("duplicate alert was allowed")
	}
	now = now.Add(61 * time.Second)
	if !d.Allow("fingerprint", 60) {
		t.Fatal("alert remained suppressed after decision TTL")
	}
}

func TestAlertDeduperUsesDefaultTTL(t *testing.T) {
	d := newAlertDeduper(AlertDedupConfig{DefaultTTLSeconds: 30}, nil)
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	if !d.Allow("fingerprint", 0) || d.Allow("fingerprint", 0) {
		t.Fatal("default TTL did not suppress duplicate")
	}
	now = now.Add(31 * time.Second)
	if !d.Allow("fingerprint", 0) {
		t.Fatal("alert remained suppressed after default TTL")
	}
}

func TestAlertDeduperForgetAllowsDeliveryRetry(t *testing.T) {
	d := newAlertDeduper(AlertDedupConfig{}, nil)
	if !d.Allow("fingerprint", 60) {
		t.Fatal("first alert was suppressed")
	}
	d.Forget("fingerprint")
	if !d.Allow("fingerprint", 60) {
		t.Fatal("failed delivery could not be retried")
	}
}
