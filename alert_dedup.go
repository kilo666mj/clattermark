package main

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

const defaultAlertDedupTTL = 15 * time.Minute

var (
	uuidPattern = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// Network logs conventionally wrap IPv6 literals in brackets so a following
	// colon can unambiguously introduce the port. Normalize the address while
	// leaving meaningful surrounding text intact.
	bracketedIPv6Pattern = regexp.MustCompile(`(?i)\[[0-9a-f:]+\]`)
	hexPattern           = regexp.MustCompile(`(?i)\b0x[0-9a-f]+\b`)
	// Long decimal values are usually ports, PIDs, counters, or request IDs. Keep
	// short values such as HTTP status codes distinct.
	numberPattern = regexp.MustCompile(`\b\d{4,}\b`)
	spacePattern  = regexp.MustCompile(`\s+`)
	// Only normalize structured log timestamp fields, not arbitrary dates in
	// error text (for example certificate expiry dates).
	logTimestampPattern = regexp.MustCompile(`("(?:time|timestamp|ts)"\s*:\s*")\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:\d{2})(")`)
)

type AlertDedupConfig struct {
	Enabled           bool `json:"enabled"`
	DefaultTTLSeconds int  `json:"default_ttl_seconds"`
}

type alertDeduper struct {
	mu         sync.Mutex
	expires    map[string]time.Time
	now        func() time.Time
	defaultTTL time.Duration
	store      dedupStore
}

type dedupStore interface {
	ReserveDedup(string, time.Duration) (bool, error)
	ForgetDedup(string) error
}

func newAlertDeduper(cfg AlertDedupConfig, store dedupStore) *alertDeduper {
	ttl := time.Duration(cfg.DefaultTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = defaultAlertDedupTTL
	}
	return &alertDeduper{expires: make(map[string]time.Time), now: time.Now, defaultTTL: ttl, store: store}
}

func normalizeAlertText(text string) string {
	text = strings.ToLower(text)
	text = logTimestampPattern.ReplaceAllString(text, "${1}<timestamp>${2}")
	text = uuidPattern.ReplaceAllString(text, "<uuid>")
	text = bracketedIPv6Pattern.ReplaceAllString(text, "<ip6>")
	text = ipv4Pattern.ReplaceAllString(text, "<ip>")
	text = hexPattern.ReplaceAllString(text, "<hex>")
	text = numberPattern.ReplaceAllString(text, "<n>")
	return strings.TrimSpace(spacePattern.ReplaceAllString(text, " "))
}

func alertFingerprint(rawLine string, parsed map[string]string) string {
	host, process, text := "<unknown>", "<unknown>", rawLine
	if parsed != nil {
		if parsed["host"] != "" {
			host = parsed["host"]
		}
		if parsed["process"] != "" {
			process = parsed["process"]
		}
		if parsed["text"] != "" {
			text = parsed["text"]
		}
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(host+"\x00"+process+"\x00"+normalizeAlertText(text))))
}

func (d *alertDeduper) Allow(fingerprint string, decisionTTLSeconds int) bool {
	ttl := time.Duration(decisionTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = d.defaultTTL
	}
	if d.store != nil {
		reserved, err := d.store.ReserveDedup(fingerprint, ttl)
		if err == nil {
			return reserved
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if expiry, ok := d.expires[fingerprint]; ok && now.Before(expiry) {
		return false
	}
	d.expires[fingerprint] = now.Add(ttl)
	for key, expiry := range d.expires {
		if !now.Before(expiry) {
			delete(d.expires, key)
		}
	}
	return true
}

func (d *alertDeduper) Forget(fingerprint string) {
	if d.store != nil {
		_ = d.store.ForgetDedup(fingerprint)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.expires, fingerprint)
}
