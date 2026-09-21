package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeDynamicExcludesRepository struct {
	excludes map[string][]string
	err      error
}

func (f *fakeDynamicExcludesRepository) GetDynExcludes() (map[string][]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return cloneDynamicExcludes(f.excludes), nil
}

func (f *fakeDynamicExcludesRepository) UpdateDynExclude(excludeType, value string, add bool) (map[string][]string, bool, error) {
	if f.err != nil {
		return nil, false, f.err
	}
	store := newDynamicExcludesStore(f.excludes)
	var changed bool
	if add {
		changed = store.Mute(excludeType, value)
	} else {
		changed = store.Unmute(excludeType, value)
	}
	f.excludes = store.Snapshot()
	return cloneDynamicExcludes(f.excludes), changed, nil
}

func TestContainsToken(t *testing.T) {
	t.Parallel()

	if !containsToken([]string{"first", "correct-token"}, "correct-token") {
		t.Fatal("expected token to match")
	}
	if containsToken([]string{"first", "correct-token"}, "wrong-token") {
		t.Fatal("unexpected token match")
	}
}

func TestRequestLimiterUsesSocketPeerAndResets(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := newRequestLimiter(2, time.Minute)
	limiter.now = func() time.Time { return now }
	if !limiter.Allow("192.0.2.1:1000") || !limiter.Allow("192.0.2.1:2000") {
		t.Fatal("requests within limit rejected")
	}
	if limiter.Allow("192.0.2.1:3000") {
		t.Fatal("request over limit accepted")
	}
	if !limiter.Allow("192.0.2.2:1000") {
		t.Fatal("different peer shared rate window")
	}
	now = now.Add(time.Minute)
	if !limiter.Allow("192.0.2.1:4000") {
		t.Fatal("window did not reset")
	}
}

func TestSlashHandlerRejectsInvalidToken(t *testing.T) {
	t.Parallel()

	h := &slashHandler{
		dynamicExcludes: newDynamicExcludesStore(nil),
		tokens:          []string{"correct-token"},
	}
	form := url.Values{"token": {"wrong-token"}, "text": {"status"}}
	req := httptest.NewRequest(http.MethodPost, "/slash", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	h.ServeHTTP(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusUnauthorized)
	}
}

func TestSlashHandlerDoesNotRouteTextContainingMute(t *testing.T) {
	t.Parallel()

	store := newDynamicExcludesStore(nil)
	h := &slashHandler{dynamicExcludes: store, tokens: []string{"correct-token"}}
	form := url.Values{"token": {"correct-token"}, "text": {"show muted processes"}}
	req := httptest.NewRequest(http.MethodPost, "/slash", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	h.ServeHTTP(resp, req)

	if got := store.Snapshot(); len(got) != 0 {
		t.Fatalf("unexpected excludes: %#v", got)
	}
}

func TestAPIHandlerRejectsInvalidToken(t *testing.T) {
	t.Parallel()

	h := &apiHandler{
		dynamicExcludes: newDynamicExcludesStore(nil),
		tokens:          []string{"correct-token"},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/mute", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp := httptest.NewRecorder()

	h.ServeHTTP(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusUnauthorized)
	}
}

func TestExcludesAPIListsCanonicalState(t *testing.T) {
	t.Parallel()
	repository := &fakeDynamicExcludesRepository{excludes: map[string][]string{"process": {"decision-service"}}}
	store := newDynamicExcludesStore(nil)
	h := &excludesAPIHandler{dynamicExcludes: store, repository: repository, tokens: []string{"correct-token"}}
	req := httptest.NewRequest(http.MethodGet, "/api/excludes", nil)
	req.Header.Set("Authorization", "Bearer correct-token")
	resp := httptest.NewRecorder()

	h.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusOK)
	}
	var got apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Excludes["process"]) != 1 || got.Excludes["process"][0] != "decision-service" {
		t.Fatalf("unexpected excludes: %#v", got.Excludes)
	}
	if len(store.Snapshot()["process"]) != 1 {
		t.Fatal("in-memory store was not refreshed")
	}
}

func TestExcludesAPIAddIsValidatedAndIdempotent(t *testing.T) {
	t.Parallel()
	repository := &fakeDynamicExcludesRepository{}
	h := &excludesAPIHandler{dynamicExcludes: newDynamicExcludesStore(nil), repository: repository, tokens: []string{"correct-token"}}

	for i, wantChanged := range []bool{true, false} {
		req := httptest.NewRequest(http.MethodPost, "/api/excludes", strings.NewReader(`{"type":"text","value":"routine noise","reason":"verified false positive"}`))
		req.Header.Set("Authorization", "Bearer correct-token")
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("call %d status = %d, want %d", i, resp.Code, http.StatusOK)
		}
		var got apiResponse
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Changed != wantChanged {
			t.Fatalf("call %d changed = %t, want %t", i, got.Changed, wantChanged)
		}
	}
}

func TestExcludesAPIRequiresKnownTypeAndReason(t *testing.T) {
	t.Parallel()
	h := &excludesAPIHandler{dynamicExcludes: newDynamicExcludesStore(nil), repository: &fakeDynamicExcludesRepository{}, tokens: []string{"correct-token"}}
	for _, body := range []string{
		`{"type":"unknown","value":"noise","reason":"test"}`,
		`{"type":"text","value":"noise"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/excludes", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer correct-token")
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d for %s", resp.Code, http.StatusBadRequest, body)
		}
	}
}

func TestExcludesAPIDoesNotMutateMemoryWhenPersistenceFails(t *testing.T) {
	t.Parallel()
	store := newDynamicExcludesStore(map[string][]string{"text": {"existing"}})
	h := &excludesAPIHandler{dynamicExcludes: store, repository: &fakeDynamicExcludesRepository{err: errors.New("unavailable")}, tokens: []string{"correct-token"}}
	req := httptest.NewRequest(http.MethodPost, "/api/excludes", strings.NewReader(`{"type":"text","value":"new","reason":"test"}`))
	req.Header.Set("Authorization", "Bearer correct-token")
	resp := httptest.NewRecorder()

	h.ServeHTTP(resp, req)

	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusServiceUnavailable)
	}
	if got := store.Snapshot()["text"]; len(got) != 1 || got[0] != "existing" {
		t.Fatalf("store changed after persistence failure: %#v", got)
	}
}
