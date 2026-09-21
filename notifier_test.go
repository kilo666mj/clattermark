package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func TestAlertFeedbackActionsUseDecisionFingerprint(t *testing.T) {
	actions := alertFeedbackActions(
		DecisionServiceConfig{FeedbackActionTarget: "decision-feedback", Source: "log_watcher"},
		alertDecision{Fingerprint: "fingerprint-1"},
		map[string]string{"host": "web01", "process": "nginx"},
	)
	if len(actions) != 1 || actions[0].Label != "Not useful" || actions[0].Target != "decision-feedback" {
		t.Fatalf("actions = %#v", actions)
	}
	var context alertFeedbackContext
	if err := json.Unmarshal(actions[0].Context, &context); err != nil {
		t.Fatal(err)
	}
	if context.Fingerprint != "fingerprint-1" || context.Host != "web01" || context.Process != "nginx" || context.Source != "log_watcher" {
		t.Fatalf("context = %#v", context)
	}
}

func TestAlertFeedbackActionsDefaultSource(t *testing.T) {
	actions := alertFeedbackActions(
		DecisionServiceConfig{FeedbackActionTarget: "decision-feedback"},
		alertDecision{Fingerprint: "fingerprint-1"},
		map[string]string{"host": "web01"},
	)
	var context alertFeedbackContext
	if len(actions) != 1 {
		t.Fatalf("actions = %#v", actions)
	}
	if err := json.Unmarshal(actions[0].Context, &context); err != nil {
		t.Fatal(err)
	}
	if context.Source != "clattermark" {
		t.Fatalf("source = %q, want clattermark", context.Source)
	}
}

func TestAlertFeedbackActionsRequireTargetAndFingerprint(t *testing.T) {
	if got := alertFeedbackActions(DecisionServiceConfig{}, alertDecision{Fingerprint: "fingerprint-1"}, nil); got != nil {
		t.Fatalf("actions without target = %#v", got)
	}
	if got := alertFeedbackActions(DecisionServiceConfig{FeedbackActionTarget: "decision-feedback"}, alertDecision{}, nil); got != nil {
		t.Fatalf("actions without fingerprint = %#v", got)
	}
	if got := alertFeedbackActions(DecisionServiceConfig{FeedbackActionTarget: "decision-feedback"}, alertDecision{Fingerprint: "fingerprint-1"}, nil); got != nil {
		t.Fatalf("actions without host = %#v", got)
	}
}

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func response(status int) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}
}

func TestNotificationClientUsesNativeTintwireCard(t *testing.T) {
	var got tintwireCard
	client := newNotificationClient("https://tintwire.example/hooks/hook-token", "")
	client.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/v1/notifications" || r.Header.Get("Authorization") != "Bearer hook-token" {
			t.Errorf("request = %s, authorization = %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return response(http.StatusCreated), nil
	})

	card := logAlertCard(map[string]string{"host": "web01", "process": "nginx", "pid": "42", "tstmp": "now", "text": "upstream failed"})
	if err := client.Send(card, "legacy", "#alerts", "legacy text", ""); err != nil {
		t.Fatal(err)
	}
	if got.Channel != "#alerts" || got.Title != "nginx alert on web01" || got.Summary != "upstream failed" || len(got.Fields) != 4 {
		t.Fatalf("card = %#v", got)
	}
}

func TestNotificationClientUsesMattermostTemplateOnFallback(t *testing.T) {
	var got mattermostPayload
	requests := 0
	client := newNotificationClient("https://tintwire.example/hooks/hook-token", "https://matter.example/hooks/fallback")
	client.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return response(http.StatusServiceUnavailable), nil
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return response(http.StatusOK), nil
	})

	if err := client.Send(rawLogAlertCard("raw"), "clattermark - web01", "#alerts", "**legacy Mattermost**", "icon"); err != nil {
		t.Fatal(err)
	}
	if got.Text != "**legacy Mattermost**" || got.Username != "clattermark - web01" || got.Channel != "#alerts" || got.IconURL != "icon" {
		t.Fatalf("fallback payload = %#v", got)
	}
}

func TestNotificationClientUsesConfiguredDefaultChannel(t *testing.T) {
	var got tintwireCard
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := newNotificationClient(server.URL+"/hooks/test-token", "")
	client.defaultChannel = "ops-alerts"
	if err := client.Send(rawLogAlertCard("raw"), "clattermark", "", "raw", ""); err != nil {
		t.Fatal(err)
	}
	if got.Channel != "ops-alerts" {
		t.Fatalf("channel = %q, want ops-alerts", got.Channel)
	}
}
