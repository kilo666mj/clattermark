package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type notificationClient struct {
	tintwireURL    string
	mattermostURL  string
	defaultChannel string
	httpClient     *http.Client
}

type tintwireCard struct {
	Version  int              `json:"version"`
	Channel  string           `json:"channel,omitempty"`
	Title    string           `json:"title"`
	Summary  string           `json:"summary"`
	Severity string           `json:"severity"`
	Source   string           `json:"source"`
	Fields   []tintwireField  `json:"fields,omitempty"`
	Actions  []tintwireAction `json:"actions,omitempty"`
}

type tintwireField struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type tintwireAction struct {
	Label   string          `json:"label"`
	Type    string          `json:"type"`
	Target  string          `json:"target"`
	Context json.RawMessage `json:"context,omitempty"`
}

type alertFeedbackContext struct {
	Feedback    string `json:"feedback"`
	Source      string `json:"source"`
	Kind        string `json:"kind"`
	Policy      string `json:"policy"`
	Fingerprint string `json:"fingerprint"`
	Host        string `json:"host,omitempty"`
	Process     string `json:"process,omitempty"`
}

func alertFeedbackActions(cfg DecisionServiceConfig, decision alertDecision, parsed map[string]string) []tintwireAction {
	target := strings.TrimSpace(cfg.FeedbackActionTarget)
	if target == "" || decision.Fingerprint == "" || strings.TrimSpace(parsed["host"]) == "" {
		return nil
	}
	context, err := json.Marshal(alertFeedbackContext{
		Feedback: "not_useful", Source: "clattermark", Kind: "log_alert", Policy: "send_alert",
		Fingerprint: decision.Fingerprint, Host: parsed["host"], Process: parsed["process"],
	})
	if err != nil {
		return nil
	}
	return []tintwireAction{{Label: "Not useful", Type: "http", Target: target, Context: context}}
}

type mattermostPayload struct {
	Username string `json:"username"`
	Channel  string `json:"channel"`
	Text     string `json:"text"`
	IconURL  string `json:"icon_url,omitempty"`
}

func newNotificationClient(tintwireURL, mattermostURL string) *notificationClient {
	return &notificationClient{
		tintwireURL: tintwireURL, mattermostURL: mattermostURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *notificationClient) Send(card tintwireCard, username, channel, mattermostText, iconURL string) error {
	if channel == "" {
		channel = c.defaultChannel
	}
	card.Channel = channel
	primaryErr := c.sendTintwire(card)
	if primaryErr == nil {
		return nil
	}
	if c.mattermostURL == "" {
		return primaryErr
	}
	payload := mattermostPayload{Username: username, Channel: channel, Text: mattermostText, IconURL: iconURL}
	if err := c.postJSON(c.mattermostURL, "", payload); err != nil {
		return fmt.Errorf("tintwire: %v; mattermost fallback: %w", primaryErr, err)
	}
	return nil
}

func (c *notificationClient) sendTintwire(card tintwireCard) error {
	endpoint, token, err := tintwireEndpoint(c.tintwireURL)
	if err != nil {
		return err
	}
	return c.postJSON(endpoint, "Bearer "+token, card)
}

func tintwireEndpoint(hookURL string) (string, string, error) {
	u, err := url.Parse(hookURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", errors.New("invalid Tintwire webhook URL")
	}
	const marker = "/hooks/"
	index := strings.Index(u.Path, marker)
	if index < 0 || strings.TrimSpace(u.Path[index+len(marker):]) == "" {
		return "", "", errors.New("tintwire URL must contain /hooks/<token>")
	}
	token := strings.Trim(u.Path[index+len(marker):], "/")
	u.Path = "/api/v1/notifications"
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	return u.String(), token, nil
}

func (c *notificationClient) postJSON(endpoint, authorization string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal notification: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("endpoint returned %s", resp.Status)
	}
	return nil
}

func logAlertCard(parsed map[string]string) tintwireCard {
	fields := []tintwireField{{Label: "Host", Value: parsed["host"]}, {Label: "Process", Value: parsed["process"]}}
	if parsed["pid"] != "" {
		fields = append(fields, tintwireField{Label: "PID", Value: parsed["pid"]})
	}
	fields = append(fields, tintwireField{Label: "Timestamp", Value: parsed["tstmp"]})
	title := "Log alert"
	if parsed["process"] != "" && parsed["host"] != "" {
		title = fmt.Sprintf("%s alert on %s", parsed["process"], parsed["host"])
	}
	return tintwireCard{Version: 1, Title: title, Summary: truncateUTF8(parsed["text"], 500), Severity: "warning", Source: "clattermark", Fields: fields}
}

func rawLogAlertCard(line string) tintwireCard {
	return tintwireCard{Version: 1, Title: "Unparsed log alert", Summary: truncateUTF8(line, 500), Severity: "warning", Source: "clattermark"}
}

func truncateUTF8(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	lastBoundary := 0
	for index := range value {
		if index > maxBytes {
			return value[:lastBoundary]
		}
		lastBoundary = index
	}
	return value[:lastBoundary]
}
