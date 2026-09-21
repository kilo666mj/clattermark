package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxDynamicExcludeValueBytes = 1024

var allowedDynamicExcludeTypes = map[string]bool{
	"host": true, "pid": true, "process": true, "text": true,
}

type dynamicExcludesRepository interface {
	GetDynExcludes() (map[string][]string, error)
	UpdateDynExclude(excludeType, value string, add bool) (map[string][]string, bool, error)
}

type slashHandler struct {
	dynamicExcludes *dynamicExcludesStore
	repository      dynamicExcludesRepository
	tokens          []string
	limiter         *requestLimiter
}

type rateWindow struct {
	start time.Time
	count int
}

type requestLimiter struct {
	mu       sync.Mutex
	windows  map[string]rateWindow
	limit    int
	duration time.Duration
	now      func() time.Time
}

func newRequestLimiter(limit int, duration time.Duration) *requestLimiter {
	return &requestLimiter{windows: make(map[string]rateWindow), limit: limit, duration: duration, now: time.Now}
}

func (l *requestLimiter) Allow(remoteAddress string) bool {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	window := l.windows[host]
	if window.start.IsZero() || now.Sub(window.start) >= l.duration {
		window = rateWindow{start: now}
	}
	window.count++
	l.windows[host] = window
	return window.count <= l.limit
}

func popFirst(slice []string) ([]string, error) {
	if len(slice) == 0 {
		return nil, fmt.Errorf("slice is empty")
	}
	return slice[1:], nil
}

func genExcludeTable(excludes map[string][]string) string {
	var messageStr string
	if len(excludes) == 0 {
		messageStr = "No excludes found"
	} else {
		messageStr = "### Clattermark Dynamic Excludes\n"
		messageStr += "| Type | Excludes |\n"
		messageStr += "|:---------------|:----|\n"
		for excludeType, excludeList := range excludes {
			strExcludeList := strings.Join(excludeList, ", ")
			messageStr += fmt.Sprintf("| %v | %v |\n", excludeType, strExcludeList)
		}
	}
	return messageStr
}

func containsToken(values []string, want string) bool {
	for _, value := range values {
		if subtle.ConstantTimeCompare([]byte(value), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

func (h *slashHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.limiter != nil && !h.limiter.Allow(r.RemoteAddr) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if r.Method == http.MethodPost {
		token := r.FormValue("token")
		data := r.FormValue("text")
		if !containsToken(h.tokens, token) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Incorrect token passed"))
			return
		}
		// Just status was given, return the current excludes
		if data == "status" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(genExcludeTable(h.dynamicExcludes.Snapshot())))
			return
		}
		// Mute or unmute was given, process the command
		splitData := strings.Fields(data)
		if len(splitData) > 0 && (splitData[0] == "mute" || splitData[0] == "unmute") {
			// Check if we received enough parameters
			if len(splitData) < 3 {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Invalid command"))
				return
			}
			command := splitData[0]
			splitData, _ = popFirst(splitData)
			excludeType := splitData[0]
			splitData, _ = popFirst(splitData)
			if excludeType != "text" && len(splitData) > 1 {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("You must provide an exclude type."))
				return
			}
			var exclude string
			if excludeType == "text" {
				exclude = strings.Join(splitData, " ")
			} else {
				exclude = splitData[0]
			}
			if err := validateDynamicExclude(excludeType, exclude); err != nil {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(err.Error()))
				return
			}
			_, changed, err := updateDynamicExclude(h.repository, h.dynamicExcludes, excludeType, exclude, command == "mute")
			if err != nil {
				log.Println("slash: failed to persist excludes:", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error saving excludes to keydb"))
				return
			}
			if command == "mute" {
				if !changed {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(fmt.Sprintf("%v already exists in %v", exclude, excludeType)))
					return
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(fmt.Sprintf("Added %v to %v", exclude, excludeType)))
			} else if command == "unmute" {
				if !changed {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(fmt.Sprintf("%v does not exist in %v", exclude, excludeType)))
					return
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(fmt.Sprintf("Removed %v from %v", exclude, excludeType)))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Invalid command"))
				return
			}
		}
	}
}

type apiHandler struct {
	dynamicExcludes *dynamicExcludesStore
	repository      dynamicExcludesRepository
	tokens          []string
	limiter         *requestLimiter
}

type apiRequest struct {
	Command string `json:"command"`
	Type    string `json:"type"`
	Value   string `json:"value"`
}

type apiResponse struct {
	Message  string              `json:"message,omitempty"`
	Error    string              `json:"error,omitempty"`
	Type     string              `json:"type,omitempty"`
	Value    string              `json:"value,omitempty"`
	Changed  bool                `json:"changed"`
	Excludes map[string][]string `json:"excludes,omitempty"`
}

func validateDynamicExclude(excludeType, value string) error {
	if !allowedDynamicExcludeTypes[excludeType] {
		return fmt.Errorf("type must be one of host, pid, process, or text")
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("value is required")
	}
	if len(value) > maxDynamicExcludeValueBytes {
		return fmt.Errorf("value must be at most %d bytes", maxDynamicExcludeValueBytes)
	}
	return nil
}

func updateDynamicExclude(repository dynamicExcludesRepository, store *dynamicExcludesStore, excludeType, value string, add bool) (map[string][]string, bool, error) {
	if repository == nil {
		return nil, false, fmt.Errorf("dynamic excludes repository is unavailable")
	}
	excludes, changed, err := repository.UpdateDynExclude(excludeType, value, add)
	if err != nil {
		return nil, false, err
	}
	store.Replace(excludes)
	return excludes, changed, nil
}

func (h *apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if h.limiter != nil && !h.limiter.Allow(r.RemoteAddr) {
		w.WriteHeader(http.StatusTooManyRequests)
		enc.Encode(apiResponse{Error: "rate limit exceeded"}) //nolint:errcheck
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		enc.Encode(apiResponse{Error: "method not allowed"}) //nolint:errcheck
		return
	}
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || !containsToken(h.tokens, token) {
		w.WriteHeader(http.StatusUnauthorized)
		enc.Encode(apiResponse{Error: "unauthorized"}) //nolint:errcheck
		return
	}
	var req apiRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(apiResponse{Error: "invalid JSON"}) //nolint:errcheck
		return
	}
	if err := validateDynamicExclude(req.Type, req.Value); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(apiResponse{Error: err.Error()}) //nolint:errcheck
		return
	}

	add := req.Command == "mute"
	switch req.Command {
	case "mute", "unmute":
	default:
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(apiResponse{Error: "unknown command: " + req.Command}) //nolint:errcheck
		return
	}
	excludes, changed, err := updateDynamicExclude(h.repository, h.dynamicExcludes, req.Type, req.Value, add)
	if err != nil {
		log.Println("api: failed to persist excludes:", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		enc.Encode(apiResponse{Error: "failed to persist excludes"}) //nolint:errcheck
		return
	}
	message := "unmuted " + req.Value + " from " + req.Type
	if add {
		message = "muted " + req.Value + " in " + req.Type
	}
	enc.Encode(apiResponse{Message: message, Type: req.Type, Value: req.Value, Changed: changed, Excludes: excludes}) //nolint:errcheck
}

type excludesAPIHandler struct {
	dynamicExcludes *dynamicExcludesStore
	repository      dynamicExcludesRepository
	tokens          []string
	limiter         *requestLimiter
}

type excludesAPIRequest struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

func (h *excludesAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if h.limiter != nil && !h.limiter.Allow(r.RemoteAddr) {
		w.WriteHeader(http.StatusTooManyRequests)
		enc.Encode(apiResponse{Error: "rate limit exceeded"}) //nolint:errcheck
		return
	}
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || !containsToken(h.tokens, token) {
		w.WriteHeader(http.StatusUnauthorized)
		enc.Encode(apiResponse{Error: "unauthorized"}) //nolint:errcheck
		return
	}
	if r.Method == http.MethodGet {
		excludes, err := h.repository.GetDynExcludes()
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			enc.Encode(apiResponse{Error: "failed to load excludes"}) //nolint:errcheck
			return
		}
		h.dynamicExcludes.Replace(excludes)
		enc.Encode(apiResponse{Excludes: excludes}) //nolint:errcheck
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		enc.Encode(apiResponse{Error: "method not allowed"}) //nolint:errcheck
		return
	}
	var req excludesAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(apiResponse{Error: "invalid JSON"}) //nolint:errcheck
		return
	}
	if err := validateDynamicExclude(req.Type, req.Value); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(apiResponse{Error: err.Error()}) //nolint:errcheck
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(apiResponse{Error: "reason is required"}) //nolint:errcheck
		return
	}
	add := r.Method == http.MethodPost
	excludes, changed, err := updateDynamicExclude(h.repository, h.dynamicExcludes, req.Type, req.Value, add)
	if err != nil {
		log.Println("excludes api: failed to persist excludes:", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		enc.Encode(apiResponse{Error: "failed to persist excludes"}) //nolint:errcheck
		return
	}
	log.Printf("dynamic exclude mutation action=%s type=%q value=%q changed=%t reason=%q", map[bool]string{true: "add", false: "remove"}[add], req.Type, req.Value, changed, req.Reason)
	enc.Encode(apiResponse{Type: req.Type, Value: req.Value, Changed: changed, Excludes: excludes}) //nolint:errcheck
}

func newWebServer(listenAddress string, dynamicExcludes *dynamicExcludesStore, repository dynamicExcludesRepository, tokens []string, apiTokens []string, metrics *telemetry) *http.Server {
	mux := http.NewServeMux()
	if metrics != nil {
		mux.HandleFunc("/healthz", metrics.healthHandler)
		mux.HandleFunc("/metrics", metrics.metricsHandler)
	}
	limiter := newRequestLimiter(30, time.Minute)
	mux.Handle("/slash", &slashHandler{dynamicExcludes: dynamicExcludes, repository: repository, tokens: tokens, limiter: limiter})
	if len(apiTokens) > 0 {
		mux.Handle("/api/mute", &apiHandler{dynamicExcludes: dynamicExcludes, repository: repository, tokens: apiTokens, limiter: limiter})
		mux.Handle("/api/excludes", &excludesAPIHandler{dynamicExcludes: dynamicExcludes, repository: repository, tokens: apiTokens, limiter: limiter})
	}
	return &http.Server{
		Addr: listenAddress, Handler: mux,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
}

func startWeb(server *http.Server) <-chan error {
	errs := make(chan error, 1)
	go func() {
		err := server.ListenAndServe()
		if err == http.ErrServerClosed {
			err = nil
		}
		errs <- err
	}()
	return errs
}

func shutdownWeb(server *http.Server, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return server.Shutdown(ctx)
}
