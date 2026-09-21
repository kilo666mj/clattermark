package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	defaultDynamicExcludesSnapshotInterval = 30 * time.Minute
)

type dynamicExcludesStore struct {
	mu       sync.RWMutex
	excludes map[string][]string
}

func newDynamicExcludesStore(initial map[string][]string) *dynamicExcludesStore {
	return &dynamicExcludesStore{excludes: cloneDynamicExcludes(initial)}
}

func cloneDynamicExcludes(src map[string][]string) map[string][]string {
	if len(src) == 0 {
		return map[string][]string{}
	}
	dst := make(map[string][]string, len(src))
	for excludeType, values := range src {
		dst[excludeType] = append([]string(nil), values...)
	}
	return dst
}

func (s *dynamicExcludesStore) Snapshot() map[string][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneDynamicExcludes(s.excludes)
}

func (s *dynamicExcludesStore) Replace(excludes map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.excludes = cloneDynamicExcludes(excludes)
}

func (s *dynamicExcludesStore) Mute(excludeType, value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.excludes == nil {
		s.excludes = map[string][]string{}
	}
	current := s.excludes[excludeType]
	for _, existing := range current {
		if existing == value {
			return false
		}
	}
	s.excludes[excludeType] = append(current, value)
	return true
}

func (s *dynamicExcludesStore) Unmute(excludeType, value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.excludes[excludeType]
	if !ok {
		return false
	}
	for i, existing := range current {
		if existing != value {
			continue
		}
		s.excludes[excludeType] = append(current[:i], current[i+1:]...)
		if len(s.excludes[excludeType]) == 0 {
			delete(s.excludes, excludeType)
		}
		return true
	}
	return false
}

func readDynamicExcludesSnapshot(path string) (map[string][]string, error) {
	path = filepath.Clean(path)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string][]string{}, nil
		}
		return nil, err
	}
	var excludes map[string][]string
	if err := json.Unmarshal(data, &excludes); err != nil {
		return nil, err
	}
	if excludes == nil {
		excludes = map[string][]string{}
	}
	return excludes, nil
}

func writeDynamicExcludesSnapshot(path string, excludes map[string][]string) error {
	path = filepath.Clean(path)
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o770); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(excludes, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *dynamicExcludesStore) SnapshotToFile(path string) error {
	return writeDynamicExcludesSnapshot(path, s.Snapshot())
}

func startDynamicExcludesSnapshotter(ctx context.Context, store *dynamicExcludesStore, path string, interval time.Duration, metrics *telemetry) {
	if store == nil || path == "" || interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := store.SnapshotToFile(path); err != nil {
					log.Println("dynamic excludes snapshot failed:", err)
				}
			}
		}
	}()
}

type dynamicExcludesSource interface {
	GetDynExcludes() (map[string][]string, error)
}

func startDynamicExcludesRefresher(ctx context.Context, store *dynamicExcludesStore, source dynamicExcludesSource, interval time.Duration, metrics *telemetry) {
	if store == nil || source == nil || interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				excludes, err := source.GetDynExcludes()
				if err != nil {
					if metrics != nil {
						metrics.keyDBFailures.Add(1)
					}
					log.Println("dynamic excludes refresh failed:", err)
					continue
				}
				store.Replace(excludes)
			}
		}
	}()
}
