package main

import (
	"path/filepath"
	"testing"
)

func TestDynamicExcludesSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dyn_excludes.json")

	want := map[string][]string{
		"text":    []string{"noise one", "noise two"},
		"process": []string{"^ansible-"},
	}

	if err := writeDynamicExcludesSnapshot(path, want); err != nil {
		t.Fatalf("writeDynamicExcludesSnapshot() error = %v", err)
	}

	got, err := readDynamicExcludesSnapshot(path)
	if err != nil {
		t.Fatalf("readDynamicExcludesSnapshot() error = %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("snapshot size = %d, want %d", len(got), len(want))
	}
	for key, wantValues := range want {
		gotValues, ok := got[key]
		if !ok {
			t.Fatalf("snapshot missing key %q", key)
		}
		if len(gotValues) != len(wantValues) {
			t.Fatalf("snapshot[%q] length = %d, want %d", key, len(gotValues), len(wantValues))
		}
		for i := range wantValues {
			if gotValues[i] != wantValues[i] {
				t.Fatalf("snapshot[%q][%d] = %q, want %q", key, i, gotValues[i], wantValues[i])
			}
		}
	}
}

func TestDynamicExcludesStoreSnapshotIsIndependent(t *testing.T) {
	store := newDynamicExcludesStore(map[string][]string{
		"text": []string{"noise"},
	})

	snapshot := store.Snapshot()
	snapshot["text"][0] = "changed"

	fresh := store.Snapshot()
	if fresh["text"][0] != "noise" {
		t.Fatalf("store snapshot was mutated, got %q", fresh["text"][0])
	}
}

func TestDynamicExcludesStoreReplaceClonesInput(t *testing.T) {
	store := newDynamicExcludesStore(nil)
	replacement := map[string][]string{"text": {"noise"}}
	store.Replace(replacement)
	replacement["text"][0] = "changed"
	if got := store.Snapshot()["text"][0]; got != "noise" {
		t.Fatalf("Replace retained caller storage: %q", got)
	}
}
