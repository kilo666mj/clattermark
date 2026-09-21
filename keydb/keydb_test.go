package keydb

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestUpdateDynExcludeIsIdempotent(t *testing.T) {
	store, _ := newTestKeyDB(t)
	excludes, changed, err := store.UpdateDynExclude("text", "routine noise", true)
	if err != nil || !changed || len(excludes["text"]) != 1 {
		t.Fatalf("first add = %#v, changed=%t, err=%v", excludes, changed, err)
	}
	_, changed, err = store.UpdateDynExclude("text", "routine noise", true)
	if err != nil || changed {
		t.Fatalf("duplicate add changed=%t, err=%v", changed, err)
	}
	excludes, changed, err = store.UpdateDynExclude("text", "routine noise", false)
	if err != nil || !changed || len(excludes) != 0 {
		t.Fatalf("remove = %#v, changed=%t, err=%v", excludes, changed, err)
	}
}

func TestUpdateDynExcludePreservesConcurrentAdds(t *testing.T) {
	store, _ := newTestKeyDB(t)
	const count = 12
	start := make(chan struct{})
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(value string) {
			defer wg.Done()
			<-start
			_, _, err := store.UpdateDynExclude("text", value, true)
			errs <- err
		}(fmt.Sprintf("noise-%02d", i))
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	excludes, err := store.GetDynExcludes()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(excludes["text"]); got != count {
		t.Fatalf("concurrent adds stored %d entries, want %d: %#v", got, count, excludes)
	}
}

func newTestKeyDB(t *testing.T) (*Keydb, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	store := New(server.Addr(), "")
	return &store, server
}

func TestQueueLengthTracksDurableOutbox(t *testing.T) {
	store, _ := newTestKeyDB(t)
	if err := store.EnqueueJSON("outbox", map[string]string{"event": "one"}, 10); err != nil {
		t.Fatal(err)
	}
	if err := store.EnqueueJSON("outbox", map[string]string{"event": "two"}, 10); err != nil {
		t.Fatal(err)
	}
	if got, err := store.QueueLength("outbox"); err != nil || got != 2 {
		t.Fatalf("queue length = %d, %v; want 2", got, err)
	}
}

func TestReserveDedupPersistsUntilTTL(t *testing.T) {
	store, server := newTestKeyDB(t)
	if ok, err := store.ReserveDedup("fingerprint", time.Minute); err != nil || !ok {
		t.Fatalf("first reservation = %v, %v", ok, err)
	}
	if ok, err := store.ReserveDedup("fingerprint", time.Minute); err != nil || ok {
		t.Fatalf("duplicate reservation = %v, %v", ok, err)
	}
	server.FastForward(time.Minute + time.Second)
	if ok, err := store.ReserveDedup("fingerprint", time.Minute); err != nil || !ok {
		t.Fatalf("reservation after expiry = %v, %v", ok, err)
	}
}

func TestIncidentLifecycleIsAtomicAndDurable(t *testing.T) {
	store, _ := newTestKeyDB(t)
	start := time.Unix(100, 0).UTC()
	quiet := 10 * time.Minute
	first, err := store.RecordIncident("dns", "DNS outage", "first", "host-a", "sshgate", start, quiet, 3)
	if err != nil || !first.Notify || first.Count != 1 {
		t.Fatalf("first update = %#v, %v", first, err)
	}
	second, err := store.RecordIncident("dns", "DNS outage", "second", "host-b", "cloudflared", start.Add(time.Second), quiet, 3)
	if err != nil || second.Notify || second.Count != 2 {
		t.Fatalf("second update = %#v, %v", second, err)
	}
	third, err := store.RecordIncident("dns", "DNS outage", "third", "host-c", "puppet-agent", start.Add(2*time.Second), quiet, 3)
	if err != nil || third.Notify || third.Count != 3 {
		t.Fatalf("third update = %#v, %v", third, err)
	}
	fourth, err := store.RecordIncident("dns", "DNS outage", "fourth", "host-d", "app", start.Add(3*time.Second), quiet, 3)
	if err != nil || !fourth.Notify || fourth.Count != 4 {
		t.Fatalf("fourth update = %#v, %v", fourth, err)
	}
	due, err := store.DueIncidents(start.Add(2*time.Second), 10)
	if err != nil || len(due) != 0 {
		t.Fatalf("incident closed early: %v, %v", due, err)
	}
	cutoff := start.Add(quiet + time.Minute)
	due, err = store.DueIncidents(cutoff, 10)
	if err != nil || len(due) != 1 || due[0] != "dns" {
		t.Fatalf("due incidents = %v, %v", due, err)
	}
	closed, err := store.CloseIncidentToOutbox("dns", cutoff, 100)
	if err != nil || !closed {
		t.Fatalf("close = %v, %v", closed, err)
	}
	outbox, err := store.PeekQueue("incident:v1:recovery-outbox", 10)
	if err != nil || len(outbox) != 1 {
		t.Fatalf("recovery outbox = %v, %v", outbox, err)
	}
}
