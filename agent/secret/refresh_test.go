package secret

import (
	"context"
	"testing"
	"time"
)

// TestConvergeNeverWaitsOnVaultAfterTheFirstRead is the point of the split. Materialize runs
// on the agent's single reconcile goroutine — the converge — so a Vault call there delays
// every workload's convergence, including workloads that reference no secret at all. Only the
// first read may block; after that a serve is a map lookup whatever the server is doing.
func TestConvergeNeverWaitsOnVaultAfterTheFirstRead(t *testing.T) {
	s := newStaticRoleServer(t, 60)
	v, stores := s.client(t)
	sec := staticRoleSecret("database/app-rw", "")
	base := time.Now()
	v.now = func() time.Time { return base }

	if _, err := v.Fetch(context.Background(), sec, stores, ""); err != nil {
		t.Fatal(err)
	}
	// The server is now gone: any read would hang until the client's timeout and take the
	// converge with it.
	s.srv.Close()

	v.now = func() time.Time { return base.Add(time.Hour) } // long past the deadline
	done := make(chan struct{})
	go func() {
		defer close(done)
		data, err := v.Fetch(context.Background(), sec, stores, "")
		if err != nil {
			t.Errorf("a cached value must still be served: %v", err)
			return
		}
		if string(data["password"]) != "pw-1" {
			t.Errorf("served %q, want the last good value", data["password"])
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Fetch blocked on the network for a value it already had")
	}
}

// TestFailedRefreshKeepsTheLastGoodValue: a credential that cannot be renewed must not tear
// down a workload running fine on the one it has — the failure is in the control path, not in
// the workload. The retry also backs off, because every cached value tends to come due
// together after an outage and retrying each on the next pass is a herd against a server that
// is already unwell.
func TestFailedRefreshKeepsTheLastGoodValue(t *testing.T) {
	s := newStaticRoleServer(t, 60)
	v, stores := s.client(t)
	sec := staticRoleSecret("database/app-rw", "")
	base := time.Now()
	v.now = func() time.Time { return base }
	if _, err := v.Fetch(context.Background(), sec, stores, ""); err != nil {
		t.Fatal(err)
	}
	s.srv.Close()

	v.now = func() time.Time { return base.Add(2 * time.Minute) }
	v.refreshDue(context.Background())

	data, err := v.Fetch(context.Background(), sec, stores, "")
	if err != nil || string(data["password"]) != "pw-1" {
		t.Fatalf("after a failed refresh: %v, %q — the last good value must survive", err, data["password"])
	}
	next, ok := v.nextDeadline()
	if !ok {
		t.Fatal("the entry was dropped by a failed refresh")
	}
	if !next.After(v.now()) {
		t.Errorf("next deadline %v is not in the future: a failed refresh must back off, not spin", next)
	}
}

// TestIdleValuesAreEvicted: an application that leaves the node stops asking for its secret,
// and nothing else tells the refresher to stop renewing it. Without eviction the agent would
// keep a departed workload's credential warm — and keep reading it out of Vault — for as long
// as it runs.
func TestIdleValuesAreEvicted(t *testing.T) {
	s := newStaticRoleServer(t, 60)
	v, stores := s.client(t)
	sec := staticRoleSecret("database/app-rw", "")
	base := time.Now()
	v.now = func() time.Time { return base }
	if _, err := v.Fetch(context.Background(), sec, stores, ""); err != nil {
		t.Fatal(err)
	}

	// Still wanted: every converge asks for it, so it never ages out.
	for i := range 4 {
		v.now = func() time.Time { return base.Add(time.Duration(i) * idleEvict / 2) }
		if _, err := v.Fetch(context.Background(), sec, stores, ""); err != nil {
			t.Fatal(err)
		}
		v.refreshDue(context.Background())
		if _, ok := v.nextDeadline(); !ok {
			t.Fatalf("a value still being asked for was evicted at step %d", i)
		}
	}

	// The application is gone: nothing asks any more, and the entry ages out.
	last := v.now()
	v.now = func() time.Time { return last.Add(idleEvict + time.Minute) }
	v.refreshDue(context.Background())
	if _, ok := v.nextDeadline(); ok {
		t.Error("a value nothing asks for is still being renewed")
	}
}

// TestRefreshLoopWakesOnANewValue: the loop sleeps until the nearest deadline, so a value
// entering the cache has to re-arm it — its deadline may be earlier than the one being slept
// on, and without the signal the first refresh would wait for whatever was already scheduled.
func TestRefreshLoopWakesOnANewValue(t *testing.T) {
	s := newStaticRoleServer(t, 1) // due almost immediately
	v, stores := s.client(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go v.Refresh(ctx)

	if _, err := v.Fetch(ctx, staticRoleSecret("database/app-rw", ""), stores, ""); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("the refresher never re-read a value due in ~1s (reads=%d)", s.readCount())
		case <-time.After(50 * time.Millisecond):
			if s.readCount() >= 2 {
				return
			}
		}
	}
}
