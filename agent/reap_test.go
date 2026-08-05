package agent

import (
	"context"
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	"google.golang.org/grpc/credentials/insecure"
)

// TestReapRunsWithoutASession is the whole point of the reaper being where it is. Finishing a stop
// that has already outstayed its budget is LOCAL state — the unit is one this agent decided to
// end — so it must not wait on a control plane that may be gone. It used to: every teardown ran
// inside the session loop, and a workload that discards SIGTERM (which is every workload without
// a signal handler, since it is PID 1 of its namespace) stood in final-sigterm for as long as the
// controller was unreachable, holding its name, its cgroup and its rootfs mount.
//
// The controller here does not exist at all: the endpoint is a port nothing listens on, so the
// session loop can only fail and back off. The reap passes must happen anyway.
func TestReapRunsWithoutASession(t *testing.T) {
	rt := newFakeRuntime()
	a := &Agent{
		endpoint:   "127.0.0.1:1", // nothing is listening, and nothing ever will be
		creds:      insecure.NewCredentials(),
		node:       "node1",
		controller: "https://127.0.0.1:8443",
		limits:     corev1.ResourceAmounts{},
		runtime:    rt,
		volumes:    fakeVolumes{},
		secrets:    fakeSecrets{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Start(ctx, 20*time.Millisecond) }()

	deadline := time.After(5 * time.Second)
	for {
		rt.mu.Lock()
		n := rt.reaps
		rt.mu.Unlock()
		if n >= 2 { // two, so a single pass at startup cannot pass for a running loop
			return
		}
		select {
		case <-deadline:
			t.Fatalf("the agent reaped %d times with no controller reachable; stalled stops would stand forever", n)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestReapStopsWithTheAgent: the pass runs on the agent's own context, so cancelling it ends the
// loop. A goroutine that outlived Start would go on driving the init system after the agent was
// told to stop.
func TestReapStopsWithTheAgent(t *testing.T) {
	rt := newFakeRuntime()
	a := &Agent{
		endpoint: "127.0.0.1:1", creds: insecure.NewCredentials(), node: "node1",
		controller: "https://127.0.0.1:8443", runtime: rt,
		volumes: fakeVolumes{}, secrets: fakeSecrets{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = a.Start(ctx, 10*time.Millisecond) }()

	for {
		rt.mu.Lock()
		started := rt.reaps > 0
		rt.mu.Unlock()
		if started {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	time.Sleep(50 * time.Millisecond)
	rt.mu.Lock()
	settled := rt.reaps
	rt.mu.Unlock()
	time.Sleep(100 * time.Millisecond) // ten more ticks would have fired
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.reaps != settled {
		t.Errorf("reaping continued after the agent stopped: %d -> %d", settled, rt.reaps)
	}
}
