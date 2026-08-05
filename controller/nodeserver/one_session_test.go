package nodeserver

import (
	"context"
	"strings"
	"testing"
	"time"

	nodeapipb "github.com/ks-tool/horchestra/api/node"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestOneNodeOneLiveSession: a node certificate buys ONE live stream. A second connection while the
// first is talking is refused — that is what an impostor with a copy of the certificate looks like,
// and the old behaviour handed it a takeover: it evicted the real agent, received that node's
// desired state and every Secret its workloads reference, and the resulting flip-flop was
// indistinguishable from a flapping network.
func TestOneNodeOneLiveSession(t *testing.T) {
	srv := New(newFake(t))
	first := &session{send: make(chan *nodeapipb.ControllerMessage, 1)}
	first.touch()
	if err := srv.register(nodeName, first); err != nil {
		t.Fatalf("the first session must be accepted: %v", err)
	}

	second := &session{send: make(chan *nodeapipb.ControllerMessage, 1)}
	second.touch()
	err := srv.register(nodeName, second)
	if err == nil {
		t.Fatal("a second live session must be refused")
	}
	if !strings.Contains(err.Error(), "already has a live session") {
		t.Fatalf("error %q does not say why", err)
	}
	srv.mu.Lock()
	current := srv.sessions[nodeName]
	srv.mu.Unlock()
	if current != first {
		t.Fatal("the refused session must not have replaced the live one")
	}
}

// TestSilentSessionCanBeTakenOver: refusing outright would lock a node out after an unclean drop,
// where its old session is still registered while its transport is already dead. So the rule is
// liveness, not arrival order: a session that has said nothing for longer than the stale window is
// presumed dead and may be replaced.
func TestSilentSessionCanBeTakenOver(t *testing.T) {
	srv := New(newFake(t))
	ctx, cancel := context.WithCancel(context.Background())
	dead := &session{send: make(chan *nodeapipb.ControllerMessage, 1), cancel: cancel}
	dead.lastSeen.Store(time.Now().Add(-2 * srv.staleAfter).UnixNano())
	if err := srv.register(nodeName, dead); err != nil {
		t.Fatal(err)
	}

	fresh := &session{send: make(chan *nodeapipb.ControllerMessage, 1)}
	fresh.touch()
	if err := srv.register(nodeName, fresh); err != nil {
		t.Fatalf("a silent session must be replaceable: %v", err)
	}
	srv.mu.Lock()
	current := srv.sessions[nodeName]
	srv.mu.Unlock()
	if current != fresh {
		t.Fatal("the reconnecting session must own the node")
	}
	if ctx.Err() == nil {
		t.Fatal("the session taken over must have been cancelled")
	}
}

// TestReconnectAfterCleanDisconnect: the ordinary agent restart — deregister on the way out, then
// connect again immediately — must not be mistaken for a second connection.
func TestReconnectAfterCleanDisconnect(t *testing.T) {
	srv := New(newFake(t))
	first := &session{send: make(chan *nodeapipb.ControllerMessage, 1)}
	first.touch()
	if err := srv.register(nodeName, first); err != nil {
		t.Fatal(err)
	}
	srv.deregister(nodeName, first)

	second := &session{send: make(chan *nodeapipb.ControllerMessage, 1)}
	second.touch()
	if err := srv.register(nodeName, second); err != nil {
		t.Fatalf("a reconnect after a clean disconnect must be accepted: %v", err)
	}
}

// TestSecondStreamGetsAlreadyExists drives the real handler: the impostor's stream is refused with a
// code it can act on, and the honest session keeps working.
func TestSecondStreamGetsAlreadyExists(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	honest := h.session(t, ctx, nodeName, []string{nodeGroup})
	if _, err := honest.Recv(); err != nil { // the first desired-state push proves it is live
		t.Fatalf("the first session must be served: %v", err)
	}

	impostor := h.session(t, ctx, nodeName, []string{nodeGroup})
	if _, err := impostor.Recv(); err == nil {
		t.Fatal("the second stream must be refused")
	} else if got := status.Code(err); got != codes.AlreadyExists {
		t.Fatalf("code = %s, want AlreadyExists (err %v)", got, err)
	}

	// The honest session is untouched: its status still lands.
	if err := honest.Send(&nodeapipb.NodeMessage{Body: &nodeapipb.NodeMessage_Status{
		Status: &nodeapipb.NodeStatus{Node: []byte(`{"metadata":{"name":"` + nodeName + `"},"status":{"ready":true}}`)},
	}}); err != nil {
		t.Fatalf("the honest session must still be usable: %v", err)
	}
}
