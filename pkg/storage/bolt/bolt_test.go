package bolt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/api/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const apiVersion = "test.horchestra.io/v1"

var (
	widgetGVK = schema.GroupVersionKind{Group: "test.horchestra.io", Version: "v1", Kind: "Widget"}
	gadgetGVK = schema.GroupVersionKind{Group: "test.horchestra.io", Version: "v1", Kind: "Gadget"}
)

// widget is a self-contained test Kind with a status subresource; it embeds the
// metav1 types like a real api/v1 object without depending on the apis/* packages.
type widget struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              widgetSpec   `json:"spec"`
	Status            widgetStatus `json:"status"`
	// Data is a payload field OUTSIDE spec, the shape a Secret has (data/type/immutable) and
	// the one an update must not silently drop.
	Data map[string]string `json:"data,omitempty"`
}

type widgetSpec struct {
	Node  string `json:"node,omitempty"`
	Image string `json:"image,omitempty"`
}

type widgetStatus struct {
	Phase string `json:"phase,omitempty"`
}

func newTestBolt(t *testing.T) *DB {
	t.Helper()
	sch := scheme.New()
	sch.AddKnownTypes(widgetGVK, func() types.Object { return new(widget) })
	sch.AddKnownTypes(gadgetGVK, func() types.Object { return new(widget) })
	b, err := Open(filepath.Join(t.TempDir(), "test.db"), sch)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func newWidget(kind, name string) *widget {
	return &widget{
		TypeMeta:   metav1.TypeMeta{APIVersion: apiVersion, Kind: kind},
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
}

func metaFor(kind, name string) types.ObjectMeta {
	return types.ObjectMeta{ApiVersion: apiVersion, Kind: kind, Name: name}
}

func TestBolt_CRUD(t *testing.T) {
	b := newTestBolt(t)
	ctx := context.Background()

	w0 := newWidget("Widget", "db")
	w0.Spec = widgetSpec{Node: "node-1", Image: "postgres:16"}
	created, err := b.Create(ctx, w0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	w := mustWidget(t, created)
	if w.Name != "db" {
		t.Errorf("identity = %s, want db", w.Name)
	}
	if w.UID == "" {
		t.Error("UID was not assigned")
	}
	if w.ResourceVersion != "1" {
		t.Errorf("resourceVersion = %q, want 1 (first write for this GVK)", w.ResourceVersion)
	}
	if w.APIVersion != apiVersion || w.Kind != "Widget" {
		t.Errorf("TypeMeta = %s/%s, want %s/Widget", w.APIVersion, w.Kind, apiVersion)
	}
	if w.CreationTimestamp.IsZero() {
		t.Error("creationTimestamp was not set")
	}
	if w0.UID != "" || w0.ResourceVersion != "" {
		t.Errorf("Create mutated caller: uid=%q rv=%q", w0.UID, w0.ResourceVersion)
	}

	if _, err := b.Create(ctx, newWidget("Widget", "db")); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Errorf("duplicate Create err = %v, want ErrAlreadyExists", err)
	}
	if _, err := b.Create(ctx, newWidget("Widget", "")); err == nil {
		t.Error("Create with empty name should fail")
	}

	got := mustWidget(t, mustGet(t, b, metaFor("Widget", "db")))
	if got.Spec.Node != "node-1" || got.Spec.Image != "postgres:16" {
		t.Errorf("Get spec = %+v", got.Spec)
	}
	// B3: the object Create returns must match what a later Get returns.
	if !w.CreationTimestamp.Time.Equal(got.CreationTimestamp.Time) {
		t.Errorf("Create creationTimestamp %v != Get %v", w.CreationTimestamp, got.CreationTimestamp)
	}
	if _, err := b.Get(ctx, metaFor("Widget", "missing")); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get(missing) err = %v, want ErrNotFound", err)
	}

	got.Spec.Image = "postgres:17"
	updated := mustWidget(t, mustUpdate(t, b, got))
	if updated.Spec.Image != "postgres:17" {
		t.Errorf("Update image = %q, want postgres:17", updated.Spec.Image)
	}
	if updated.UID != w.UID {
		t.Errorf("Update changed UID: %q -> %q", w.UID, updated.UID)
	}
	if updated.ResourceVersion == got.ResourceVersion {
		t.Error("Update did not bump resourceVersion")
	}
	if _, err := b.Update(ctx, newWidget("Widget", "ghost")); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Update(missing) err = %v, want ErrNotFound", err)
	}

	if err := b.Delete(ctx, metaFor("Widget", "db")); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := b.Get(ctx, metaFor("Widget", "db")); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get after Delete err = %v, want ErrNotFound", err)
	}
	if err := b.Delete(ctx, metaFor("Widget", "db")); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Delete(missing) err = %v, want ErrNotFound", err)
	}
}

// TestBolt_PerGVKResourceVersion pins the core requirement: each GVK has its own
// monotonic resourceVersion counter (mirrors gvk_resource_version_seq).
func TestBolt_PerGVKResourceVersion(t *testing.T) {
	b := newTestBolt(t)

	w1 := mustWidget(t, mustCreate(t, b, newWidget("Widget", "w1")))
	if w1.ResourceVersion != "1" {
		t.Fatalf("widget rv = %q, want 1", w1.ResourceVersion)
	}
	g1 := mustWidget(t, mustCreate(t, b, newWidget("Gadget", "g1")))
	if g1.ResourceVersion != "1" {
		t.Fatalf("gadget rv = %q, want 1 (independent per-GVK counter)", g1.ResourceVersion)
	}
	w2 := mustWidget(t, mustCreate(t, b, newWidget("Widget", "w2")))
	if w2.ResourceVersion != "2" {
		t.Fatalf("second widget rv = %q, want 2", w2.ResourceVersion)
	}
	g2 := mustWidget(t, mustCreate(t, b, newWidget("Gadget", "g2")))
	if g2.ResourceVersion != "2" {
		t.Fatalf("second gadget rv = %q, want 2", g2.ResourceVersion)
	}
}

func TestBolt_UpdateConflict(t *testing.T) {
	b := newTestBolt(t)
	ctx := context.Background()

	first := mustWidget(t, mustCreate(t, b, newWidget("Widget", "db")))
	staleRV := first.ResourceVersion

	first.Spec.Image = "v2"
	if _, err := b.Update(ctx, first); err != nil {
		t.Fatalf("conditional Update: %v", err)
	}
	if first.ResourceVersion != staleRV {
		t.Fatalf("Update mutated caller resourceVersion: %q", first.ResourceVersion)
	}

	first.Spec.Image = "v3"
	if _, err := b.Update(ctx, first); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("stale Update err = %v, want ErrConflict", err)
	}

	first.ResourceVersion = ""
	first.Spec.Image = "v4"
	if _, err := b.Update(ctx, first); err != nil {
		t.Fatalf("unconditional Update: %v", err)
	}
	if got := mustWidget(t, mustGet(t, b, metaFor("Widget", "db"))); got.Spec.Image != "v4" {
		t.Fatalf("image = %q, want v4", got.Spec.Image)
	}
}

func TestBolt_UpdateSubresource(t *testing.T) {
	b := newTestBolt(t)
	ctx := context.Background()

	w := newWidget("Widget", "db")
	w.Spec.Image = "img"
	created := mustWidget(t, mustCreate(t, b, w))
	if created.Generation != 1 {
		t.Errorf("Create generation = %d, want 1", created.Generation)
	}

	// A status update must persist status but leave spec untouched.
	created.Status.Phase = "Running"
	created.Spec.Image = "IGNORED"
	updated := mustWidget(t, mustUpdateSub(t, b, "status", created))
	if updated.Status.Phase != "Running" {
		t.Errorf("status.phase = %q, want Running", updated.Status.Phase)
	}
	if updated.Spec.Image != "img" {
		t.Errorf("subresource update changed spec.image to %q, want img", updated.Spec.Image)
	}
	// A status write advances neither version: not generation (what lets a spec-watcher ignore
	// it) and not resourceVersion (the token a spec writer holds for optimistic concurrency).
	if updated.ResourceVersion != created.ResourceVersion {
		t.Errorf("UpdateSubresource moved resourceVersion %q -> %q; a subresource is not a version of the object",
			created.ResourceVersion, updated.ResourceVersion)
	}
	if updated.Generation != created.Generation {
		t.Errorf("UpdateSubresource moved generation %d -> %d; a status write must leave it put", created.Generation, updated.Generation)
	}

	got := mustWidget(t, mustGet(t, b, metaFor("Widget", "db")))
	if got.Status.Phase != "Running" || got.Spec.Image != "img" {
		t.Errorf("persisted = spec %q status %q, want img/Running", got.Spec.Image, got.Status.Phase)
	}

	if _, err := b.UpdateSubresource(ctx, "nonexistent", newWidget("Widget", "db")); err == nil {
		t.Error("UpdateSubresource with unknown field should fail")
	}
	if _, err := b.UpdateSubresource(ctx, "status", newWidget("Widget", "ghost")); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("UpdateSubresource(missing) err = %v, want ErrNotFound", err)
	}
}

// TestBolt_StatusDoesNotInvalidateASpecWriter is the reason a status write leaves resourceVersion
// alone. A reporting node and an editing operator touch disjoint halves of the object, so the
// node's heartbeat must not turn the operator's read-modify-write into a conflict — which, at a
// heartbeat every few seconds, it otherwise would with near certainty.
// TestBolt_UpdateKeepsPayloadOutsideSpec is the regression guard for a Secret losing its value on
// every update. The core/subresource split used to be an ALLOW-list — apiVersion, kind, metadata,
// spec — so a Kind whose payload does not live under spec had that payload dropped by Update,
// which then reported success and advanced the generation. The write said "configured" and stored
// the old secret.
func TestBolt_UpdateKeepsPayloadOutsideSpec(t *testing.T) {
	b := newTestBolt(t)

	w := newWidget("Widget", "creds")
	w.Data = map[string]string{"password": "old"}
	created := mustWidget(t, mustCreate(t, b, w))

	created.Data = map[string]string{"password": "rotated"}
	updated := mustWidget(t, mustUpdate(t, b, created))
	if got := updated.Data["password"]; got != "rotated" {
		t.Errorf("returned password = %q, want rotated", got)
	}
	if got := mustWidget(t, mustGet(t, b, metaFor("Widget", "creds"))).Data["password"]; got != "rotated" {
		t.Errorf("stored password = %q, want rotated — the update reported success and kept the old value", got)
	}

	// The other half still holds: status is the server's, and an update does not carry it back.
	cur := mustWidget(t, mustGet(t, b, metaFor("Widget", "creds")))
	cur.Status.Phase = "Running"
	if _, err := b.UpdateSubresource(context.Background(), "status", cur); err != nil {
		t.Fatalf("UpdateSubresource: %v", err)
	}
	stale := mustWidget(t, mustGet(t, b, metaFor("Widget", "creds")))
	stale.Status.Phase = ""
	stale.Data = map[string]string{"password": "again"}
	if _, err := b.Update(context.Background(), stale); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got := mustWidget(t, mustGet(t, b, metaFor("Widget", "creds")))
	if got.Status.Phase != "Running" {
		t.Errorf("status.phase = %q, want Running — a spec write must not carry a stale status back", got.Status.Phase)
	}
	if got.Data["password"] != "again" {
		t.Errorf("password = %q, want again", got.Data["password"])
	}
}

func TestBolt_StatusDoesNotInvalidateASpecWriter(t *testing.T) {
	b := newTestBolt(t)

	w := newWidget("Widget", "db")
	w.Spec.Image = "v1"
	created := mustWidget(t, mustCreate(t, b, w))

	// The operator has read the object; the node reports status before they write back.
	operatorCopy := *created
	held := &operatorCopy
	reported := mustWidget(t, mustGet(t, b, metaFor("Widget", "db")))
	reported.Status.Phase = "Running"
	if _, err := b.UpdateSubresource(context.Background(), "status", reported); err != nil {
		t.Fatalf("UpdateSubresource: %v", err)
	}

	held.Spec.Image = "v2"
	out, err := b.Update(context.Background(), held)
	if err != nil {
		t.Fatalf("a spec write held across a status report must still land: %v", err)
	}
	// And the spec write must not erase the status it never saw.
	if got := mustWidget(t, out); got.Status.Phase != "Running" {
		t.Errorf("status.phase = %q after the spec write, want Running", got.Status.Phase)
	}
}

// TestBolt_StatusKeepsNoHistory: history is what Rollback restores, and Rollback restores core
// state alone. A status snapshot in it is not merely useless — maxHistory is finite, so a node
// reporting every few seconds would evict every real spec revision within a minute and leave
// nothing to roll back to.
func TestBolt_StatusKeepsNoHistory(t *testing.T) {
	b := newTestBolt(t)
	ctx := context.Background()

	w := newWidget("Widget", "db")
	w.Spec.Image = "v1"
	c1 := mustWidget(t, mustCreate(t, b, w))
	uid := string(c1.UID)
	rv1, _ := strconv.ParseInt(c1.ResourceVersion, 10, 64)

	for i := range maxHistory * 2 {
		cur := mustWidget(t, mustGet(t, b, metaFor("Widget", "db")))
		cur.Status.Phase = fmt.Sprintf("tick-%d", i)
		if _, err := b.UpdateSubresource(ctx, "status", cur); err != nil {
			t.Fatalf("UpdateSubresource: %v", err)
		}
	}

	rb := mustWidget(t, mustRollback(t, b, metaFor("Widget", "db"), uid, rv1))
	if rb.Spec.Image != "v1" {
		t.Errorf("rollback image = %q, want v1 — %d status writes evicted the only spec revision",
			rb.Spec.Image, maxHistory*2)
	}
}

// TestBolt_UnchangedStatusIsNotAWrite: the node reports its status every tick whether or not it
// moved — that is the level-driven design, and it must cost nothing. An unchanged status wakes no
// watcher; a changed one still does, which is what a live `get -w` shows.
func TestBolt_UnchangedStatusIsNotAWrite(t *testing.T) {
	b := newTestBolt(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	created := mustWidget(t, mustCreate(t, b, newWidget("Widget", "db")))
	ch, err := b.Watch(ctx, metaFor("Widget", ""), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	created.Status.Phase = "Running"
	if _, err := b.UpdateSubresource(ctx, "status", created); err != nil {
		t.Fatalf("UpdateSubresource: %v", err)
	}
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("a real status change must reach a watcher")
	}

	for range 3 {
		cur := mustWidget(t, mustGet(t, b, metaFor("Widget", "db")))
		if _, err := b.UpdateSubresource(ctx, "status", cur); err != nil {
			t.Fatalf("re-reporting the same status: %v", err)
		}
	}
	select {
	case evt := <-ch:
		t.Fatalf("an unchanged status woke a watcher: %s", evt.Object.Raw)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestBolt_Rollback(t *testing.T) {
	b := newTestBolt(t)
	ctx := context.Background()

	w := newWidget("Widget", "db")
	w.Spec.Image = "v1"
	c1 := mustWidget(t, mustCreate(t, b, w))
	uid := string(c1.UID)
	rv1, _ := strconv.ParseInt(c1.ResourceVersion, 10, 64)

	c1.Spec.Image = "v2"
	c2 := mustWidget(t, mustUpdate(t, b, c1))
	if c2.Generation <= c1.Generation {
		t.Errorf("Update did not advance generation (%d -> %d)", c1.Generation, c2.Generation)
	}
	c2.Spec.Image = "v3"
	c3 := mustWidget(t, mustUpdate(t, b, c2))

	rb := mustWidget(t, mustRollback(t, b, metaFor("Widget", "db"), uid, rv1))
	if rb.Spec.Image != "v1" {
		t.Errorf("rollback image = %q, want v1", rb.Spec.Image)
	}
	if rb.UID != c1.UID {
		t.Errorf("rollback changed uid")
	}
	if rb.ResourceVersion == c1.ResourceVersion {
		t.Error("rollback must assign a new resourceVersion, not reuse the target")
	}
	// Rollback rewrites spec, so it advances generation forward from the current head — never back
	// to the snapshot's older value.
	if rb.Generation <= c3.Generation {
		t.Errorf("rollback generation = %d, want > current head %d (must not regress)", rb.Generation, c3.Generation)
	}
	if got := mustWidget(t, mustGet(t, b, metaFor("Widget", "db"))); got.Spec.Image != "v1" {
		t.Errorf("persisted image after rollback = %q, want v1", got.Spec.Image)
	}

	if _, err := b.Rollback(ctx, metaFor("Widget", "db"), uid, 9999); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("rollback to unknown rv err = %v, want ErrNotFound", err)
	}
	if _, err := b.Rollback(ctx, metaFor("Widget", "db"), "wrong-uid", rv1); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("rollback with wrong uid err = %v, want ErrNotFound", err)
	}
}

func TestBolt_ListAndSelector(t *testing.T) {
	b := newTestBolt(t)
	ctx := context.Background()

	mustCreate(t, b, labeled(newWidget("Widget", "a"), "web"))
	mustCreate(t, b, labeled(newWidget("Widget", "b"), "db"))
	mustCreate(t, b, labeled(newWidget("Widget", "c"), "web"))

	all, err := b.List(ctx, metaFor("Widget", ""), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if names := listNames(t, all); !slices.Equal(names, []string{"a", "b", "c"}) {
		t.Errorf("list all names = %v, want [a b c]", names)
	}

	web, _ := b.List(ctx, metaFor("Widget", ""), metav1.ListOptions{LabelSelector: "app=web"})
	if names := listNames(t, web); !slices.Equal(names, []string{"a", "c"}) {
		t.Errorf("list app=web names = %v, want [a c]", names)
	}
}

func TestBolt_Watch(t *testing.T) {
	b := newTestBolt(t)
	ctx, cancel := context.WithCancel(context.Background())

	ch, err := b.Watch(ctx, metaFor("Widget", ""), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	w := newWidget("Widget", "db")
	w.Spec.Image = "postgres:16"
	created := mustWidget(t, mustCreate(t, b, w))
	if e := waitEvent(t, ch); e.Type != "ADDED" {
		t.Fatalf("event type = %q, want ADDED", e.Type)
	} else if got := decodeWidget(t, e.Object.Raw); got.Name != "db" {
		t.Fatalf("ADDED object name = %q, want db", got.Name)
	}

	created.Spec.Image = "postgres:17"
	mustUpdate(t, b, created)
	if e := waitEvent(t, ch); e.Type != "MODIFIED" {
		t.Fatalf("event type = %q, want MODIFIED", e.Type)
	}

	if err := b.Delete(ctx, metaFor("Widget", "db")); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if e := waitEvent(t, ch); e.Type != "DELETED" {
		t.Fatalf("event type = %q, want DELETED", e.Type)
	}

	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected watch channel to be closed after cancel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watch channel not closed after context cancel")
	}
}

func TestBolt_WatchNamespaceScoped(t *testing.T) {
	b := newTestBolt(t)
	ctx := context.Background()

	ch, err := b.Watch(ctx, types.ObjectMeta{ApiVersion: apiVersion, Kind: "Widget", Namespace: "team-a"}, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	// An event in another namespace must not reach a namespace-scoped watch.
	other := newWidget("Widget", "w")
	other.Namespace = "team-b"
	mustCreate(t, b, other)
	select {
	case e := <-ch:
		t.Fatalf("namespaced watch saw a cross-namespace event: %+v", e)
	case <-time.After(200 * time.Millisecond):
	}

	// An event in the watched namespace does arrive.
	mine := newWidget("Widget", "w")
	mine.Namespace = "team-a"
	mustCreate(t, b, mine)
	e := waitEvent(t, ch)
	if e.Type != "ADDED" {
		t.Fatalf("event type = %q, want ADDED", e.Type)
	}
	if got := decodeWidget(t, e.Object.Raw); got.Namespace != "team-a" {
		t.Fatalf("event namespace = %q, want team-a", got.Namespace)
	}
}

func TestBolt_WatchFilters(t *testing.T) {
	b := newTestBolt(t)
	ctx := t.Context()

	ch, err := b.Watch(ctx, metaFor("Widget", ""), metav1.ListOptions{LabelSelector: "app=web"})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	mustCreate(t, b, labeled(newWidget("Widget", "y"), "db"))  // dropped: selector miss
	mustCreate(t, b, labeled(newWidget("Widget", "z"), "web")) // delivered

	if got := decodeWidget(t, waitEvent(t, ch).Object.Raw); got.Name != "z" {
		t.Fatalf("watch delivered %q, want z (only app=web matches)", got.Name)
	}
}

// B2: Rollback rolls back spec but preserves the current status subresource.
func TestBolt_RollbackPreservesStatus(t *testing.T) {
	b := newTestBolt(t)

	w := newWidget("Widget", "db")
	w.Spec.Image = "v1"
	c1 := mustWidget(t, mustCreate(t, b, w))
	uid := string(c1.UID)
	rv1, _ := strconv.ParseInt(c1.ResourceVersion, 10, 64)

	c1.Status.Phase = "Running"
	mustUpdateSub(t, b, "status", c1)

	got := mustWidget(t, mustGet(t, b, metaFor("Widget", "db")))
	got.Spec.Image = "v2"
	mustUpdate(t, b, got)

	rb := mustWidget(t, mustRollback(t, b, metaFor("Widget", "db"), uid, rv1))
	if rb.Spec.Image != "v1" {
		t.Errorf("rollback spec.image = %q, want v1", rb.Spec.Image)
	}
	if rb.Status.Phase != "Running" {
		t.Errorf("rollback wiped status.phase = %q, want Running (subresource must be preserved)", rb.Status.Phase)
	}
}

// B4: Close tears down live watches even when their context is never cancelled.
func TestBolt_CloseClosesWatches(t *testing.T) {
	sch := scheme.New()
	sch.AddKnownTypes(widgetGVK, func() types.Object { return new(widget) })
	b, err := Open(filepath.Join(t.TempDir(), "test.db"), sch)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ch, err := b.Watch(context.Background(), metaFor("Widget", ""), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected watch channel to be closed after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watch channel not closed after Close")
	}
}

// D1: history is bounded to maxHistory revisions; older ones are pruned.
func TestBolt_HistoryRetention(t *testing.T) {
	b := newTestBolt(t)
	ctx := context.Background()

	w := newWidget("Widget", "db")
	w.Spec.Image = "v0"
	last := mustWidget(t, mustCreate(t, b, w))
	uid := string(last.UID)
	rv1, _ := strconv.ParseInt(last.ResourceVersion, 10, 64)

	for i := 0; i < maxHistory+2; i++ {
		last.Spec.Image = fmt.Sprintf("v%d", i+1)
		last = mustWidget(t, mustUpdate(t, b, last))
	}

	if _, err := b.Rollback(ctx, metaFor("Widget", "db"), uid, rv1); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("rollback to pruned rv err = %v, want ErrNotFound", err)
	}
	recentRV, _ := strconv.ParseInt(last.ResourceVersion, 10, 64)
	if _, err := b.Rollback(ctx, metaFor("Widget", "db"), uid, recentRV-1); err != nil {
		t.Errorf("rollback to a retained rv failed: %v", err)
	}
}

// --- helpers ---

func labeled(w *widget, app string) *widget {
	w.Labels = map[string]string{"app": app}
	return w
}

func mustWidget(t *testing.T, o types.Object) *widget {
	t.Helper()
	w, ok := o.(*widget)
	if !ok {
		t.Fatalf("object is %T, want *widget", o)
	}
	return w
}

func mustCreate(t *testing.T, b *DB, o types.Object) types.Object {
	t.Helper()
	got, err := b.Create(context.Background(), o)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return got
}

func mustGet(t *testing.T, b *DB, m types.ObjectMeta) types.Object {
	t.Helper()
	got, err := b.Get(context.Background(), m)
	if err != nil {
		t.Fatalf("Get(%s): %v", m, err)
	}
	return got
}

func mustUpdate(t *testing.T, b *DB, o types.Object) types.Object {
	t.Helper()
	got, err := b.Update(context.Background(), o)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	return got
}

func mustUpdateSub(t *testing.T, b *DB, subresource string, o types.Object) types.Object {
	t.Helper()
	got, err := b.UpdateSubresource(context.Background(), subresource, o)
	if err != nil {
		t.Fatalf("UpdateSubresource: %v", err)
	}
	return got
}

func mustRollback(t *testing.T, b *DB, m types.ObjectMeta, uid string, targetRV int64) types.Object {
	t.Helper()
	got, err := b.Rollback(context.Background(), m, uid, targetRV)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	return got
}

func listNames(t *testing.T, list []types.Object) []string {
	t.Helper()
	names := make([]string, 0, len(list))
	for _, o := range list {
		names = append(names, mustWidget(t, o).Name)
	}
	return names
}

func waitEvent(t *testing.T, ch <-chan metav1.WatchEvent) metav1.WatchEvent {
	t.Helper()
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatal("watch channel closed unexpectedly")
		}
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for watch event")
		return metav1.WatchEvent{}
	}
}

func decodeWidget(t *testing.T, raw []byte) *widget {
	t.Helper()
	var w widget
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatalf("unmarshal event object: %v", err)
	}
	return &w
}
