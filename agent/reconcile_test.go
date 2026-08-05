package agent

import (
	"context"
	"errors"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	secretsv1 "github.com/ks-tool/horchestra/api/secrets/v1"
)

// recorder is the shared call log the ordering fakes append to. The reconcile core drives
// three injected ports and the order it drives them in is a data dependency, not a style
// choice: a mount destination must exist before the rootfs is assembled, and a secret must be
// materialized before the unit that reads it is started.
type recorder struct{ calls []string }

func (r *recorder) note(s string) { r.calls = append(r.calls, s) }

type orderedVolumes struct {
	rec     *recorder
	fits    bool
	resolve error
}

func (v *orderedVolumes) Provision(context.Context, map[string]corev1.PersistentVolume) error {
	v.rec.note("volumes.Provision")
	return nil
}

func (v *orderedVolumes) Fits(workload.App, map[string]corev1.PersistentVolume) bool {
	v.rec.note("volumes.Fits")
	return v.fits
}

func (v *orderedVolumes) Resolve(workload.App, map[string]corev1.PersistentVolume) ([]workload.Volume, error) {
	v.rec.note("volumes.Resolve")
	return nil, v.resolve
}

func (v *orderedVolumes) Reclaim(context.Context, map[string]bool, map[string]workload.App) error {
	v.rec.note("volumes.Reclaim")
	return nil
}

type orderedSecrets struct {
	rec         *recorder
	materialize error
	env         error
}

func (s *orderedSecrets) Materialize(context.Context, workload.App, []corev1.Secret, []secretsv1.SecretStore) ([]workload.Volume, error) {
	s.rec.note("secrets.Materialize")
	return nil, s.materialize
}

func (s *orderedSecrets) MaterializeEnv(context.Context, workload.App, []corev1.Secret, []secretsv1.SecretStore) ([]string, error) {
	s.rec.note("secrets.MaterializeEnv")
	return nil, s.env
}

// orderedRuntime records Apply/States/Remove and answers States from a fixed set, standing in
// for the node's actual state.
type orderedRuntime struct {
	rec *recorder
	// held is what the runtime reports holding: ids, or ids with a phase when the test cares
	// which state they are in.
	held    []workload.State
	removed []string
	applied []workload.App
}

func (r *orderedRuntime) Name() string { return "ordered" }

func (r *orderedRuntime) Apply(_ context.Context, app workload.App, _ []workload.Volume) error {
	r.rec.note("runtime.Apply")
	r.applied = append(r.applied, app)
	return nil
}

func (r *orderedRuntime) Remove(_ context.Context, name string, _ time.Duration) error {
	r.rec.note("runtime.Remove")
	r.removed = append(r.removed, name)
	return nil
}

func (r *orderedRuntime) States(context.Context) ([]workload.State, error) {
	r.rec.note("runtime.States")
	return r.held, nil
}

func (r *orderedRuntime) Reap(context.Context) error { return nil }

func (r *orderedRuntime) GC(context.Context, []string) ([]string, error) {
	r.rec.note("runtime.GC")
	return nil, nil
}

func (r *orderedRuntime) Metrics(context.Context, string) (workload.Usage, error) {
	return workload.Usage{}, nil
}

func (r *orderedRuntime) Logs(context.Context, string, bool, int64) (io.ReadCloser, error) {
	return nil, errors.New("not used")
}

func orderedAgent(rec *recorder, vols *orderedVolumes, secs *orderedSecrets, rt *orderedRuntime) *Agent {
	return &Agent{volumes: vols, secrets: secs, runtime: rt}
}

// wantedUID and staleUID are object uids, which is what a workload is keyed by on the node.
const (
	wantedUID = "b4e95624-75d6-4639-9f6d-2a4aa651df6f"
	staleUID  = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
)

func oneApp() map[string]workload.App {
	return map[string]workload.App{wantedUID: {UID: wantedUID, Namespace: "ns", Name: "app", Generation: 1}}
}

// TestReconcileProviderOrdering pins the order the reconcile core drives its ports in.
//
// It exists to fail a refactor into a generic provider list. The sequence is a real data
// dependency — volumes resolve to the mount destinations the rootfs is assembled around, and
// secrets must exist before the unit that reads them starts — so a list that happens to be in
// the right order today is one reordering away from a workload starting without its secret.
func TestReconcileProviderOrdering(t *testing.T) {
	rec := &recorder{}
	rt := &orderedRuntime{rec: rec}
	a := orderedAgent(rec, &orderedVolumes{rec: rec, fits: true}, &orderedSecrets{rec: rec}, rt)

	if errs := a.reconcileApps(context.Background(), oneApp(), nil, nil, nil); len(errs) > 0 {
		t.Fatalf("converge must succeed, got %v", errs)
	}
	want := []string{
		"volumes.Fits",
		"volumes.Resolve",
		"secrets.Materialize",
		"secrets.MaterializeEnv",
		"runtime.Apply",
		"runtime.States",
	}
	if !slices.Equal(rec.calls, want) {
		t.Fatalf("provider order\n got %v\nwant %v", rec.calls, want)
	}
}

// TestReconcileFailClosedShortCircuits checks each stage is a gate, not a step: a failure at
// any provider must stop before the Apply, never start a workload with a half-resolved
// dependency. The fail-closed rule is what makes the ordering above meaningful.
func TestReconcileFailClosedShortCircuits(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name string
		vols *orderedVolumes
		secs *orderedSecrets
		want []string
	}{
		{"volumes do not fit this node", &orderedVolumes{fits: false}, &orderedSecrets{},
			[]string{"volumes.Fits", "runtime.States"}},
		{"volume resolution fails", &orderedVolumes{fits: true, resolve: boom}, &orderedSecrets{},
			[]string{"volumes.Fits", "volumes.Resolve", "runtime.States"}},
		{"secret materialization fails", &orderedVolumes{fits: true}, &orderedSecrets{materialize: boom},
			[]string{"volumes.Fits", "volumes.Resolve", "secrets.Materialize", "runtime.States"}},
		{"secret env fails", &orderedVolumes{fits: true}, &orderedSecrets{env: boom},
			[]string{"volumes.Fits", "volumes.Resolve", "secrets.Materialize", "secrets.MaterializeEnv", "runtime.States"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			tc.vols.rec, tc.secs.rec = rec, rec
			rt := &orderedRuntime{rec: rec}
			a := orderedAgent(rec, tc.vols, tc.secs, rt)

			a.reconcileApps(context.Background(), oneApp(), nil, nil, nil)
			if slices.Contains(rec.calls, "runtime.Apply") {
				t.Fatalf("a failed dependency must not reach Apply; calls: %v", rec.calls)
			}
			if !slices.Equal(rec.calls, tc.want) {
				t.Fatalf("calls\n got %v\nwant %v", rec.calls, tc.want)
			}
		})
	}
}

// TestReconcileReadsActualStateFromRuntime holds the no-node-local-durable-state invariant for
// the desired/actual pair: what is running is asked of the Runtime every pass, never read back
// from a record the agent persisted. A fresh Agent — the state after a crash or an upgrade,
// with an empty `applied` map — must still remove a workload it never applied itself.
func TestReconcileReadsActualStateFromRuntime(t *testing.T) {
	rec := &recorder{}
	rt := &orderedRuntime{rec: rec, held: []workload.State{{ID: staleUID, Phase: corev1.AppPhaseRunning}}}
	a := orderedAgent(rec, &orderedVolumes{rec: rec, fits: true}, &orderedSecrets{rec: rec}, rt)
	if a.applied != nil {
		t.Fatal("a fresh Agent must start with no recollection of what it applied")
	}

	a.reconcileApps(context.Background(), oneApp(), nil, nil, nil)

	if !slices.Equal(rt.removed, []string{staleUID}) {
		t.Fatalf("a workload the runtime reports but nothing wants must be removed, got %v", rt.removed)
	}
	if len(rt.applied) != 1 || rt.applied[0].ID() != wantedUID {
		t.Fatalf("the wanted workload must be applied, got %v", rt.applied)
	}
	if got := a.applied[wantedUID]; got != 1 {
		t.Fatalf("applied generation = %d, want 1 (in memory only — nothing here is persisted)", got)
	}
}

// TestAppsForNodeDropsAppsWithoutAUID: the node keys a workload by its object uid — the unit
// name, the config file and the state directories all derive from it. An application that
// arrives without one has no identity here, and keying it under "" would be worse than dropping
// it: a second such application would displace the first in the desired map, and both would name
// the same unit and the same config file.
func TestAppsForNodeDropsAppsWithoutAUID(t *testing.T) {
	got := appsForNode([]workload.App{
		{UID: wantedUID, Namespace: "ns", Name: "app", Node: "n1"},
		{Namespace: "ns", Name: "no-uid", Node: "n1"},
		{Namespace: "ns", Name: "other-no-uid", Node: "n1"},
	}, "n1")

	if _, ok := got[""]; ok {
		t.Fatal("an application with no uid was keyed under the empty id")
	}
	if len(got) != 1 || got[wantedUID].Name != "app" {
		t.Fatalf("only the identified application must be wanted, got %v", got)
	}
}
