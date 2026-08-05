package plugins

import (
	"context"

	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// VolumeBindingName is the plugin's registry name.
const VolumeBindingName = "VolumeBinding"

// volumeStateKey is where PreFilter stashes the app's resolved volume constraint for
// Filter and PreBind to read back within the cycle.
const volumeStateKey = "VolumeBinding"

// VolumeBinding is the control-plane half of storage: it makes an app's inline pv
// volumes real and co-locates them with the app.
//
//   - PreFilter: for each pv volume, ensure a PersistentVolume exists (creating a
//     nodeless one on demand — implicit provisioning), record the node an
//     already-bound volume forces the app onto, and the nodeless volumes still to
//     place. Two bound volumes on different nodes is Unschedulable (an app and its
//     volumes live on one node).
//   - Filter: keep only the node an already-bound volume requires.
//   - PreBind: pin the nodeless volumes to the node the app landed on.
type VolumeBinding struct {
	handle framework.Handle
}

// NewVolumeBinding builds the plugin.
func NewVolumeBinding(h framework.Handle) *VolumeBinding { return &VolumeBinding{handle: h} }

func (*VolumeBinding) Name() string { return VolumeBindingName }

// volumeState is the per-cycle result of PreFilter.
type volumeState struct {
	required string   // node an already-bound volume forces the app onto ("" = free)
	nodeless []string // pv names with no node yet, to co-schedule onto the chosen node
}

func (p *VolumeBinding) PreFilter(ctx context.Context, state *framework.CycleState, app *corev1.Application) *framework.Status {
	var vs volumeState
	for _, m := range app.Spec.Volumes {
		if !m.IsPV() {
			continue
		}
		name := m.PVName(app.Name)
		pv, ok := p.handle.PV(app.Namespace, name)
		if !ok {
			if err := p.handle.CreatePV(ctx, app.Namespace, name, m.Volume.Size); err != nil {
				return framework.AsError(err)
			}
			vs.nodeless = append(vs.nodeless, name)
			continue
		}
		if pv.Spec.Node == "" {
			vs.nodeless = append(vs.nodeless, name)
			continue
		}
		if vs.required != "" && vs.required != pv.Spec.Node {
			return framework.NewStatus(framework.Unschedulable, "mounted volumes are on conflicting nodes")
		}
		vs.required = pv.Spec.Node
	}
	state.Write(volumeStateKey, &vs)
	return nil
}

func (p *VolumeBinding) Filter(_ context.Context, state *framework.CycleState, _ *corev1.Application, node *framework.NodeInfo) *framework.Status {
	vs := volumeStateOf(state)
	if vs.required != "" && vs.required != node.Node.Name {
		return framework.NewStatus(framework.Unschedulable, "a mounted volume is backed on another node")
	}
	return nil
}

func (p *VolumeBinding) PreBind(ctx context.Context, state *framework.CycleState, app *corev1.Application, node string) *framework.Status {
	for _, name := range volumeStateOf(state).nodeless {
		if err := p.handle.BindPV(ctx, app.Namespace, name, node); err != nil {
			return framework.AsError(err)
		}
	}
	return nil
}

// volumeStateOf reads PreFilter's result; an absent entry (e.g. an app with no pv
// volumes) yields the empty constraint.
func volumeStateOf(state *framework.CycleState) *volumeState {
	if v, ok := state.Read(volumeStateKey); ok {
		if vs, ok := v.(*volumeState); ok {
			return vs
		}
	}
	return &volumeState{}
}
