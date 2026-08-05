package appset

import (
	"fmt"
	"maps"
	"slices"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// A run-to-completion component of a set is an INIT STEP, not a peer.
//
// A set is this system's bundle — named components, shared config, one lifecycle — so the
// question a job inside one raises is the question initContainers answer in a Pod: does it run
// alongside the services or before them? Alongside is the answer that cannot be made to mean
// anything. A migration that runs beside the service it migrates for races it; a set whose
// roll-up counts a finished job as a missing replica is never Ready; and a job that must simply
// have happened has no way to say so. So a component with restartPolicy Never gates the rest:
// the services of a set are not created until every init step has succeeded.
//
// There is no separate field for it. Never ALREADY says "this runs once and ends", and a flag
// beside it would only add a way to write a set whose declared shape and behaviour disagree.

// initComponents indexes which of a set's components are init steps, by component name.
func initComponents(set *corev1.ApplicationSet) map[string]bool {
	out := make(map[string]bool, len(set.Spec.Applications))
	for _, comp := range set.Spec.Applications {
		out[comp.Name] = comp.Spec.Lifecycle.RestartPolicy == corev1.RestartNever
	}
	return out
}

// componentOf is the component a child was rendered from; Expand stamps it on every child.
func componentOf(app corev1.Application) string { return app.Labels[corev1.LabelComponent] }

// childrenOf is the rendered children of one component, in name order so every pass sees the
// same sequence.
func childrenOf(desired map[string]corev1.Application, component string) []string {
	var names []string
	for name, app := range desired {
		if componentOf(app) == component {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// anchorChild is the child a co-located set places first and pins the rest to.
//
// With an init step it is that step's first child, and the ordering is why: initialization has
// to happen on the node the set will live on, so the node is chosen by the thing that runs
// first. Picking the lexically first child overall instead would leave the anchor undefined
// while the services are still withheld — the set would place nothing, and wait forever for a
// child it was never going to create.
func anchorChild(set *corev1.ApplicationSet, desired map[string]corev1.Application) string {
	isInit := initComponents(set)
	for _, comp := range set.Spec.Applications {
		if !isInit[comp.Name] {
			continue
		}
		if names := childrenOf(desired, comp.Name); len(names) > 0 {
			return names[0]
		}
	}
	names := slices.Sorted(maps.Keys(desired))
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// initGate reduces a set's rendered children to those that may exist right now, and explains
// any hold. Init steps run in declaration order, one step at a time — the order a set's author
// wrote them in is the order they meant — while the children WITHIN one step (a nodeSpread init
// component renders one per node) run together, since that step is one thing happening on
// several machines rather than several things.
//
// A step's children stay in the returned set once they have succeeded: they are the record that
// the step ran, and dropping them would have the set recreate — and re-run — its own history.
func initGate(set *corev1.ApplicationSet, desired, existing map[string]corev1.Application) (map[string]corev1.Application, *corev1.Condition) {
	isInit := initComponents(set)
	allowed := make(map[string]corev1.Application, len(desired))
	for _, comp := range set.Spec.Applications {
		if !isInit[comp.Name] {
			continue
		}
		names := childrenOf(desired, comp.Name)
		for _, name := range names {
			allowed[name] = desired[name]
		}
		if cond := stepHold(comp.Name, names, existing); cond != nil {
			return allowed, cond // this step is not done: everything after it waits
		}
	}
	for name, app := range desired {
		if !isInit[componentOf(app)] {
			allowed[name] = app
		}
	}
	return allowed, nil
}

// stepHold reports why an init step is not done yet, or nil when it is.
func stepHold(component string, names []string, existing map[string]corev1.Application) *corev1.Condition {
	for _, name := range names {
		cur, ok := existing[name]
		switch {
		case !ok:
			return initializing(component, fmt.Sprintf("child %q has not been created yet", name))
		case cur.Status.Phase == corev1.AppPhaseFailed:
			// A failed init step is not retried: restartPolicy Never means the node will not run
			// it again, and recreating the child here would be this controller quietly overruling
			// that. It is fixed the way everything else here is — by changing the spec.
			return &corev1.Condition{
				Type: "Initialized", Status: "False", Reason: "InitFailed",
				Message: fmt.Sprintf("init step %q failed: %s", component, exitDetail(cur)),
			}
		case !cur.Finished():
			return initializing(component, fmt.Sprintf("child %q is still running", name))
		}
	}
	return nil
}

func initializing(component, detail string) *corev1.Condition {
	return &corev1.Condition{
		Type: "Initialized", Status: "False", Reason: "Initializing",
		Message: fmt.Sprintf("init step %q has not completed: %s", component, detail),
	}
}

// exitDetail names the exit status when the node reported one, since "failed" alone does not
// tell two failures apart once the process is gone.
func exitDetail(app corev1.Application) string {
	if app.Status.ExitCode == nil {
		return "the node reported no exit status"
	}
	return fmt.Sprintf("exit %d", *app.Status.ExitCode)
}
