package plugins

import (
	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// PrioritySortName is the plugin's registry name.
const PrioritySortName = "PrioritySort"

// PrioritySort is the QueueSort plugin: it orders pending Applications by descending
// spec.priority, then oldest-first (FIFO by creationTimestamp), then by name — a total,
// stable order. It replaces the scheduler loop's previously hard-coded oldest-first sort,
// making the queue policy a swappable plugin like every other extension point.
type PrioritySort struct{}

var _ framework.QueueSortPlugin = (*PrioritySort)(nil)

// NewPrioritySort builds the plugin.
func NewPrioritySort() *PrioritySort { return &PrioritySort{} }

func (*PrioritySort) Name() string { return PrioritySortName }

// Less reports whether a is scheduled before b: higher priority first, then the older app,
// then the lexicographically smaller name (so equal-priority equal-age apps still order
// deterministically).
func (*PrioritySort) Less(a, b *corev1.Application) bool {
	if pa, pb := priorityOf(a), priorityOf(b); pa != pb {
		return pa > pb
	}
	ta, tb := a.CreationTimestamp.Time, b.CreationTimestamp.Time
	if !ta.Equal(tb) {
		return ta.Before(tb)
	}
	return a.Name < b.Name
}

// priorityOf reads an app's scheduling priority, treating an unset priority as 0.
func priorityOf(a *corev1.Application) int32 {
	if a.Spec.Placement.Priority == nil {
		return 0
	}
	return *a.Spec.Placement.Priority
}
