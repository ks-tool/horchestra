package plugins

import (
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPrioritySortLess(t *testing.T) {
	sorter := NewPrioritySort()
	base := time.Now()
	p := func(v int32) *int32 { return &v }
	mk := func(name string, prio *int32, age time.Duration) *corev1.Application {
		a := &corev1.Application{}
		a.Name = name
		a.CreationTimestamp = metav1.NewTime(base.Add(-age))
		a.Spec.Placement.Priority = prio
		return a
	}

	// Higher priority sorts first, even when it is the younger app.
	hi, lo := mk("hi", p(10), 0), mk("lo", p(1), time.Hour)
	if !sorter.Less(hi, lo) {
		t.Error("higher priority must sort first")
	}
	if sorter.Less(lo, hi) {
		t.Error("lower priority must not sort before higher")
	}

	// Equal priority (both unset → 0): the older app sorts first (FIFO).
	older, younger := mk("old", nil, time.Hour), mk("new", nil, 0)
	if !sorter.Less(older, younger) {
		t.Error("at equal priority the older app must sort first")
	}
	if sorter.Less(younger, older) {
		t.Error("the younger app must not sort before the older")
	}

	// Equal priority and age: break the tie by name so the order is total.
	a1, b1 := mk("a", nil, time.Hour), mk("b", nil, time.Hour)
	b1.CreationTimestamp = a1.CreationTimestamp
	if !sorter.Less(a1, b1) || sorter.Less(b1, a1) {
		t.Error("equal priority+age must break ties by name")
	}
}
