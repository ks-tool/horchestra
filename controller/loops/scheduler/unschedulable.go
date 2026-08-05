package scheduler

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"
)

// An application no node will take is the one an operator goes looking for, and until now it was
// the one that said nothing. Every failing path through a scheduling cycle logged its reason into
// the CONTROLLER's journal and left the object blank: no phase, no message, no event. From the
// outside a workload nothing can place and a workload the scheduler has not reached yet are the
// same object, and the operator's next move — find the controller's logs and read them — is one
// they cannot make in a cluster they only have kubectl for.
//
// The reasons were never missing. Filter runs per node and its verdicts are collected, then
// dropped on the floor; this is where they land instead.

// unschedulable records why the app is still pending, on the app.
//
// Through the STATUS subresource, so explaining a placement failure does not bump generation and
// wake every spec-watcher — the node's own push loop dedups on that field. And written only when
// the text actually changes: the scheduler retries every cycle, and a message rewritten each
// pass would be a write per app per cycle, forever, for an object nobody has touched.
func (s *Scheduler) unschedulable(ctx context.Context, app *corev1.Application, message string) {
	if app.Status.Phase == corev1.AppPhasePending && app.Status.Message == message {
		return
	}
	next := *app
	next.Status.Phase = corev1.AppPhasePending
	next.Status.Message = message
	if err := s.cluster.UpdateAppStatus(ctx, &next); err != nil {
		s.log.Warn().Err(err).Str("app", app.Name).Msg("scheduler: report unschedulable")
	}
}

// scheduled clears a stale placement failure once the app is placed.
//
// The node takes over reporting from here, and its first push overwrites this field — but only
// once it has one to send, and an operator reading the object in between would see a placed
// workload still carrying the reason it could not be placed.
func (s *Scheduler) scheduled(ctx context.Context, app *corev1.Application) {
	if app.Status.Message == "" {
		return
	}
	next := *app
	next.Status.Message = ""
	if err := s.cluster.UpdateAppStatus(ctx, &next); err != nil {
		s.log.Warn().Err(err).Str("app", app.Name).Msg("scheduler: clear placement message")
	}
}

// noNodeFits summarises a whole cycle's filter verdicts the way a reader can act on: how many
// nodes were considered, and how many rejected the app for each distinct reason. One line per
// node would be unreadable on a fleet and unstable between cycles; the counted form is neither.
func noNodeFits(considered int, filtered map[string]*framework.Status) string {
	if considered == 0 {
		return "no node is registered"
	}
	counts := map[string]int{}
	for _, st := range filtered {
		reason := "filtered"
		if st != nil && st.Message() != "" {
			reason = st.Message()
		}
		counts[reason]++
	}
	reasons := make([]string, 0, len(counts))
	for reason := range counts {
		reasons = append(reasons, reason)
	}
	// Commonest first, then alphabetically: a summary that reshuffles between cycles is one that
	// rewrites the object for no reason.
	sort.Slice(reasons, func(i, j int) bool {
		if counts[reasons[i]] != counts[reasons[j]] {
			return counts[reasons[i]] > counts[reasons[j]]
		}
		return reasons[i] < reasons[j]
	})
	parts := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		parts = append(parts, fmt.Sprintf("%d %s", counts[reason], reason))
	}
	return fmt.Sprintf("0/%d nodes are available: %s", considered, strings.Join(parts, ", "))
}
