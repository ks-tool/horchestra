//go:build !linux

package agent

import corev1 "github.com/ks-tool/horchestra/api/core/v1"

// nodeCapacity is a no-op off Linux: capacity measurement reads /proc and uname,
// which are Linux-only. The agent runs on Linux nodes; this stub keeps the
// cross-platform reconcile code buildable and testable on other platforms.
func nodeCapacity(_ corev1.ResourceAmounts) (corev1.ResourceAmounts, string) {
	return corev1.ResourceAmounts{}, ""
}
