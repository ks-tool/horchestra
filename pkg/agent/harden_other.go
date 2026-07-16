//go:build !linux

package agent

// hardenLayout/unlockLayout are no-ops off Linux: the immutable-flag protection
// is a node-side (Linux) feature, and Pull/Purge/RemoveImage stay cross-platform
// (buildable and testable on darwin) by calling these stubs.
func hardenLayout(_ string) {}
func unlockLayout(_ string) {}
