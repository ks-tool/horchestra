package main

import "strings"

// grantJournalAccess builds the elevated step that puts the agent's user in the journal group and
// makes that grant EFFECTIVE.
//
// Both halves are needed and the second is the surprising one. Supplementary groups are fixed when
// a process starts, and the user manager starts at LOGIN — which is this very SSH connection,
// before anything here runs. So a grant alone changes nothing until that manager restarts, and an
// install that stopped at the grant produced a node whose `kubectl logs` was silently empty forever.
//
// The restart is conditional on the manager actually lacking the group, because it takes every
// workload on the node with it. On a first apply there are none and it is free; on a re-apply of a
// node that already has the group, nothing happens at all.
func grantJournalAccess(r *remote, user string) string {
	script := `set -e
getent group ` + journalGroup + ` >/dev/null 2>&1 || exit 0
usermod -aG ` + journalGroup + ` ` + user + `
uid=$(id -u ` + user + `)
systemctl is-active --quiet user@$uid || exit 0
gid=$(getent group ` + journalGroup + ` | cut -d: -f3)
mp=$(systemctl show user@$uid -p MainPID --value)
if [ -n "$mp" ] && ! grep -qE "^Groups:.*(^|[[:space:]])$gid([[:space:]]|$)" /proc/$mp/status; then
  systemctl restart user@$uid
fi`
	cmd, _ := r.elevate("sh -c "+shellQuote(script), nil)
	return cmd
}

// shellQuote wraps s so a remote `sh -c` receives it as one argument.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
