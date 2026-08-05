//go:build !linux

package agent

import (
	"context"
	"fmt"
	"io"
)

// agentUnitLogs has no meaning off linux: there is no journal to read and no unit to read it for.
// The agent is a linux-only role; this exists so the package type-checks where the rest of the
// tree still builds.
func agentUnitLogs(context.Context, string, bool, int64) (io.ReadCloser, error) {
	return nil, fmt.Errorf("node logs are only available on linux")
}
