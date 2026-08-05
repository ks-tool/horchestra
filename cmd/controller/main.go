// Command horchestra-controller is the standalone control-plane binary — the controller command
// as its own process, built on any OS (the control plane is cross-platform).
package main

import (
	"github.com/ks-tool/horchestra/cmd/internal/root"
)

func main() {
	root.Run(controllerCmd())
}
