//go:build linux

package main

import "github.com/spf13/cobra"

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "install a horchestra role as a systemd unit",
}

func init() {
	rootCmd.AddCommand(installCmd)
}
