package main

import (
	"path/filepath"
	"time"

	"github.com/ks-tool/horchestra/api/pki"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// certCmd issues a client certificate signed by the local CA.
func certCmd() *cobra.Command {
	var dir, group, out string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "cert <cn>",
		Short: "issue a client certificate signed by the CA",
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			cn := args[0]
			prefix := out
			if len(prefix) == 0 {
				prefix = cn
			}

			ca, err := pki.LoadCA(read(filepath.Join(dir, "ca.crt")), read(filepath.Join(dir, "ca.key")))
			fatal(err, "load CA")
			cert, key, err := ca.IssueClient(cn, splitGroups(group), ttl)
			fatal(err, "issue certificate")

			write(prefix+".crt", cert, 0o644)
			write(prefix+".key", key, 0o600)
			log.Info().Str("cn", cn).Str("out", prefix).Msg("issued client certificate")
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&dir, "pki-dir", "pki", "PKI directory")
	fs.StringVar(&group, "group", "", "comma-separated groups (certificate Organization)")
	fs.StringVar(&out, "out", "", "output path prefix (writes <out>.crt and <out>.key; defaults to the CN)")
	fs.DurationVar(&ttl, "ttl", pki.DefaultClientTTL, "certificate lifetime")
	return cmd
}
