package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ks-tool/horchestra/api/pki"
	"github.com/ks-tool/horchestra/pkg/vaultpki"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
)

// kubeconfigCmd issues a client certificate and emits a self-contained kubeconfig (CA, client
// certificate and key embedded) for reaching the controller with kubectl. The CN becomes the
// request identity and --group the request groups.
//
// WHERE the certificate comes from follows the fleet, not a flag: a fleet whose file says
// `vaultPKI` has no signing key on disk to use, so the certificate is signed through the same
// engine that signs everything else in it. A fleet with a local CA key is signed by that, as
// before. The difference is invisible in the result — the same kubeconfig either way — which is
// the point of asking the fleet instead of the operator.
func kubeconfigCmd() *cobra.Command {
	var dir, group, server, name, out, file, vaultRole string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "kubeconfig <cn>",
		Short: "issue a certificate and emit a kubeconfig for kubectl",
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			cn := args[0]
			groups := splitGroups(group)

			// The CA in a kubeconfig verifies the SERVER, and the controller's serving
			// certificate is issued by the fleet's own CA in every mode — so this half never
			// changes, and only the client half moves to Vault.
			caCert := read(filepath.Join(dir, "ca.crt"))

			var cert, key []byte
			if v := vaultSigningSpec(file); v != nil {
				var err error
				cert, key, err = vaultClientCert(v, vaultRole, cn, groups, ttl)
				fatal(err, "sign through Vault")
				log.Info().Str("cn", cn).Str("server", v.Server).Str("role", vaultRoleFor(v, vaultRole)).
					Msg("certificate signed by the fleet's PKI engine")
			} else {
				ca, err := pki.LoadCA(caCert, read(filepath.Join(dir, "ca.key")))
				fatal(err, "load CA")
				cert, key, err = ca.IssueClient(cn, groups, ttl)
				fatal(err, "issue certificate")
			}

			data, err := clientcmd.Write(newKubeconfig(name, cn, server, caCert, cert, key))
			fatal(err, "marshal kubeconfig")

			if len(out) == 0 {
				_, _ = os.Stdout.Write(data)
				return
			}
			write(out, data, 0o600) // contains the client private key
			log.Info().Str("cn", cn).Str("out", out).Msg("wrote kubeconfig")
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&dir, "pki-dir", "pki", "PKI directory")
	fs.StringVarP(&file, "filename", "f", fleetFileName, "the fleet description, read to learn how this fleet signs (absent: a local CA key)")
	fs.StringVar(&vaultRole, "vault-role", "", "PKI role to issue under, overriding the fleet's vaultPKI.adminRole")
	fs.StringVar(&group, "group", "", "comma-separated groups (certificate Organization)")
	fs.StringVar(&server, "server", "https://127.0.0.1:8443", "controller API URL")
	fs.StringVar(&name, "name", "horchestra", "cluster and context name")
	fs.StringVar(&out, "out", "", "output file (defaults to stdout)")
	fs.DurationVar(&ttl, "ttl", pki.DefaultClientTTL, "certificate lifetime")
	return cmd
}

// vaultSigningSpec reports the fleet's Vault configuration when it signs that way, and nil when it
// does not — including when there is no fleet file at all, which is the ordinary case for a CA
// created before one existed. A file that is present but unreadable is fatal rather than ignored:
// silently falling back to a local key would sign with an authority the fleet retired.
func vaultSigningSpec(file string) *VaultPKISpec {
	if _, err := os.Stat(file); err != nil {
		return nil
	}
	f, err := loadFleet(file)
	fatal(err, "read "+file)
	mode, err := f.Controller.Spec.signerMode()
	fatal(err, "node-certificate signer")
	if mode != signerVault {
		return nil
	}
	// The cert/key paths in the file are the operator's OWN copies — the same ones apply
	// uploads — so signing here needs nothing that is not already on this machine.
	v := *f.Controller.Spec.VaultPKI
	return &v
}

// vaultRoleFor picks the role to issue under: an explicit --vault-role wins, else the fleet's
// adminRole.
func vaultRoleFor(v *VaultPKISpec, override string) string {
	if len(override) > 0 {
		return override
	}
	return v.AdminRole
}

// vaultClientCert generates a key and CSR locally and has the fleet's PKI engine sign it.
//
// The private key never leaves this process's memory until it is written into the kubeconfig, and
// Vault never sees it — a CSR carries the public half only, which is the whole reason to sign this
// way rather than asking an engine to generate the pair.
//
// What comes back is a BUNDLE, not a leaf: the engine is an intermediate under the fleet's CA, so
// the intermediates travel with the certificate. Without them a kubectl handshake builds no path
// to the root the controller holds, and the failure reads as a rejected certificate rather than as
// a missing link.
func vaultClientCert(v *VaultPKISpec, override, cn string, groups []string, ttl time.Duration) (cert, key []byte, err error) {
	role := vaultRoleFor(v, override)
	if role == "" {
		return nil, nil, errors.New("this fleet signs through Vault and vaultPKI.adminRole is unset: an operator certificate needs a role of its own, because vaultPKI.role pins organization to system:nodes and cannot issue one. Set it in the fleet file, or pass --vault-role")
	}
	if len(groups) == 0 {
		return nil, nil, errors.New("--group is required when signing through Vault: the PKI role pins the Organization it issues, and this is the value that must match it")
	}

	cfg := vaultpki.Config{
		Server:   v.Server,
		Mount:    v.Mount,
		Role:     role,
		AuthPath: v.AuthPath,
		AuthRole: v.AuthRole,
	}
	if cfg.CertPEM, err = os.ReadFile(v.Cert); err != nil {
		return nil, nil, fmt.Errorf("vaultPKI.cert: %w", err)
	}
	if cfg.KeyPEM, err = os.ReadFile(v.Key); err != nil {
		return nil, nil, fmt.Errorf("vaultPKI.key: %w", err)
	}
	if v.CABundle != "" {
		if cfg.CABundle, err = os.ReadFile(v.CABundle); err != nil {
			return nil, nil, fmt.Errorf("vaultPKI.caBundle: %w", err)
		}
	}
	signer, err := vaultpki.New(cfg)
	if err != nil {
		return nil, nil, err
	}

	csrPEM, keyPEM, err := pki.GenerateCSR(cn)
	if err != nil {
		return nil, nil, err
	}
	// SignCSR verifies the Organization that came back is the one asked for, so a role pinned to
	// a different group is refused here rather than producing a kubeconfig that authenticates as
	// somebody else.
	bundle, err := signer.SignCSR(csrPEM, groups, ttl)
	if err != nil {
		return nil, nil, err
	}
	return bundle, keyPEM, nil
}
