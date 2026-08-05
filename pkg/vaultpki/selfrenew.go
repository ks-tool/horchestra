package vaultpki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ks-tool/horchestra/api/pki"

	"github.com/rs/zerolog/log"
)

// renewFraction of the remaining life is when the controller's own credential is renewed —
// the same two-thirds the node agent uses for its certificate, so being late by a tick is
// absorbed. checkFloor keeps a short-lived or already-expiring certificate from turning the
// loop into a spin.
const (
	renewNumer = 2
	renewDenom = 3
	checkFloor = time.Minute
)

// SelfRenew keeps the controller's OWN Vault credential current, through the same engine it
// signs node certificates with. Run it as its own goroutine for the process's lifetime.
//
// Without it the hand-bootstrapped certificate is a recurring chore with a deadline: when it
// expires the controller can no longer authenticate to Vault, and every node certificate
// rotation stops — quietly, because nothing else in the system depends on that credential
// until the moment it is needed. With it, the manual step is genuinely once.
//
// It renews rather than re-enrolls: the current certificate is what authenticates the request
// for the next one, which is the same property a node's rotation has. There is no bootstrap
// path here on purpose — a controller that has let its credential lapse needs an operator,
// because the alternative is a way to obtain the credential without holding one.
func (s *Signer) SelfRenew(ctx context.Context) {
	if s.cfg.SelfRole == "" {
		return // not configured: the operator renews the credential out of band
	}
	if s.cfg.CertFile == "" || s.cfg.KeyFile == "" {
		log.Warn().Msg("vaultpki: self-renewal needs the credential's file paths; renewing out of band")
		return
	}
	for {
		leaf, err := s.currentLeaf()
		if err != nil {
			log.Error().Err(err).Msg("vaultpki: cannot read the controller's own certificate; self-renewal stopped")
			return
		}
		wait := max(checkFloor, time.Until(leaf.NotAfter)*renewNumer/renewDenom)
		log.Info().Time("expires", leaf.NotAfter).Dur("renewIn", wait).Str("cn", leaf.Subject.CommonName).
			Msg("vaultpki: controller credential renewal scheduled")
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if err := s.renewSelf(ctx, leaf); err != nil {
			// Not fatal and not a reason to stop: the current certificate is still valid for
			// the remaining third of its life, which is the margin this schedule exists to
			// leave. Retry on the floor rather than waiting out the whole fraction again.
			log.Error().Err(err).Time("expires", leaf.NotAfter).Msg("vaultpki: renewing the controller credential failed; will retry")
			select {
			case <-ctx.Done():
				return
			case <-time.After(checkFloor):
			}
		}
	}
}

// currentLeaf parses the credential the signer is using right now.
func (s *Signer) currentLeaf() (*x509.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.pair.Certificate) == 0 {
		return nil, fmt.Errorf("vaultpki: no client certificate")
	}
	return x509.ParseCertificate(s.pair.Certificate[0])
}

// renewSelf obtains a fresh certificate for the same identity and swaps it in.
//
// A NEW KEY every time, not a re-signing of the old one: a renewal that keeps the key gives
// an attacker who once copied it a credential that never stops working, which is most of what
// rotation is for.
func (s *Signer) renewSelf(ctx context.Context, leaf *x509.Certificate) error {
	csrPEM, keyPEM, err := pki.GenerateCSR(leaf.Subject.CommonName)
	if err != nil {
		return err
	}
	// The groups asked for are the ones this credential already carries — SignCSR verifies the
	// issued certificate against them, so a self-role that pins something else fails loudly
	// here rather than silently re-identifying the controller.
	ttl := leaf.NotAfter.Sub(leaf.NotBefore)
	certPEM, err := s.signWithRole(ctx, s.cfg.SelfRole, csrPEM, leaf.Subject.Organization, ttl)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("vaultpki: the renewed credential does not load: %w", err)
	}
	// On disk before in memory: a process that swapped first and then failed to write would
	// come back after a restart on the OLD certificate, which the next renewal has already
	// been scheduled against — and if that one had expired, with no way in at all.
	if err := writeFileAtomic(s.cfg.CertFile, certPEM, 0o644); err != nil {
		return err
	}
	if err := writeFileAtomic(s.cfg.KeyFile, keyPEM, 0o600); err != nil {
		return err
	}
	s.mu.Lock()
	s.pair = pair
	s.mu.Unlock()

	renewed, _ := x509.ParseCertificate(pair.Certificate[0])
	log.Info().Str("cn", leaf.Subject.CommonName).Time("expires", renewed.NotAfter).
		Msg("vaultpki: renewed the controller's own Vault credential")
	return nil
}

// writeFileAtomic replaces path so a reader never sees it half-written — the credential is
// read by this process on the next start and possibly by an operator's tooling in between.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// pemLeaf is the first certificate in a PEM bundle, for tests and for reading a credential
// off disk without loading its key.
func pemLeaf(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("vaultpki: not a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
