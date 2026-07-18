package main

import (
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// fatal aborts the process with err when it is non-null — node-tool's commands are
// fail-fast, so each step logs and exits rather than unwinding an error.
func fatal(err error, msg string) {
	if err != nil {
		log.Fatal().Err(err).Msg(msg)
	}
}

// write writes data to path with mode, aborting on error.
func write(path string, data []byte, mode os.FileMode) {
	fatal(os.WriteFile(path, data, mode), "write "+path)
}

// read reads path, aborting on error.
func read(path string) []byte {
	data, err := os.ReadFile(path)
	fatal(err, "read "+path)
	return data
}

// splitGroups parses a comma-separated group list (certificate Organization); an
// empty value yields no groups.
func splitGroups(s string) []string {
	if len(s) == 0 {
		return nil
	}
	return strings.Split(s, ",")
}

// newKubeconfig builds a single-context client config: cluster `name` (server +
// CA), user `user` (client cert/key), and a current context binding them — the
// kubeconfig node-tool emits for controllers, admins and nodes.
func newKubeconfig(name, user, server string, ca, cert, key []byte) clientcmdapi.Config {
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters[name] = &clientcmdapi.Cluster{Server: server, CertificateAuthorityData: ca}
	cfg.AuthInfos[user] = &clientcmdapi.AuthInfo{ClientCertificateData: cert, ClientKeyData: key}
	cfg.Contexts[name] = &clientcmdapi.Context{Cluster: name, AuthInfo: user}
	cfg.CurrentContext = name
	return *cfg
}

// writeKubeconfig marshals kc and writes it 0600 (it embeds a private key).
func writeKubeconfig(path string, kc clientcmdapi.Config) {
	data, err := clientcmd.Write(kc)
	fatal(err, "marshal kubeconfig "+path)
	write(path, data, 0o600)
}
