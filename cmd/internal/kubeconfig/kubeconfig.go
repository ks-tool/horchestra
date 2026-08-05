// Package kubeconfig builds the single-context client configs the operator CLI (node-tool) and
// a node's self-enrollment emit — controller.conf, admin.conf and node.conf — each one cluster,
// one user and one current context. It is the single home for that assembly, shared so the two
// callers cannot drift.
package kubeconfig

import clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

// Build returns a single-context kubeconfig: cluster `name` (server + CA), user `user` (client
// cert/key), and a current context binding them.
func Build(name, user, server string, ca, cert, key []byte) clientcmdapi.Config {
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters[name] = &clientcmdapi.Cluster{Server: server, CertificateAuthorityData: ca}
	cfg.AuthInfos[user] = &clientcmdapi.AuthInfo{ClientCertificateData: cert, ClientKeyData: key}
	cfg.Contexts[name] = &clientcmdapi.Context{Cluster: name, AuthInfo: user}
	cfg.CurrentContext = name
	return *cfg
}
