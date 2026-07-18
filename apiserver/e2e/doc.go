// Package e2e holds black-box end-to-end tests that drive a running APIServer
// over HTTP with the real registered Kinds (core + rbac), backed by the bolt
// storage engine — exercising the full transport → service → admission → storage
// path exactly as a client would.
package e2e
