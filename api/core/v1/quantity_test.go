package v1

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestQuantityBombRejected asserts the decode refuses a literal whose exponent makes
// resource.ParseQuantity superlinear, on every quantity-bearing Kind, and that it refuses it
// FAST (the point of the bound is that the parse never runs).
func TestQuantityBombRejected(t *testing.T) {
	for name, body := range map[string]string{
		"application resources": `{"resources":{"requests":{"cpu":"1e-100000000"}}}`,
		"volume size":           `{"volumes":[{"volume":{"type":"pv","size":"1e-100000000"},"mountPath":"/d"}]}`,
		"pv size":               `{"size":"1e-100000000"}`,
		"escaped exponent":      `{"resources":{"limits":{"memory":"1e-100000000"}}}`,
		"bare number":           `{"resources":{"requests":{"cpu":1e-100000000}}}`,
		"fold-spelled key":      `{"volumes":[{"volume":{"type":"pv","ſize":"1e-100000000"},"mountPath":"/d"}]}`,
		"overlong literal":      `{"resources":{"requests":{"cpu":"` + strings.Repeat("9", 4096) + `"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var (
				obj  any = new(ApplicationSpec)
				done     = make(chan error, 1)
			)
			if name == "pv size" {
				obj = new(PersistentVolumeSpec)
			}
			start := time.Now()
			go func() { done <- json.Unmarshal([]byte(body), obj) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("decoded %s without error after %s; the parse bomb ran", name, time.Since(start))
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("decode of %s did not return: the exponent bound is not in effect", name)
			}
		})
	}
}

// TestQuantityLiteralsAccepted asserts the bound does not reject anything a real spec carries —
// including the non-numeric strings that share these structs.
func TestQuantityLiteralsAccepted(t *testing.T) {
	for name, body := range map[string]string{
		"suffixed":       `{"resources":{"requests":{"cpu":"500m","memory":"512Mi"},"limits":{"cpu":"2","memory":"8Gi"}}}`,
		"exa suffix":     `{"volumes":[{"volume":{"type":"pv","size":"1E"},"mountPath":"/d"}]}`,
		"small exponent": `{"volumes":[{"volume":{"type":"tmpfs","size":"1e9"},"mountPath":"/d"}]}`,
		"zero exponent":  `{"volumes":[{"volume":{"type":"tmpfs","size":"64e000"},"mountPath":"/d"}]}`,
		"paths and names": `{"volumes":[{"name":"data","volume":{"type":"pv","name":"vol-1","size":"10Gi"},` +
			`"mountPath":"/var/lib/data","subPath":"sub"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(body), new(ApplicationSpec)); err != nil {
				t.Fatalf("rejected a legitimate spec: %v", err)
			}
		})
	}
	pv := `{"size":"10Gi","node":"n1","mode":"0755","driver":"local","path":"/srv/v"}`
	if err := json.Unmarshal([]byte(pv), new(PersistentVolumeSpec)); err != nil {
		t.Fatalf("rejected a legitimate persistentvolume spec: %v", err)
	}
}
