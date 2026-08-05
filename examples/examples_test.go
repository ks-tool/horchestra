// Package examples_test keeps examples/ honest. Every manifest here is decoded STRICTLY —
// unknown and duplicate keys are errors, which the production decode path deliberately does not
// enforce — and then run through the real admission chain, so an example cannot drift into
// naming a field that no longer exists, or into a shape the server would reject. A hand-written
// manifest that silently does nothing is worse than no example at all, and that is exactly what
// a typo'd key produces without this test.
package examples_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ks-tool/horchestra/agent"
	certv1 "github.com/ks-tool/horchestra/api/certificates/v1"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/features"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/scheme"
	secretsv1 "github.com/ks-tool/horchestra/api/secrets/v1"
	"github.com/ks-tool/horchestra/controller/admission"

	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

// nonKind lists the example files that are not API objects, with the loader that owns each.
// They are still parsed, so a field renamed in the Go type breaks the example that documents it.
var nonKind = map[string]func(path string) error{
	"node-config.yaml": func(path string) error {
		cfg, err := agent.LoadNodeConfig(path)
		if err != nil {
			return err
		}
		// The file documents caps, so it must actually set some: an example that parses to
		// nothing would keep "passing" after a field is renamed.
		if cfg.Resources.CPU.IsZero() || cfg.Images.MaxLayers == 0 || cfg.Images.StoreBudget.IsZero() {
			return errors.New("parsed to an empty config: resources.cpu, images.maxLayers and images.storeBudget must all be set")
		}
		return nil
	},
}

func TestExamplesDecodeAndPassAdmission(t *testing.T) {
	sch := scheme.New()
	corev1.AddToScheme(sch)
	rbacv1.AddToScheme(sch)
	certv1.AddToScheme(sch)
	secretsv1.AddToScheme(sch)
	// A nil Lister disables only the plugins that need to read the cluster (does the node
	// exist, does it have room); every shape and policy rule still runs.
	//
	// Every feature gate is ON here. These files document what the API can EXPRESS, and a gate
	// is a deployment's choice about what to admit, not a statement about the shape — so an
	// example of a gated capability has to be checkable, while an operator still has to opt in
	// to use it. The gate itself is tested where it lives (controller/admission).
	chain := admission.DefaultChain(nil, allGates())

	files, err := filepath.Glob("*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no examples found")
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			if load, ok := nonKind[filepath.Base(file)]; ok {
				if err := load(file); err != nil {
					t.Fatalf("%s: %v", file, err)
				}
				return
			}
			docs, err := documents(file)
			if err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			if len(docs) == 0 {
				t.Fatalf("%s: no YAML documents", file)
			}
			for i, doc := range docs {
				obj, gvk, err := decodeStrict(sch, doc)
				if err != nil {
					t.Fatalf("%s doc %d: %v", file, i, err)
				}
				body, err := yaml.YAMLToJSON(doc)
				if err != nil {
					t.Fatalf("%s doc %d: %v", file, i, err)
				}
				// The server checks the raw body against the Kind's input schema before it
				// decodes anything, so an example must pass that too — and this is the gate
				// that catches a schema grown stricter than the shape it documents.
				if err := sch.Validate(gvk, body).ToAggregate(); err != nil {
					t.Fatalf("%s doc %d (%s %s): the input schema rejects it: %v",
						file, i, gvk.Kind, name(obj), err)
				}
				a := &admission.Attributes{GVK: gvk, Operation: admission.Create, Object: obj}
				if err := chain.Run(context.Background(), a); err != nil {
					t.Fatalf("%s doc %d (%s %s): admission rejects it: %v",
						file, i, gvk.Kind, name(obj), err)
				}
			}
		})
	}
}

// decodeStrict resolves a document's apiVersion/kind through the scheme and unmarshals into that
// type with unknown and duplicate keys refused.
func decodeStrict(sch *scheme.Scheme, doc []byte) (obj interface {
	GetObjectKind() schema.ObjectKind
}, gvk schema.GroupVersionKind, err error) {
	var probe struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
	}
	if err := yaml.Unmarshal(doc, &probe); err != nil {
		return nil, gvk, err
	}
	if probe.APIVersion == "" || probe.Kind == "" {
		return nil, gvk, errors.New("document has no apiVersion/kind")
	}
	gv, err := schema.ParseGroupVersion(probe.APIVersion)
	if err != nil {
		return nil, gvk, err
	}
	gvk = gv.WithKind(probe.Kind)
	typed, err := sch.New(gvk)
	if err != nil {
		return nil, gvk, err
	}
	if err := yaml.UnmarshalStrict(doc, typed); err != nil {
		return nil, gvk, err
	}
	typed.GetObjectKind().SetGroupVersionKind(gvk) // what the server's defaulting stamps
	return typed, gvk, nil
}

// documents splits a multi-document YAML file.
func documents(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	r := utilyaml.NewYAMLReader(bufio.NewReader(f))
	var docs [][]byte
	for {
		doc, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return docs, nil
			}
			return nil, err
		}
		if len(bytes.TrimSpace(stripComments(doc))) == 0 {
			continue // a trailing comment block is not a document
		}
		docs = append(docs, doc)
	}
}

// stripComments removes whole-line comments so a comment-only tail is not read as a document.
func stripComments(doc []byte) []byte {
	var out bytes.Buffer
	for _, line := range bytes.Split(doc, []byte("\n")) {
		if t := bytes.TrimSpace(line); len(t) == 0 || t[0] == '#' {
			continue
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func name(obj any) string {
	if m, ok := obj.(interface{ GetName() string }); ok {
		return m.GetName()
	}
	return "?"
}

// allGates turns on every gate this build knows, so a gated example is still validated.
func allGates() features.Gates {
	g := features.Gates{}
	for _, name := range features.Names() {
		g[features.Feature(name)] = true
	}
	return g
}
