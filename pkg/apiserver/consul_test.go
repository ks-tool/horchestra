package apiserver

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestConsulSD exercises the /sd/consul projection: applications' spec.expose
// ports are rendered as Consul catalog services (named ports become
// "<app>-<name>", unnamed ports the app's own name), reachable at the node's
// reported address, with the Enterprise Namespace field omitted and apps whose
// node has no address yet left out.
func TestConsulSD(t *testing.T) {
	srv := httptest.NewServer(newTestServer(t))
	defer srv.Close()
	c := srv.Client()

	// n1 has reported an address; n2 has not.
	mustPost(t, c, srv.URL+"/apis/orch.ks-tool.dev/v1/nodes",
		`{"apiVersion":"orch.ks-tool.dev/v1","kind":"Node","metadata":{"name":"n1"},"status":{"ip":"10.0.0.11","ready":true}}`)
	mustPost(t, c, srv.URL+"/apis/orch.ks-tool.dev/v1/nodes",
		`{"apiVersion":"orch.ks-tool.dev/v1","kind":"Node","metadata":{"name":"n2"}}`)

	apps := srv.URL + "/apis/orch.ks-tool.dev/v1/applications"
	// Two named ports -> two services with tags.
	mustPost(t, c, apps, `{"apiVersion":"orch.ks-tool.dev/v1","kind":"Application","metadata":{"name":"web"},"spec":{"image":"reg/web:v1","nodeName":"n1","ports":[{"name":"http","port":8080},{"name":"metrics","port":9090}]}}`)
	// One unnamed port -> a service under the app's own name, no tags.
	mustPost(t, c, apps, `{"apiVersion":"orch.ks-tool.dev/v1","kind":"Application","metadata":{"name":"cache"},"spec":{"image":"reg/cache:v1","nodeName":"n1","ports":[{"port":6379}]}}`)
	// No ports -> contributes nothing.
	mustPost(t, c, apps, `{"apiVersion":"orch.ks-tool.dev/v1","kind":"Application","metadata":{"name":"db"},"spec":{"image":"reg/db:v1","nodeName":"n1"}}`)
	// Has a port, but its node has no address yet -> skipped.
	mustPost(t, c, apps, `{"apiVersion":"orch.ks-tool.dev/v1","kind":"Application","metadata":{"name":"pending"},"spec":{"image":"reg/p:v1","nodeName":"n2","ports":[{"port":5432}]}}`)

	// The bare endpoint and Consul's own catalog path both serve the services map.
	for _, path := range []string{"/sd/consul", "/sd/consul/v1/catalog/services"} {
		resp, err := c.Get(srv.URL + path)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: err=%v status=%v", path, err, resp.StatusCode)
		}
		var services map[string][]string
		decode(t, resp, &services)
		want := map[string][]string{"web-http": {"http"}, "web-metrics": {"metrics"}, "cache": {}}
		if len(services) != len(want) {
			t.Fatalf("%s: services = %v, want keys %v", path, services, want)
		}
		for name, tags := range want {
			got, ok := services[name]
			if !ok {
				t.Errorf("%s: missing service %q", path, name)
				continue
			}
			if strings.Join(got, ",") != strings.Join(tags, ",") {
				t.Errorf("%s: service %q tags = %v, want %v", path, name, got, tags)
			}
		}
		if _, ok := services["db"]; ok {
			t.Errorf("%s: unexposed app db must not appear", path)
		}
		if _, ok := services["pending"]; ok {
			t.Errorf("%s: app on an address-less node must not appear", path)
		}
	}

	// One service's instances, in Consul's catalog-service shape.
	body := mustGet(t, c, srv.URL+"/sd/consul/v1/catalog/service/web-http")
	if strings.Contains(body, "Namespace") {
		t.Errorf("catalog service must omit the Namespace field: %s", body)
	}
	var instances []catalogService
	if err := json.Unmarshal([]byte(body), &instances); err != nil {
		t.Fatalf("decode instances: %v (body %s)", err, body)
	}
	if len(instances) != 1 {
		t.Fatalf("web-http instances = %d, want 1: %s", len(instances), body)
	}
	got := instances[0]
	if got.Node != "n1" || got.Address != "10.0.0.11" || got.ServiceAddress != "10.0.0.11" ||
		got.ServiceName != "web-http" || got.ServiceID != "web-http" || got.ServicePort != 8080 ||
		strings.Join(got.ServiceTags, ",") != "http" {
		t.Fatalf("web-http instance = %+v", got)
	}

	// An unknown service is an empty array (as Consul returns), not a 404.
	empty := mustGet(t, c, srv.URL+"/sd/consul/v1/catalog/service/nope")
	if strings.TrimSpace(empty) != "[]" {
		t.Fatalf("unknown service = %q, want []", empty)
	}
}

func mustPost(t *testing.T, c *http.Client, url, body string) {
	t.Helper()
	resp, err := c.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s: status=%v body=%s", url, resp.StatusCode, b)
	}
}

func mustGet(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: err=%v status=%v", url, err, resp.StatusCode)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
