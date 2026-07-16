package apiserver

import (
	"mime"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bunrouter"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/duration"

	v1 "ks-tool.dev/horchestra/api/v1"
)

// tableRequested reports whether the client asked for server-side Table
// printing, i.e. an Accept entry like
// `application/json;as=Table;v=v1;g=meta.k8s.io` — what `kubectl get` sends.
// Answering with a Table (rather than a plain List) is what lets kubectl render
// real columns and, because the Table carries the resource's scope even when
// empty, print "No resources found" instead of "…in default namespace" for a
// cluster-scoped resource.
func tableRequested(req bunrouter.Request) bool {
	return acceptsTable(req.Header.Get("Accept"))
}

func acceptsTable(accept string) bool {
	for _, entry := range strings.Split(accept, ",") {
		mt, params, err := mime.ParseMediaType(strings.TrimSpace(entry))
		if err != nil {
			continue
		}
		if mt == "application/json" && params["as"] == "Table" && params["g"] == "meta.k8s.io" {
			return true
		}
	}
	return false
}

type column struct {
	def     metav1.TableColumnDefinition
	extract func(*unstructured.Unstructured) any
}

var (
	nameColumn = column{
		def:     metav1.TableColumnDefinition{Name: "Name", Type: "string", Format: "name"},
		extract: func(u *unstructured.Unstructured) any { return u.GetName() },
	}
	// kubectl's server-side Table printer prints cells verbatim — it does not
	// turn a timestamp into an age (that only happens in its client-side
	// fallback), so the age is formatted here, as kube-apiserver does.
	ageColumn = column{
		def: metav1.TableColumnDefinition{Name: "Age", Type: "string"},
		extract: func(u *unstructured.Unstructured) any {
			ct := u.GetCreationTimestamp()
			if ct.IsZero() {
				return "<unknown>"
			}
			return duration.HumanDuration(time.Since(ct.Time))
		},
	}
)

func nestedStringColumn(name string, fields ...string) column {
	return column{
		def: metav1.TableColumnDefinition{Name: name, Type: "string"},
		extract: func(u *unstructured.Unstructured) any {
			s, _, _ := unstructured.NestedString(u.Object, fields...)
			return s
		},
	}
}

// wideStringColumn is a nested string column hidden unless `kubectl get -o wide`.
func wideStringColumn(name string, fields ...string) column {
	c := nestedStringColumn(name, fields...)
	c.def.Priority = 1
	return c
}

// defaultNodeReadyTimeout is the fallback heartbeat age before a node reads
// NotReady when the controller config leaves it unset. It spans a few default
// reconcile intervals (15s), so a couple of missed reports do not flap the
// status but a stopped agent is caught quickly.
const defaultNodeReadyTimeout = 45 * time.Second

// nodeStatusColumn reports a node as Ready only when the agent last reported
// Ready and its heartbeat is still fresh; a stopped agent goes NotReady on its
// own as the heartbeat ages past readyTimeout.
func nodeStatusColumn(readyTimeout time.Duration) column {
	return column{
		def: metav1.TableColumnDefinition{Name: "Status", Type: "string"},
		extract: func(u *unstructured.Unstructured) any {
			ready, _, _ := unstructured.NestedBool(u.Object, "status", "ready")
			hb, _, _ := unstructured.NestedString(u.Object, "status", "heartbeat")
			if ready && !heartbeatStale(hb, readyTimeout) {
				return "Ready"
			}
			return "NotReady"
		},
	}
}

// heartbeatStale reports whether an RFC3339 heartbeat is missing, unparseable, or
// older than readyTimeout.
func heartbeatStale(ts string, readyTimeout time.Duration) bool {
	if len(ts) == 0 {
		return true
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return true
	}
	return time.Since(t) > readyTimeout
}

// nodeQuantity reads a status.<kind>.<field> Kubernetes resource quantity string
// (e.g. "8", "16Gi", "500m") into a Quantity; a missing or invalid value is zero.
func nodeQuantity(u *unstructured.Unstructured, kind, field string) resource.Quantity {
	s, _, _ := unstructured.NestedString(u.Object, "status", kind, field)
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return resource.Quantity{}
	}
	return q
}

// resColumn shows the allocated/capacity of a node resource, formatted by ratio
// — the amounts convey utilization directly, so it doubles as the at-a-glance
// view without a separate percentage column.
func resColumn(name, field string, ratio func(alloc, capacity resource.Quantity) string) column {
	return column{
		def: metav1.TableColumnDefinition{Name: name, Type: "string"},
		extract: func(u *unstructured.Unstructured) any {
			return ratio(nodeQuantity(u, "allocated", field), nodeQuantity(u, "capacity", field))
		},
	}
}

// cpuRatio shows CPU in cores as the quantities print them, e.g. "2/8", "500m/4".
func cpuRatio(alloc, capacity resource.Quantity) string {
	return alloc.String() + "/" + capacity.String()
}

// memRatio shows memory in GiB, e.g. "0/7.8Gi" — MemTotal is rarely an exact Gi
// multiple, so Quantity.String() would fall back to a noisy "…Ki".
func memRatio(alloc, capacity resource.Quantity) string {
	return gib(alloc) + "/" + gib(capacity) + "Gi"
}

// gib renders a byte quantity as a GiB number, dropping a trailing ".0".
func gib(q resource.Quantity) string {
	g := float64(q.Value()) / (1 << 30)
	if g == float64(int64(g)) {
		return strconv.FormatInt(int64(g), 10)
	}
	return strconv.FormatFloat(g, 'f', 1, 64)
}

// columnsFor returns the table columns for a kind: Name and Age for everything,
// plus a couple of kind-specific columns so `kubectl get` shows useful output.
func columnsFor(gvk schema.GroupVersionKind, readyTimeout time.Duration) []column {
	cols := []column{nameColumn}
	switch {
	case gvk.Group == v1.GroupName && gvk.Kind == "Application":
		cols = append(cols, nestedStringColumn("IMAGE", "spec", "image"))
	case gvk.Group == v1.GroupName && gvk.Kind == "Node":
		cols = append(cols,
			nodeStatusColumn(readyTimeout),
			resColumn("CPU", "cpu", cpuRatio),
			resColumn("MEM", "memory", memRatio),
			// IP and OS are detail, shown only with -o wide.
			wideStringColumn("IP", "status", "ip"),
			wideStringColumn("OS", "status", "os"))
	case gvk.Group == v1.GroupName && gvk.Kind == "PersistentVolume":
		cols = append(cols,
			nestedStringColumn("SIZE", "spec", "size"),
			nestedStringColumn("NODE", "spec", "node"))
	case gvk.Group == v1.RBACGroup && gvk.Kind == "RoleBinding":
		cols = append(cols, nestedStringColumn("Role", "spec", "roleRef", "name"))
	}
	return append(cols, ageColumn)
}

// newTable renders objs as a metav1.Table for the given kind. An empty objs
// still yields a Table with column definitions (and zero rows), which is what
// fixes kubectl's empty-list scope message.
func newTable(gvk schema.GroupVersionKind, objs []unstructured.Unstructured, readyTimeout time.Duration) (*metav1.Table, error) {
	cols := columnsFor(gvk, readyTimeout)
	t := &metav1.Table{
		TypeMeta:          metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "Table"},
		ColumnDefinitions: make([]metav1.TableColumnDefinition, 0, len(cols)),
	}
	for _, c := range cols {
		t.ColumnDefinitions = append(t.ColumnDefinitions, c.def)
	}
	for i := range objs {
		u := &objs[i]
		row := metav1.TableRow{Cells: make([]any, 0, len(cols))}
		for _, c := range cols {
			row.Cells = append(row.Cells, c.extract(u))
		}
		pom, err := partialObjectMetadata(u)
		if err != nil {
			return nil, err
		}
		row.Object = runtime.RawExtension{Object: pom}
		t.Rows = append(t.Rows, row)
	}
	return t, nil
}

// partialObjectMetadata is the per-row object kubectl expects: enough metadata
// (name, uid, resourceVersion, creationTimestamp) to act on the row.
func partialObjectMetadata(u *unstructured.Unstructured) (*metav1.PartialObjectMetadata, error) {
	pom := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"},
	}
	meta, found, err := unstructured.NestedMap(u.Object, "metadata")
	if err != nil {
		return nil, err
	}
	if found {
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(meta, &pom.ObjectMeta); err != nil {
			return nil, err
		}
	}
	return pom, nil
}
