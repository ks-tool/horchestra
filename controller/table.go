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

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
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
	for entry := range strings.SplitSeq(accept, ",") {
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

// appStatusColumn shows what the Application is ACTUALLY doing, which the node-reported phase
// alone does not say: a node that cannot apply a new spec keeps the previous workload running
// and keeps reporting Running. So a workload that is up but on an older generation than the
// stored spec reads Updating, not Running — the table must not claim a change is live when the
// node never took it. Pending when no node has reported at all.
func appStatusColumn() column {
	return column{
		def: metav1.TableColumnDefinition{Name: "Status", Type: "string"},
		extract: func(u *unstructured.Unstructured) any {
			phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
			if phase == "" {
				return corev1.AppPhasePending
			}
			gen, _, _ := unstructured.NestedInt64(u.Object, "metadata", "generation")
			obs, _, _ := unstructured.NestedInt64(u.Object, "status", "observedGeneration")
			if phase == corev1.AppPhaseRunning && obs > 0 && obs != gen {
				return "Updating"
			}
			return phase
		},
	}
}

// addressColumn shows the address a workload answers on. It comes from the node's report rather
// than from anything the control plane decided, which is what makes it the truth and not an
// intention: the address is chosen here, delivered in the push, and becomes real only once the node
// that wired it says so.
//
// Empty for a workload on the host network — it answers on its node's address, which is the Node's
// to print and not this object's.
//
// The prefix is stripped. The field is stored in CIDR form because that is the form pushed to the
// node and configured on the interface, but a /32 under a heading that says IP is noise: every
// workload's address is a /32 by construction, each veth being its own point-to-point link.
func addressColumn() column {
	c := column{
		def: metav1.TableColumnDefinition{Name: "IP", Type: "string"},
		extract: func(u *unstructured.Unstructured) any {
			addr, _, _ := unstructured.NestedString(u.Object, "status", "address")
			if i := strings.IndexByte(addr, '/'); i >= 0 {
				return addr[:i]
			}
			return addr
		},
	}
	c.def.Priority = 1
	return c
}

// servicePorts reads the ports slice once for the three columns that print it, so a malformed
// entry is skipped in one place rather than in three slightly different ways.
func servicePorts(u *unstructured.Unstructured) []map[string]any {
	raw, _, _ := unstructured.NestedSlice(u.Object, "spec", "ports")
	out := make([]map[string]any, 0, len(raw))
	for _, p := range raw {
		if m, ok := p.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// serviceAddressColumn prints the address callers connect to. Empty is an ORDINARY Service and not
// a failure to allocate one — the address is DECLARED here, never assigned — so it prints <none>
// rather than a blank that reads as something missing.
func serviceAddressColumn() column {
	return column{
		def: metav1.TableColumnDefinition{Name: "Cluster-IP", Type: "string"},
		extract: func(u *unstructured.Unstructured) any {
			ip, _, _ := unstructured.NestedString(u.Object, "spec", "clusterIP")
			if ip == "" {
				return "<none>"
			}
			return ip
		},
	}
}

// servicePortsColumn prints the ports callers address, in the shape a kubectl user already reads
// elsewhere (80/TCP). An absent protocol prints TCP because that is the field's default, not
// because the value is unknown: a column is the wrong place to learn that an object predates a
// defaulter.
func servicePortsColumn() column {
	return column{
		def: metav1.TableColumnDefinition{Name: "Ports", Type: "string"},
		extract: func(u *unstructured.Unstructured) any {
			var out []string
			for _, p := range servicePorts(u) {
				port, _, _ := unstructured.NestedInt64(p, "port")
				proto, _, _ := unstructured.NestedString(p, "protocol")
				if proto == "" {
					proto = "TCP"
				}
				out = append(out, strconv.FormatInt(port, 10)+"/"+proto)
			}
			if len(out) == 0 {
				return "<none>"
			}
			return strings.Join(out, ",")
		},
	}
}

// serviceTargetsColumn is what the ports column hides: where each port actually goes on an
// instance. It prints what the author DECLARED, in ServicePort.TargetFor's own order — an explicit
// number, else the instance's name for its port, else the service's port targeting itself — and
// deliberately stops there. Resolving a name into a number needs the Application it names, and this
// table renders one kind at a time; a column that guessed would be wrong exactly when the workload
// had moved its port, which is the case the naming exists for.
func serviceTargetsColumn() column {
	c := column{
		def: metav1.TableColumnDefinition{Name: "Targets", Type: "string"},
		extract: func(u *unstructured.Unstructured) any {
			var out []string
			for _, p := range servicePorts(u) {
				if tp, _, _ := unstructured.NestedInt64(p, "targetPort"); tp != 0 {
					out = append(out, strconv.FormatInt(tp, 10))
					continue
				}
				if name, _, _ := unstructured.NestedString(p, "targetName"); name != "" {
					out = append(out, name)
					continue
				}
				port, _, _ := unstructured.NestedInt64(p, "port")
				out = append(out, strconv.FormatInt(port, 10))
			}
			if len(out) == 0 {
				return "<none>"
			}
			return strings.Join(out, ",")
		},
	}
	c.def.Priority = 1
	return c
}

// serviceCatalogColumn prints the names a consumer actually resolves, which stop being the object's
// own name the moment it has more than one port: the catalog splits a multi-port service into
// `<service>-<port>` entries, so an object called `db` is discovered as `db-pg` and `db-metrics`.
// That rule lives in Service.CatalogName and is CALLED here rather than restated — a table that
// computed the name a second way is a table that can disagree with the catalog it describes.
func serviceCatalogColumn() column {
	c := column{
		def: metav1.TableColumnDefinition{Name: "Catalog", Type: "string"},
		extract: func(u *unstructured.Unstructured) any {
			var svc corev1.Service
			svc.Name = u.GetName()
			var out []string
			for _, p := range servicePorts(u) {
				name, _, _ := unstructured.NestedString(p, "name")
				out = append(out, svc.CatalogName(corev1.ServicePort{Name: name}))
			}
			if len(out) == 0 {
				return "<none>"
			}
			return strings.Join(out, ",")
		},
	}
	c.def.Priority = 1
	return c
}

// nestedIntColumn prints an integer status counter (0 when absent, which is what an
// unreconciled set reports).
func nestedIntColumn(name string, fields ...string) column {
	return column{
		def: metav1.TableColumnDefinition{Name: name, Type: "string"},
		extract: func(u *unstructured.Unstructured) any {
			n, _, _ := unstructured.NestedInt64(u.Object, fields...)
			return strconv.FormatInt(n, 10)
		},
	}
}

// appsetStatusColumn shows the set's rollup phase, falling back to Progressing before the
// loop has ever written a status (a set that exists but has not been reconciled is not Ready).
func appsetStatusColumn() column {
	return column{
		def: metav1.TableColumnDefinition{Name: "Status", Type: "string"},
		extract: func(u *unstructured.Unstructured) any {
			if phase, _, _ := unstructured.NestedString(u.Object, "status", "phase"); phase != "" {
				return phase
			}
			return corev1.AppSetPhaseProgressing
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
	case gvk.Group == corev1.GroupName && gvk.Kind == "Application":
		cols = append(cols,
			nestedStringColumn("IMAGE", "spec", "image"),
			appStatusColumn(),
			wideStringColumn("NODE", "spec", "placement", "nodeName"),
			addressColumn())
	case gvk.Group == corev1.GroupName && gvk.Kind == "ApplicationSet":
		// The Deployment-shaped read: how many children are wanted, exist and actually run,
		// plus the one-word rollup (RolloutHeld / AwaitingAnchor / Progressing / Ready).
		cols = append(cols,
			nestedIntColumn("DESIRED", "status", "desired"),
			nestedIntColumn("CURRENT", "status", "current"),
			nestedIntColumn("RUNNING", "status", "running"),
			appsetStatusColumn())
	case gvk.Group == corev1.GroupName && gvk.Kind == "Node":
		cols = append(cols,
			nodeStatusColumn(readyTimeout),
			resColumn("CPU", "cpu", cpuRatio),
			resColumn("MEM", "memory", memRatio),
			// IP and OS are detail, shown only with -o wide.
			wideStringColumn("IP", "status", "ip"),
			wideStringColumn("OS", "status", "os"))
	case gvk.Group == corev1.GroupName && gvk.Kind == "PersistentVolume":
		cols = append(cols,
			nestedStringColumn("SIZE", "spec", "size"),
			nestedStringColumn("NODE", "spec", "node"))
	case gvk.Group == corev1.GroupName && gvk.Kind == "Service":
		// No TYPE column: there are no service types here, no NodePort and no LoadBalancer. No
		// SELECTOR either, and that one is not an omission — a Service has none by design, since
		// instances join by declaring `spec.serviceName`, so there is nothing for the column to
		// print. What is left is the whole object: the address, and the ports behind it.
		cols = append(cols,
			serviceAddressColumn(),
			servicePortsColumn(),
			// Detail, shown only with -o wide: where each port goes, and what the catalog calls it.
			serviceTargetsColumn(),
			serviceCatalogColumn())
	case gvk.Group == rbacv1.GroupName && gvk.Kind == "RoleBinding":
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
