package apiserver

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

func TestAcceptsTable(t *testing.T) {
	cases := map[string]bool{
		"application/json;as=Table;v=v1;g=meta.k8s.io,application/json": true,
		"application/json;as=Table;v=v1beta1;g=meta.k8s.io":             true,
		"application/json": false,
		"":                 false,
		"application/yaml": false,
	}
	for accept, want := range cases {
		if got := acceptsTable(accept); got != want {
			t.Errorf("acceptsTable(%q) = %v, want %v", accept, got, want)
		}
	}
}

func TestNewTableEmptyKeepsColumns(t *testing.T) {
	// The empty case is the one that fixes kubectl's scope message: a Table with
	// column definitions and zero rows (not a plain empty List).
	tbl, err := newTable(corev1.GroupVersion.WithKind("Application"), nil, defaultNodeReadyTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if tbl.Kind != "Table" || tbl.APIVersion != "meta.k8s.io/v1" {
		t.Fatalf("wrong typemeta: %s/%s", tbl.APIVersion, tbl.Kind)
	}
	if len(tbl.Rows) != 0 {
		t.Fatalf("want 0 rows, got %d", len(tbl.Rows))
	}
	if len(tbl.ColumnDefinitions) == 0 {
		t.Fatal("empty table must still declare columns")
	}
}

func TestNewTableRows(t *testing.T) {
	app := unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "web"},
		"spec":     map[string]any{"image": "reg/web:v1"},
	}}
	tbl, err := newTable(corev1.GroupVersion.WithKind("Application"), []unstructured.Unstructured{app}, defaultNodeReadyTimeout)
	if err != nil {
		t.Fatal(err)
	}

	cols := []string{}
	for _, c := range tbl.ColumnDefinitions {
		cols = append(cols, c.Name)
	}
	if got := join(cols); got != "Name,IMAGE,Status,NODE,IP,Age" {
		t.Fatalf("columns = %s", got)
	}
	if len(tbl.Rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(tbl.Rows))
	}
	row := tbl.Rows[0]
	if row.Cells[0] != "web" || row.Cells[1] != "reg/web:v1" {
		t.Fatalf("cells = %v", row.Cells)
	}
	// No node has reported status yet, so it renders as Pending.
	if row.Cells[2] != "Pending" {
		t.Fatalf("status cell = %v, want Pending", row.Cells[2])
	}
	// No node has wired it, so there is no address to answer on — the cell is empty rather than
	// carrying an address the control plane merely intends.
	if row.Cells[4] != "" {
		t.Fatalf("ip cell = %v, want empty until a node reports one", row.Cells[4])
	}
	// A zero creationTimestamp renders as <unknown> rather than a bogus age.
	if row.Cells[5] != "<unknown>" {
		t.Fatalf("age cell = %v, want <unknown>", row.Cells[5])
	}
	// The row carries a typed PartialObjectMetadata, not a raw map.
	pom, ok := row.Object.Object.(*metav1.PartialObjectMetadata)
	if !ok {
		t.Fatalf("row object = %T, want *metav1.PartialObjectMetadata", row.Object.Object)
	}
	if pom.Name != "web" || pom.Kind != "PartialObjectMetadata" {
		t.Fatalf("pom = %+v", pom)
	}
}

func TestNodeTableColumns(t *testing.T) {
	// Round-trip through JSON so the status numbers land as int64/float64 the way
	// they do in the real store, exercising nodeAmount's shape handling.
	n := corev1.Node{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Node"},
		ObjectMeta: metav1.ObjectMeta{Name: "sav-01"},
		Status: corev1.NodeStatus{
			Capacity:  corev1.ResourceAmounts{CPU: resource.MustParse("8"), Memory: resource.MustParse("16Gi")},
			Allocated: corev1.ResourceAmounts{CPU: resource.MustParse("2"), Memory: resource.MustParse("8Gi")},
			OS:        "Ubuntu 22.04 (6.2.0)",
			IP:        "10.92.16.25",
			Ready:     true,
			Heartbeat: metav1.Now(),
		},
	}
	data, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	u := unstructured.Unstructured{}
	if err := u.UnmarshalJSON(data); err != nil {
		t.Fatal(err)
	}

	tbl, err := newTable(corev1.GroupVersion.WithKind("Node"), []unstructured.Unstructured{u}, defaultNodeReadyTimeout)
	if err != nil {
		t.Fatal(err)
	}

	cols := []string{}
	for _, c := range tbl.ColumnDefinitions {
		cols = append(cols, c.Name)
	}
	if got := join(cols); got != "Name,Status,CPU,MEM,IP,OS,Age" {
		t.Fatalf("columns = %s", got)
	}
	// CPU/MEM show raw allocated/capacity and are always visible; IP and OS are
	// wide-only (Priority 1).
	for _, c := range tbl.ColumnDefinitions {
		wantWide := c.Name == "IP" || c.Name == "OS"
		if (c.Priority != 0) != wantWide {
			t.Errorf("column %s priority = %d, wide=%v", c.Name, c.Priority, wantWide)
		}
	}

	cells := tbl.Rows[0].Cells
	want := []any{"sav-01", "Ready", "2/8", "8/16Gi", "10.92.16.25", "Ubuntu 22.04 (6.2.0)"}
	for i, w := range want {
		if cells[i] != w {
			t.Errorf("cell[%d] = %v, want %v", i, cells[i], w)
		}
	}
}

func TestNodeMemGiB(t *testing.T) {
	// MemTotal from /proc is kB*1024 — an exact Ki multiple but not Gi, which
	// Quantity.String() renders as a noisy "8130904Ki"; the MEM column uses GiB.
	n := corev1.Node{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Node"},
		ObjectMeta: metav1.ObjectMeta{Name: "n"},
		Status: corev1.NodeStatus{
			Capacity:  corev1.ResourceAmounts{Memory: resource.MustParse("8130904Ki")},
			Allocated: corev1.ResourceAmounts{Memory: resource.MustParse("512Mi")},
		},
	}
	data, _ := json.Marshal(n)
	u := unstructured.Unstructured{}
	if err := u.UnmarshalJSON(data); err != nil {
		t.Fatal(err)
	}
	tbl, err := newTable(corev1.GroupVersion.WithKind("Node"), []unstructured.Unstructured{u}, defaultNodeReadyTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if mem := tbl.Rows[0].Cells[3]; mem != "0.5/7.8Gi" { // MEM column
		t.Fatalf("MEM = %v, want 0.5/7.8Gi", mem)
	}
}

func TestPersistentVolumeColumns(t *testing.T) {
	pv := corev1.PersistentVolume{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "PersistentVolume"},
		ObjectMeta: metav1.ObjectMeta{Name: "data"},
		Spec:       corev1.PersistentVolumeSpec{Size: resource.MustParse("10Gi"), Node: "sav-01"},
	}
	data, err := json.Marshal(pv)
	if err != nil {
		t.Fatal(err)
	}
	u := unstructured.Unstructured{}
	if err := u.UnmarshalJSON(data); err != nil {
		t.Fatal(err)
	}
	tbl, err := newTable(corev1.GroupVersion.WithKind("PersistentVolume"), []unstructured.Unstructured{u}, defaultNodeReadyTimeout)
	if err != nil {
		t.Fatal(err)
	}
	cols := []string{}
	for _, c := range tbl.ColumnDefinitions {
		cols = append(cols, c.Name)
	}
	if got := join(cols); got != "Name,SIZE,NODE,Age" {
		t.Fatalf("columns = %s", got)
	}
	if cells := tbl.Rows[0].Cells; cells[0] != "data" || cells[1] != "10Gi" || cells[2] != "sav-01" {
		t.Fatalf("cells = %v", cells)
	}
}

func TestNodeReadyStatus(t *testing.T) {
	cases := map[string]corev1.NodeStatus{
		"Ready":    {Ready: true, Heartbeat: metav1.Now()},
		"NotReady": {Ready: false, Heartbeat: metav1.Now()},                                    // agent reported not-ready
		"stale":    {Ready: true, Heartbeat: metav1.NewTime(time.Now().Add(-2 * time.Minute))}, // heartbeat aged out
		"never":    {Ready: false},                                                             // no heartbeat at all
	}
	want := map[string]string{"Ready": "Ready", "NotReady": "NotReady", "stale": "NotReady", "never": "NotReady"}
	for name, st := range cases {
		n := corev1.Node{TypeMeta: metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Node"}, ObjectMeta: metav1.ObjectMeta{Name: name}, Status: st}
		data, _ := json.Marshal(n)
		u := unstructured.Unstructured{}
		if err := u.UnmarshalJSON(data); err != nil {
			t.Fatal(err)
		}
		tbl, err := newTable(corev1.GroupVersion.WithKind("Node"), []unstructured.Unstructured{u}, defaultNodeReadyTimeout)
		if err != nil {
			t.Fatal(err)
		}
		if got := tbl.Rows[0].Cells[1]; got != want[name] {
			t.Errorf("%s: status = %v, want %v", name, got, want[name])
		}
	}
}

// TestNodeTableNoStatus checks a node that has not yet reported renders 0/0 raw
// amounts and an empty IP rather than failing.
func TestNodeTableNoStatus(t *testing.T) {
	u := unstructured.Unstructured{Object: map[string]any{"metadata": map[string]any{"name": "fresh"}}}
	tbl, err := newTable(corev1.GroupVersion.WithKind("Node"), []unstructured.Unstructured{u}, defaultNodeReadyTimeout)
	if err != nil {
		t.Fatal(err)
	}
	cells := tbl.Rows[0].Cells
	// Name, Status, CPU, MEM, IP, OS, Age: an unreported node is NotReady with 0/0
	// amounts and an empty IP.
	if cells[1] != "NotReady" || cells[2] != "0/0" || cells[4] != "" {
		t.Fatalf("cells = %v", cells)
	}
}

func join(ss []string) string {
	return strings.Join(ss, ",")
}

// TestApplicationStatusReflectsTheObservedGeneration is the table half of what a live node
// exposed: a workload that is up but on an OLDER generation than the stored spec must not
// read Running — the node kept the previous workload alive because it could not apply the
// new spec, and a table claiming Running would hide exactly that.
func TestApplicationStatusReflectsTheObservedGeneration(t *testing.T) {
	app := func(gen, observed int64, phase string) unstructured.Unstructured {
		return unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": "web", "generation": gen},
			"spec":     map[string]any{"image": "reg/web:v1"},
			"status":   map[string]any{"phase": phase, "observedGeneration": observed},
		}}
	}
	statusOf := func(u unstructured.Unstructured) any {
		tbl, err := newTable(corev1.GroupVersion.WithKind("Application"), []unstructured.Unstructured{u}, defaultNodeReadyTimeout)
		if err != nil {
			t.Fatal(err)
		}
		return tbl.Rows[0].Cells[2]
	}

	if got := statusOf(app(7, 7, "Running")); got != "Running" {
		t.Fatalf("converged app = %v, want Running", got)
	}
	if got := statusOf(app(7, 6, "Running")); got != "Updating" {
		t.Fatalf("app running an older generation = %v, want Updating", got)
	}
	if got := statusOf(app(7, 6, "Failed")); got != "Failed" {
		t.Fatalf("a failed app keeps its phase, got %v", got)
	}
}

// TestServiceColumns: `kubectl get service` printed a name and an age and nothing else, because the
// kind had no case in columnsFor at all — which also meant -o wide had nothing to add. These cover
// the object's whole content, since a Service has no status: the declared address and the ports
// callers ask for by default, and with -o wide where each port goes and what the catalog calls it.
func TestServiceColumns(t *testing.T) {
	cellsOf := func(u unstructured.Unstructured) ([]any, *metav1.Table) {
		tbl, err := newTable(corev1.GroupVersion.WithKind("Service"), []unstructured.Unstructured{u}, defaultNodeReadyTimeout)
		if err != nil {
			t.Fatal(err)
		}
		return tbl.Rows[0].Cells, tbl
	}

	// Name, Cluster-IP, Ports, Targets, Catalog, Age.
	cells, tbl := cellsOf(unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "db"},
		"spec": map[string]any{
			"clusterIP": "10.96.0.7",
			"ports": []any{
				map[string]any{"name": "pg", "port": int64(5432), "targetName": "postgres"},
				map[string]any{"name": "metrics", "port": int64(9187), "targetPort": int64(9100), "protocol": "TCP"},
			},
		},
	}})
	if cells[1] != "10.96.0.7" || cells[2] != "5432/TCP,9187/TCP" {
		t.Fatalf("default columns = %v", cells)
	}
	// A named target stays a name — resolving it needs the Application — and an explicit number
	// wins, which is TargetFor's own order.
	if cells[3] != "postgres,9100" {
		t.Errorf("targets = %v, want postgres,9100", cells[3])
	}
	// Multi-port: the catalog splits per port, so neither entry is the object's own name.
	if cells[4] != "db-pg,db-metrics" {
		t.Errorf("catalog = %v, want db-pg,db-metrics", cells[4])
	}
	for _, i := range []int{1, 2} {
		if tbl.ColumnDefinitions[i].Priority != 0 {
			t.Errorf("%q is hidden without -o wide", tbl.ColumnDefinitions[i].Name)
		}
	}
	for _, i := range []int{3, 4} {
		if tbl.ColumnDefinitions[i].Priority != 1 {
			t.Errorf("%q shows without -o wide, and it is detail", tbl.ColumnDefinitions[i].Name)
		}
	}

	// No address is an ORDINARY Service here — declared, never allocated — so it must not read as
	// a blank where something failed. A single unnamed port is discovered under the service's own
	// name, and targets itself.
	cells, _ = cellsOf(unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "cache"},
		"spec":     map[string]any{"ports": []any{map[string]any{"port": int64(6379)}}},
	}})
	if cells[1] != "<none>" || cells[2] != "6379/TCP" || cells[3] != "6379" || cells[4] != "cache" {
		t.Fatalf("addressless single-port service = %v", cells)
	}
}

// TestApplicationSetColumns: the set reads like a Deployment — wanted / existing / actually
// running, plus the one-word rollup, so a held rollout is visible in `kubectl get appset`.
func TestApplicationSetColumns(t *testing.T) {
	set := unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "cache"},
		"status": map[string]any{
			"desired": int64(3), "current": int64(3), "running": int64(2), "phase": "RolloutHeld",
		},
	}}
	tbl, err := newTable(corev1.GroupVersion.WithKind("ApplicationSet"), []unstructured.Unstructured{set}, defaultNodeReadyTimeout)
	if err != nil {
		t.Fatal(err)
	}
	cols := []string{}
	for _, c := range tbl.ColumnDefinitions {
		cols = append(cols, c.Name)
	}
	if got := join(cols); got != "Name,DESIRED,CURRENT,RUNNING,Status,Age" {
		t.Fatalf("columns = %s", got)
	}
	if cells := tbl.Rows[0].Cells; cells[1] != "3" || cells[2] != "3" || cells[3] != "2" || cells[4] != "RolloutHeld" {
		t.Fatalf("cells = %v", cells)
	}

	// A set the loop has not reconciled yet has no status at all: it must read Progressing,
	// never Ready.
	fresh := unstructured.Unstructured{Object: map[string]any{"metadata": map[string]any{"name": "new"}}}
	tbl, err = newTable(corev1.GroupVersion.WithKind("ApplicationSet"), []unstructured.Unstructured{fresh}, defaultNodeReadyTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if got := tbl.Rows[0].Cells[4]; got != corev1.AppSetPhaseProgressing {
		t.Fatalf("unreconciled set = %v, want Progressing", got)
	}
}

// TestWatchEventsCarryTables: a watch has to answer in the shape the list did.
//
// kubectl asks for a Table on both, and a stream carrying plain API objects does not make it
// error — it falls back to the columns it hardcodes for an unknown kind. `kubectl get app -w`
// therefore printed the real columns from the initial list and then a bare NAME/AGE table for
// every event after it, which reads as the watch having lost the object rather than the server
// having answered in the wrong shape.
func TestWatchEventsCarryTables(t *testing.T) {
	gvk := corev1.GroupVersion.WithKind("Application")
	app := corev1.Application{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"},
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec:       corev1.ApplicationSpec{Image: "reg.io/ns/app:v1"},
		Status:     corev1.ApplicationStatus{Phase: corev1.AppPhaseRunning},
	}
	raw, err := json.Marshal(&app)
	if err != nil {
		t.Fatal(err)
	}
	evt := tableEvent(gvk, metav1.WatchEvent{Type: "ADDED", Object: runtime.RawExtension{Raw: raw}})

	if evt.Type != "ADDED" {
		t.Fatalf("the event type must survive the rendering, got %q", evt.Type)
	}
	var tbl metav1.Table
	if err := json.Unmarshal(evt.Object.Raw, &tbl); err != nil {
		t.Fatalf("the event object must be a Table: %v", err)
	}
	if len(tbl.Rows) != 1 {
		t.Fatalf("want exactly the event's own object as one row, got %d", len(tbl.Rows))
	}
	// The definitions ride on every frame, so a client that joined late still knows the columns.
	var names []string
	for _, c := range tbl.ColumnDefinitions {
		names = append(names, c.Name)
	}
	for _, want := range []string{"Name", "IMAGE", "Status"} {
		if !slices.Contains(names, want) {
			t.Errorf("column %q missing from the watch frame: %v", want, names)
		}
	}

	// An object that cannot be rendered is passed through rather than dropped: the wrong columns
	// are recoverable, a swallowed event leaves the client believing nothing changed.
	broken := metav1.WatchEvent{Type: "DELETED", Object: runtime.RawExtension{Raw: []byte("not json")}}
	if got := tableEvent(gvk, broken); string(got.Object.Raw) != "not json" || got.Type != "DELETED" {
		t.Fatalf("an unrenderable event must pass through untouched, got %+v", got)
	}
}

// TestTheAddressColumnShowsWhatTheNodeReported: the IP column is the node's report, printed without
// the prefix. The field is stored in CIDR form because that is what is pushed to the node and
// configured on the interface; a /32 under a heading that says IP is noise.
func TestTheAddressColumnShowsWhatTheNodeReported(t *testing.T) {
	col := addressColumn()
	if col.def.Name != "IP" {
		t.Fatalf("column = %q, want IP", col.def.Name)
	}
	if col.def.Priority != 1 {
		t.Error("the address belongs to -o wide, like the column it replaced")
	}
	for _, c := range []struct{ stored, want string }{
		{"10.244.0.2/32", "10.244.0.2"}, // what a node actually reports
		{"10.244.0.2", "10.244.0.2"},    // a bare address is the same fact
		{"", ""},                        // on the host network, or not wired yet
	} {
		u := &unstructured.Unstructured{Object: map[string]any{}}
		if c.stored != "" {
			_ = unstructured.SetNestedField(u.Object, c.stored, "status", "address")
		}
		if got := col.extract(u); got != c.want {
			t.Errorf("stored %q rendered as %q, want %q", c.stored, got, c.want)
		}
	}
}
