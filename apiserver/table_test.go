package apiserver

import (
	"encoding/json"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

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
	if got := join(cols); got != "Name,IMAGE,Age" {
		t.Fatalf("columns = %s", got)
	}
	if len(tbl.Rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(tbl.Rows))
	}
	row := tbl.Rows[0]
	if row.Cells[0] != "web" || row.Cells[1] != "reg/web:v1" {
		t.Fatalf("cells = %v", row.Cells)
	}
	// A zero creationTimestamp renders as <unknown> rather than a bogus age.
	if row.Cells[2] != "<unknown>" {
		t.Fatalf("age cell = %v, want <unknown>", row.Cells[2])
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
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
