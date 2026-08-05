package admission

import (
	"context"
	"fmt"
	"slices"
	"strings"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/types"
)

// referenceCheck runs a table of cross-object reference invariants over the Lister in one
// validation pass. It replaces a set of near-identical per-validator plugins — each of
// which repeated the same skeleton (nil-lister guard, an operation filter, a list-and-
// check) and differed only in the object type and the check body. Each rule keeps its own
// type and check as a hook; a nil lister disables them all (the unit-test default). New
// reference rules (secretRef, a volume-policy existence check, …) are added to the table,
// not as another chain entry.
type referenceCheck struct {
	lister Lister
	rules  []referenceRule
}

// referenceRule is one cross-object invariant: guards selects the operations it runs on,
// and check reports a violation (nil when satisfied) given the object under review and the
// Lister. A rule returning a *ForbiddenError denies on authorization grounds (403); a
// plain error is a validation failure (422).
type referenceRule struct {
	name   string
	guards func(Operation) bool
	check  func(ctx context.Context, a *Attributes, l Lister) error
}

func (referenceCheck) Admit(context.Context, *Attributes) error { return nil }

func (c referenceCheck) Validate(ctx context.Context, a *Attributes) error {
	// A subresource write cannot change a reference: storage merges only the named field, so the
	// spec these rules read is the stored one they already passed. Skipping it also takes the
	// full-table Lists off the node-status path, where a ~40-byte report was forcing them.
	if a.IsSubresource() {
		return nil
	}
	if c.lister == nil {
		return nil
	}
	for _, r := range c.rules {
		if !r.guards(a.Operation) {
			continue
		}
		if err := r.check(ctx, a, c.lister); err != nil {
			return err
		}
	}
	return nil
}

// notDelete guards a create-time invariant (Create/Update, never Delete); onlyDelete
// guards a deletion invariant.
func notDelete(op Operation) bool  { return op != Delete }
func onlyDelete(op Operation) bool { return op == Delete }

// newReferenceCheck builds the default reference-rule table the controller runs.
func newReferenceCheck(lister Lister) referenceCheck {
	return referenceCheck{lister: lister, rules: []referenceRule{
		namespaceExistsRule,
		namespaceProtectionRule,
		nodeExistsRule,
		pvProtectionRule,
		pvExclusiveRule,
		secretRefRule,
		secretProtectionRule,
		serviceRefRule,
		serviceProtectionRule,
	}}
}

// namespaceExistsRule rejects a namespaced object whose metadata.namespace names a
// Namespace that does not exist — the tenancy analogue of nodeExistsRule. A cluster-scoped
// object (empty namespace) is skipped.
var namespaceExistsRule = referenceRule{name: "namespaceExists", guards: notDelete, check: checkNamespaceExists}

func checkNamespaceExists(ctx context.Context, a *Attributes, l Lister) error {
	acc, err := apimeta.Accessor(a.Object)
	if err != nil {
		return nil
	}
	ns := acc.GetNamespace()
	if ns == "" {
		return nil // cluster-scoped object
	}
	list, err := l.List(ctx, resourceMeta("Namespace"), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, obj := range list {
		if n, ok := obj.(*corev1.Namespace); ok && n.Name == ns {
			return nil
		}
	}
	return fmt.Errorf("metadata.namespace: namespace %q does not exist", ns)
}

// namespacedKinds are the Kinds a Namespace must be empty of before it can be deleted. The list
// has to hold EVERY namespaced Kind: TestNamespacedKindsMatchTheScheme asserts it against the
// scheme's registry, so a newly added Kind cannot be silently left out of the check.
var namespacedKinds = []types.ObjectMeta{
	resourceMeta("Application"),
	resourceMeta("ApplicationSet"),
	resourceMeta("PersistentVolume"),
	resourceMeta("Secret"),
	resourceMeta("Service"),
	rbacMeta("Role"),
	rbacMeta("RoleBinding"),
}

// namespaceProtectionRule refuses to delete a Namespace that still contains objects. Deleting
// one used to remove a single record and nothing else: there is no finalizer, no owner-driven GC
// and no namespace controller, so the tenant's Applications kept running on their nodes, their
// Secrets and PersistentVolume data stayed on disk, and their RoleBindings kept granting. Since
// the key is the NAME, handing the same namespace name to a second tenant then gave each of them
// the other's data — B reading A's leftover Secret payloads and mounting A's volumes, while A's
// surviving RoleBinding granted full CRUD over everything B created.
//
// Refusing is the whole fix rather than half of it: an operator has to reap the contents first,
// and once the delete succeeds nothing namespaced is left behind to be inherited.
var namespaceProtectionRule = referenceRule{name: "namespaceProtection", guards: onlyDelete, check: checkNamespaceEmpty}

func checkNamespaceEmpty(ctx context.Context, a *Attributes, l Lister) error {
	ns, ok := a.Object.(*corev1.Namespace)
	if !ok {
		return nil
	}
	var remaining []string
	for _, kind := range namespacedKinds {
		kind.Namespace = ns.Name
		list, err := l.List(ctx, kind, metav1.ListOptions{})
		if err != nil {
			return err
		}
		if names := objectNames(list, ns.Name); len(names) > 0 {
			remaining = append(remaining, fmt.Sprintf("%s %s", strings.ToLower(kind.Kind), strings.Join(names, ", ")))
		}
	}
	if len(remaining) > 0 {
		return Forbidden("namespace %q is not empty: it still holds %s — delete its contents first",
			ns.Name, strings.Join(remaining, "; "))
	}
	return nil
}

// objectNames lists the names of the objects in namespace, bounded so an error message cannot
// echo a whole namespace back at the caller.
func objectNames(list []types.Object, namespace string) []string {
	const maxNames = 3
	var names []string
	for _, obj := range list {
		acc, err := apimeta.Accessor(obj)
		if err != nil || acc.GetNamespace() != namespace {
			continue
		}
		if len(names) == maxNames {
			names = append(names, "…")
			break
		}
		names = append(names, acc.GetName())
	}
	return names
}

// nodeExistsRule rejects an Application whose spec.placement.nodeName names a Node that does not
// exist: an app is pinned to exactly one node, so a typo or a not-yet-registered node
// would otherwise create an app that silently never runs (no agent claims it). It runs
// regardless of resource requests — unlike capacityCheck, which only accounts apps that
// declare them.
var nodeExistsRule = referenceRule{name: "nodeExists", guards: notDelete, check: checkNodeExists}

func checkNodeExists(ctx context.Context, a *Attributes, l Lister) error {
	app, ok := a.Object.(*corev1.Application)
	if !ok || len(app.Spec.Placement.NodeName) == 0 {
		return nil // not an Application, or node absent (the input schema requires it)
	}
	list, err := l.List(ctx, resourceMeta("Node"), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, obj := range list {
		if node, ok := obj.(*corev1.Node); ok && node.Name == app.Spec.Placement.NodeName {
			return nil
		}
	}
	return fmt.Errorf("spec.placement.nodeName: node %q does not exist", app.Spec.Placement.NodeName)
}

// serviceRefRule rejects an Application whose spec.serviceName names a Service that does not
// exist in its namespace. Membership is declared by the instance, which is what keeps a service
// from asserting anything about a fleet it cannot see — but a declaration nobody checks is a
// typo that silently produces a workload in no catalog, reachable by nothing, and looking
// perfectly healthy while it is.
var serviceRefRule = referenceRule{name: "serviceRef", guards: notDelete, check: checkServiceRef}

func checkServiceRef(ctx context.Context, a *Attributes, l Lister) error {
	app, ok := a.Object.(*corev1.Application)
	if !ok || len(app.Spec.ServiceName) == 0 {
		return nil // not an Application, or joining no service — which is a normal thing to be
	}
	svc, err := findService(ctx, l, app.Namespace, app.Spec.ServiceName)
	if err != nil {
		return err
	}
	if svc == nil {
		return fmt.Errorf("spec.serviceName: service %q does not exist in namespace %q",
			app.Spec.ServiceName, app.Namespace)
	}
	return nil
}

// serviceProtectionRule rejects deleting a Service that Applications still declare themselves
// members of. The address is the object's, and it is released with the object — so deleting one
// out from under its members would take the name and the VIP away from workloads that are still
// running and still expect to be reachable by it. Repoint or remove the members first. It is the
// same interlock pvProtection applies to data, applied to a name.
var serviceProtectionRule = referenceRule{name: "serviceProtection", guards: onlyDelete, check: checkServiceProtection}

func checkServiceProtection(ctx context.Context, a *Attributes, l Lister) error {
	svc, ok := a.Object.(*corev1.Service)
	if !ok {
		return nil
	}
	apps, err := l.List(ctx, resourceMeta("Application"), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, obj := range apps {
		app, ok := obj.(*corev1.Application)
		if !ok || app.Namespace != svc.Namespace || app.Spec.ServiceName != svc.Name {
			continue
		}
		return fmt.Errorf("service %q is still declared by application %q; repoint or remove it first",
			svc.Name, app.Name)
	}
	return nil
}

// findService returns the Service named name in namespace, or nil when there is none.
func findService(ctx context.Context, l Lister, namespace, name string) (*corev1.Service, error) {
	list, err := l.List(ctx, resourceMeta("Service"), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, obj := range list {
		if svc, ok := obj.(*corev1.Service); ok && svc.Namespace == namespace && svc.Name == name {
			return svc, nil
		}
	}
	return nil, nil
}

// pvProtectionRule rejects deleting a PersistentVolume that an Application still mounts. A
// PV is a directory of data with a lifecycle independent of any app; deleting it reclaims
// the data from disk on the next reconcile, so removing one from under a running app would
// destroy live data. Delete the mounting apps (or repoint their volumeMounts) first. A
// tmpfs mount references no PV and never triggers it.
var pvProtectionRule = referenceRule{name: "pvProtection", guards: onlyDelete, check: checkPVProtection}

func checkPVProtection(ctx context.Context, a *Attributes, l Lister) error {
	pv, ok := a.Object.(*corev1.PersistentVolume)
	if !ok {
		return nil
	}
	users, err := appsMountingPV(ctx, l, pv.Namespace, pv.Name, "")
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return Forbidden("persistentvolume %q is in use by application(s) %s; delete or repoint them first",
			pv.Name, strings.Join(users, ", "))
	}
	return nil
}

// appsMountingPV names the Applications in namespace whose spec mounts the PersistentVolume
// name — the one question both PV rules ask. except is skipped by name: an Application being
// updated is already stored, and comparing it against its own stored copy would make every
// re-apply of an unchanged spec read as a second mounter.
//
// A PV is reachable only from its own namespace (a volume mount has no namespace field), so
// the scan is namespace-scoped and cross-tenant sharing is structurally impossible rather
// than merely refused.
func appsMountingPV(ctx context.Context, l Lister, namespace, name, except string) ([]string, error) {
	list, err := l.List(ctx, resourceMeta("Application"), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var users []string
	for _, obj := range list {
		app, ok := obj.(*corev1.Application)
		if !ok || app.Namespace != namespace || app.Name == except {
			continue
		}
		for _, m := range app.Spec.Volumes {
			if m.IsPV() && m.PVName(app.Name) == name {
				users = append(users, app.Name)
				break // one app mounting the same volume twice (a subPath beside the root) is one user
			}
		}
	}
	return users, nil
}

// pvExclusiveRule holds a PersistentVolume to ONE Application unless the volume itself says
// otherwise. A volume is a directory two workloads can write to at the same time, and whether
// that is fine or is silent corruption depends on what the data IS — safe for a content store,
// fatal for a database — which nothing in the mount declares. So the default is exclusive and
// sharing is stated on the PersistentVolume, by whoever authored the volume and knows.
//
// The rule guards both doors to the same invariant, because either write alone would break it:
// an Application naming a volume another one already mounts, and a PersistentVolume clearing
// spec.shared while several still mount it. What it deliberately does NOT offer is a way for an
// Application to declare the sharing itself — an inline pv volume has no such field, so a
// workload cannot grant itself access to another's storage, and the volume the scheduler creates
// from an inline mount is exclusive.
var pvExclusiveRule = referenceRule{name: "pvExclusive", guards: notDelete, check: checkPVExclusive}

func checkPVExclusive(ctx context.Context, a *Attributes, l Lister) error {
	switch obj := a.Object.(type) {
	case *corev1.Application:
		return checkAppMountsExclusive(ctx, obj, l)
	case *corev1.PersistentVolume:
		return checkSharingStillHolds(ctx, obj, l)
	}
	return nil
}

func checkAppMountsExclusive(ctx context.Context, app *corev1.Application, l Lister) error {
	var mounted []string
	for _, m := range app.Spec.Volumes {
		if m.IsPV() && !slices.Contains(mounted, m.PVName(app.Name)) {
			mounted = append(mounted, m.PVName(app.Name))
		}
	}
	if len(mounted) == 0 {
		return nil
	}
	shared, err := sharedPVs(ctx, l, app.Namespace)
	if err != nil {
		return err
	}
	for _, name := range mounted {
		if _, ok := shared[name]; ok {
			continue
		}
		// An absent PersistentVolume is exclusive too: the scheduler creates one implicitly
		// from this mount, and it creates it unshared. Two applications racing to claim the
		// same name are refused here rather than one of them silently winning.
		users, err := appsMountingPV(ctx, l, app.Namespace, name, app.Name)
		if err != nil {
			return err
		}
		if len(users) > 0 {
			return Forbidden("persistentvolume %q is already mounted by application(s) %s; a volume belongs to one application unless its spec.shared says otherwise",
				name, strings.Join(users, ", "))
		}
	}
	return nil
}

func checkSharingStillHolds(ctx context.Context, pv *corev1.PersistentVolume, l Lister) error {
	if pv.Spec.Shared {
		return nil
	}
	users, err := appsMountingPV(ctx, l, pv.Namespace, pv.Name, "")
	if err != nil {
		return err
	}
	if len(users) > 1 {
		return Forbidden("persistentvolume %q is mounted by application(s) %s; spec.shared cannot be cleared while more than one mounts it",
			pv.Name, strings.Join(users, ", "))
	}
	return nil
}

// sharedPVs is the set of PersistentVolume names in namespace that allow concurrent mounters.
func sharedPVs(ctx context.Context, l Lister, namespace string) (map[string]struct{}, error) {
	list, err := l.List(ctx, resourceMeta("PersistentVolume"), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := map[string]struct{}{}
	for _, obj := range list {
		if pv, ok := obj.(*corev1.PersistentVolume); ok && pv.Namespace == namespace && pv.Spec.Shared {
			out[pv.Name] = struct{}{}
		}
	}
	return out, nil
}

// secretRefRule rejects an Application that references a non-optional Secret which does not
// exist in the app's namespace — so a typo'd or cross-tenant secret ref fails at the API rather
// than silently holding the app pending forever. It covers BOTH ways an app consumes a secret,
// a volume mount and a spec.env secretRef, through Application.RequiredSecretRefs: one
// definition, so the two cannot diverge. A secret is referenced only by name within the app's
// own namespace (neither shape has a namespace field), so cross-namespace theft is structurally
// impossible. An optional reference may be absent.
var secretRefRule = referenceRule{name: "secretRef", guards: notDelete, check: checkSecretRef}

func checkSecretRef(ctx context.Context, a *Attributes, l Lister) error {
	app, ok := a.Object.(*corev1.Application)
	if !ok {
		return nil
	}
	required := app.RequiredSecretRefs()
	if len(required) == 0 {
		return nil
	}
	list, err := l.List(ctx, resourceMeta("Secret"), metav1.ListOptions{})
	if err != nil {
		return err
	}
	have := map[string]struct{}{}
	for _, o := range list {
		if s, ok := o.(*corev1.Secret); ok && s.Namespace == app.Namespace {
			have[s.Name] = struct{}{}
		}
	}
	for _, name := range required {
		if _, ok := have[name]; !ok {
			return fmt.Errorf("secret %q does not exist in namespace %q", name, app.Namespace)
		}
	}
	return nil
}

// secretProtectionRule rejects deleting a Secret that an Application still consumes — as a
// volume mount or through a spec.env secretRef, optional or not, since a disappearing value
// changes a live workload's behaviour either way. It is the secret analogue of
// pvProtectionRule, so a live workload's credentials cannot be pulled out from under it.
// Delete the consuming apps (or repoint them) first.
var secretProtectionRule = referenceRule{name: "secretProtection", guards: onlyDelete, check: checkSecretProtection}

func checkSecretProtection(ctx context.Context, a *Attributes, l Lister) error {
	sec, ok := a.Object.(*corev1.Secret)
	if !ok {
		return nil
	}
	list, err := l.List(ctx, resourceMeta("Application"), metav1.ListOptions{})
	if err != nil {
		return err
	}
	var users []string
	for _, obj := range list {
		app, ok := obj.(*corev1.Application)
		if !ok || app.Namespace != sec.Namespace {
			continue
		}
		if slices.Contains(app.SecretRefs(), sec.Name) {
			users = append(users, app.Name)
		}
	}
	if len(users) > 0 {
		return Forbidden("secret %q is in use by application(s) %s; delete or repoint them first",
			sec.Name, strings.Join(users, ", "))
	}
	return nil
}
