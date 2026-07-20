package admission

import (
	"strings"

	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// pvProtection rejects deleting a PersistentVolume that an Application still mounts.
// A PV is a directory of data with a lifecycle independent of any app, and deleting
// it reclaims the data from disk on the next reconcile — so removing one out from
// under a running application would destroy live data. Delete the mounting
// applications (or repoint their volumeMounts) first. It guards only Delete of a
// PersistentVolume; tmpfs mounts (which reference no PV) never trigger it.
type pvProtection struct{ lister Lister }

func (pvProtection) Admit(context.Context, *Attributes) error { return nil }

func (c pvProtection) Validate(ctx context.Context, a *Attributes) error {
	if c.lister == nil || a.Operation != Delete {
		return nil
	}
	pv, ok := a.Object.(*corev1.PersistentVolume)
	if !ok {
		return nil
	}
	list, err := c.lister.List(ctx, resourceMeta("Application"), metav1.ListOptions{})
	if err != nil {
		return err
	}
	var users []string
	for _, obj := range list {
		app, ok := obj.(*corev1.Application)
		if !ok {
			continue
		}
		for _, m := range app.Spec.VolumeMounts {
			if m.PV == pv.Name {
				users = append(users, app.Name)
				break
			}
		}
	}
	if len(users) > 0 {
		return Forbidden("persistentvolume %q is in use by application(s) %s; delete or repoint them first",
			pv.Name, strings.Join(users, ", "))
	}
	return nil
}
