package v1

// specSectionsWithDefaults are the trait sections of an ApplicationSpec that declare defaults of
// their own. A declared default fills a FIELD, never the object that would hold it (scheme.Default
// says why: an absent required object must stay reported as missing, not be conjured out of its
// children's defaults). So a spec that omits such a section entirely would be stored with none of
// the section's defaults applied — an Application carrying no restartPolicy at all, which the node
// would read as neither a service nor a job.
//
// Conjuring the empty section before the declared defaults run is what keeps "what a reader sees
// is what the node will do" true for an author who wrote no traits. It is deliberately only the
// sections that HAVE defaults: an empty placement on every stored object would be noise.
var specSectionsWithDefaults = []string{"lifecycle"}

// defaultApplication conjures the defaulted trait sections of an Application's spec.
func defaultApplication(obj map[string]any) {
	conjureSpecSections(obj["spec"])
}

// defaultApplicationSet does the same for every component spec of a set — each is an
// ApplicationSpec and reaches a node exactly like a directly-authored one, so a component that
// declares no lifecycle must default identically to an Application that declares none.
func defaultApplicationSet(obj map[string]any) {
	spec, ok := obj["spec"].(map[string]any)
	if !ok {
		return
	}
	comps, ok := spec["applications"].([]any)
	if !ok {
		return
	}
	for _, c := range comps {
		if comp, ok := c.(map[string]any); ok {
			conjureSpecSections(comp["spec"])
		}
	}
}

// conjureSpecSections adds an empty object for each defaulted section v does not have. An
// explicit null counts as absent; anything else is left alone, so a section written with the
// wrong type still reaches validation and is reported instead of being quietly replaced.
func conjureSpecSections(v any) {
	spec, ok := v.(map[string]any)
	if !ok {
		return
	}
	for _, name := range specSectionsWithDefaults {
		if s, ok := spec[name]; !ok || s == nil {
			spec[name] = map[string]any{}
		}
	}
}
