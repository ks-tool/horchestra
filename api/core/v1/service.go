package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Service is a name in the catalog and the address behind it — a directory, in the sense that it
// exists before anything is in it and independently of what is. It owns exactly two things: the
// name clients resolve, and the address they connect to. It owns no workloads.
//
// There is no selector, and that absence is the design. An instance joins by DECLARING it —
// `Application.spec.serviceName` — the way a Consul instance registers under a service name,
// rather than by matching labels a service asserts about a fleet it cannot see. A selector can be
// squatted by a foreign object and can drift from what is actually running; a declaration cannot
// disagree with the declarer. It also means this object never has to be reconciled against
// reality: it is not a claim about the world, it is a name and an address.
//
// Because its identity is independent of its members, an empty Service is an ordinary Service —
// which is what makes the address's lifetime the OBJECT's lifetime. The alternative (a service
// computed from whichever workloads currently exist) has to answer what happens in the seconds
// between the last old instance and the first new one during a rolling update, and every answer
// to that is a heuristic.
//
// Renaming is therefore a move, not a rename: members reference the name, so a new name is a new
// directory with a new address, and the instances are re-pointed by whoever wrote them.
type Service struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec ServiceSpec `json:"spec"`
}

// ServiceSpec is what the author declares: the ports, and the address callers reach them at.
// Everything an external consumer reads BESIDE those is either DERIVED or the object's own
// annotations: the catalog's ServiceTags are generated from what the control plane knows for
// certain (namespace, service, port, protocol, the bundle an instance came from), and annotations
// become its ServiceMeta.
//
// Nobody writes a tag. An author-supplied one is a free string nobody validates, one more place
// for the same fact to be stale, and — the moment it carries an edge product's configuration
// format — the point at which the API takes sides about which edge you run. Configure the edge in
// the edge; this publishes facts.
type ServiceSpec struct {
	// ClusterIP is the address callers connect to, and it is DECLARED rather than allocated:
	// whatever balances this service already has an address — a node-local balancer bound to a
	// loopback address, a shared HAProxy on its own IP, a keepalived pair — and this is where that
	// address is written down so clients and the catalog agree on it.
	//
	// It is optional, and empty is an ordinary Service: the catalog's names are the discovery
	// surface either way, and a client that resolves instances by name (a balancer reading
	// /servicediscovery, an application doing its own selection) never needs one. What an address
	// adds is a single point to connect to when the caller cannot choose between instances itself.
	//
	// The control plane does not allocate it and does not verify that anything answers there — it
	// publishes it. An address for which nothing was deployed refuses connections, and that is a
	// deployment's own doing, not a promise the API made. Automatic allocation belongs with the
	// eBPF datapath, which is what makes an address real without anything binding it; until that
	// exists, inventing one would mean handing out a value nothing in the fleet has heard of.
	//
	// Two Services may share an address as long as their ports differ — one balancer commonly
	// fronts several services — which is why the address alone is not required to be unique but
	// (address, port) is.
	ClusterIP string `json:"clusterIP,omitempty"`
	// Ports are the ports this service answers on. They are the service's own vocabulary, not a
	// copy of any workload's: an instance declares the port it listens on, and this declares the
	// port callers ask for. A name is required once there is more than one, because the catalog
	// splits service names per port (Consul's own answer to a multi-port service) and an unnamed
	// second port would have nothing to be called.
	Ports []ServicePort `json:"ports"`
}

// ServicePort is one port of a service.
type ServicePort struct {
	// Name distinguishes the ports of one service and becomes part of the catalog's service name
	// (`<service>-<port>`), so it is DNS-1123 shaped. Optional for a single-port service.
	Name string `json:"name,omitempty" jsonschema:"maxLength=63"`
	// Port is the port callers address. An instance may listen on a different one — see
	// TargetPort — so that a workload's own port is not part of the service's contract.
	Port int32 `json:"port" jsonschema:"minimum=1,maximum=65535"`
	// TargetName names the port ON THE INSTANCE — an entry of the Application's own
	// `spec.ports[]`. It is a different namespace from Name above: that one is the service's
	// name for the port and follows it into the catalog, this one is the workload's name for
	// its own, and there is no reason a service called `http` must front a port its instances
	// also call `http`.
	//
	// Naming is the useful direction because it keeps somebody else's arithmetic out of the
	// service's contract: a workload can move its port on a rebuild and neither the Service nor
	// anything calling it is edited. A number pins the service to today's value of an
	// implementation detail.
	TargetName string `json:"targetName,omitempty" jsonschema:"maxLength=63"`
	// TargetPort is the same thing said as a number, for an instance whose port has no name.
	// Setting both is refused: one of them would be dead text, and which one is not obvious from
	// reading the manifest.
	TargetPort int32 `json:"targetPort,omitempty" jsonschema:"minimum=0,maximum=65535"`
	// Protocol is TCP (default) or UDP.
	Protocol string `json:"protocol,omitempty" jsonschema:"enum=TCP,enum=UDP,default=TCP"`
}

// TargetFor resolves the port an instance is actually listening on for p, in the order that puts
// the least implementation detail in the service's contract:
//
//  1. an explicit numeric TargetPort, when somebody had to say a number;
//  2. the instance's port called TargetName — the preferred form, because it lets the workload
//     move its port without the service or its callers noticing;
//  3. the service's own Port, for the ordinary case where they are simply the same.
//
// It deliberately does NOT fall back to matching the service's own Name against the instance's
// port names. Those are two namespaces — what the service calls a port and what a workload calls
// its own — and quietly joining them would make a rename on either side reach across and change
// where traffic goes.
func (p ServicePort) TargetFor(app *Application) int32 {
	if p.TargetPort != 0 {
		return p.TargetPort
	}
	if p.TargetName != "" && app != nil {
		for _, ap := range app.Spec.Ports {
			if ap.Name == p.TargetName {
				return int32(ap.Port)
			}
		}
	}
	return p.Port
}

// CatalogName is the name this port is registered under in the catalog: the service's own name
// for a single unnamed port, `<service>-<port>` otherwise. The port participates in the NAME and
// not only in the tags because a consumer asking for `cache` must not also be handed `cache`'s
// metrics port — which is what one service carrying every port would do.
func (s Service) CatalogName(p ServicePort) string {
	if p.Name == "" {
		return s.Name
	}
	return s.Name + "-" + p.Name
}

// ServiceList is a list of Services.
type ServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Service `json:"items"`
}
