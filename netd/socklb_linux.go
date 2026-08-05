//go:build linux

package netd

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	netdapi "github.com/ks-tool/horchestra/api/netd"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// socklbELF is the compiled datapath, embedded rather than read from disk. A root daemon that
// loaded kernel code from a path could be pointed at another file; this one can only load what was
// linked into it, which is the same rule the gRPC surface follows by refusing to accept a program
// at all (see proto/netd.proto).
//
// It is COMMITTED to the tree, so no build of horchestra needs clang: `make bpf` recompiles it in a
// container and the object is reviewed like any other artefact.
//
//go:embed bpf/socklb.bpf.o
var socklbELF []byte

// SockLB is the loaded socket load balancer: two cgroup programs and the two maps they read.
//
// Its whole state is in the kernel. There is no shadow copy of the service table here, on purpose —
// a second record is a second thing to be wrong, and the reconciliation this type does (below) is
// against what the maps actually contain, so a netd restart converges from whatever is there
// instead of from what it remembers having put there.
type SockLB struct {
	coll     *ebpf.Collection
	links    []link.Link
	services *ebpf.Map
	backends *ebpf.Map
	pinDir   string
}

// The map layouts, mirrored from bpf/socklb.bpf.c. They are byte offsets and not a Go struct
// because half of these fields hold NETWORK byte order (they are compared against, and assigned to,
// the kernel's __be32/__be16 socket fields) and half hold host order (an index, a count) — a struct
// marshalled with one endianness cannot express both, and expressing it wrongly is a lookup that
// silently never matches.
const (
	svcKeySize     = 8  // __be32 address, __be16 port, u8 protocol, u8 pad
	svcValSize     = 4  // u32 backend count
	backendKeySize = 12 // svc_key, u16 index, u16 pad
	backendValSize = 8  // __be32 address, __be16 port, u16 pad
)

// LoadSockLB loads the datapath and attaches it to the cgroup root, which is where every process on
// the node lives — including the workloads, whose systemd scopes are subtrees of it. Attaching per
// workload would need this helper to be told about each one and to re-attach after every restart;
// attaching once at the root is what makes a ClusterIP answer for anything on the node, which is
// what a ClusterIP means.
//
// It is BPF_F_ALLOW_MULTI (link.AttachCgroup's default for links): another program on the same hook
// — Cilium, systemd, a distro's own — keeps working, and neither of us silently displaces the
// other.
func LoadSockLB(cgroupRoot, pinDir string) (*SockLB, error) {
	if ok, reason := datapathSupport(); !ok {
		return nil, errors.New(reason)
	}
	if err := preparePinDir(pinDir); err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(socklbELF))
	if err != nil {
		return nil, fmt.Errorf("read the embedded datapath: %w", err)
	}
	coll, err := loadPinned(spec, filepath.Join(pinDir, pinMaps))
	if err != nil {
		// The verifier's log is the only thing that ever explains a rejected program, and it
		// arrives in this error — truncating it would leave an operator with "invalid argument".
		return nil, fmt.Errorf("load the datapath: %w", err)
	}
	s := &SockLB{coll: coll, pinDir: pinDir,
		services: coll.Maps["horc_services"], backends: coll.Maps["horc_backends"]}
	if s.services == nil || s.backends == nil {
		coll.Close()
		return nil, errors.New("the embedded datapath has no service maps: it was built from other sources than this tree")
	}
	for prog, attach := range map[string]ebpf.AttachType{
		"horc_connect4": ebpf.AttachCGroupInet4Connect,
		"horc_sendmsg4": ebpf.AttachCGroupUDP4Sendmsg,
	} {
		p := coll.Programs[prog]
		if p == nil {
			s.Close()
			return nil, fmt.Errorf("the embedded datapath has no %s program", prog)
		}
		pin := filepath.Join(pinDir, pinSockLinks, prog)
		// Adopt what a previous netd left attached, rather than adding a second program to the same
		// hook — with ALLOW_MULTI both would run, and the second would find an address the first had
		// already rewritten.
		if l, err := link.LoadPinnedLink(pin, nil); err == nil {
			if err := l.Update(p); err != nil {
				_ = l.Close()
				s.Close()
				return nil, fmt.Errorf("adopt %s: %w", prog, err)
			}
			s.links = append(s.links, l)
			continue
		}
		l, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupRoot, Attach: attach, Program: p})
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("attach %s to %s: %w", prog, cgroupRoot, err)
		}
		if err := l.Pin(pin); err != nil {
			_ = l.Close()
			s.Close()
			return nil, fmt.Errorf("pin %s: %w", prog, err)
		}
		s.links = append(s.links, l)
	}
	return s, nil
}

// Close drops this process's descriptors and leaves the programs attached and the tables populated:
// a ClusterIP goes on answering while netd is not running. The next netd adopts the same links
// instead of adding a second copy to the hook.
func (s *SockLB) Close() error {
	for _, l := range s.links {
		_ = l.Close()
	}
	s.links = nil
	if s.coll != nil {
		s.coll.Close()
	}
	return nil
}

// Services makes the kernel's service table equal to rules — a REPLACE, as the API says, computed
// against what the maps hold rather than against a remembered previous call.
//
// The write order is the only thing standing between an update and a black hole, and it is one
// order for both directions: every backend entry a service will name is written BEFORE the count
// that names it, and the entries it no longer names are removed AFTER. So the count in the map is
// never higher than the number of entries present, which is the one state in which this program
// picks an index that resolves to nothing and a connection to a live ClusterIP fails.
func (s *SockLB) Services(rules []*netdapi.ServiceRule) error {
	want, err := serviceTable(rules)
	if err != nil {
		return err // a malformed rule is refused whole: half a service table is worse than none
	}
	// Refused here rather than in the kernel: a map that is full answers E2BIG for SOME services,
	// leaving a table that is silently missing whichever ones lost the race.
	if uint32(len(want)) > s.services.MaxEntries() {
		return fmt.Errorf("%d services exceed the datapath's capacity of %d", len(want), s.services.MaxEntries())
	}
	var total int
	for _, bes := range want {
		total += len(bes)
	}
	if uint32(total) > s.backends.MaxEntries() {
		return fmt.Errorf("%d backends exceed the datapath's capacity of %d", total, s.backends.MaxEntries())
	}

	var errs []error
	for key, bes := range want {
		for i, be := range bes {
			bk := backendKey(key, uint16(i))
			if err := s.backends.Update(bk[:], be[:], ebpf.UpdateAny); err != nil {
				errs = append(errs, fmt.Errorf("backend %d of %s: %w", i, formatKey(key), err))
			}
		}
		var val [svcValSize]byte
		binary.NativeEndian.PutUint32(val[:], uint32(len(bes)))
		if err := s.services.Update(key[:], val[:], ebpf.UpdateAny); err != nil {
			errs = append(errs, fmt.Errorf("service %s: %w", formatKey(key), err))
		}
	}

	// Services first, then backends: a service deleted from the lookup map cannot be reached by
	// the time its entries go, so nothing ever picks an index out of a set being emptied.
	stale, err := s.staleServices(want)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, key := range stale {
		if err := s.services.Delete(key[:]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("remove service %s: %w", formatKey(key), err))
		}
	}
	if err := s.reclaimBackends(want); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// staleServices is every key in the kernel's table that the request does not name. Read from the
// map, so a service left behind by a netd that died mid-update is found on the next pass — which is
// what makes this a replace and not a delta.
func (s *SockLB) staleServices(want map[[svcKeySize]byte][][backendValSize]byte) ([][svcKeySize]byte, error) {
	var (
		out  [][svcKeySize]byte
		key  [svcKeySize]byte
		val  [svcValSize]byte
		iter = s.services.Iterate()
	)
	for iter.Next(&key, &val) {
		if _, ok := want[key]; !ok {
			out = append(out, key)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("read the service table: %w", err)
	}
	return out, nil
}

// reclaimBackends removes every backend entry the new table does not cover: the ones belonging to a
// service that is gone, and the tail indices of a service that shrank.
func (s *SockLB) reclaimBackends(want map[[svcKeySize]byte][][backendValSize]byte) error {
	var (
		stale [][backendKeySize]byte
		key   [backendKeySize]byte
		val   [backendValSize]byte
		iter  = s.backends.Iterate()
	)
	for iter.Next(&key, &val) {
		var svc [svcKeySize]byte
		copy(svc[:], key[:svcKeySize])
		index := binary.NativeEndian.Uint16(key[svcKeySize : svcKeySize+2])
		if bes, ok := want[svc]; !ok || int(index) >= len(bes) {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("read the backend table: %w", err)
	}
	// Collected first, deleted after: a hash map iterated while it is being deleted from may skip
	// entries the kernel has moved, and a skipped entry here is a backend that outlives its service.
	var errs []error
	for _, k := range stale {
		if err := s.backends.Delete(k[:]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("remove a backend: %w", err))
		}
	}
	return errors.Join(errs...)
}

// serviceTable validates the request whole and encodes it into the kernel's layout. Everything that
// can be refused is refused here, before the first map write.
func serviceTable(rules []*netdapi.ServiceRule) (map[[svcKeySize]byte][][backendValSize]byte, error) {
	want := make(map[[svcKeySize]byte][][backendValSize]byte, len(rules))
	for _, r := range rules {
		proto, err := protocolNumber(r.GetProtocol())
		if err != nil {
			return nil, fmt.Errorf("service %s:%d: %w", r.GetClusterIp(), r.GetPort(), err)
		}
		ip, err := address4(r.GetClusterIp())
		if err != nil {
			return nil, fmt.Errorf("service clusterIP %q: %w", r.GetClusterIp(), err)
		}
		port, err := port16(r.GetPort())
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", r.GetClusterIp(), err)
		}
		key := serviceKey(ip, port, proto)
		if _, dup := want[key]; dup {
			// Two rules for one (address, port, protocol) is a caller disagreeing with itself:
			// picking one would make the datapath's behaviour depend on map iteration order.
			return nil, fmt.Errorf("service %s is named twice", formatKey(key))
		}
		bes := make([][backendValSize]byte, 0, len(r.GetBackends()))
		for _, b := range r.GetBackends() {
			bip, err := address4(b.GetAddress())
			if err != nil {
				return nil, fmt.Errorf("backend of %s: %w", formatKey(key), err)
			}
			bport, err := port16(b.GetPort())
			if err != nil {
				return nil, fmt.Errorf("backend of %s: %w", formatKey(key), err)
			}
			bes = append(bes, backendValue(bip, bport))
		}
		want[key] = bes
	}
	return want, nil
}

// serviceKey lays out struct svc_key. The address and port bytes are written in NETWORK order
// because that is how the kernel hands them to the program (bpf_sock_addr's user_ip4 and user_port
// are __be), and a BPF hash compares keys byte for byte — there is no conversion on the datapath,
// which is the point of storing them this way.
func serviceKey(ip netip.Addr, port uint16, proto uint8) [svcKeySize]byte {
	var k [svcKeySize]byte
	a := ip.As4()
	copy(k[0:4], a[:])
	binary.BigEndian.PutUint16(k[4:6], port)
	k[6] = proto
	return k // k[7] is the explicit pad: zero here and zero in the C, or the lookup misses
}

// backendKey lays out struct backend_key. The index is a plain integer the program computes, so it
// is HOST order — the one field here that is not network order.
func backendKey(svc [svcKeySize]byte, index uint16) [backendKeySize]byte {
	var k [backendKeySize]byte
	copy(k[:svcKeySize], svc[:])
	binary.NativeEndian.PutUint16(k[svcKeySize:svcKeySize+2], index)
	return k
}

// backendValue lays out struct backend: what gets written into the socket, so network order again.
func backendValue(ip netip.Addr, port uint16) [backendValSize]byte {
	var v [backendValSize]byte
	a := ip.As4()
	copy(v[0:4], a[:])
	binary.BigEndian.PutUint16(v[4:6], port)
	return v
}

func address4(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	if !ip.Is4() {
		// connect4/sendmsg4 are IPv4 hooks. Accepting a v6 address would store a key nothing can
		// ever match, and the service would look programmed and answer nothing.
		return netip.Addr{}, fmt.Errorf("%s is not IPv4: this datapath answers on IPv4 only", s)
	}
	return ip, nil
}

func port16(p int32) (uint16, error) {
	if p <= 0 || p > 65535 {
		return 0, fmt.Errorf("port %d is out of range", p)
	}
	return uint16(p), nil
}

// protocolNumber maps the API's protocol to the kernel's. Empty means TCP, which is the API's own
// default and is spelled here rather than assumed at the call site.
func protocolNumber(p string) (uint8, error) {
	switch strings.ToUpper(p) {
	case "", "TCP":
		return unix.IPPROTO_TCP, nil
	case "UDP":
		return unix.IPPROTO_UDP, nil
	default:
		return 0, fmt.Errorf("protocol %q is neither TCP nor UDP", p)
	}
}

// formatKey renders a key the way an operator wrote it, for errors. Decoding rather than carrying
// the original strings around keeps the failure paths honest: what is printed is what is in the map.
func formatKey(k [svcKeySize]byte) string {
	ip := netip.AddrFrom4([4]byte{k[0], k[1], k[2], k[3]})
	proto := "tcp"
	if k[6] == unix.IPPROTO_UDP {
		proto = "udp"
	}
	return fmt.Sprintf("%s:%d/%s", ip, binary.BigEndian.Uint16(k[4:6]), proto)
}
