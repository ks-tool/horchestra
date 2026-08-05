//go:build linux

package netd

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// This is a hand-written RTNETLINK client, deliberately: the helper is the one root process on the
// node, and its dependency list is part of its attack surface — the same reason the sandbox has
// exactly one dependency and the OCI layout is written here rather than wrapped. What it needs is
// seven messages (create a veth, find an index, bring a link up, add an address, add a route, add a
// neighbour, delete a link), and seven messages are less code than the general-purpose library that
// would bring the other two hundred.
//
// Everything here speaks to the kernel in the CURRENT thread's network namespace. That is what
// makes the namespace work possible at all: enter the workload's namespace on a locked thread, do
// the addressing, come back — see withNetns.

// VETH_INFO_PEER is the nested attribute carrying the peer's own ifinfomsg. x/sys/unix does not
// export it (it is in linux/veth.h, not in the netlink headers the package generates from), so it
// is spelled out here with the reference rather than left as a bare 1.
const vethInfoPeer = 1

// nlConn is one netlink socket. It is not shared: a socket per operation costs a syscall pair and
// removes every question about sequence numbers racing between goroutines, which for a helper that
// serializes its calls anyway is a trade with no downside.
type nlConn struct {
	fd  int
	seq uint32
}

func dialNetlink() (*nlConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	// Bind with pid 0: the kernel assigns the port id, so two of these in one process cannot
	// collide the way a hand-picked one would.
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	return &nlConn{fd: fd}, nil
}

func (c *nlConn) Close() error { return unix.Close(c.fd) }

// do sends one request and waits for its acknowledgement, returning the messages that came back.
//
// NLM_F_ACK is always set: a netlink write that is not acknowledged is a write whose failure this
// helper would report as success, and the caller — an agent converging a workload — would go on to
// start something in a namespace that was never wired.
func (c *nlConn) do(msgType uint16, flags uint16, payload []byte, attrs []byte) ([][]byte, error) {
	c.seq++
	length := unix.NLMSG_HDRLEN + len(payload) + len(attrs)
	buf := make([]byte, unix.NLMSG_HDRLEN, length)
	hdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	hdr.Len = uint32(length)
	hdr.Type = msgType
	hdr.Flags = unix.NLM_F_REQUEST | unix.NLM_F_ACK | flags
	hdr.Seq = c.seq
	buf = append(buf, payload...)
	buf = append(buf, attrs...)

	if err := unix.Sendto(c.fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("netlink send: %w", err)
	}
	return c.receive(c.seq)
}

// receive reads until the request's acknowledgement (or error) arrives.
func (c *nlConn) receive(seq uint32) ([][]byte, error) {
	var out [][]byte
	rb := make([]byte, os.Getpagesize()*4)
	for {
		n, _, err := unix.Recvfrom(c.fd, rb, 0)
		if err != nil {
			return nil, fmt.Errorf("netlink receive: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(rb[:n])
		if err != nil {
			return nil, fmt.Errorf("netlink parse: %w", err)
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue // another request's reply on a socket we own alone: ignore rather than fail
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				// The payload starts with an int32 errno; 0 IS the acknowledgement.
				if len(m.Data) < 4 {
					return nil, fmt.Errorf("netlink: truncated error message")
				}
				errno := int32(binary.LittleEndian.Uint32(m.Data[:4]))
				if errno == 0 {
					return out, nil
				}
				return nil, fmt.Errorf("netlink: %w", unix.Errno(-errno))
			default:
				out = append(out, m.Data)
				if m.Header.Flags&unix.NLM_F_MULTI == 0 {
					return out, nil
				}
			}
		}
	}
}

// attr encodes one netlink attribute: a 4-byte header and a value padded to a 4-byte boundary.
func attr(typ uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	buf := make([]byte, rtaAlign(length))
	binary.LittleEndian.PutUint16(buf[0:2], uint16(length))
	binary.LittleEndian.PutUint16(buf[2:4], typ)
	copy(buf[unix.SizeofRtAttr:], value)
	return buf
}

// attrString is a NUL-terminated string attribute, the form the kernel expects for names.
func attrString(typ uint16, s string) []byte { return attr(typ, append([]byte(s), 0)) }

func attrU32(typ uint16, v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return attr(typ, b[:])
}

// attrNested wraps children in one attribute, with NLA_F_NESTED set the way iproute2 does.
func attrNested(typ uint16, children ...[]byte) []byte {
	var body []byte
	for _, c := range children {
		body = append(body, c...)
	}
	return attr(typ|unix.NLA_F_NESTED, body)
}

func rtaAlign(n int) int { return (n + unix.RTA_ALIGNTO - 1) & ^(unix.RTA_ALIGNTO - 1) }

// ifInfomsg is the fixed part of a link message.
func ifInfomsg(index int32, flags, change uint32) []byte {
	buf := make([]byte, unix.SizeofIfInfomsg)
	msg := (*unix.IfInfomsg)(unsafe.Pointer(&buf[0]))
	msg.Family = unix.AF_UNSPEC
	msg.Index = index
	msg.Flags = flags
	msg.Change = change
	return buf
}

// ifAddrmsg is the fixed part of an address message.
func ifAddrmsg(family uint8, prefixLen uint8, index uint32) []byte {
	buf := make([]byte, unix.SizeofIfAddrmsg)
	msg := (*unix.IfAddrmsg)(unsafe.Pointer(&buf[0]))
	msg.Family = family
	msg.Prefixlen = prefixLen
	msg.Scope = unix.RT_SCOPE_UNIVERSE
	msg.Index = index
	return buf
}

// rtMsg is the fixed part of a route message.
func rtMsg(family uint8, dstLen uint8, scope uint8, flags uint32) []byte {
	buf := make([]byte, unix.SizeofRtMsg)
	msg := (*unix.RtMsg)(unsafe.Pointer(&buf[0]))
	msg.Family = family
	msg.Dst_len = dstLen
	msg.Table = unix.RT_TABLE_MAIN
	msg.Protocol = unix.RTPROT_BOOT
	msg.Scope = scope
	msg.Type = unix.RTN_UNICAST
	msg.Flags = flags
	return buf
}

// setMAC changes an existing link's ethernet address. Needed only for a device this helper made
// before the one-address rule existed — a veth is recreated with its workload, but the tunnel
// outlives every version of netd that made it.
func setMAC(c *nlConn, index int, mac net.HardwareAddr) error {
	_, err := c.do(unix.RTM_NEWLINK, 0, ifInfomsg(int32(index), 0, 0), attr(unix.IFLA_ADDRESS, mac))
	return err
}

// ndMsg is the fixed part of a neighbour message. PERMANENT is the whole point of the one caller:
// an entry the kernel neither ages out nor re-resolves, so the address it names is never ARPed for.
func ndMsg(family uint8, index int32, state uint16) []byte {
	buf := make([]byte, unix.SizeofNdMsg)
	msg := (*unix.NdMsg)(unsafe.Pointer(&buf[0]))
	msg.Family = family
	msg.Ifindex = index
	msg.State = state
	msg.Type = unix.RTN_UNICAST
	return buf
}

// addNeighbour writes a permanent address→MAC entry. REPLACE rather than CREATE|EXCL: unlike the
// address and the route, this one is re-applied over whatever the kernel may already have learned
// by ARP, and a converge that repeated must not fail on its own previous pass.
func addNeighbour(c *nlConn, index int, addr netip.Addr, mac net.HardwareAddr) error {
	attrs := attr(unix.NDA_DST, addrBytes(addr))
	attrs = append(attrs, attr(unix.NDA_LLADDR, mac)...)
	_, err := c.do(unix.RTM_NEWNEIGH, unix.NLM_F_CREATE|unix.NLM_F_REPLACE,
		ndMsg(addrFamily(addr), int32(index), unix.NUD_PERMANENT), attrs)
	return err
}

// addrFamily and addrBytes reduce a netip.Addr to what netlink wants, keeping the v4/v6 branch in
// one place instead of at every call site.
func addrFamily(a netip.Addr) uint8 {
	if a.Is4() {
		return unix.AF_INET
	}
	return unix.AF_INET6
}

func addrBytes(a netip.Addr) []byte {
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	b := a.As16()
	return b[:]
}
