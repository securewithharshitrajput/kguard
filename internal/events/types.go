// Package events defines the event types shared with the kernel-side eBPF
// programs and the decoder that turns raw ring-buffer bytes into Go values.
package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// Kind mirrors enum event_kind in bpf/common.h.
type Kind uint8

const (
	KindExec    Kind = 1
	KindExit    Kind = 2
	KindConnect Kind = 3
	KindAccept  Kind = 4
	KindFile    Kind = 5
)

func (k Kind) String() string {
	switch k {
	case KindExec:
		return "exec"
	case KindExit:
		return "exit"
	case KindConnect:
		return "connect"
	case KindAccept:
		return "accept"
	case KindFile:
		return "file"
	default:
		return "unknown"
	}
}

const (
	taskCommLen    = 16
	maxFilenameLen = 256
	maxArgsLen     = 256
)

// rawEvent matches `struct event` in bpf/common.h byte for byte.
// The eBPF target is always little-endian on the architectures we support
// (x86_64, arm64), so we decode with binary.LittleEndian.
type rawEvent struct {
	Kind     uint8
	_        [3]uint8
	Pid      uint32
	Ppid     uint32
	Uid      uint32
	Gid      uint32
	ExitCode uint32
	TsNs     uint64
	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
	Comm     [taskCommLen]byte
	Filename [maxFilenameLen]byte
	Args     [maxArgsLen]byte
}

// Event is the decoded, user-friendly form passed around the pipeline.
type Event struct {
	Kind     Kind
	Pid      uint32
	Ppid     uint32
	Uid      uint32
	Gid      uint32
	ExitCode uint32
	TsNs     uint64
	SrcIP    net.IP
	DstIP    net.IP
	Sport    uint16
	Dport    uint16
	Comm     string
	Filename string
	Args     []string

	// Filled in later by the enrich stage.
	Username    string   `json:",omitempty"`
	ContainerID string   `json:",omitempty"`
	ExeSHA256   string   `json:",omitempty"`
	ParentComm  string   `json:",omitempty"`
	Ancestry    []string `json:",omitempty"`
}

// Decode parses one ring-buffer record into an Event.
func Decode(raw []byte) (*Event, error) {
	var r rawEvent
	if len(raw) < binary.Size(&r) {
		return nil, fmt.Errorf("short event: got %d bytes, want %d", len(raw), binary.Size(&r))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &r); err != nil {
		return nil, err
	}

	e := &Event{
		Kind:     Kind(r.Kind),
		Pid:      r.Pid,
		Ppid:     r.Ppid,
		Uid:      r.Uid,
		Gid:      r.Gid,
		ExitCode: r.ExitCode,
		TsNs:     r.TsNs,
		Sport:    r.Sport,
		Dport:    r.Dport,
		Comm:     cstr(r.Comm[:]),
		Filename: cstr(r.Filename[:]),
		Args:     splitArgs(r.Args[:]),
	}
	if r.Saddr != 0 || r.Daddr != 0 {
		e.SrcIP = ipv4(r.Saddr)
		e.DstIP = ipv4(r.Daddr)
	}
	return e, nil
}

// ipv4 converts a network-byte-order u32 (as stored by the kernel) to net.IP.
func ipv4(addr uint32) net.IP {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, addr)
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// cstr trims a NUL-terminated C string out of a fixed byte array.
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// splitArgs turns the NUL-separated argv blob into a slice of strings.
func splitArgs(b []byte) []string {
	b = bytes.TrimRight(b, "\x00")
	if len(b) == 0 {
		return nil
	}
	parts := bytes.Split(b, []byte{0})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) > 0 {
			out = append(out, string(p))
		}
	}
	return out
}
