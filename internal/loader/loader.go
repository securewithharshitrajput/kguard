// Package loader compiles-in the eBPF objects (via bpf2go) and attaches the
// programs to their kernel hooks. It exposes the ring buffer as a stream of
// raw event byte slices.
package loader

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// go:generate runs bpf2go, which compiles bpf/kguard.bpf.c and produces Go
// bindings (kguardObjects, etc.) in this package. Requires clang + the kernel
// headers / a generated vmlinux.h.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Wno-missing-declarations -Wno-address-of-packed-member" -target native kguard ../../bpf/kguard.bpf.c -- -I../../bpf

// Loader owns the loaded objects and attached links.
type Loader struct {
	objs   kguardObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// New removes the memlock limit, loads the objects, attaches every program,
// and opens the ring buffer. Call Close when done.
func New() (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	l := &Loader{}
	if err := loadKguardObjects(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	if err := l.attach(); err != nil {
		l.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}
	l.reader = rd
	return l, nil
}

func (l *Loader) attach() error {
	// Tracepoints are available on essentially every kernel.
	tpExec, err := link.Tracepoint("sched", "sched_process_exec", l.objs.HandleExec, nil)
	if err != nil {
		return fmt.Errorf("attach exec tracepoint: %w", err)
	}
	l.links = append(l.links, tpExec)

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", l.objs.HandleExit, nil)
	if err != nil {
		return fmt.Errorf("attach exit tracepoint: %w", err)
	}
	l.links = append(l.links, tpExit)

	// fentry/fexit need BTF + a reasonably recent kernel. Treat failure as
	// non-fatal so process monitoring still works on older systems.
	if fc, err := link.AttachTracing(link.TracingOptions{Program: l.objs.HandleConnect}); err != nil {
		fmt.Printf("warning: tcp_connect hook unavailable (network connect events off): %v\n", err)
	} else {
		l.links = append(l.links, fc)
	}
	if fa, err := link.AttachTracing(link.TracingOptions{Program: l.objs.HandleAccept}); err != nil {
		fmt.Printf("warning: inet_csk_accept hook unavailable (network accept events off): %v\n", err)
	} else {
		l.links = append(l.links, fa)
	}
	return nil
}

// Read blocks for the next raw event record. It returns ringbuf.ErrClosed
// after Close is called, which the caller should treat as a clean shutdown.
func (l *Loader) Read() ([]byte, error) {
	rec, err := l.reader.Read()
	if err != nil {
		return nil, err
	}
	return rec.RawSample, nil
}

// Closed reports whether err means the reader was closed (clean shutdown).
func Closed(err error) bool {
	return errors.Is(err, ringbuf.ErrClosed)
}

// Close detaches everything and frees resources. Safe to call more than once.
func (l *Loader) Close() {
	if l.reader != nil {
		l.reader.Close()
		l.reader = nil
	}
	for _, lk := range l.links {
		lk.Close()
	}
	l.links = nil
	l.objs.Close()
}
