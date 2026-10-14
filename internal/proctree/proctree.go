// Package proctree keeps a live, in-memory view of the process hierarchy so
// detections can reason about lineage (e.g. "nginx -> bash -> curl").
package proctree

import (
	"sync"
)

type node struct {
	pid  uint32
	ppid uint32
	comm string
}

// Tree is a concurrency-safe process table. It is intentionally simple: we
// learn processes from exec events and forget them on exit. Processes that
// already existed before kguard started are backfilled lazily from /proc by
// the enrich stage when needed.
type Tree struct {
	mu    sync.RWMutex
	nodes map[uint32]*node
}

func New() *Tree {
	return &Tree{nodes: make(map[uint32]*node)}
}

// Add records (or updates) a process.
func (t *Tree) Add(pid, ppid uint32, comm string) {
	t.mu.Lock()
	t.nodes[pid] = &node{pid: pid, ppid: ppid, comm: comm}
	t.mu.Unlock()
}

// Remove drops a process once it has exited.
func (t *Tree) Remove(pid uint32) {
	t.mu.Lock()
	delete(t.nodes, pid)
	t.mu.Unlock()
}

// ParentComm returns the recorded command name of pid's parent, if known.
func (t *Tree) ParentComm(ppid uint32) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if n, ok := t.nodes[ppid]; ok {
		return n.comm
	}
	return ""
}

// Ancestry walks up the tree from pid and returns comm names from the nearest
// ancestor outward, stopping at the root, a cycle, or maxDepth.
func (t *Tree) Ancestry(pid uint32, maxDepth int) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var out []string
	seen := make(map[uint32]bool)
	cur := pid
	for i := 0; i < maxDepth; i++ {
		n, ok := t.nodes[cur]
		if !ok || seen[cur] {
			break
		}
		seen[cur] = true
		if n.ppid == 0 || n.ppid == cur {
			break
		}
		if p, ok := t.nodes[n.ppid]; ok {
			out = append(out, p.comm)
			cur = n.ppid
		} else {
			break
		}
	}
	return out
}

// Len reports how many processes are currently tracked (useful for tests/metrics).
func (t *Tree) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.nodes)
}
