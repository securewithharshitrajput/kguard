// Package enrich adds human/context information to raw events: resolving the
// uid to a username, deriving a container id from the process cgroup, and
// (for exec events) hashing the executable on disk.
package enrich

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"sync"

	"github.com/harry/kguard/internal/events"
	"github.com/harry/kguard/internal/proctree"
)

// Enricher fills in derived fields. It caches uid->name and exe->hash lookups
// because those are relatively expensive and highly repetitive.
type Enricher struct {
	tree *proctree.Tree

	mu       sync.Mutex
	userByID map[uint32]string
	hashByPath map[string]string

	// HashExecutables controls whether exec events get a SHA-256 of their
	// binary. Hashing touches disk, so it can be disabled for very hot hosts.
	HashExecutables bool
}

func New(tree *proctree.Tree) *Enricher {
	return &Enricher{
		tree:            tree,
		userByID:        make(map[uint32]string),
		hashByPath:      make(map[string]string),
		HashExecutables: true,
	}
}

// Apply mutates e in place with enrichment data.
func (en *Enricher) Apply(e *events.Event) {
	e.Username = en.username(e.Uid)
	e.ParentComm = en.tree.ParentComm(e.Ppid)
	e.Ancestry = en.tree.Ancestry(e.Pid, 8)
	e.ContainerID = containerID(e.Pid)

	if e.Kind == events.KindExec && en.HashExecutables && e.Filename != "" {
		e.ExeSHA256 = en.hashFile(e.Filename)
	}
}

func (en *Enricher) username(uid uint32) string {
	en.mu.Lock()
	defer en.mu.Unlock()
	if name, ok := en.userByID[uid]; ok {
		return name
	}
	name := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	en.userByID[uid] = name
	return name
}

func (en *Enricher) hashFile(path string) string {
	en.mu.Lock()
	if h, ok := en.hashByPath[path]; ok {
		en.mu.Unlock()
		return h
	}
	en.mu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 256<<20)); err != nil { // cap at 256MB
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))

	en.mu.Lock()
	en.hashByPath[path] = sum
	en.mu.Unlock()
	return sum
}

// containerID best-effort extracts a container id from /proc/<pid>/cgroup.
// Works for Docker, containerd and Kubernetes cgroup layouts. Returns "" on
// the host or when the process has already gone.
var cgroupIDRe = regexp.MustCompile(`[0-9a-f]{64}`)

func containerID(pid uint32) string {
	f, err := os.Open("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cgroup")
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := cgroupIDRe.FindString(sc.Text()); m != "" {
			return m[:12] // short id, like docker ps
		}
	}
	return ""
}
