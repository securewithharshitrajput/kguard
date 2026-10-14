// Package rules implements a small YAML-driven detection engine. Each rule
// describes a condition over a single event; Match returns every rule that
// fires for a given event. Rules are data, not code, so analysts can add
// detections without recompiling.
package rules

import (
	"fmt"
	"os"
	"strings"

	"github.com/harry/kguard/internal/events"
	"gopkg.in/yaml.v3"
)

// Severity levels, ordered.
type Severity string

const (
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Match is the condition block of a rule. All populated fields must be
// satisfied (logical AND). Within a field, a list means "any of" (OR).
type MatchSpec struct {
	Event       string   `yaml:"event"`        // exec|exit|connect|accept|file ("" = any)
	Comm        []string `yaml:"comm"`         // process name is one of these
	ParentComm  []string `yaml:"parent_comm"`  // parent name is one of these
	Ancestor    []string `yaml:"ancestor"`     // any ancestor name is one of these
	User        []string `yaml:"user"`         // username is one of these
	NotUser     []string `yaml:"not_user"`     // username is none of these
	FilePrefix  []string `yaml:"file_prefix"`  // filename starts with one of these
	FileContains []string `yaml:"file_contains"` // filename contains one of these
	ArgsContains []string `yaml:"args_contains"` // any arg contains one of these
	DstPort     []uint16 `yaml:"dst_port"`     // destination port is one of these
	MinUID      *uint32  `yaml:"min_uid"`      // uid >= this (nil = no bound)
	MaxUID      *uint32  `yaml:"max_uid"`      // uid <= this (nil = no bound)
}

// Rule is one detection.
type Rule struct {
	ID          string    `yaml:"id"`
	Description string    `yaml:"description"`
	Severity    Severity  `yaml:"severity"`
	Mitre       string    `yaml:"mitre"`
	Match       MatchSpec `yaml:"match"`
}

// Set is a compiled, loaded collection of rules.
type Set struct {
	rules []Rule
}

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// Load reads rules from one or more YAML files and validates them.
func Load(paths ...string) (*Set, error) {
	s := &Set{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read rules %s: %w", p, err)
		}
		var rf ruleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			return nil, fmt.Errorf("parse rules %s: %w", p, err)
		}
		s.rules = append(s.rules, rf.Rules...)
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Set) validate() error {
	seen := make(map[string]bool)
	for i, r := range s.rules {
		if r.ID == "" {
			return fmt.Errorf("rule #%d has no id", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		switch r.Severity {
		case SevLow, SevMedium, SevHigh, SevCritical:
		case "":
			s.rules[i].Severity = SevMedium
		default:
			return fmt.Errorf("rule %q has invalid severity %q", r.ID, r.Severity)
		}
	}
	return nil
}

// Len returns the number of loaded rules.
func (s *Set) Len() int { return len(s.rules) }

// Match returns all rules that fire for e.
func (s *Set) Match(e *events.Event) []Rule {
	var hits []Rule
	for _, r := range s.rules {
		if matches(&r.Match, e) {
			hits = append(hits, r)
		}
	}
	return hits
}

func matches(m *MatchSpec, e *events.Event) bool {
	if m.Event != "" && m.Event != e.Kind.String() {
		return false
	}
	if len(m.Comm) > 0 && !containsFold(m.Comm, e.Comm) {
		return false
	}
	if len(m.ParentComm) > 0 && !containsFold(m.ParentComm, e.ParentComm) {
		return false
	}
	if len(m.Ancestor) > 0 && !anyInFold(m.Ancestor, e.Ancestry) {
		return false
	}
	if len(m.User) > 0 && !containsFold(m.User, e.Username) {
		return false
	}
	if len(m.NotUser) > 0 && containsFold(m.NotUser, e.Username) {
		return false
	}
	if len(m.FilePrefix) > 0 && !hasAnyPrefix(e.Filename, m.FilePrefix) {
		return false
	}
	if len(m.FileContains) > 0 && !containsAny(e.Filename, m.FileContains) {
		return false
	}
	if len(m.ArgsContains) > 0 && !argsContainAny(e.Args, m.ArgsContains) {
		return false
	}
	if len(m.DstPort) > 0 && !portIn(m.DstPort, e.Dport) {
		return false
	}
	if m.MinUID != nil && e.Uid < *m.MinUID {
		return false
	}
	if m.MaxUID != nil && e.Uid > *m.MaxUID {
		return false
	}
	return true
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

func anyInFold(list, vals []string) bool {
	for _, v := range vals {
		if containsFold(list, v) {
			return true
		}
	}
	return false
}

func hasAnyPrefix(v string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
}

func containsAny(v string, subs []string) bool {
	for _, s := range subs {
		if strings.Contains(v, s) {
			return true
		}
	}
	return false
}

func argsContainAny(args, subs []string) bool {
	for _, a := range args {
		if containsAny(a, subs) {
			return true
		}
	}
	return false
}

func portIn(ports []uint16, p uint16) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}
