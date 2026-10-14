// Package output renders events and alerts to the console, a JSONL log file,
// and (optionally) an HTTP webhook such as Slack or a generic SIEM collector.
package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/harry/kguard/internal/events"
	"github.com/harry/kguard/internal/rules"
)

// Alert bundles an event with the rule(s) it tripped.
type Alert struct {
	Time   string         `json:"time"`
	Rule   string         `json:"rule"`
	Severity rules.Severity `json:"severity"`
	Mitre  string         `json:"mitre,omitempty"`
	Desc   string         `json:"description,omitempty"`
	Event  *events.Event  `json:"event"`
}

// Sink is a set of destinations. Nil fields are skipped.
type Sink struct {
	mu sync.Mutex

	// Console enables human-readable stderr output.
	Console bool
	// JSONLog, if non-nil, receives one JSON object per line.
	JSONLog io.Writer
	// WebhookURL, if set, receives a POST per alert.
	WebhookURL string
	// AlertsOnly suppresses plain (non-alerting) events on the console.
	AlertsOnly bool

	client *http.Client
}

func NewSink() *Sink {
	return &Sink{client: &http.Client{Timeout: 5 * time.Second}}
}

// Event handles a plain event (no rule hit).
func (s *Sink) Event(e *events.Event) {
	if s.JSONLog != nil {
		s.writeJSON(map[string]any{"type": "event", "event": e})
	}
	if s.Console && !s.AlertsOnly {
		fmt.Fprintln(os.Stderr, formatEvent(e))
	}
}

// Alert handles an event that tripped one or more rules.
func (s *Sink) Alert(e *events.Event, hits []rules.Rule) {
	for _, r := range hits {
		a := &Alert{
			Time:     time.Now().UTC().Format(time.RFC3339),
			Rule:     r.ID,
			Severity: r.Severity,
			Mitre:    r.Mitre,
			Desc:     r.Description,
			Event:    e,
		}
		if s.JSONLog != nil {
			s.writeJSON(a)
		}
		if s.Console {
			fmt.Fprintln(os.Stderr, formatAlert(a))
		}
		if s.WebhookURL != "" {
			s.postWebhook(a)
		}
	}
}

func (s *Sink) writeJSON(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.JSONLog.Write(append(b, '\n'))
}

func (s *Sink) postWebhook(a *Alert) {
	// Format as a Slack-compatible message, which generic collectors also accept.
	payload := map[string]string{
		"text": fmt.Sprintf("[%s] %s (%s) pid=%d comm=%s user=%s file=%s",
			a.Severity, a.Rule, a.Mitre, a.Event.Pid, a.Event.Comm,
			a.Event.Username, a.Event.Filename),
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, s.WebhookURL, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "webhook error: %v\n", err)
		return
	}
	resp.Body.Close()
}

// --- formatting -----------------------------------------------------------

const (
	colReset  = "\033[0m"
	colRed    = "\033[31m"
	colYellow = "\033[33m"
	colCyan   = "\033[36m"
	colGray   = "\033[90m"
)

func formatEvent(e *events.Event) string {
	switch e.Kind {
	case events.KindExec:
		return fmt.Sprintf("%sEXEC%s  pid=%d ppid=%d user=%s %s %v",
			colGray, colReset, e.Pid, e.Ppid, e.Username, e.Filename, e.Args)
	case events.KindExit:
		return fmt.Sprintf("%sEXIT%s  pid=%d code=%d comm=%s",
			colGray, colReset, e.Pid, e.ExitCode, e.Comm)
	case events.KindConnect:
		return fmt.Sprintf("%sCONN%s  pid=%d comm=%s -> %s:%d",
			colCyan, colReset, e.Pid, e.Comm, e.DstIP, e.Dport)
	case events.KindAccept:
		return fmt.Sprintf("%sACPT%s  pid=%d comm=%s <- %s:%d",
			colCyan, colReset, e.Pid, e.Comm, e.DstIP, e.Dport)
	case events.KindFile:
		return fmt.Sprintf("%sFILE%s  pid=%d comm=%s %s",
			colGray, colReset, e.Pid, e.Comm, e.Filename)
	default:
		return fmt.Sprintf("????  %+v", e)
	}
}

func formatAlert(a *Alert) string {
	color := colYellow
	if a.Severity == rules.SevHigh || a.Severity == rules.SevCritical {
		color = colRed
	}
	return fmt.Sprintf("%s>> ALERT [%s] %s%s %s | pid=%d comm=%s parent=%s user=%s file=%s %v",
		color, a.Severity, a.Rule, colReset, a.Mitre,
		a.Event.Pid, a.Event.Comm, a.Event.ParentComm, a.Event.Username,
		a.Event.Filename, a.Event.Args)
}
