// Command kguard is an eBPF-based Linux endpoint monitor. It watches process
// launches, exits and TCP connections at the kernel level, enriches them with
// process lineage and identity, evaluates YAML detection rules, and emits
// events and alerts to the console, a JSONL log, and/or a webhook.
//
// Usage:
//
//	sudo kguard run   [flags]    # start monitoring
//	kguard rules test [flags]    # load rules and print a summary (no root needed)
//	kguard version
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/harry/kguard/internal/enrich"
	"github.com/harry/kguard/internal/events"
	"github.com/harry/kguard/internal/loader"
	"github.com/harry/kguard/internal/output"
	"github.com/harry/kguard/internal/proctree"
	"github.com/harry/kguard/internal/rules"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		runCmd(os.Args[2:])
	case "rules":
		rulesCmd(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("kguard %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `kguard — eBPF Linux endpoint monitor

Commands:
  run           Start monitoring (requires root / CAP_BPF)
  rules test    Validate and summarize detection rules
  version       Print version

Run "kguard run -h" for run flags.
`)
}

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	rulesPath := fs.String("rules", "rules/default.yaml", "path to a rules YAML file")
	logPath := fs.String("log", "", "write JSONL events/alerts to this file (default: none)")
	webhook := fs.String("webhook", "", "POST alerts to this URL (Slack-compatible)")
	alertsOnly := fs.Bool("alerts-only", false, "only print alerts to the console, not every event")
	noHash := fs.Bool("no-hash", false, "do not SHA-256 executables (lower overhead)")
	fs.Parse(args)

	ruleSet, err := rules.Load(*rulesPath)
	if err != nil {
		fatal("loading rules: %v", err)
	}
	fmt.Printf("kguard %s — loaded %d rules from %s\n", version, ruleSet.Len(), *rulesPath)

	// Output sink.
	sink := output.NewSink()
	sink.Console = true
	sink.AlertsOnly = *alertsOnly
	sink.WebhookURL = *webhook
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			fatal("opening log file: %v", err)
		}
		defer f.Close()
		sink.JSONLog = f
	}

	// Load + attach eBPF. This is the step that requires root.
	ld, err := loader.New()
	if err != nil {
		fatal("initializing eBPF (are you root?): %v", err)
	}
	defer ld.Close()
	fmt.Println("kguard is running. Press Ctrl-C to stop.")

	tree := proctree.New()
	en := enrich.New(tree)
	en.HashExecutables = !*noHash

	// Stop cleanly on SIGINT/SIGTERM by closing the reader, which unblocks Read.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nshutting down...")
		ld.Close()
	}()

	for {
		raw, err := ld.Read()
		if err != nil {
			if loader.Closed(err) {
				return
			}
			fmt.Fprintf(os.Stderr, "read error: %v\n", err)
			continue
		}

		e, err := events.Decode(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode error: %v\n", err)
			continue
		}

		// Maintain the process tree before enrichment so lineage is current.
		if e.Kind == events.KindExec {
			tree.Add(e.Pid, e.Ppid, e.Comm)
		}

		en.Apply(e)

		if hits := ruleSet.Match(e); len(hits) > 0 {
			sink.Alert(e, hits)
		} else {
			sink.Event(e)
		}

		if e.Kind == events.KindExit {
			tree.Remove(e.Pid)
		}
	}
}

func rulesCmd(args []string) {
	if len(args) < 1 || args[0] != "test" {
		fmt.Fprintln(os.Stderr, "usage: kguard rules test [-rules path]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("rules test", flag.ExitOnError)
	rulesPath := fs.String("rules", "rules/default.yaml", "path to a rules YAML file")
	fs.Parse(args[1:])

	rs, err := rules.Load(*rulesPath)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("OK: %s parsed cleanly, %d rules loaded.\n", *rulesPath, rs.Len())
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "kguard: "+format+"\n", a...)
	os.Exit(1)
}
