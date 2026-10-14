# kguard

**An eBPF-based Linux endpoint monitor.** kguard watches process launches,
exits, and TCP connections at the kernel level, enriches each event with
process lineage and identity, runs it through a YAML detection ruleset, and
reports events and alerts to the console, a JSON log, or a webhook.

It's a lightweight, open version of the behavioral detection engine inside
commercial EDR products — built on the same technology (eBPF + CO-RE) that
Cilium, Falco, and Tetragon use in production.

> **Scope / ethics:** kguard is a *defensive* tool. Run it only on systems you
> own or are authorized to monitor. It observes activity; it does not attack
> anything. Loading eBPF programs requires root (or `CAP_BPF` + `CAP_PERFMON`).

---

## How it works

```
            LINUX KERNEL                                 USER SPACE (Go)
 ┌───────────────────────────────┐        ┌────────────────────────────────────────┐
 │ eBPF programs (C)             │        │ kguard                                 │
 │                               │        │                                        │
 │ sched_process_exec ─┐         │  ring  │ loader   load + attach eBPF, read ring │
 │ sched_process_exit ─┤         │ buffer │ events   decode raw records            │
 │ tcp_connect        ─┼─ filter ─────────►│ proctree keep live process lineage     │
 │ inet_csk_accept    ─┘ in-kernel        │ enrich   user, container, exe SHA-256  │
 │                               │        │ rules    match YAML detections         │
 │  (ring buffer map)            │        │ output   console / JSONL / webhook     │
 └───────────────────────────────┘        └────────────────────────────────────────┘
```

Events are filtered in the kernel so a busy host doesn't flood user space.
Only the records that matter cross the boundary, through a 256 KiB ring buffer.

## Features

- **Process telemetry** — every `execve` and process exit, with PID, PPID,
  UID, command, path, and arguments.
- **Network telemetry** — outbound (`tcp_connect`) and inbound
  (`inet_csk_accept`) IPv4 connections with addresses and ports.
- **Enrichment** — username resolution, container ID (Docker/containerd/K8s),
  SHA-256 of the executing binary, and full parent/ancestor lineage.
- **Detection engine** — data-driven YAML rules mapped to
  [MITRE ATT&CK](https://attack.mitre.org/) techniques. Add rules without
  recompiling.
- **Outputs** — colorized console, newline-delimited JSON (`JSONL`) for
  ingestion into a SIEM, and a Slack-compatible webhook.
- **Portable** — CO-RE (Compile Once, Run Everywhere) via BTF: build on one
  kernel, run on others without recompiling.

## Requirements

- Linux kernel **5.8+** with BTF (`/sys/kernel/btf/vmlinux` present). Modern
  distributions (Fedora, Ubuntu 20.10+, Debian 11+, RHEL 9) qualify.
- Build toolchain: `clang`, `llvm`, `bpftool`, `libbpf-devel`, Go **1.23+**.
- Root (or `CAP_BPF` + `CAP_PERFMON`) to run.

### Install the toolchain

**Fedora / RHEL:**
```bash
sudo dnf install -y clang llvm bpftool libbpf-devel golang
```

**Debian / Ubuntu:**
```bash
sudo apt-get install -y clang llvm libbpf-dev linux-tools-common golang
```

## Build

```bash
make build
```

This generates `bpf/vmlinux.h` from your kernel's BTF, compiles the eBPF C with
clang, generates the Go bindings with `bpf2go`, and builds `bin/kguard`.

## Usage

Start monitoring (needs root):
```bash
sudo ./bin/kguard run
```

Only show alerts, and log everything as JSON for a SIEM:
```bash
sudo ./bin/kguard run --alerts-only --log /var/log/kguard.jsonl
```

Send alerts to a Slack / webhook endpoint:
```bash
sudo ./bin/kguard run --webhook https://hooks.slack.com/services/XXX/YYY/ZZZ
```

Validate your rules without starting the monitor (no root needed):
```bash
./bin/kguard rules test -rules rules/default.yaml
```

### Run flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--rules` | `rules/default.yaml` | Path to the detection ruleset |
| `--log` | *(none)* | Write JSONL events/alerts to this file |
| `--webhook` | *(none)* | POST alerts to this URL (Slack-compatible) |
| `--alerts-only` | `false` | Print only alerts to the console |
| `--no-hash` | `false` | Skip SHA-256 of executables (lower overhead) |

## Try the detections

In one terminal:
```bash
sudo ./bin/kguard run
```
In another:
```bash
./test/simulate.sh
```
`simulate.sh` runs only harmless stand-ins (copying `/bin/true` into `/tmp`,
opening a localhost socket, etc.) and you should see `ALERT` lines appear in
the monitor.

## Detection rules

Rules live in [`rules/default.yaml`](rules/default.yaml). Each rule matches a
single event; within a field a list is OR, and across fields it's AND.

```yaml
- id: webserver-spawns-shell
  description: A web server process launched an interactive shell.
  severity: high
  mitre: T1505.003
  match:
    event: exec
    parent_comm: [nginx, apache2, httpd, php-fpm]
    comm: [sh, bash, dash, zsh]
```

Supported match fields: `event`, `comm`, `parent_comm`, `ancestor`, `user`,
`not_user`, `file_prefix`, `file_contains`, `args_contains`, `dst_port`,
`min_uid`, `max_uid`.

### Shipped rules

| ID | Severity | MITRE | Catches |
|----|----------|-------|---------|
| `webserver-spawns-shell` | high | T1505.003 | Web shell / RCE |
| `exec-from-tmp` | high | T1059 | Malware run from `/tmp`, `/dev/shm` |
| `shell-makes-network-connection` | high | T1059.004 | Reverse shell |
| `download-piped-to-shell` | high | T1105 | `curl … \| sh` |
| `read-etc-shadow` | critical | T1003.008 | Credential dumping |
| `modify-authorized-keys` | high | T1098.004 | SSH backdoor |
| `modify-persistence` | medium | T1053 | Cron / systemd persistence |
| `connect-to-mining-pool-port` | medium | T1496 | Crypto miner |
| `suspicious-discovery-tooling` | medium | T1046 | Recon tools |
| `exec-deleted-or-memfd` | high | T1620 | Fileless execution |

## Project layout

```
kguard/
├── bpf/
│   ├── common.h          event structs shared by C and Go
│   ├── kguard.bpf.c      kernel-side eBPF programs
│   └── vmlinux.h         generated from kernel BTF (make vmlinux)
├── cmd/kguard/main.go    CLI entry point
├── internal/
│   ├── loader/           load + attach eBPF, expose ring buffer
│   ├── events/           decode raw records into Go structs
│   ├── proctree/         live process lineage
│   ├── enrich/           user / container / hash enrichment
│   ├── rules/            YAML detection engine
│   └── output/           console / JSONL / webhook sinks
├── rules/default.yaml    shipped detections
├── test/simulate.sh      harmless triggers for every rule
├── Makefile
└── .github/workflows/ci.yml
```

## Roadmap

- [ ] File-open monitoring via the BPF LSM hook (sensitive paths only)
- [ ] **Blocking mode** — deny exec from `/tmp` live via BPF LSM
- [ ] Per-event rate limiting and in-kernel allowlists
- [ ] Prometheus metrics endpoint
- [ ] Central collector for fleets of hosts

## License

Go code: MIT. eBPF C (`bpf/`): GPL-2.0 (required for GPL-only kernel helpers).
See [LICENSE](LICENSE).
