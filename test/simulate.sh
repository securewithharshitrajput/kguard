#!/usr/bin/env bash
# simulate.sh - trigger kguard detections using only HARMLESS commands.
#
# This runs benign stand-ins for attacker behavior so you can confirm that the
# detection rules fire. It does NOT download or run any malware. Run it in a
# second terminal while `sudo kguard run` is active in the first.
set -u

say() { printf '\n=== %s ===\n' "$1"; }

say "1. exec-from-tmp: copy a harmless binary to /tmp and run it"
cp /bin/true /tmp/kguard_demo_true 2>/dev/null && /tmp/kguard_demo_true; rm -f /tmp/kguard_demo_true

say "2. webserver-spawns-shell: rename a shell to 'nginx' and have it spawn bash"
cp /bin/bash /tmp/nginx 2>/dev/null && /tmp/nginx -c "bash -c true"; rm -f /tmp/nginx

say "3. shell-makes-network-connection: bash opens a TCP connection to localhost"
timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22' 2>/dev/null || true

say "4. download-piped-to-shell: curl invoked with a pipe-to-shell style arg (no network needed)"
curl "http://127.0.0.1/nonexistent|sh" >/dev/null 2>&1 || true

say "5. suspicious-discovery-tooling: run a binary named like a recon tool"
cp /bin/true /tmp/pspy 2>/dev/null && /tmp/pspy; rm -f /tmp/pspy

say "6. connect-to-mining-pool-port: attempt a connection to a mining port"
timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/3333' 2>/dev/null || true

say "done - check the kguard terminal for ALERT lines"
