#!/usr/bin/env bash
# Red Lobster v5 — Shared Helper Library
# Sourced by all flag scripts. Do not execute directly.
# Provides: rl_init_flag, rl_check, rl_run, rl_run_file, rl_summary, rl_cleanup

ALERT_LOG="/var/log/clawtower/alerts.jsonl"
RL_OUTDIR="/tmp/redlobster"

# Set by rl_init_flag
FLAG_DIR=""
FLAG_RESULTS=""
TOTAL=0
DETECTED=0
BYPASSED=0

rl_init_flag() {
    local flag_name="$1"
    local title="$2"

    FLAG_DIR="$RL_OUTDIR/$flag_name"
    FLAG_RESULTS="$RL_OUTDIR/results/${flag_name}.md"
    TOTAL=0
    DETECTED=0
    BYPASSED=0

    mkdir -p "$FLAG_DIR" "$RL_OUTDIR/results"

    if [[ ! -f "$ALERT_LOG" ]]; then
        echo "ERROR: Alert log not found: $ALERT_LOG"
        exit 1
    fi

    echo "═══════════════════════════════════════════════════"
    echo "  🦞🔴 Red Lobster — $title"
    echo "═══════════════════════════════════════════════════"
    echo ""

    {
        echo "# 🏴 Red Lobster — $title"
        echo "**Date:** $(date)"
        echo ""
        echo "| # | Attack Vector | Detected? | Alerts |"
        echo "|---|--------------|-----------|--------|"
    } > "$FLAG_RESULTS"
}

rl_check() {
    local name="$1"
    local before="$2"
    local after
    after=$(wc -l < "$ALERT_LOG")
    local new=$((after - before))
    local detected="❌ No"
    local alert_detail="none"

    if [[ $new -gt 0 ]]; then
        alert_detail=$(tail -n "$new" "$ALERT_LOG" | jq -r '.severity + " " + .source + ": " + .message' 2>/dev/null | head -3 | tr '\n' '; ')
        if tail -n "$new" "$ALERT_LOG" | jq -r '.severity' 2>/dev/null | grep -qE 'Critical|Warning'; then
            detected="✅ Yes"
            ((DETECTED++))
        else
            detected="⚠️ Info only"
            ((BYPASSED++))
        fi
    else
        ((BYPASSED++))
    fi

    ((TOTAL++))
    echo "| $TOTAL | $name | $detected | ${alert_detail:0:80} |" >> "$FLAG_RESULTS"
    echo "  [$TOTAL] $name → $detected"
}

rl_run() {
    local name="$1"
    shift
    local before
    before=$(wc -l < "$ALERT_LOG")
    eval "$@" 2>/dev/null || true
    sleep 3
    rl_check "$name" "$before"
}

rl_run_file() {
    local name="$1"
    shift
    local before
    before=$(wc -l < "$ALERT_LOG")
    eval "$@" 2>/dev/null || true
    sleep 3
    rl_check "$name" "$before"
}

rl_summary() {
    local pct=0
    if [[ $TOTAL -gt 0 ]]; then
        pct=$(( (DETECTED * 100) / TOTAL ))
    fi

    local known_count="${KNOWN:-0}"

    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "  📊 Results: $DETECTED/$TOTAL detected ($pct%)"
    echo "  ✅ Detected: $DETECTED | ❌ Bypassed: $BYPASSED | ⚠️ Known: $known_count"
    echo "═══════════════════════════════════════════════════"

    {
        echo ""
        echo "## Summary"
        echo "- **Total (scored):** $TOTAL"
        echo "- **Detected:** $DETECTED ($pct%)"
        echo "- **Bypassed:** $BYPASSED"
        echo "- **Known limitations:** $known_count (shell-level, not scored)"
    } >> "$FLAG_RESULTS"

    echo ""
    echo "📄 Full results: $FLAG_RESULTS"
}

rl_cleanup() {
    [[ -n "$FLAG_DIR" && -d "$FLAG_DIR" ]] && rm -rf "$FLAG_DIR"
}
