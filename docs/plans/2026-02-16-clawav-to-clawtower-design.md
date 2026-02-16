# ClawAV → ClawTower Rename Design

**Date:** 2026-02-16
**Status:** Approved
**Problem:** "ClawAV" implies antivirus (signature scanning, malware database) which is misleading. The product is a behavioral security monitor / agent watchdog. "ClawTower" is accurate and honest.

## Rename Scope

### String Replacements (~1,290 occurrences across 78 files)

| Old | New | Context |
|-----|-----|---------|
| `ClawAV` | `ClawTower` | Product name in docs, comments |
| `clawav` | `clawtower` | Binary name, crate name, paths, config |
| `CLAWAV` | `CLAWTOWER` | Env vars, log prefixes, auditd tags |

### NOT Renamed
- `clawsudo` — separate binary, stays as-is
- `secureclaw` — vendor dependency
- `openclaw` — separate product

### File Renames
- `src/bin/clawav-ctl.rs` → `src/bin/clawtower-ctl.rs`
- `src/bin/clawav-tray.rs` → `src/bin/clawtower-tray.rs`
- `openclawav.service` → `clawtower.service`
- `apparmor/etc.clawav.protect` → `apparmor/etc.clawtower.protect`
- `assets/clawav-tray.desktop` → `assets/clawtower-tray.desktop`
- `assets/com.clawav.policy` → `assets/com.clawtower.policy`

### System Paths
- `/etc/clawav/` → `/etc/clawtower/`
- `/var/log/clawav/` → `/var/log/clawtower/`
- `/var/run/clawav/` → `/var/run/clawtower/`
- `clawav.service` → `clawtower.service`

### GitHub
- `coltz108/ClawAV` → `coltz108/ClawTower`

## Execution Order

1. Rename GitHub repo (manual, in GitHub settings)
2. Update git remote locally
3. Bulk find/replace all strings
4. File renames (6 files)
5. Update Cargo.toml (crate name, binary names)
6. Build + test
7. Single commit: `chore: rename ClawAV → ClawTower`
8. Tag v0.3.0
9. Uninstall old ClawAV on Pi (step-by-step checklist)
10. Fresh install as ClawTower

## Versioning
- v0.3.0 — this rename
- v0.4.0 — first public release
