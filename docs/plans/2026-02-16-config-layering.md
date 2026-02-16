# Config Layering Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement drop-in config overrides (`config.d/*.toml`) and policy layering so upstream updates never clobber user customizations.

**Architecture:** Config loader merges base `config.toml` with alphabetically-ordered `config.d/*.toml` files (scalar replace, list `_add`/`_remove`). Policy loader merges `default.yaml` with user `*.yaml` files by rule name. Install script removes `chattr +i` on config.toml, creates `config.d/` directory.

**Tech Stack:** Rust, TOML (`toml` crate), serde, YAML (`serde_yaml` crate)

**Design doc:** `docs/plans/2026-02-16-config-layering-design.md`

---

### Task 1: Config overlay merge logic

**Files:**
- Create: `src/config_merge.rs`
- Modify: `src/main.rs` (add `mod config_merge;`)
- Test: inline `#[cfg(test)]` in `src/config_merge.rs`

This task builds a generic TOML merge function that takes a base `toml::Value::Table` and an overlay `toml::Value::Table` and produces a merged result. The merge rules:

- Scalars: overlay value replaces base value
- Tables: recursive merge (field by field)
- Lists: if overlay has `field_add`, append to base's `field`; if `field_remove`, remove from base's `field`; if just `field`, replace entirely
- After merge, strip `_add`/`_remove` keys so downstream deserialization sees clean fields

**Step 1: Write the failing tests**

```rust
// src/config_merge.rs

use toml::Value;

/// Merge an overlay TOML table onto a base TOML table.
///
/// - Scalars: overlay wins
/// - Tables: recursive field-by-field merge
/// - Arrays: `key_add` appends, `key_remove` removes, plain `key` replaces
/// - After merge, `_add`/`_remove` suffixed keys are stripped
pub fn merge_toml(base: &mut Value, overlay: Value) {
    todo!()
}

/// Strip all `_add` and `_remove` suffixed keys from a table (recursive).
fn strip_suffixes(table: &mut toml::map::Map<String, Value>) {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Value {
        s.parse::<Value>().unwrap()
    }

    #[test]
    fn test_scalar_override() {
        let mut base = parse(r#"
            [falco]
            enabled = true
            log_path = "/var/log/falco.log"
        "#);
        let overlay = parse(r#"
            [falco]
            enabled = false
        "#);
        merge_toml(&mut base, overlay);
        assert_eq!(base["falco"]["enabled"].as_bool(), Some(false));
        // Unset fields preserved
        assert_eq!(base["falco"]["log_path"].as_str(), Some("/var/log/falco.log"));
    }

    #[test]
    fn test_list_replace() {
        let mut base = parse(r#"
            [netpolicy]
            allowed_hosts = ["a.com", "b.com"]
        "#);
        let overlay = parse(r#"
            [netpolicy]
            allowed_hosts = ["c.com"]
        "#);
        merge_toml(&mut base, overlay);
        let hosts = base["netpolicy"]["allowed_hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].as_str(), Some("c.com"));
    }

    #[test]
    fn test_list_add() {
        let mut base = parse(r#"
            [netpolicy]
            allowed_hosts = ["a.com", "b.com"]
        "#);
        let overlay = parse(r#"
            [netpolicy]
            allowed_hosts_add = ["c.com"]
        "#);
        merge_toml(&mut base, overlay);
        let hosts = base["netpolicy"]["allowed_hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 3);
        assert!(hosts.iter().any(|v| v.as_str() == Some("c.com")));
        // _add key should be stripped
        assert!(base["netpolicy"].get("allowed_hosts_add").is_none());
    }

    #[test]
    fn test_list_remove() {
        let mut base = parse(r#"
            [netpolicy]
            allowed_hosts = ["a.com", "b.com", "c.com"]
        "#);
        let overlay = parse(r#"
            [netpolicy]
            allowed_hosts_remove = ["b.com"]
        "#);
        merge_toml(&mut base, overlay);
        let hosts = base["netpolicy"]["allowed_hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 2);
        assert!(!hosts.iter().any(|v| v.as_str() == Some("b.com")));
        // _remove key should be stripped
        assert!(base["netpolicy"].get("allowed_hosts_remove").is_none());
    }

    #[test]
    fn test_list_add_and_remove_combined() {
        let mut base = parse(r#"
            [netpolicy]
            allowed_hosts = ["a.com", "b.com"]
        "#);
        let overlay = parse(r#"
            [netpolicy]
            allowed_hosts_add = ["c.com"]
            allowed_hosts_remove = ["a.com"]
        "#);
        merge_toml(&mut base, overlay);
        let hosts = base["netpolicy"]["allowed_hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 2);
        assert!(hosts.iter().any(|v| v.as_str() == Some("b.com")));
        assert!(hosts.iter().any(|v| v.as_str() == Some("c.com")));
        assert!(!hosts.iter().any(|v| v.as_str() == Some("a.com")));
    }

    #[test]
    fn test_nested_table_merge() {
        let mut base = parse(r#"
            [slack]
            enabled = true
            channel = "#devops"
            min_slack_level = "critical"
        "#);
        let overlay = parse(r#"
            [slack]
            min_slack_level = "warning"
        "#);
        merge_toml(&mut base, overlay);
        assert_eq!(base["slack"]["enabled"].as_bool(), Some(true));
        assert_eq!(base["slack"]["min_slack_level"].as_str(), Some("warning"));
        assert_eq!(base["slack"]["channel"].as_str(), Some("#devops"));
    }

    #[test]
    fn test_add_to_nonexistent_base_list() {
        let mut base = parse(r#"
            [netpolicy]
            mode = "blocklist"
        "#);
        let overlay = parse(r#"
            [netpolicy]
            allowed_hosts_add = ["x.com"]
        "#);
        merge_toml(&mut base, overlay);
        let hosts = base["netpolicy"]["allowed_hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].as_str(), Some("x.com"));
    }

    #[test]
    fn test_empty_overlay_is_noop() {
        let mut base = parse(r#"
            [general]
            watched_user = "1000"
        "#);
        let overlay = parse("");
        merge_toml(&mut base, overlay);
        assert_eq!(base["general"]["watched_user"].as_str(), Some("1000"));
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/openclaw/.openclaw/workspace/projects/ClawAV && cargo test config_merge --lib -- --nocapture 2>&1 | tail -20`
Expected: FAIL with "not yet implemented"

**Step 3: Implement merge_toml and strip_suffixes**

```rust
pub fn merge_toml(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Table(base_table), Value::Table(overlay_table)) => {
            // First pass: handle _add and _remove
            let mut add_remove_keys: Vec<String> = Vec::new();
            for (key, val) in &overlay_table {
                if let Some(base_key) = key.strip_suffix("_add") {
                    if let Value::Array(add_items) = val {
                        let entry = base_table.entry(base_key.to_string())
                            .or_insert_with(|| Value::Array(Vec::new()));
                        if let Value::Array(base_arr) = entry {
                            base_arr.extend(add_items.clone());
                        }
                    }
                    add_remove_keys.push(key.clone());
                } else if let Some(base_key) = key.strip_suffix("_remove") {
                    if let Value::Array(remove_items) = val {
                        if let Some(Value::Array(base_arr)) = base_table.get_mut(base_key) {
                            base_arr.retain(|item| !remove_items.contains(item));
                        }
                    }
                    add_remove_keys.push(key.clone());
                }
            }

            // Second pass: merge remaining keys (scalars, tables, full list replace)
            for (key, val) in overlay_table {
                if add_remove_keys.contains(&key) {
                    continue;
                }
                match base_table.get_mut(&key) {
                    Some(base_val @ Value::Table(_)) if val.is_table() => {
                        merge_toml(base_val, val);
                    }
                    _ => {
                        base_table.insert(key, val);
                    }
                }
            }

            // Strip any leftover _add/_remove keys
            strip_suffixes(base_table);
        }
        (base, overlay) => {
            *base = overlay;
        }
    }
}

fn strip_suffixes(table: &mut toml::map::Map<String, Value>) {
    table.retain(|key, _| !key.ends_with("_add") && !key.ends_with("_remove"));
    for val in table.values_mut() {
        if let Value::Table(inner) = val {
            strip_suffixes(inner);
        }
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/openclaw/.openclaw/workspace/projects/ClawAV && cargo test config_merge --lib -- --nocapture 2>&1 | tail -20`
Expected: all 8 tests PASS

**Step 5: Commit**

```bash
cd /home/openclaw/.openclaw/workspace/projects/ClawAV
git add src/config_merge.rs src/main.rs
git commit -m "feat: TOML config merge with _add/_remove list semantics"
```

---

### Task 2: Config loader with config.d/ overlay support

**Files:**
- Modify: `src/config.rs` — add `Config::load_with_overrides()` method
- Modify: `src/main.rs` — call new method instead of `Config::load()`
- Test: inline `#[cfg(test)]` in `src/config.rs`

**Step 1: Write the failing test**

Add to `src/config.rs` tests module:

```rust
#[test]
fn test_load_with_overrides_dir() {
    // Create temp dir structure: config.toml + config.d/override.toml
    let dir = tempfile::tempdir().unwrap();
    let base_path = dir.path().join("config.toml");
    let config_d = dir.path().join("config.d");
    std::fs::create_dir(&config_d).unwrap();

    // Minimal valid base config
    std::fs::write(&base_path, r#"
        [general]
        watched_user = "1000"
        min_alert_level = "info"
        log_file = "/var/log/clawav/watchdog.log"

        [slack]
        webhook_url = "https://hooks.slack.com/test"
        channel = "#devops"
        min_slack_level = "critical"

        [auditd]
        log_path = "/var/log/audit/audit.log"
        enabled = true

        [network]
        log_path = "/var/log/syslog"
        log_prefix = "CLAWAV_NET"
        enabled = true

        [scans]
        interval = 3600

        [falco]
        enabled = true
    "#).unwrap();

    // Override: disable falco
    std::fs::write(config_d.join("00-my-overrides.toml"), r#"
        [falco]
        enabled = false
    "#).unwrap();

    let config = Config::load_with_overrides(&base_path, &config_d).unwrap();
    assert!(!config.falco.enabled, "Falco should be disabled by override");
    // Base values should survive
    assert_eq!(config.general.min_alert_level, "info");
}

#[test]
fn test_load_with_overrides_list_add() {
    let dir = tempfile::tempdir().unwrap();
    let base_path = dir.path().join("config.toml");
    let config_d = dir.path().join("config.d");
    std::fs::create_dir(&config_d).unwrap();

    std::fs::write(&base_path, r#"
        [general]
        watched_user = "1000"
        min_alert_level = "info"
        log_file = "/var/log/clawav/watchdog.log"

        [slack]
        webhook_url = "https://hooks.slack.com/test"
        channel = "#devops"
        min_slack_level = "critical"

        [auditd]
        log_path = "/var/log/audit/audit.log"
        enabled = true

        [network]
        log_path = "/var/log/syslog"
        log_prefix = "CLAWAV_NET"
        enabled = true

        [netpolicy]
        allowed_hosts = ["a.com"]

        [scans]
        interval = 3600
    "#).unwrap();

    std::fs::write(config_d.join("01-hosts.toml"), r#"
        [netpolicy]
        allowed_hosts_add = ["b.com"]
    "#).unwrap();

    let config = Config::load_with_overrides(&base_path, &config_d).unwrap();
    assert!(config.netpolicy.allowed_hosts.contains(&"a.com".to_string()));
    assert!(config.netpolicy.allowed_hosts.contains(&"b.com".to_string()));
}

#[test]
fn test_load_with_overrides_empty_dir() {
    let dir = tempfile::tempdir().unwrap();
    let base_path = dir.path().join("config.toml");
    let config_d = dir.path().join("config.d");
    std::fs::create_dir(&config_d).unwrap();

    std::fs::write(&base_path, r#"
        [general]
        watched_user = "1000"
        min_alert_level = "info"
        log_file = "/var/log/clawav/watchdog.log"

        [slack]
        webhook_url = "https://hooks.slack.com/test"
        channel = "#devops"
        min_slack_level = "critical"

        [auditd]
        log_path = "/var/log/audit/audit.log"
        enabled = true

        [network]
        log_path = "/var/log/syslog"
        log_prefix = "CLAWAV_NET"
        enabled = true

        [scans]
        interval = 3600
    "#).unwrap();

    let config = Config::load_with_overrides(&base_path, &config_d).unwrap();
    assert_eq!(config.general.watched_user, Some("1000".to_string()));
}

#[test]
fn test_load_with_overrides_no_dir() {
    let dir = tempfile::tempdir().unwrap();
    let base_path = dir.path().join("config.toml");

    std::fs::write(&base_path, r#"
        [general]
        watched_user = "1000"
        min_alert_level = "info"
        log_file = "/var/log/clawav/watchdog.log"

        [slack]
        webhook_url = "https://hooks.slack.com/test"
        channel = "#devops"
        min_slack_level = "critical"

        [auditd]
        log_path = "/var/log/audit/audit.log"
        enabled = true

        [network]
        log_path = "/var/log/syslog"
        log_prefix = "CLAWAV_NET"
        enabled = true

        [scans]
        interval = 3600
    "#).unwrap();

    // config.d doesn't exist — should still load fine
    let nonexistent = dir.path().join("config.d");
    let config = Config::load_with_overrides(&base_path, &nonexistent).unwrap();
    assert_eq!(config.general.watched_user, Some("1000".to_string()));
}
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/openclaw/.openclaw/workspace/projects/ClawAV && cargo test test_load_with_overrides --lib -- --nocapture 2>&1 | tail -20`
Expected: FAIL — method doesn't exist

**Step 3: Implement Config::load_with_overrides**

Add to `Config` impl block in `src/config.rs`:

```rust
use crate::config_merge::merge_toml;

impl Config {
    // ... existing load() and save() ...

    /// Load config from base path, then merge overlays from config_d directory.
    /// Files in config_d are loaded in alphabetical order.
    pub fn load_with_overrides(base_path: &Path, config_d: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(base_path)
            .with_context(|| format!("Failed to read config: {}", base_path.display()))?;
        let mut base: toml::Value = toml::from_str(&content)
            .with_context(|| "Failed to parse base config")?;

        // Load overlay files from config.d/
        if config_d.exists() && config_d.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(config_d)
                .with_context(|| format!("Failed to read config.d: {}", config_d.display()))?
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path().extension()
                        .and_then(|ext| ext.to_str())
                        .map(|ext| ext == "toml")
                        .unwrap_or(false)
                })
                .collect();
            entries.sort_by_key(|e| e.file_name());

            for entry in entries {
                let overlay_content = std::fs::read_to_string(entry.path())
                    .with_context(|| format!("Failed to read overlay: {}", entry.path().display()))?;
                let overlay: toml::Value = toml::from_str(&overlay_content)
                    .with_context(|| format!("Failed to parse overlay: {}", entry.path().display()))?;
                merge_toml(&mut base, overlay);
            }
        }

        let config: Config = base.try_into()
            .with_context(|| "Failed to deserialize merged config")?;
        Ok(config)
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/openclaw/.openclaw/workspace/projects/ClawAV && cargo test test_load_with_overrides --lib -- --nocapture 2>&1 | tail -20`
Expected: all 4 tests PASS

**Step 5: Update main.rs to use load_with_overrides**

In `src/main.rs`, change line ~375 from:

```rust
let config = Config::load(&config_path)?;
```

to:

```rust
let config_d = config_path.parent()
    .unwrap_or(Path::new("/etc/clawav"))
    .join("config.d");
let config = Config::load_with_overrides(&config_path, &config_d)?;
eprintln!("Config loaded (with overlays from {})", config_d.display());
```

**Step 6: Run full test suite**

Run: `cd /home/openclaw/.openclaw/workspace/projects/ClawAV && cargo test 2>&1 | tail -5`
Expected: all tests pass

**Step 7: Commit**

```bash
cd /home/openclaw/.openclaw/workspace/projects/ClawAV
git add src/config.rs src/main.rs
git commit -m "feat: Config::load_with_overrides — config.d/ drop-in overlay support"
```

---

### Task 3: Policy layering with name-based merge and enabled flag

**Files:**
- Modify: `src/policy.rs` — add `enabled` field, name-based merge logic
- Test: inline `#[cfg(test)]` in `src/policy.rs`

**Step 1: Write the failing tests**

Add to `src/policy.rs` tests module:

```rust
#[test]
fn test_enabled_false_disables_rule() {
    let yaml = r#"
rules:
  - name: "test-rule"
    description: "test"
    match:
      command: ["curl"]
    action: critical
    enabled: false
"#;
    let engine = load_from_str(yaml);
    let event = make_exec_event(&["curl", "http://evil.com"]);
    assert!(engine.evaluate(&event).is_none(), "Disabled rule should not match");
}

#[test]
fn test_name_based_override() {
    let yaml_base = r#"
rules:
  - name: "exfil"
    description: "base"
    match:
      command: ["curl"]
      exclude_args: ["a.com"]
    action: critical
"#;
    let yaml_override = r#"
rules:
  - name: "exfil"
    description: "user override"
    match:
      command: ["curl"]
      exclude_args: ["a.com", "b.com"]
    action: warning
"#;
    let base_pf: PolicyFile = serde_yaml::from_str(yaml_base).unwrap();
    let override_pf: PolicyFile = serde_yaml::from_str(yaml_override).unwrap();
    let merged = PolicyEngine::merge_rules(base_pf.rules, override_pf.rules);
    let engine = PolicyEngine { rules: merged };

    assert_eq!(engine.rule_count(), 1);
    assert_eq!(engine.rules[0].description, "user override");
    assert_eq!(engine.rules[0].action, "warning");
}

#[test]
fn test_user_adds_new_rule() {
    let yaml_base = r#"
rules:
  - name: "exfil"
    description: "base"
    match:
      command: ["curl"]
    action: critical
"#;
    let yaml_user = r#"
rules:
  - name: "my-custom-rule"
    description: "custom"
    match:
      command: ["python3"]
    action: warning
"#;
    let base_pf: PolicyFile = serde_yaml::from_str(yaml_base).unwrap();
    let user_pf: PolicyFile = serde_yaml::from_str(yaml_user).unwrap();
    let merged = PolicyEngine::merge_rules(base_pf.rules, user_pf.rules);
    let engine = PolicyEngine { rules: merged };

    assert_eq!(engine.rule_count(), 2);
}

#[test]
fn test_load_merges_multiple_files_by_name() {
    let dir = tempfile::tempdir().unwrap();

    // default.yaml — loaded first
    std::fs::write(dir.path().join("default.yaml"), r#"
rules:
  - name: "exfil"
    description: "base exfil"
    match:
      command: ["curl"]
    action: critical
  - name: "recon"
    description: "base recon"
    match:
      command: ["whoami"]
    action: warning
"#).unwrap();

    // custom.yaml — overrides exfil, disables recon
    std::fs::write(dir.path().join("custom.yaml"), r#"
rules:
  - name: "exfil"
    description: "user exfil"
    match:
      command: ["curl"]
      exclude_args: ["mysite.com"]
    action: critical
  - name: "recon"
    enabled: false
"#).unwrap();

    let engine = PolicyEngine::load(dir.path()).unwrap();
    // exfil overridden, recon disabled
    let event_curl = make_exec_event(&["curl", "http://evil.com"]);
    let verdict = engine.evaluate(&event_curl).unwrap();
    assert_eq!(verdict.description, "user exfil");

    let event_whoami = make_exec_event(&["whoami"]);
    assert!(engine.evaluate(&event_whoami).is_none(), "Recon should be disabled");
}
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/openclaw/.openclaw/workspace/projects/ClawAV && cargo test test_enabled_false --lib -- --nocapture 2>&1 | tail -10`
Expected: FAIL — `enabled` field doesn't exist on PolicyRule

**Step 3: Implement changes**

3a. Add `enabled` field to `PolicyRule`:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "match")]
    pub match_spec: MatchSpec,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default)]
    pub enforcement: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool { true }
fn default_action() -> String { "critical".to_string() }
```

Note: `action` gets a default so that disable-only overrides (which have no `match`/`action`) can parse. `MatchSpec` already derives `Default`.

3b. Filter disabled rules in `evaluate()` — add at top of the loop:

```rust
if !rule.enabled {
    continue;
}
```

3c. Add `merge_rules` method to `PolicyEngine`:

```rust
/// Merge override rules onto base rules by name.
/// If an override has the same name as a base rule, it replaces it.
/// New names are appended.
pub fn merge_rules(base: Vec<PolicyRule>, overrides: Vec<PolicyRule>) -> Vec<PolicyRule> {
    let mut merged = base;
    for override_rule in overrides {
        if let Some(pos) = merged.iter().position(|r| r.name == override_rule.name) {
            merged[pos] = override_rule;
        } else {
            merged.push(override_rule);
        }
    }
    // Filter out disabled rules
    merged.retain(|r| r.enabled);
    merged
}
```

3d. Update `PolicyEngine::load()` to sort files (default.yaml first) and merge by name:

```rust
pub fn load(dir: &Path) -> Result<Self> {
    if !dir.exists() {
        return Ok(Self { rules: Vec::new() });
    }

    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read policy dir: {}", dir.display()))?;

    let mut files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            let path = e.path();
            match path.extension().and_then(|ext| ext.to_str()) {
                Some("yaml") | Some("yml") => {
                    // Skip clawsudo policies
                    !path.file_name()
                        .and_then(|f| f.to_str())
                        .map(|f| f.starts_with("clawsudo"))
                        .unwrap_or(false)
                }
                _ => false,
            }
        })
        .collect();

    // Sort: default.yaml first, then alphabetical
    files.sort_by(|a, b| {
        let a_name = a.file_name();
        let b_name = b.file_name();
        let a_is_default = a_name.to_str().map(|s| s.starts_with("default")).unwrap_or(false);
        let b_is_default = b_name.to_str().map(|s| s.starts_with("default")).unwrap_or(false);
        match (a_is_default, b_is_default) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a_name.cmp(&b_name),
        }
    });

    let mut all_rules: Vec<PolicyRule> = Vec::new();
    for entry in files {
        let path = entry.path();
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let pf: PolicyFile = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;
        all_rules = Self::merge_rules(all_rules, pf.rules);
    }

    Ok(Self { rules: all_rules })
}
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/openclaw/.openclaw/workspace/projects/ClawAV && cargo test policy --lib -- --nocapture 2>&1 | tail -20`
Expected: all policy tests pass (old + new)

**Step 5: Run full test suite**

Run: `cd /home/openclaw/.openclaw/workspace/projects/ClawAV && cargo test 2>&1 | tail -5`
Expected: all tests pass

**Step 6: Commit**

```bash
cd /home/openclaw/.openclaw/workspace/projects/ClawAV
git add src/policy.rs
git commit -m "feat: policy layering — name-based merge, enabled flag, default.yaml-first ordering"
```

---

### Task 4: Install script updates

**Files:**
- Modify: `scripts/install.sh` — remove `chattr +i` on config.toml, create config.d/
- Test: manual verification

**Step 1: Edit install.sh**

In section 4 ("Set immutable attributes"), change the `for` loop to exclude `config.toml`:

```bash
# Before:
for f in /usr/local/bin/clawav /etc/clawav/config.toml /etc/systemd/system/clawav.service; do

# After:
for f in /usr/local/bin/clawav /etc/systemd/system/clawav.service; do
```

Add config.d directory creation after the config copy section (around section 2 or 3, wherever config files are set up):

```bash
# Create config.d directory for user overrides
mkdir -p /etc/clawav/config.d
chown root:root /etc/clawav/config.d
chmod 755 /etc/clawav/config.d
log "Created /etc/clawav/config.d/ for user overrides"
```

**Step 2: Verify syntax**

Run: `bash -n /home/openclaw/.openclaw/workspace/projects/ClawAV/scripts/install.sh`
Expected: no errors

**Step 3: Update uninstall.sh — remove chattr -i for config.toml**

In `scripts/uninstall.sh` line 144, remove:
```bash
sudo chattr -i /etc/clawav/config.toml 2>/dev/null || true
```

**Step 4: Commit**

```bash
cd /home/openclaw/.openclaw/workspace/projects/ClawAV
git add scripts/install.sh scripts/uninstall.sh
git commit -m "chore: install script — drop config.toml immutable flag, create config.d/"
```

---

### Task 5: Documentation updates

**Files:**
- Create: `docs/CONFIGURATION.md` — full guide to config layering
- Modify: `docs/TUNING.md` — add reference to config.d/ approach
- Modify: `docs/DAY1-OPERATIONS.md` — remove chattr instructions
- Modify: `docs/INDEX.md` — add CONFIGURATION.md link

**Step 1: Write CONFIGURATION.md**

```markdown
# ClawAV Configuration Guide

## Overview

ClawAV uses a layered configuration system. Upstream defaults ship in base files;
your customizations live in separate override files that are never touched by updates.

## Config Files

| File | Owner | Purpose |
|------|-------|---------|
| `/etc/clawav/config.toml` | Upstream | Base config — replaced on updates |
| `/etc/clawav/config.d/*.toml` | You | Your overrides — never touched by updates |
| `/etc/clawav/policies/default.yaml` | Upstream | Base detection rules |
| `/etc/clawav/policies/*.yaml` | You | Your custom/override rules |

## Config Overrides (config.d/)

Create `.toml` files in `/etc/clawav/config.d/`. They're loaded alphabetically
after `config.toml` and merged:

- **Scalars** — your value replaces the default
- **Lists** — use `_add` to append, `_remove` to remove, or set the field directly to replace

### Examples

Disable Falco and add a host to the network allowlist:

```toml
# /etc/clawav/config.d/my-overrides.toml
[falco]
enabled = false

[netpolicy]
allowed_hosts_add = ["myapi.example.com"]
```

Remove a default allowlisted CIDR:

```toml
# /etc/clawav/config.d/strict-network.toml
[network]
allowlisted_cidrs_remove = ["169.254.0.0/16"]
```

### Naming Convention

Prefix with numbers to control load order: `00-first.toml`, `50-middle.toml`, `99-last.toml`.

## Policy Overrides

Create `.yaml` files in `/etc/clawav/policies/`. Rules are merged by `name`:

- Same name as a default rule → **your version replaces it entirely**
- New name → added to the rule set
- `enabled: false` → disables a rule

### Example

```yaml
# /etc/clawav/policies/custom.yaml
rules:
  # Override the exfil rule to add your API
  - name: "block-data-exfiltration"
    description: "Customized exfil detection"
    match:
      command: ["curl", "wget", "nc", "ncat", "netcat", "socat"]
      exclude_args:
        - "gottamolt.gg"
        - "mycompany-api.com"
    action: critical

  # Disable a noisy rule
  - name: "detect-scheduled-tasks"
    enabled: false
```

### Important

When you override a rule by name, you own that rule. Future upstream improvements
to that rule won't auto-merge — this is by design. If you customize it, you maintain it.

## Updates

When ClawAV updates:

1. `config.toml` and `default.yaml` are replaced with new versions
2. Your files in `config.d/` and custom policy yamls are untouched
3. Service restarts with merged config

You don't need to do anything.
```

**Step 2: Update TUNING.md**

Add a note near the top:

```markdown
> **Tip:** Use `/etc/clawav/config.d/` for all customizations instead of editing
> `config.toml` directly. See [CONFIGURATION.md](CONFIGURATION.md) for details.
> Your overrides survive updates automatically.
```

**Step 3: Update DAY1-OPERATIONS.md**

Remove any references to `chattr -i`/`chattr +i` for config.toml editing. Replace with:

```markdown
Create `/etc/clawav/config.d/my-overrides.toml` with your changes.
See [CONFIGURATION.md](CONFIGURATION.md) for the full guide.
```

**Step 4: Update INDEX.md**

Add entry:
```markdown
- **[CONFIGURATION.md](CONFIGURATION.md)** — Config layering, overrides, policy customization
```

**Step 5: Commit**

```bash
cd /home/openclaw/.openclaw/workspace/projects/ClawAV
git add docs/CONFIGURATION.md docs/TUNING.md docs/DAY1-OPERATIONS.md docs/INDEX.md
git commit -m "docs: configuration layering guide, updated tuning and day1 docs"
```

---

### Task 6: Build and push

**Files:** none (verification only)

**Step 1: Run full test suite**

Run: `cd /home/openclaw/.openclaw/workspace/projects/ClawAV && cargo test 2>&1 | tail -10`
Expected: all tests pass

**Step 2: Build release**

Run: `cd /home/openclaw/.openclaw/workspace/projects/ClawAV && cargo build --release 2>&1 | tail -5`
Expected: build succeeds

**Step 3: Push**

```bash
cd /home/openclaw/.openclaw/workspace/projects/ClawAV
git push origin main
```
