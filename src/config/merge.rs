// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

// src/config_merge.rs

use toml::Value;

/// Merge an overlay TOML table onto a base TOML table.
///
/// - Scalars: overlay wins
/// - Tables: recursive field-by-field merge
/// - Arrays: `key_add` appends, `key_remove` removes, plain `key` replaces
/// - After merge, `_add`/`_remove` suffixed keys are stripped
pub fn merge_toml(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Table(base_table), Value::Table(overlay_table)) => {
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

            strip_suffixes(base_table);
        }
        (base, overlay) => {
            *base = overlay;
        }
    }
}

fn strip_suffixes(table: &mut toml::map::Map<String, Value>) {
    table.retain(|key, _| !key.ends_with("_add") && !key.ends_with("_remove"));
    let keys: Vec<String> = table.keys().cloned().collect();
    for key in keys {
        if let Some(Value::Table(ref mut inner)) = table.get_mut(&key) {
            strip_suffixes(inner);
        }
    }
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
        let mut base = parse(r##"
            [slack]
            enabled = true
            channel = "#devops"
            min_slack_level = "critical"
        "##);
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
