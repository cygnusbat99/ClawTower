// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Shared utility functions used across multiple modules.

/// Extract the basename from a path (everything after the last '/').
///
/// Returns the full string if no '/' is present.
///
/// # Examples
/// ```ignore
/// assert_eq!(extract_binary_name("/usr/bin/curl"), "curl");
/// assert_eq!(extract_binary_name("curl"), "curl");
/// ```
pub fn extract_binary_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Format a chrono Duration as a short human-readable age string.
///
/// Returns strings like "5s ago", "3m ago", "2h ago", "1d ago".
pub fn format_age_short(age: chrono::Duration) -> String {
    if age.num_seconds() < 60 {
        format!("{}s ago", age.num_seconds())
    } else if age.num_minutes() < 60 {
        format!("{}m ago", age.num_minutes())
    } else if age.num_hours() < 24 {
        format!("{}h ago", age.num_hours())
    } else {
        format!("{}d ago", age.num_days())
    }
}

/// Format a chrono Duration as a compact age string (no "ago" suffix).
///
/// Returns strings like "5m", "2h", "1d".
pub fn format_age_compact(age: chrono::Duration) -> String {
    if age.num_minutes() < 60 {
        format!("{}m", age.num_minutes())
    } else if age.num_hours() < 24 {
        format!("{}h", age.num_hours())
    } else {
        format!("{}d", age.num_days())
    }
}

/// Format a chrono Duration as a long human-readable age string.
///
/// Returns strings like "5 seconds ago", "3 minutes ago", "2 hours ago", "1 days ago".
pub fn format_age_long(age: chrono::Duration) -> String {
    if age.num_seconds() < 60 {
        format!("{} seconds ago", age.num_seconds())
    } else if age.num_minutes() < 60 {
        format!("{} minutes ago", age.num_minutes())
    } else if age.num_hours() < 24 {
        format!("{} hours ago", age.num_hours())
    } else {
        format!("{} days ago", age.num_days())
    }
}

/// Format a std::time::Duration as a compact uptime string.
///
/// Returns strings like "5d 2h 30m", "2h 15m", "5m".
pub fn format_uptime(uptime: std::time::Duration) -> String {
    let days = uptime.as_secs() / 86400;
    let hours = (uptime.as_secs() % 86400) / 3600;
    let minutes = (uptime.as_secs() % 3600) / 60;
    if days > 0 {
        format!("{}d {}h {}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_binary_name_absolute_path() {
        assert_eq!(extract_binary_name("/usr/bin/curl"), "curl");
    }

    #[test]
    fn test_extract_binary_name_bare() {
        assert_eq!(extract_binary_name("curl"), "curl");
    }

    #[test]
    fn test_extract_binary_name_empty() {
        assert_eq!(extract_binary_name(""), "");
    }

    #[test]
    fn test_extract_binary_name_trailing_slash() {
        assert_eq!(extract_binary_name("/usr/bin/"), "");
    }

    #[test]
    fn test_format_age_short_seconds() {
        let age = chrono::Duration::seconds(30);
        assert_eq!(format_age_short(age), "30s ago");
    }

    #[test]
    fn test_format_age_short_minutes() {
        let age = chrono::Duration::minutes(5);
        assert_eq!(format_age_short(age), "5m ago");
    }

    #[test]
    fn test_format_age_short_hours() {
        let age = chrono::Duration::hours(3);
        assert_eq!(format_age_short(age), "3h ago");
    }

    #[test]
    fn test_format_age_short_days() {
        let age = chrono::Duration::days(2);
        assert_eq!(format_age_short(age), "2d ago");
    }

    #[test]
    fn test_format_age_compact() {
        assert_eq!(format_age_compact(chrono::Duration::minutes(5)), "5m");
        assert_eq!(format_age_compact(chrono::Duration::hours(3)), "3h");
        assert_eq!(format_age_compact(chrono::Duration::days(2)), "2d");
    }

    #[test]
    fn test_format_age_long() {
        assert_eq!(format_age_long(chrono::Duration::seconds(30)), "30 seconds ago");
        assert_eq!(format_age_long(chrono::Duration::minutes(5)), "5 minutes ago");
    }

    #[test]
    fn test_format_uptime() {
        assert_eq!(format_uptime(std::time::Duration::from_secs(300)), "5m");
        assert_eq!(format_uptime(std::time::Duration::from_secs(3900)), "1h 5m");
        assert_eq!(format_uptime(std::time::Duration::from_secs(90060)), "1d 1h 1m");
    }
}
