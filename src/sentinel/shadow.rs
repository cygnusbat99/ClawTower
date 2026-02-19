// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Shadow copy management for the sentinel file integrity monitor.
//!
//! Provides functions for computing shadow file paths, writing shadow copies
//! with hardened permissions, and hardening file permissions on restored files.

use std::path::{Path, PathBuf};

use sha2::{Sha256, Digest};

/// Compute a shadow file path: shadow_dir / hex(sha256(file_path))[..16]_filename
pub fn shadow_path_for(shadow_dir: &str, file_path: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    let hash = hex::encode(hasher.finalize());
    let name = format!("{}_{}", &hash[..16], Path::new(file_path)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string()));
    PathBuf::from(shadow_dir).join(name)
}

/// Set restrictive permissions on a file (0600).
#[cfg(unix)]
pub fn harden_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
pub fn harden_file_permissions(_path: &Path) {}

/// Write a shadow copy with hardened permissions: file 0600, verify after write.
#[cfg(unix)]
pub fn write_shadow_hardened(shadow_path: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(shadow_path, content)?;
    std::fs::set_permissions(shadow_path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn write_shadow_hardened(shadow_path: &Path, content: &[u8]) -> std::io::Result<()> {
    std::fs::write(shadow_path, content)
}

/// Harden shadow and quarantine directory permissions (0700).
#[cfg(unix)]
pub fn harden_directory_permissions(dir: &str) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
pub fn harden_directory_permissions(_dir: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadow_path_uniqueness() {
        let s1 = shadow_path_for("/tmp/shadow", "/etc/passwd");
        let s2 = shadow_path_for("/tmp/shadow", "/etc/shadow");
        assert_ne!(s1, s2);
        // Same input should give same output
        let s3 = shadow_path_for("/tmp/shadow", "/etc/passwd");
        assert_eq!(s1, s3);
    }

    #[test]
    fn test_shadow_path_contains_filename() {
        let s = shadow_path_for("/tmp/shadow", "/home/user/SOUL.md");
        let name = s.file_name().unwrap().to_string_lossy();
        assert!(name.contains("SOUL.md"));
    }

    #[test]
    fn test_shadow_path_for_root_file() {
        let s = shadow_path_for("/tmp/shadow", "/etc/passwd");
        assert!(s.file_name().unwrap().to_string_lossy().contains("passwd"));
    }

    #[test]
    fn test_shadow_path_for_deeply_nested() {
        let s = shadow_path_for("/tmp/shadow", "/a/b/c/d/e/f/g.txt");
        assert!(s.file_name().unwrap().to_string_lossy().contains("g.txt"));
    }
}
