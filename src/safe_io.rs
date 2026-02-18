//! Symlink-safe file I/O utilities.
//!
//! Provides hardened file operations that prevent TOCTOU races, symlink attacks,
//! and permission vulnerabilities. These functions are designed to be used across
//! multiple modules that handle sensitive file operations (sentinel, cognitive,
//! audit_chain, config, update, admin).
//!
//! Key properties:
//! - **`open_nofollow`**: Opens files with `O_NOFOLLOW` to reject symlinks
//! - **`read_nofollow`**: Reads file contents without following symlinks
//! - **`atomic_write`**: Write-to-temp + fsync + rename pattern for crash safety
//! - **`mkdir_safe`**: Creates directories after verifying no symlink components
//! - **`check_permissions`**: Validates ownership and mode via `lstat`
//! - **`redact_env`**: Scrubs sensitive environment variables before logging

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::FromRawFd;
use std::path::Path;

/// Open a file without following symlinks.
///
/// Uses `libc::open` with `O_NOFOLLOW | O_RDONLY` to ensure the target path
/// is not a symbolic link. Returns `io::Error` with `ELOOP` if the path is
/// a symlink.
pub fn open_nofollow(path: &Path) -> io::Result<File> {
    let c_path = path_to_cstring(path)?;

    let fd = unsafe {
        libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW)
    };

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Read file contents without following symlinks.
///
/// Opens the file with `O_NOFOLLOW` and reads up to `max_size` bytes.
/// If `max_size` is `None`, the entire file is read.
pub fn read_nofollow(path: &Path, max_size: Option<usize>) -> io::Result<String> {
    let mut file = open_nofollow(path)?;

    match max_size {
        Some(limit) => {
            let mut buf = vec![0u8; limit];
            let n = file.read(&mut buf)?;
            buf.truncate(n);
            String::from_utf8(buf).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, e)
            })
        }
        None => {
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            Ok(contents)
        }
    }
}

/// Atomically write contents to a file with explicit permissions.
///
/// 1. Creates a temp file in the same directory as `path`
/// 2. Writes `contents` to the temp file
/// 3. Sets permissions to `mode` via `fchmod`
/// 4. Calls `fsync` to flush to disk
/// 5. Verifies `path` is not a symlink via `lstat`
/// 6. Renames temp file to `path`
///
/// On any failure, the temp file is cleaned up. This ensures that readers
/// never see a partially-written file.
pub fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;

    // Generate a unique temp file name in the same directory
    let temp_name = format!(
        ".{}.tmp.{}",
        path.file_name()
            .unwrap_or_default()
            .to_string_lossy(),
        std::process::id()
    );
    let temp_path = parent.join(&temp_name);

    // Clean up on failure
    let _guard = TempFileGuard { path: &temp_path };

    // Create temp file with restrictive initial permissions
    let c_temp = path_to_cstring(&temp_path)?;
    let fd = unsafe {
        libc::open(
            c_temp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Write contents
    {
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(contents)?;

        // Set target permissions via fchmod
        use std::os::unix::io::AsRawFd;
        let ret = unsafe { libc::fchmod(file.as_raw_fd(), mode) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        // fsync to ensure durability
        file.sync_all()?;
    }

    // Check that the target path is not a symlink before renaming
    if path.exists() {
        let c_path = path_to_cstring(path)?;
        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::lstat(c_path.as_ptr(), &mut stat_buf) };
        if ret == 0 && (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFLNK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("target path is a symlink: {}", path.display()),
            ));
        }
    }

    // Atomic rename
    let c_target = path_to_cstring(path)?;
    let ret = unsafe { libc::rename(c_temp.as_ptr(), c_target.as_ptr()) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    // Rename succeeded, don't clean up the temp file
    _guard.defuse();

    Ok(())
}

/// Create a directory with explicit permissions, verifying no symlink components.
///
/// Walks each component of `path` and checks via `lstat` that no existing
/// component is a symbolic link. Then creates the directory with the specified
/// `mode`.
pub fn mkdir_safe(path: &Path, mode: u32) -> io::Result<()> {
    // Verify no existing component is a symlink
    let mut checked = std::path::PathBuf::new();
    for component in path.components() {
        checked.push(component);
        if checked.exists() {
            let c_checked = path_to_cstring(&checked)?;
            let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
            let ret = unsafe { libc::lstat(c_checked.as_ptr(), &mut stat_buf) };
            if ret == 0 && (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("path component is a symlink: {}", checked.display()),
                ));
            }
        }
    }

    let c_path = path_to_cstring(path)?;
    let ret = unsafe { libc::mkdir(c_path.as_ptr(), mode) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        // EEXIST is not an error if the directory already exists and is not a symlink
        if err.raw_os_error() == Some(libc::EEXIST) {
            // Verify the existing path is actually a directory
            let meta = std::fs::symlink_metadata(path)?;
            if meta.is_dir() {
                return Ok(());
            }
        }
        return Err(err);
    }

    Ok(())
}

/// Check file permissions and ownership without following symlinks.
///
/// Uses `lstat` to verify:
/// - The file owner matches `expected_uid`
/// - The permission bits do not exceed `max_mode` (i.e., no extra bits are set)
///
/// Returns `Ok(())` if checks pass, or `Err(String)` with a human-readable
/// description of the violation.
pub fn check_permissions(path: &Path, expected_uid: u32, max_mode: u32) -> Result<(), String> {
    let c_path = path_to_cstring(path).map_err(|e| format!("invalid path: {}", e))?;

    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::lstat(c_path.as_ptr(), &mut stat_buf) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        return Err(format!("lstat failed for {}: {}", path.display(), err));
    }

    let actual_uid = stat_buf.st_uid;
    if actual_uid != expected_uid {
        return Err(format!(
            "{}: owned by uid {} (expected {})",
            path.display(),
            actual_uid,
            expected_uid,
        ));
    }

    let actual_mode = stat_buf.st_mode & 0o7777;
    // Check if any bits are set that aren't in max_mode
    let excess = actual_mode & !max_mode;
    if excess != 0 {
        return Err(format!(
            "{}: mode {:04o} exceeds max {:04o} (excess bits: {:04o})",
            path.display(),
            actual_mode,
            max_mode,
            excess,
        ));
    }

    Ok(())
}

/// Redact sensitive environment variable values.
///
/// Clones the provided map and replaces values of keys that match any of:
/// - Exact names: `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`, `SLACK_WEBHOOK_URL`
/// - Suffix patterns: `*_TOKEN`, `*_KEY`, `*_PASSWORD`, `*_SECRET`, `*_CREDENTIAL`
///
/// Matching is case-insensitive. Non-matching keys are preserved as-is.
pub fn redact_env(env: &HashMap<String, String>) -> HashMap<String, String> {
    const EXACT_MATCHES: &[&str] = &[
        "AWS_SECRET_ACCESS_KEY",
        "DATABASE_URL",
        "SLACK_WEBHOOK_URL",
    ];

    const SUFFIX_PATTERNS: &[&str] = &[
        "_TOKEN",
        "_KEY",
        "_PASSWORD",
        "_SECRET",
        "_CREDENTIAL",
    ];

    let mut redacted = env.clone();

    for (key, value) in redacted.iter_mut() {
        let upper = key.to_uppercase();

        let should_redact = EXACT_MATCHES.iter().any(|exact| upper == *exact)
            || SUFFIX_PATTERNS.iter().any(|suffix| upper.ends_with(suffix));

        if should_redact {
            *value = "[REDACTED]".to_string();
        }
    }

    redacted
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert a `Path` to a `CString`, returning an IO error on interior NUL bytes.
fn path_to_cstring(path: &Path) -> io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path contains NUL byte: {}", path.display()),
        )
    })
}

/// RAII guard that removes a temp file on drop unless defused.
struct TempFileGuard<'a> {
    path: &'a Path,
}

impl<'a> TempFileGuard<'a> {
    /// Prevent the guard from removing the temp file.
    fn defuse(self) {
        std::mem::forget(self);
    }
}

impl<'a> Drop for TempFileGuard<'a> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.path);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    // -- open_nofollow tests --

    #[test]
    fn test_open_nofollow_regular_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("regular.txt");
        std::fs::write(&file_path, "hello").unwrap();

        let result = open_nofollow(&file_path);
        assert!(result.is_ok(), "should open regular files");
    }

    #[test]
    fn test_open_nofollow_rejects_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, "secret").unwrap();

        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = open_nofollow(&link);
        assert!(result.is_err(), "should reject symlinks");
        let err = result.unwrap_err();
        // ELOOP (40) is returned when O_NOFOLLOW encounters a symlink
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
    }

    #[test]
    fn test_open_nofollow_nonexistent() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does_not_exist.txt");

        let result = open_nofollow(&missing);
        assert!(result.is_err(), "should fail on non-existent path");
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ENOENT));
    }

    // -- read_nofollow tests --

    #[test]
    fn test_read_nofollow_full() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("data.txt");
        std::fs::write(&file_path, "full content here").unwrap();

        let content = read_nofollow(&file_path, None).unwrap();
        assert_eq!(content, "full content here");
    }

    #[test]
    fn test_read_nofollow_with_max_size() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("data.txt");
        std::fs::write(&file_path, "abcdefghij").unwrap();

        let content = read_nofollow(&file_path, Some(5)).unwrap();
        assert_eq!(content, "abcde");
    }

    #[test]
    fn test_read_nofollow_max_size_larger_than_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("small.txt");
        std::fs::write(&file_path, "hi").unwrap();

        let content = read_nofollow(&file_path, Some(1024)).unwrap();
        assert_eq!(content, "hi");
    }

    #[test]
    fn test_read_nofollow_rejects_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, "secret data").unwrap();

        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = read_nofollow(&link, None);
        assert!(result.is_err(), "should reject symlinks");
    }

    #[test]
    fn test_read_nofollow_empty_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("empty.txt");
        std::fs::write(&file_path, "").unwrap();

        let content = read_nofollow(&file_path, None).unwrap();
        assert_eq!(content, "");
    }

    // -- atomic_write tests --

    #[test]
    fn test_atomic_write_creates_file() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("output.txt");

        atomic_write(&target, b"hello world", 0o644).unwrap();

        let contents = std::fs::read_to_string(&target).unwrap();
        assert_eq!(contents, "hello world");
    }

    #[test]
    fn test_atomic_write_sets_permissions() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("perms.txt");

        atomic_write(&target, b"data", 0o600).unwrap();

        let meta = std::fs::metadata(&target).unwrap();
        let mode = meta.permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_atomic_write_overwrites_existing() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("existing.txt");
        std::fs::write(&target, "old content").unwrap();

        atomic_write(&target, b"new content", 0o644).unwrap();

        let contents = std::fs::read_to_string(&target).unwrap();
        assert_eq!(contents, "new content");
    }

    #[test]
    fn test_atomic_write_rejects_symlink_target() {
        let dir = TempDir::new().unwrap();
        let real_file = dir.path().join("real.txt");
        std::fs::write(&real_file, "original").unwrap();

        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real_file, &link).unwrap();

        let result = atomic_write(&link, b"malicious", 0o644);
        assert!(result.is_err(), "should reject symlink targets");

        // Original file should be untouched
        let contents = std::fs::read_to_string(&real_file).unwrap();
        assert_eq!(contents, "original");
    }

    #[test]
    fn test_atomic_write_cleans_up_on_bad_parent() {
        let dir = TempDir::new().unwrap();
        let bad_path = dir.path().join("nonexistent_dir").join("file.txt");

        let result = atomic_write(&bad_path, b"data", 0o644);
        assert!(result.is_err(), "should fail when parent dir missing");

        // No temp files should remain
        let remaining: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(remaining.is_empty(), "no temp files should remain");
    }

    #[test]
    fn test_atomic_write_empty_contents() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("empty.txt");

        atomic_write(&target, b"", 0o644).unwrap();

        let contents = std::fs::read_to_string(&target).unwrap();
        assert_eq!(contents, "");
    }

    // -- mkdir_safe tests --

    #[test]
    fn test_mkdir_safe_creates_directory() {
        let dir = TempDir::new().unwrap();
        let new_dir = dir.path().join("subdir");

        mkdir_safe(&new_dir, 0o755).unwrap();

        assert!(new_dir.is_dir());
    }

    #[test]
    fn test_mkdir_safe_existing_directory() {
        let dir = TempDir::new().unwrap();
        let existing = dir.path().join("existing");
        std::fs::create_dir(&existing).unwrap();

        // Should succeed because directory already exists
        let result = mkdir_safe(&existing, 0o755);
        assert!(result.is_ok());
    }

    #[test]
    fn test_mkdir_safe_rejects_symlink_component() {
        let dir = TempDir::new().unwrap();
        let real_dir = dir.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();

        let target = link.join("subdir");
        let result = mkdir_safe(&target, 0o755);
        assert!(result.is_err(), "should reject path with symlink component");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("symlink"),
            "error should mention symlink: {}",
            err_msg
        );
    }

    // -- check_permissions tests --

    #[test]
    fn test_check_permissions_pass() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("good.txt");
        std::fs::write(&file_path, "ok").unwrap();
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let uid = unsafe { libc::getuid() };
        let result = check_permissions(&file_path, uid, 0o600);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_permissions_excess_mode() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("loose.txt");
        std::fs::write(&file_path, "data").unwrap();
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o777)).unwrap();

        let uid = unsafe { libc::getuid() };
        let result = check_permissions(&file_path, uid, 0o600);
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("exceeds max"), "error: {}", err_msg);
        assert!(err_msg.contains("0777"), "error should show actual mode: {}", err_msg);
    }

    #[test]
    fn test_check_permissions_wrong_uid() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("owned.txt");
        std::fs::write(&file_path, "data").unwrap();

        // Use an impossible UID
        let wrong_uid = 99999;
        let result = check_permissions(&file_path, wrong_uid, 0o777);
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("owned by uid"), "error: {}", err_msg);
    }

    #[test]
    fn test_check_permissions_nonexistent() {
        let result = check_permissions(Path::new("/nonexistent/path"), 0, 0o644);
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("lstat failed"), "error: {}", err_msg);
    }

    #[test]
    fn test_check_permissions_exact_max_mode() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("exact.txt");
        std::fs::write(&file_path, "ok").unwrap();
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let uid = unsafe { libc::getuid() };
        // max_mode == actual_mode should pass
        let result = check_permissions(&file_path, uid, 0o644);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_permissions_stricter_than_max() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("strict.txt");
        std::fs::write(&file_path, "ok").unwrap();
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o400)).unwrap();

        let uid = unsafe { libc::getuid() };
        // File is 0400 which is within 0644 — should pass
        let result = check_permissions(&file_path, uid, 0o644);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_permissions_symlink_not_followed() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, "data").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();

        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let uid = unsafe { libc::getuid() };
        // lstat on a symlink reports the symlink's own mode (typically 0777),
        // but we check the symlink itself, not the target. The symlink mode
        // varies by filesystem but this tests that lstat is used.
        let result = check_permissions(&link, uid, 0o600);
        // On most Linux filesystems, symlink mode is 0777, so this should fail
        // because 0777 exceeds 0600
        assert!(result.is_err(), "should use lstat on symlink, not follow it");
    }

    // -- redact_env tests --

    #[test]
    fn test_redact_env_exact_matches() {
        let mut env = HashMap::new();
        env.insert("AWS_SECRET_ACCESS_KEY".to_string(), "AKIAEXAMPLE".to_string());
        env.insert("DATABASE_URL".to_string(), "postgres://secret".to_string());
        env.insert("SLACK_WEBHOOK_URL".to_string(), "https://hooks.slack.com/xxx".to_string());

        let redacted = redact_env(&env);
        assert_eq!(redacted["AWS_SECRET_ACCESS_KEY"], "[REDACTED]");
        assert_eq!(redacted["DATABASE_URL"], "[REDACTED]");
        assert_eq!(redacted["SLACK_WEBHOOK_URL"], "[REDACTED]");
    }

    #[test]
    fn test_redact_env_suffix_patterns() {
        let mut env = HashMap::new();
        env.insert("GITHUB_TOKEN".to_string(), "ghp_xxx".to_string());
        env.insert("API_KEY".to_string(), "sk-xxx".to_string());
        env.insert("DB_PASSWORD".to_string(), "hunter2".to_string());
        env.insert("APP_SECRET".to_string(), "shhh".to_string());
        env.insert("OAUTH_CREDENTIAL".to_string(), "cred".to_string());

        let redacted = redact_env(&env);
        assert_eq!(redacted["GITHUB_TOKEN"], "[REDACTED]");
        assert_eq!(redacted["API_KEY"], "[REDACTED]");
        assert_eq!(redacted["DB_PASSWORD"], "[REDACTED]");
        assert_eq!(redacted["APP_SECRET"], "[REDACTED]");
        assert_eq!(redacted["OAUTH_CREDENTIAL"], "[REDACTED]");
    }

    #[test]
    fn test_redact_env_case_insensitive() {
        let mut env = HashMap::new();
        env.insert("aws_secret_access_key".to_string(), "lower".to_string());
        env.insert("Aws_Secret_Access_Key".to_string(), "mixed".to_string());
        env.insert("github_token".to_string(), "token_lower".to_string());
        env.insert("Api_Key".to_string(), "key_mixed".to_string());
        env.insert("db_password".to_string(), "pass_lower".to_string());

        let redacted = redact_env(&env);
        assert_eq!(redacted["aws_secret_access_key"], "[REDACTED]");
        assert_eq!(redacted["Aws_Secret_Access_Key"], "[REDACTED]");
        assert_eq!(redacted["github_token"], "[REDACTED]");
        assert_eq!(redacted["Api_Key"], "[REDACTED]");
        assert_eq!(redacted["db_password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_env_preserves_safe_keys() {
        let mut env = HashMap::new();
        env.insert("HOME".to_string(), "/home/user".to_string());
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        env.insert("SHELL".to_string(), "/bin/bash".to_string());
        env.insert("TERM".to_string(), "xterm-256color".to_string());
        env.insert("LANG".to_string(), "en_US.UTF-8".to_string());

        let redacted = redact_env(&env);
        assert_eq!(redacted["HOME"], "/home/user");
        assert_eq!(redacted["PATH"], "/usr/bin");
        assert_eq!(redacted["SHELL"], "/bin/bash");
        assert_eq!(redacted["TERM"], "xterm-256color");
        assert_eq!(redacted["LANG"], "en_US.UTF-8");
    }

    #[test]
    fn test_redact_env_empty_map() {
        let env = HashMap::new();
        let redacted = redact_env(&env);
        assert!(redacted.is_empty());
    }

    #[test]
    fn test_redact_env_does_not_modify_original() {
        let mut env = HashMap::new();
        env.insert("API_KEY".to_string(), "secret".to_string());

        let _redacted = redact_env(&env);
        assert_eq!(env["API_KEY"], "secret", "original map should be unchanged");
    }

    #[test]
    fn test_redact_env_partial_suffix_no_match() {
        // Keys that contain but don't end with the suffix should NOT be redacted
        let mut env = HashMap::new();
        env.insert("TOKEN_COUNT".to_string(), "42".to_string());
        env.insert("KEY_BINDINGS".to_string(), "vim".to_string());
        env.insert("PASSWORD_POLICY".to_string(), "strict".to_string());

        let redacted = redact_env(&env);
        assert_eq!(redacted["TOKEN_COUNT"], "42");
        assert_eq!(redacted["KEY_BINDINGS"], "vim");
        assert_eq!(redacted["PASSWORD_POLICY"], "strict");
    }
}
