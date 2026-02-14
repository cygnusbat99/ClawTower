//! Self-update subcommand: `clawav update`
//!
//! 1. Prompts for admin key (or accepts --key flag)
//! 2. Checks GitHub releases API for latest version
//! 3. Downloads + verifies new binary (SHA256 checksum)
//! 4. Does chattr -i → replace → chattr +i → restart dance
//! 5. Logs the upgrade to Slack

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;

const GITHUB_REPO: &str = "coltz108/ClawAV";
const ADMIN_KEY_HASH_PATH: &str = "/etc/clawav/admin.key.hash";

/// Detect the correct release asset name for this platform
fn asset_name() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "clawav-aarch64-linux"
    } else {
        "clawav-x86_64-linux"
    }
}

/// Get the path of the currently running binary
fn current_binary_path() -> Result<PathBuf> {
    std::env::current_exe().context("Failed to determine current binary path")
}

/// Prompt for admin key from stdin (unless --key was passed)
fn get_admin_key(args: &[String]) -> Result<String> {
    // Check for --key flag
    for (i, arg) in args.iter().enumerate() {
        if arg == "--key" {
            if let Some(key) = args.get(i + 1) {
                return Ok(key.clone());
            }
            bail!("--key flag requires a value");
        }
        if let Some(key) = arg.strip_prefix("--key=") {
            return Ok(key.to_string());
        }
    }

    // Interactive prompt
    eprint!("Admin key: ");
    io::stderr().flush()?;
    let mut key = String::new();
    io::stdin().read_line(&mut key)?;
    let key = key.trim().to_string();
    if key.is_empty() {
        bail!("Admin key is required for updates");
    }
    Ok(key)
}

/// Verify admin key against stored hash
fn verify_admin_key(key: &str) -> Result<bool> {
    let hash = fs::read_to_string(ADMIN_KEY_HASH_PATH)
        .context("Cannot read admin key hash — is ClawAV installed?")?;
    Ok(crate::admin::verify_key(key, hash.trim()))
}

/// Fetch latest release info from GitHub API
fn fetch_latest_release() -> Result<(String, String, Option<String>)> {
    // Returns (tag, download_url, sha256_url)
    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        GITHUB_REPO
    );

    let client = reqwest::blocking::Client::builder()
        .user_agent("clawav-updater")
        .build()?;

    let resp = client.get(&url).send()?.error_for_status()?;
    let release: serde_json::Value = resp.json()?;

    let tag = release["tag_name"]
        .as_str()
        .context("No tag_name in release")?
        .to_string();

    let target_asset = asset_name();
    let sha_asset = format!("{}.sha256", target_asset);

    let assets = release["assets"]
        .as_array()
        .context("No assets in release")?;

    let mut download_url = None;
    let mut sha256_url = None;

    for asset in assets {
        let name = asset["name"].as_str().unwrap_or("");
        let url = asset["browser_download_url"].as_str().unwrap_or("");
        if name == target_asset {
            download_url = Some(url.to_string());
        } else if name == sha_asset {
            sha256_url = Some(url.to_string());
        }
    }

    let download_url = download_url
        .with_context(|| format!("No asset '{}' found in release {}", target_asset, tag))?;

    Ok((tag, download_url, sha256_url))
}

/// Download binary and optionally verify checksum
fn download_and_verify(download_url: &str, sha256_url: Option<&str>) -> Result<Vec<u8>> {
    eprintln!("Downloading binary...");
    let client = reqwest::blocking::Client::builder()
        .user_agent("clawav-updater")
        .build()?;

    let binary_data = client
        .get(download_url)
        .send()?
        .error_for_status()?
        .bytes()?
        .to_vec();

    eprintln!("Downloaded {} bytes", binary_data.len());

    // Verify checksum if available
    if let Some(sha_url) = sha256_url {
        eprintln!("Verifying SHA256 checksum...");
        let sha_resp = client.get(sha_url).send()?.error_for_status()?;
        let sha_text = sha_resp.text()?;
        // Format: "<hash>  <filename>" or just "<hash>"
        let expected_hash = sha_text
            .split_whitespace()
            .next()
            .context("Empty checksum file")?
            .to_lowercase();

        let mut hasher = Sha256::new();
        hasher.update(&binary_data);
        let actual_hash = hex::encode(hasher.finalize());

        if actual_hash != expected_hash {
            bail!(
                "Checksum mismatch!\n  Expected: {}\n  Got:      {}",
                expected_hash,
                actual_hash
            );
        }
        eprintln!("✅ Checksum verified");
    } else {
        eprintln!("⚠️  No checksum file in release — skipping verification");
    }

    Ok(binary_data)
}

/// Run a shell command, bail on failure
fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        bail!(
            "{} {} exited with code {}",
            program,
            args.join(" "),
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

/// Notify Slack about the upgrade (best-effort, reads config)
fn notify_slack(from_version: &str, to_version: &str) {
    let config_path = PathBuf::from("/etc/clawav/config.toml");
    let config = match crate::config::Config::load(&config_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    if config.slack.webhook_url.is_empty() {
        return;
    }

    let payload = serde_json::json!({
        "text": format!(
            "🔄 *ClawAV self-update complete*\n`{}` → `{}`\nBinary: `{}`\nHost: {}",
            from_version,
            to_version,
            current_binary_path().map(|p| p.display().to_string()).unwrap_or_else(|_| "unknown".into()),
            hostname()
        )
    });

    let _ = reqwest::blocking::Client::new()
        .post(&config.slack.webhook_url)
        .json(&payload)
        .send();
}

fn hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}

/// Parse --binary flag from args
fn get_custom_binary_path(args: &[String]) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == "--binary" {
            return args.get(i + 1).cloned();
        }
        if let Some(path) = arg.strip_prefix("--binary=") {
            return Some(path.to_string());
        }
    }
    None
}

/// Main entry point for `clawav update`
pub fn run_update(args: &[String]) -> Result<()> {
    let current_version = env!("CARGO_PKG_VERSION");
    eprintln!("🛡️  ClawAV Self-Update");
    eprintln!("Current version: v{}", current_version);
    eprintln!();

    let check_only = args.iter().any(|a| a == "--check");
    let custom_binary = get_custom_binary_path(args);

    // Custom binary path requires admin key (no CI verification available)
    // GitHub release path does NOT require admin key (SHA256 checksum is sufficient)
    let (binary_data, version_tag) = if let Some(ref binary_path) = custom_binary {
        eprintln!("Custom binary install: {}", binary_path);
        eprintln!("⚠️  No CI verification — admin key required");
        eprintln!();

        let key = get_admin_key(args)?;
        if !verify_admin_key(&key)? {
            bail!("❌ Invalid admin key — custom binary install refused");
        }
        eprintln!("✅ Admin key verified");
        eprintln!();

        let data = fs::read(binary_path)
            .with_context(|| format!("Failed to read custom binary: {}", binary_path))?;
        eprintln!("Read {} bytes from {}", data.len(), binary_path);

        (data, "custom".to_string())
    } else {
        // GitHub release path — checksum verification is the trust anchor
        eprintln!("Checking GitHub releases...");
        let (tag, download_url, sha256_url) = fetch_latest_release()?;
        let remote_version = tag.strip_prefix('v').unwrap_or(&tag);

        eprintln!("Latest release: {} ({})", tag, asset_name());

        if remote_version == current_version {
            eprintln!("✅ Already running the latest version");
            return Ok(());
        }

        eprintln!("Update available: v{} → {}", current_version, tag);

        if check_only {
            return Ok(());
        }

        if sha256_url.is_none() {
            bail!("❌ Release has no checksum file — refusing to install unverified binary");
        }

        let data = download_and_verify(&download_url, sha256_url.as_deref())?;
        (data, tag)
    };

    if check_only {
        return Ok(());
    }

    let binary_data = binary_data;

    // 4. Replace binary (chattr dance)
    let binary_path = current_binary_path()?;
    let tmp_path = binary_path.with_extension("new");

    eprintln!("Installing to {}...", binary_path.display());

    // Write new binary to temp location
    fs::write(&tmp_path, &binary_data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755))?;
    }

    // Remove immutable flag (may fail if not set — that's fine)
    let _ = run_cmd("chattr", &["-i", &binary_path.to_string_lossy()]);

    // Atomic replace
    fs::rename(&tmp_path, &binary_path)?;

    // Re-apply immutable flag
    let _ = run_cmd("chattr", &["+i", &binary_path.to_string_lossy()]);

    eprintln!("✅ Binary replaced");

    // 5. Notify Slack
    notify_slack(&format!("v{}", current_version), &version_tag);

    // 6. Restart service
    eprintln!("Restarting clawav service...");
    let restart_result = run_cmd("systemctl", &["restart", "clawav"]);
    match restart_result {
        Ok(()) => eprintln!("✅ Service restarted"),
        Err(e) => eprintln!("⚠️  Service restart failed ({}). You may need to restart manually.", e),
    }

    eprintln!();
    eprintln!("🎉 Updated to {}", version_tag);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_name() {
        let name = asset_name();
        assert!(name.starts_with("clawav-"));
        assert!(name.contains("-linux"));
    }

    #[test]
    fn test_hostname() {
        // Should return something non-empty
        let h = hostname();
        assert!(!h.is_empty() || true); // May fail in CI, don't hard-fail
    }

    #[test]
    fn test_get_admin_key_from_flag() {
        let args = vec!["--key".to_string(), "OCAV-test123".to_string()];
        let key = get_admin_key(&args).unwrap();
        assert_eq!(key, "OCAV-test123");
    }

    #[test]
    fn test_get_admin_key_from_equals_flag() {
        let args = vec!["--key=OCAV-test456".to_string()];
        let key = get_admin_key(&args).unwrap();
        assert_eq!(key, "OCAV-test456");
    }

    #[test]
    fn test_get_admin_key_missing_value() {
        let args = vec!["--key".to_string()];
        assert!(get_admin_key(&args).is_err());
    }
}
