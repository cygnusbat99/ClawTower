// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Tamper-evident hash-chained audit log.
//!
//! Every alert that passes through the aggregator is appended to a JSONL file
//! where each entry contains a SHA-256 hash linking it to the previous entry
//! (blockchain-style). This makes post-hoc deletion or modification of individual
//! entries detectable via `clawtower verify-audit`.
//!
//! The genesis entry uses a zero hash as its prev_hash.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

use crate::alerts::Alert;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A single entry in the hash-chained audit log.
///
/// Each entry contains the alert data plus a SHA-256 hash computed over
/// `seq|ts|severity|source|message|prev_hash`, creating an unbreakable chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts: String,
    pub severity: String,
    pub source: String,
    pub message: String,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditEntry {
    fn compute_hash(seq: u64, ts: &str, severity: &str, source: &str, message: &str, prev_hash: &str) -> String {
        let input = format!("{}|{}|{}|{}|{}|{}", seq, ts, severity, source, message, prev_hash);
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn compute_hmac(seq: u64, ts: &str, severity: &str, source: &str, message: &str, prev_hash: &str, secret: &str) -> String {
        let input = format!("{}|{}|{}|{}|{}|{}", seq, ts, severity, source, message, prev_hash);
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .expect("HMAC accepts any key size");
        mac.update(input.as_bytes());
        format!("{:x}", mac.finalize().into_bytes())
    }
}

/// Append-only hash chain for tamper-evident audit logging.
///
/// Resumes from existing chain files, maintaining the last sequence number
/// and hash for continuity. Use [`AuditChain::verify`] to validate integrity.
pub struct AuditChain {
    path: PathBuf,
    last_seq: u64,
    last_hash: String,
    hmac_secret: Option<String>,
}

impl AuditChain {
    /// Create or resume chain from file
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("Failed to create audit chain directory")?;
        }

        let (last_seq, last_hash) = if path.exists() {
            // Resume: read last entry
            let file = fs::File::open(&path)?;
            let reader = BufReader::new(file);
            let mut last_seq = 0u64;
            let mut last_hash = GENESIS_HASH.to_string();

            for line in reader.lines() {
                let line = line?;
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_str::<AuditEntry>(line) {
                    Ok(entry) => {
                        last_seq = entry.seq;
                        last_hash = entry.hash;
                    }
                    Err(_) => {
                        // Skip malformed entries — chain may have been truncated or corrupted
                        continue;
                    }
                }
            }
            // Verify chain integrity on resume
            if last_seq > 0 {
                if let Err(e) = Self::verify(&path) {
                    bail!("Audit chain integrity check failed on resume: {}. Run `clawtower verify-audit` for details.", e);
                }
            }

            (last_seq, last_hash)
        } else {
            (0, GENESIS_HASH.to_string())
        };

        Ok(Self { path, last_seq, last_hash, hmac_secret: None })
    }

    /// Create or resume chain from file, with HMAC secret for chain integrity.
    ///
    /// When an HMAC secret is provided, `append()` uses HMAC-SHA256 instead of
    /// plain SHA-256, making the chain unforgeable without the secret key.
    /// Use [`AuditChain::verify_with_hmac`] to verify HMAC-protected chains.
    pub fn new_with_hmac<P: AsRef<Path>>(path: P, hmac_secret: Option<String>) -> Result<Self> {
        let path_ref = path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = path_ref.parent() {
            fs::create_dir_all(parent).context("Failed to create audit chain directory")?;
        }

        let (last_seq, last_hash) = if path_ref.exists() {
            // Resume: read last entry
            let file = fs::File::open(&path_ref)?;
            let reader = BufReader::new(file);
            let mut last_seq = 0u64;
            let mut last_hash = GENESIS_HASH.to_string();

            for line in reader.lines() {
                let line = line?;
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_str::<AuditEntry>(line) {
                    Ok(entry) => {
                        last_seq = entry.seq;
                        last_hash = entry.hash;
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
            // Verify chain integrity on resume
            if last_seq > 0 {
                let verify_result = match &hmac_secret {
                    Some(secret) => Self::verify_with_hmac(&path_ref, secret),
                    None => Self::verify(&path_ref),
                };
                if let Err(e) = verify_result {
                    bail!("Audit chain integrity check failed on resume: {}. Run `clawtower verify-audit` for details.", e);
                }
            }

            (last_seq, last_hash)
        } else {
            (0, GENESIS_HASH.to_string())
        };

        Ok(Self { path: path_ref, last_seq, last_hash, hmac_secret })
    }

    /// Append an alert to the chain
    pub fn append(&mut self, alert: &Alert) -> Result<AuditEntry> {
        let seq = self.last_seq + 1;
        let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let severity = alert.severity.to_string().to_lowercase();
        let source = &alert.source;
        let message = &alert.message;
        let prev_hash = &self.last_hash;

        let hash = match &self.hmac_secret {
            Some(secret) => AuditEntry::compute_hmac(seq, &ts, &severity, source, message, prev_hash, secret),
            None => AuditEntry::compute_hash(seq, &ts, &severity, source, message, prev_hash),
        };

        let entry = AuditEntry {
            seq,
            ts,
            severity,
            source: source.clone(),
            message: message.clone(),
            prev_hash: prev_hash.clone(),
            hash: hash.clone(),
        };

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .context("Failed to open audit chain file")?;

        let json = serde_json::to_string(&entry)?;
        writeln!(file, "{}", json)?;

        self.last_seq = seq;
        self.last_hash = hash;

        Ok(entry)
    }

    /// Verify the entire chain. Returns Ok(entry_count) or error with first broken entry.
    pub fn verify(path: &Path) -> Result<u64> {
        let file = fs::File::open(path).context("Failed to open audit chain file")?;
        let reader = BufReader::new(file);
        let mut expected_prev_hash = GENESIS_HASH.to_string();
        let mut expected_seq = 1u64;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(line)
                .context(format!("Failed to parse entry at seq {}", expected_seq))?;

            if entry.seq != expected_seq {
                bail!("Sequence mismatch at entry {}: expected {}, got {}", entry.seq, expected_seq, entry.seq);
            }

            if entry.prev_hash != expected_prev_hash {
                bail!("Chain broken at seq {}: prev_hash mismatch", entry.seq);
            }

            let computed = AuditEntry::compute_hash(
                entry.seq, &entry.ts, &entry.severity, &entry.source, &entry.message, &entry.prev_hash,
            );

            if entry.hash != computed {
                bail!("Hash mismatch at seq {}: expected {}, got {}", entry.seq, computed, entry.hash);
            }

            expected_prev_hash = entry.hash;
            expected_seq += 1;
        }

        Ok(expected_seq - 1)
    }

    /// Verify the entire chain using HMAC. Returns Ok(entry_count) or error with first broken entry.
    ///
    /// Use this for chains created with [`AuditChain::new_with_hmac`]. The same secret
    /// used during creation must be provided for verification to succeed.
    pub fn verify_with_hmac(path: &Path, secret: &str) -> Result<u64> {
        let file = fs::File::open(path).context("Failed to open audit chain file")?;
        let reader = BufReader::new(file);
        let mut expected_prev_hash = GENESIS_HASH.to_string();
        let mut expected_seq = 1u64;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(line)
                .context(format!("Failed to parse entry at seq {}", expected_seq))?;

            if entry.seq != expected_seq {
                bail!("Sequence mismatch at entry {}: expected {}, got {}", entry.seq, expected_seq, entry.seq);
            }

            if entry.prev_hash != expected_prev_hash {
                bail!("Chain broken at seq {}: prev_hash mismatch", entry.seq);
            }

            let computed = AuditEntry::compute_hmac(
                entry.seq, &entry.ts, &entry.severity, &entry.source, &entry.message, &entry.prev_hash, secret,
            );

            if entry.hash != computed {
                bail!("HMAC mismatch at seq {}: expected {}, got {}", entry.seq, computed, entry.hash);
            }

            expected_prev_hash = entry.hash;
            expected_seq += 1;
        }

        Ok(expected_seq - 1)
    }
}

/// Run verify-audit subcommand
pub fn run_verify_audit(path: Option<&str>) -> Result<()> {
    let path = path.unwrap_or("/var/log/clawtower/audit.chain");
    let path = Path::new(path);

    match AuditChain::verify(path) {
        Ok(count) => {
            println!("✅ Audit chain verified: {} entries, all hashes valid", count);
            Ok(())
        }
        Err(e) => {
            println!("❌ Audit chain verification FAILED: {}", e);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::{Alert, Severity};
    use tempfile::NamedTempFile;

    fn test_alert(sev: Severity, source: &str, msg: &str) -> Alert {
        Alert::new(sev, source, msg)
    }

    #[test]
    fn test_genesis_entry_has_correct_prev_hash() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        // Remove the file so AuditChain creates fresh
        drop(tmp);
        std::fs::remove_file(&path).ok();

        let mut chain = AuditChain::new(&path).unwrap();
        let entry = chain.append(&test_alert(Severity::Info, "test", "genesis")).unwrap();

        assert_eq!(entry.seq, 1);
        assert_eq!(entry.prev_hash, GENESIS_HASH);
        assert!(!entry.hash.is_empty());
        assert_ne!(entry.hash, GENESIS_HASH);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_chain_of_5_verifies() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);
        std::fs::remove_file(&path).ok();

        let mut chain = AuditChain::new(&path).unwrap();
        for i in 0..5 {
            chain.append(&test_alert(Severity::Warning, "test", &format!("msg {}", i))).unwrap();
        }

        let count = AuditChain::verify(&path).unwrap();
        assert_eq!(count, 5);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_tampered_entry_fails() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);
        std::fs::remove_file(&path).ok();

        let mut chain = AuditChain::new(&path).unwrap();
        for i in 0..3 {
            chain.append(&test_alert(Severity::Info, "test", &format!("msg {}", i))).unwrap();
        }

        // Tamper with the second entry
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let mut entry: AuditEntry = serde_json::from_str(&lines[1]).unwrap();
        entry.message = "TAMPERED".to_string();
        lines[1] = serde_json::to_string(&entry).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let result = AuditChain::verify(&path);
        assert!(result.is_err());

        std::fs::remove_file(&path).ok();
    }

    // --- NEW REGRESSION TESTS ---

    #[test]
    fn test_empty_chain_verifies_as_zero() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        // Empty file
        std::fs::write(&path, "").unwrap();
        let count = AuditChain::verify(&path).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_single_entry_chain_verifies() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);
        std::fs::remove_file(&path).ok();

        let mut chain = AuditChain::new(&path).unwrap();
        chain.append(&test_alert(Severity::Info, "test", "only one")).unwrap();

        let count = AuditChain::verify(&path).unwrap();
        assert_eq!(count, 1);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_tampered_hash_detected() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);
        std::fs::remove_file(&path).ok();

        let mut chain = AuditChain::new(&path).unwrap();
        chain.append(&test_alert(Severity::Info, "test", "entry one")).unwrap();

        // Tamper with the hash field directly
        let content = std::fs::read_to_string(&path).unwrap();
        let mut entry: AuditEntry = serde_json::from_str(content.trim()).unwrap();
        entry.hash = "0000000000000000000000000000000000000000000000000000000000000bad".to_string();
        std::fs::write(&path, serde_json::to_string(&entry).unwrap() + "\n").unwrap();

        let result = AuditChain::verify(&path);
        assert!(result.is_err(), "Tampered hash should fail verification");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_prev_hash_tampering_detected() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);
        std::fs::remove_file(&path).ok();

        let mut chain = AuditChain::new(&path).unwrap();
        chain.append(&test_alert(Severity::Info, "test", "one")).unwrap();
        chain.append(&test_alert(Severity::Info, "test", "two")).unwrap();

        // Tamper: change prev_hash of second entry
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let mut entry: AuditEntry = serde_json::from_str(&lines[1]).unwrap();
        entry.prev_hash = GENESIS_HASH.to_string(); // wrong prev_hash
        lines[1] = serde_json::to_string(&entry).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let result = AuditChain::verify(&path);
        assert!(result.is_err());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_deleted_middle_entry_detected() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);
        std::fs::remove_file(&path).ok();

        let mut chain = AuditChain::new(&path).unwrap();
        for i in 0..3 {
            chain.append(&test_alert(Severity::Info, "test", &format!("msg {}", i))).unwrap();
        }

        // Remove second entry
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let tampered = format!("{}\n{}\n", lines[0], lines[2]);
        std::fs::write(&path, tampered).unwrap();

        let result = AuditChain::verify(&path);
        assert!(result.is_err(), "Deleted entry should break sequence/chain");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_chain_with_blank_lines() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);
        std::fs::remove_file(&path).ok();

        let mut chain = AuditChain::new(&path).unwrap();
        chain.append(&test_alert(Severity::Info, "test", "one")).unwrap();
        chain.append(&test_alert(Severity::Info, "test", "two")).unwrap();

        // Insert blank lines
        let content = std::fs::read_to_string(&path).unwrap();
        let with_blanks = content.replace("\n", "\n\n");
        std::fs::write(&path, with_blanks).unwrap();

        // Should still verify (blank lines are skipped)
        let count = AuditChain::verify(&path).unwrap();
        assert_eq!(count, 2);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_chain_entry_hash_deterministic() {
        let h1 = AuditEntry::compute_hash(1, "2024-01-01T00:00:00Z", "info", "test", "msg", GENESIS_HASH);
        let h2 = AuditEntry::compute_hash(1, "2024-01-01T00:00:00Z", "info", "test", "msg", GENESIS_HASH);
        assert_eq!(h1, h2, "Same inputs must produce same hash");
    }

    #[test]
    fn test_chain_entry_hash_changes_with_seq() {
        let h1 = AuditEntry::compute_hash(1, "2024-01-01T00:00:00Z", "info", "test", "msg", GENESIS_HASH);
        let h2 = AuditEntry::compute_hash(2, "2024-01-01T00:00:00Z", "info", "test", "msg", GENESIS_HASH);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_verify_nonexistent_file() {
        let result = AuditChain::verify(Path::new("/nonexistent/chain.log"));
        assert!(result.is_err());
    }

    #[test]
    fn test_resume_detects_corrupted_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.chain");

        // Write valid chain
        {
            let mut chain = AuditChain::new(&path).unwrap();
            for i in 0..3 {
                chain.append(&test_alert(Severity::Info, "test", &format!("msg {}", i))).unwrap();
            }
        }

        // Corrupt middle entry
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let mut entry: AuditEntry = serde_json::from_str(&lines[1]).unwrap();
        entry.message = "TAMPERED".to_string();
        lines[1] = serde_json::to_string(&entry).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        // Resume should detect corruption
        let result = AuditChain::new(&path);
        assert!(result.is_err(), "Resuming from corrupted chain must fail");
    }

    #[test]
    fn test_chain_entry_with_hmac_differs_from_plain_hash() {
        let h1 = AuditEntry::compute_hash(1, "2024-01-01T00:00:00Z", "info", "test", "msg", GENESIS_HASH);
        let h2 = AuditEntry::compute_hmac(1, "2024-01-01T00:00:00Z", "info", "test", "msg", GENESIS_HASH, "secret-key");
        assert_ne!(h1, h2, "HMAC must differ from plain hash");
    }

    #[test]
    fn test_hmac_deterministic() {
        let h1 = AuditEntry::compute_hmac(1, "2024-01-01T00:00:00Z", "info", "test", "msg", GENESIS_HASH, "secret-key");
        let h2 = AuditEntry::compute_hmac(1, "2024-01-01T00:00:00Z", "info", "test", "msg", GENESIS_HASH, "secret-key");
        assert_eq!(h1, h2, "Same inputs and key must produce same HMAC");
    }

    #[test]
    fn test_hmac_different_keys_produce_different_hashes() {
        let h1 = AuditEntry::compute_hmac(1, "2024-01-01T00:00:00Z", "info", "test", "msg", GENESIS_HASH, "key-one");
        let h2 = AuditEntry::compute_hmac(1, "2024-01-01T00:00:00Z", "info", "test", "msg", GENESIS_HASH, "key-two");
        assert_ne!(h1, h2, "Different keys must produce different HMACs");
    }

    #[test]
    fn test_hmac_chain_creates_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hmac_audit.chain");
        let secret = "test-instance-secret";

        let mut chain = AuditChain::new_with_hmac(&path, Some(secret.to_string())).unwrap();
        for i in 0..5 {
            chain.append(&test_alert(Severity::Info, "test", &format!("hmac msg {}", i))).unwrap();
        }

        let count = AuditChain::verify_with_hmac(&path, secret).unwrap();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_hmac_chain_fails_plain_verify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hmac_audit.chain");
        let secret = "test-instance-secret";

        let mut chain = AuditChain::new_with_hmac(&path, Some(secret.to_string())).unwrap();
        chain.append(&test_alert(Severity::Info, "test", "hmac entry")).unwrap();

        // Plain verify should fail because hashes are HMAC, not plain SHA-256
        let result = AuditChain::verify(&path);
        assert!(result.is_err(), "HMAC chain must not pass plain hash verification");
    }

    #[test]
    fn test_hmac_chain_fails_wrong_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hmac_audit.chain");

        let mut chain = AuditChain::new_with_hmac(&path, Some("correct-secret".to_string())).unwrap();
        chain.append(&test_alert(Severity::Info, "test", "hmac entry")).unwrap();

        let result = AuditChain::verify_with_hmac(&path, "wrong-secret");
        assert!(result.is_err(), "Wrong secret must fail HMAC verification");
    }

    #[test]
    fn test_new_with_hmac_none_behaves_like_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain_audit.chain");

        // new_with_hmac(None) should produce plain hashes
        let mut chain = AuditChain::new_with_hmac(&path, None).unwrap();
        chain.append(&test_alert(Severity::Info, "test", "plain entry")).unwrap();

        // Plain verify should work
        let count = AuditChain::verify(&path).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_hmac_chain_resume() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hmac_resume.chain");
        let secret = "resume-secret";

        // Write initial entries
        {
            let mut chain = AuditChain::new_with_hmac(&path, Some(secret.to_string())).unwrap();
            for i in 0..3 {
                chain.append(&test_alert(Severity::Info, "test", &format!("msg {}", i))).unwrap();
            }
        }

        // Resume and write more
        {
            let mut chain = AuditChain::new_with_hmac(&path, Some(secret.to_string())).unwrap();
            assert_eq!(chain.last_seq, 3);
            for i in 3..5 {
                chain.append(&test_alert(Severity::Warning, "test", &format!("msg {}", i))).unwrap();
            }
        }

        let count = AuditChain::verify_with_hmac(&path, secret).unwrap();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_resume_from_existing_file() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);
        std::fs::remove_file(&path).ok();

        // Write 3 entries
        {
            let mut chain = AuditChain::new(&path).unwrap();
            for i in 0..3 {
                chain.append(&test_alert(Severity::Info, "test", &format!("msg {}", i))).unwrap();
            }
        }

        // Resume and write 2 more
        {
            let mut chain = AuditChain::new(&path).unwrap();
            assert_eq!(chain.last_seq, 3);
            for i in 3..5 {
                chain.append(&test_alert(Severity::Critical, "test", &format!("msg {}", i))).unwrap();
            }
        }

        let count = AuditChain::verify(&path).unwrap();
        assert_eq!(count, 5);

        std::fs::remove_file(&path).ok();
    }
}
