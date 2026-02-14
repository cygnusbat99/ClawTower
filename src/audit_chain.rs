use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::alerts::Alert;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

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
}

pub struct AuditChain {
    path: PathBuf,
    last_seq: u64,
    last_hash: String,
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
                let entry: AuditEntry = serde_json::from_str(line)
                    .context("Failed to parse audit chain entry")?;
                last_seq = entry.seq;
                last_hash = entry.hash;
            }
            (last_seq, last_hash)
        } else {
            (0, GENESIS_HASH.to_string())
        };

        Ok(Self { path, last_seq, last_hash })
    }

    /// Append an alert to the chain
    pub fn append(&mut self, alert: &Alert) -> Result<AuditEntry> {
        let seq = self.last_seq + 1;
        let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let severity = alert.severity.to_string().to_lowercase();
        let source = &alert.source;
        let message = &alert.message;
        let prev_hash = &self.last_hash;

        let hash = AuditEntry::compute_hash(seq, &ts, &severity, source, message, prev_hash);

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
}

/// Run verify-audit subcommand
pub fn run_verify_audit(path: Option<&str>) -> Result<()> {
    let path = path.unwrap_or("/var/log/clawav/audit.chain");
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
    use std::io::Write;
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
