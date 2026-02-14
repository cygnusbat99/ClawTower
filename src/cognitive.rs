use anyhow::Result;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::scanner::{ScanResult, ScanStatus};

/// Cognitive files that control agent behavior
const COGNITIVE_FILES: &[&str] = &[
    "SOUL.md",
    "IDENTITY.md", 
    "TOOLS.md",
    "AGENTS.md",
    "MEMORY.md",
    "USER.md",
    "HEARTBEAT.md",
];

/// Stores SHA-256 baselines for cognitive files
pub struct CognitiveBaseline {
    baselines: HashMap<PathBuf, String>,
    workspace_dir: PathBuf,
}

impl CognitiveBaseline {
    /// Create baselines from current state of files
    pub fn from_workspace(workspace_dir: &Path) -> Self {
        let mut baselines = HashMap::new();
        for filename in COGNITIVE_FILES {
            let path = workspace_dir.join(filename);
            if path.exists() {
                if let Ok(hash) = compute_sha256(&path) {
                    baselines.insert(path, hash);
                }
            }
        }
        Self {
            baselines,
            workspace_dir: workspace_dir.to_path_buf(),
        }
    }

    /// Load baselines from a saved file
    pub fn load(baseline_path: &Path, workspace_dir: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(baseline_path)?;
        let mut baselines = HashMap::new();
        for line in content.lines() {
            let parts: Vec<&str> = line.splitn(2, " ").collect();
            if parts.len() == 2 {
                baselines.insert(PathBuf::from(parts[1]), parts[0].to_string());
            }
        }
        Ok(Self {
            baselines,
            workspace_dir: workspace_dir.to_path_buf(),
        })
    }

    /// Save baselines to a file
    pub fn save(&self, baseline_path: &Path) -> Result<()> {
        let mut content = String::new();
        let mut sorted: Vec<_> = self.baselines.iter().collect();
        sorted.sort_by_key(|(p, _)| (*p).clone());
        for (path, hash) in sorted {
            content.push_str(&format!("{} {}\n", hash, path.display()));
        }
        if let Some(parent) = baseline_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(baseline_path, content)?;
        Ok(())
    }

    /// Check all cognitive files against baselines
    pub fn check(&self) -> Vec<CognitiveAlert> {
        let mut alerts = Vec::new();

        // Check for modified or deleted files
        for (path, expected_hash) in &self.baselines {
            if !path.exists() {
                alerts.push(CognitiveAlert {
                    file: path.clone(),
                    kind: CognitiveAlertKind::Deleted,
                });
            } else if let Ok(current_hash) = compute_sha256(path) {
                if &current_hash != expected_hash {
                    alerts.push(CognitiveAlert {
                        file: path.clone(),
                        kind: CognitiveAlertKind::Modified,
                    });
                }
            }
        }

        // Check for new cognitive files that weren't in baseline
        for filename in COGNITIVE_FILES {
            let path = self.workspace_dir.join(filename);
            if path.exists() && !self.baselines.contains_key(&path) {
                alerts.push(CognitiveAlert {
                    file: path,
                    kind: CognitiveAlertKind::NewFile,
                });
            }
        }

        alerts
    }

    /// Update baselines to current state
    pub fn rebaseline(&mut self) {
        self.baselines.clear();
        for filename in COGNITIVE_FILES {
            let path = self.workspace_dir.join(filename);
            if path.exists() {
                if let Ok(hash) = compute_sha256(&path) {
                    self.baselines.insert(path, hash);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct CognitiveAlert {
    pub file: PathBuf,
    pub kind: CognitiveAlertKind,
}

#[derive(Debug, Clone)]
pub enum CognitiveAlertKind {
    Modified,
    Deleted,
    NewFile,
}

impl std::fmt::Display for CognitiveAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let filename = self.file.file_name().unwrap_or_default().to_string_lossy();
        match self.kind {
            CognitiveAlertKind::Modified => write!(f, "{} has been modified", filename),
            CognitiveAlertKind::Deleted => write!(f, "{} has been deleted", filename),
            CognitiveAlertKind::NewFile => write!(f, "{} is new (no baseline)", filename),
        }
    }
}

fn compute_sha256(path: &Path) -> Result<String> {
    let data = std::fs::read(path)?;
    let hash = Sha256::digest(&data);
    Ok(hex::encode(hash))
}

/// Scanner integration: check cognitive file integrity
pub fn scan_cognitive_integrity(workspace_dir: &Path, baseline_path: &Path) -> ScanResult {
    // If no baseline exists yet, create one
    if !baseline_path.exists() {
        let baseline = CognitiveBaseline::from_workspace(workspace_dir);
        if baseline.baselines.is_empty() {
            return ScanResult::new("cognitive", ScanStatus::Warn, "No cognitive files found in workspace");
        }
        match baseline.save(baseline_path) {
            Ok(_) => return ScanResult::new("cognitive", ScanStatus::Pass, 
                &format!("Created baselines for {} cognitive files", baseline.baselines.len())),
            Err(e) => return ScanResult::new("cognitive", ScanStatus::Warn, 
                &format!("Cannot save baselines: {}", e)),
        }
    }

    // Load and check
    match CognitiveBaseline::load(baseline_path, workspace_dir) {
        Ok(baseline) => {
            let alerts = baseline.check();
            if alerts.is_empty() {
                ScanResult::new("cognitive", ScanStatus::Pass, "All cognitive files intact")
            } else {
                let details: Vec<String> = alerts.iter().map(|a| a.to_string()).collect();
                ScanResult::new("cognitive", ScanStatus::Fail, 
                    &format!("TAMPERING DETECTED: {}", details.join("; ")))
            }
        }
        Err(e) => ScanResult::new("cognitive", ScanStatus::Warn, 
            &format!("Cannot load baselines: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_baseline_creation() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "I am an agent").unwrap();
        fs::write(dir.path().join("IDENTITY.md"), "Name: Claw").unwrap();

        let baseline = CognitiveBaseline::from_workspace(dir.path());
        assert_eq!(baseline.baselines.len(), 2);
    }

    #[test]
    fn test_detect_modification() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "I am an agent").unwrap();

        let baseline = CognitiveBaseline::from_workspace(dir.path());

        // Modify the file
        fs::write(dir.path().join("SOUL.md"), "I am now evil").unwrap();

        let alerts = baseline.check();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].kind, CognitiveAlertKind::Modified));
    }

    #[test]
    fn test_detect_deletion() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "I am an agent").unwrap();

        let baseline = CognitiveBaseline::from_workspace(dir.path());

        // Delete the file
        fs::remove_file(dir.path().join("SOUL.md")).unwrap();

        let alerts = baseline.check();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].kind, CognitiveAlertKind::Deleted));
    }

    #[test]
    fn test_detect_new_file() {
        let dir = TempDir::new().unwrap();
        let baseline = CognitiveBaseline::from_workspace(dir.path());

        // Create a new cognitive file
        fs::write(dir.path().join("SOUL.md"), "surprise").unwrap();

        let alerts = baseline.check();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].kind, CognitiveAlertKind::NewFile));
    }

    #[test]
    fn test_no_changes_passes() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "I am an agent").unwrap();
        fs::write(dir.path().join("TOOLS.md"), "my tools").unwrap();

        let baseline = CognitiveBaseline::from_workspace(dir.path());
        let alerts = baseline.check();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_save_and_load() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "I am an agent").unwrap();

        let baseline = CognitiveBaseline::from_workspace(dir.path());
        let baseline_path = dir.path().join("baselines.sha256");
        baseline.save(&baseline_path).unwrap();

        let loaded = CognitiveBaseline::load(&baseline_path, dir.path()).unwrap();
        assert_eq!(loaded.baselines.len(), 1);

        let alerts = loaded.check();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_rebaseline() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "original").unwrap();

        let mut baseline = CognitiveBaseline::from_workspace(dir.path());
        fs::write(dir.path().join("SOUL.md"), "modified").unwrap();

        // Before rebaseline: detects change
        assert_eq!(baseline.check().len(), 1);

        // After rebaseline: clean
        baseline.rebaseline();
        assert!(baseline.check().is_empty());
    }
}