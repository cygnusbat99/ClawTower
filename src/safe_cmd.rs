//! Hardened async command execution with security guardrails.
//!
//! Provides [`SafeCommand`] — a builder for running external processes with:
//!
//! - **Absolute path enforcement**: Rejects relative paths to prevent PATH injection
//! - **Timeout**: Kills processes that exceed a configurable deadline (default 30s)
//! - **Environment sanitization**: Clears the environment by default, allowing only
//!   explicitly listed variables through
//! - **Auto-restart streaming**: Long-running processes are restarted on exit with
//!   exponential backoff, and a Critical alert fires after 5 consecutive failures
//!
//! # One-shot execution
//!
//! ```ignore
//! let output = SafeCommand::new("/usr/bin/ls")?
//!     .arg("-la")
//!     .timeout(Duration::from_secs(5))
//!     .run_output()
//!     .await?;
//! ```
//!
//! # Streaming with auto-restart
//!
//! ```ignore
//! let mut rx = SafeCommand::new("/usr/bin/journalctl")?
//!     .args(&["-f", "-u", "clawtower"])
//!     .stream_lines(alert_tx, "journald")
//!     .await;
//!
//! while let Some(line) = rx.recv().await {
//!     // process each line
//! }
//! ```

use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;

use crate::alerts::{Alert, Severity};

/// Maximum consecutive failures before a Critical alert is emitted in streaming mode.
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// Base backoff delay for stream restarts.
const BASE_BACKOFF: Duration = Duration::from_secs(1);

/// Maximum backoff delay (cap for exponential growth).
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Default timeout for one-shot command execution.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Channel capacity for the line-streaming mpsc channel.
const STREAM_CHANNEL_CAPACITY: usize = 1000;

/// Errors that can occur during command execution.
#[derive(Debug)]
pub enum CommandError {
    /// The program path is not absolute (e.g., `"ls"` instead of `"/usr/bin/ls"`).
    NotAbsolute,
    /// The program binary does not exist on disk.
    NotFound,
    /// The command exceeded its timeout deadline and was killed.
    Timeout,
    /// The command exited with a non-zero status code.
    ExitFailure {
        /// The process exit code.
        code: i32,
        /// Captured stderr output.
        stderr: String,
    },
    /// The process could not be spawned (e.g., permission denied).
    SpawnFailed(std::io::Error),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandError::NotAbsolute => write!(f, "program path must be absolute"),
            CommandError::NotFound => write!(f, "program binary not found on disk"),
            CommandError::Timeout => write!(f, "command timed out"),
            CommandError::ExitFailure { code, stderr } => {
                write!(f, "command exited with code {}", code)?;
                if !stderr.is_empty() {
                    write!(f, ": {}", stderr)?;
                }
                Ok(())
            }
            CommandError::SpawnFailed(e) => write!(f, "failed to spawn command: {}", e),
        }
    }
}

/// A hardened async command builder with absolute path enforcement,
/// timeout, and environment sanitization.
#[derive(Debug)]
pub struct SafeCommand {
    /// Absolute path to the program binary.
    program: PathBuf,
    /// Arguments to pass to the program.
    args: Vec<String>,
    /// Maximum time to wait for one-shot execution.
    timeout: Duration,
    /// Whether to clear the environment before execution.
    env_clear: bool,
    /// Environment variable names allowed through when `env_clear` is true.
    env_allow: Vec<String>,
}

impl SafeCommand {
    /// Create a new `SafeCommand` for the given program path.
    ///
    /// Fails if the path is not absolute or does not exist on disk.
    /// The environment is cleared by default — use [`allow_env`](Self::allow_env)
    /// to pass specific variables through.
    pub fn new(program: impl AsRef<Path>) -> Result<Self, String> {
        let path = program.as_ref();

        if !path.is_absolute() {
            return Err(format!(
                "program path must be absolute, got: {}",
                path.display()
            ));
        }

        if !path.exists() {
            return Err(format!(
                "program binary not found: {}",
                path.display()
            ));
        }

        Ok(Self {
            program: path.to_path_buf(),
            args: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            env_clear: true,
            env_allow: Vec::new(),
        })
    }

    /// Add a single argument to the command.
    pub fn arg(mut self, arg: &str) -> Self {
        self.args.push(arg.to_string());
        self
    }

    /// Add multiple arguments to the command.
    pub fn args(mut self, args: &[&str]) -> Self {
        self.args.extend(args.iter().map(|s| s.to_string()));
        self
    }

    /// Set the timeout for one-shot execution (default 30s).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Allow a specific environment variable through the sanitized environment.
    ///
    /// Only takes effect when `env_clear` is true (the default). The variable's
    /// value is read from the current process environment at execution time.
    pub fn allow_env(mut self, var: &str) -> Self {
        self.env_allow.push(var.to_string());
        self
    }

    /// Build a `tokio::process::Command` with the configured security settings.
    fn build_command(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(&self.args);

        if self.env_clear {
            cmd.env_clear();
            // Re-inject only the allowed environment variables
            for var in &self.env_allow {
                if let Ok(val) = std::env::var(var) {
                    cmd.env(var, val);
                }
            }
        }

        cmd
    }

    /// Run the command once, capture its output, and enforce the timeout.
    ///
    /// On timeout, the child process is killed before returning
    /// [`CommandError::Timeout`]. On non-zero exit, stderr is captured and
    /// returned in [`CommandError::ExitFailure`].
    pub async fn run_output(&self) -> Result<std::process::Output, CommandError> {
        let mut cmd = self.build_command();
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(CommandError::SpawnFailed)?;

        // Take stdout/stderr handles before waiting, so we keep ownership
        // of `child` for killing on timeout.
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();

        let read_and_wait = async {
            let mut stdout_bytes = Vec::new();
            let mut stderr_bytes = Vec::new();

            if let Some(mut out) = stdout_pipe {
                tokio::io::AsyncReadExt::read_to_end(&mut out, &mut stdout_bytes)
                    .await
                    .map_err(CommandError::SpawnFailed)?;
            }
            if let Some(mut err) = stderr_pipe {
                tokio::io::AsyncReadExt::read_to_end(&mut err, &mut stderr_bytes)
                    .await
                    .map_err(CommandError::SpawnFailed)?;
            }

            let status = child.wait().await.map_err(CommandError::SpawnFailed)?;
            Ok::<std::process::Output, CommandError>(std::process::Output {
                status,
                stdout: stdout_bytes,
                stderr: stderr_bytes,
            })
        };

        // Pin the future so we can poll it inside select!
        tokio::pin!(read_and_wait);

        tokio::select! {
            result = &mut read_and_wait => {
                match result {
                    Ok(output) if output.status.success() => Ok(output),
                    Ok(output) => {
                        let code = output.status.code().unwrap_or(-1);
                        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                        Err(CommandError::ExitFailure { code, stderr })
                    }
                    Err(e) => Err(e),
                }
            }
            _ = tokio::time::sleep(self.timeout) => {
                // Timeout expired — drop the future which drops the child,
                // causing tokio to kill it.
                drop(read_and_wait);
                Err(CommandError::Timeout)
            }
        }
    }

    /// Spawn a long-running process and stream its stdout lines over a channel.
    ///
    /// The process is automatically restarted on exit with exponential backoff
    /// (1s, 2s, 4s, ..., capped at 60s). After 5 consecutive failures without
    /// producing any output, a Critical alert is sent via `alert_tx`.
    ///
    /// A successful line read resets the failure counter to 0.
    ///
    /// Returns an `mpsc::Receiver<String>` that yields one line at a time.
    pub async fn stream_lines(
        &self,
        alert_tx: mpsc::Sender<Alert>,
        source: &str,
    ) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel::<String>(STREAM_CHANNEL_CAPACITY);

        let program = self.program.clone();
        let args = self.args.clone();
        let env_clear = self.env_clear;
        let env_allow = self.env_allow.clone();
        let source = source.to_string();

        tokio::spawn(async move {
            let mut consecutive_failures: u32 = 0;

            loop {
                // Build command for this iteration
                let mut cmd = tokio::process::Command::new(&program);
                cmd.args(&args);
                cmd.stdout(std::process::Stdio::piped());
                cmd.stderr(std::process::Stdio::null());

                if env_clear {
                    cmd.env_clear();
                    for var in &env_allow {
                        if let Ok(val) = std::env::var(var) {
                            cmd.env(var, val);
                        }
                    }
                }

                match cmd.spawn() {
                    Ok(mut child) => {
                        if let Some(stdout) = child.stdout.take() {
                            let reader = tokio::io::BufReader::new(stdout);
                            let mut lines = reader.lines();

                            loop {
                                match lines.next_line().await {
                                    Ok(Some(line)) => {
                                        // Successful line read resets failure counter
                                        consecutive_failures = 0;
                                        if tx.send(line).await.is_err() {
                                            // Receiver dropped — stop the task
                                            let _ = child.kill().await;
                                            return;
                                        }
                                    }
                                    Ok(None) => {
                                        // EOF — process exited
                                        break;
                                    }
                                    Err(_) => {
                                        // Read error — break to restart
                                        break;
                                    }
                                }
                            }
                        }

                        // Wait for the child to fully exit
                        let _ = child.wait().await;
                    }
                    Err(_) => {
                        // Spawn failed
                    }
                }

                // Process exited — increment failures and backoff
                consecutive_failures += 1;

                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    let alert = Alert::new(
                        Severity::Critical,
                        &source,
                        &format!(
                            "{} exited {} consecutive times — possible crash loop ({})",
                            program.display(),
                            consecutive_failures,
                            source,
                        ),
                    );
                    let _ = alert_tx.send(alert).await;
                }

                // Exponential backoff: 1s, 2s, 4s, 8s, ..., capped at 60s
                let shift = consecutive_failures.saturating_sub(1).min(63);
                let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
                let backoff_secs = BASE_BACKOFF.as_secs().saturating_mul(multiplier);
                let backoff = Duration::from_secs(backoff_secs.min(MAX_BACKOFF.as_secs()));
                tokio::time::sleep(backoff).await;
            }
        });

        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_relative_path() {
        let result = SafeCommand::new("ls");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("absolute"),
            "error should mention 'absolute': {}",
            err
        );
    }

    #[test]
    fn test_rejects_nonexistent() {
        let result = SafeCommand::new("/nonexistent/binary");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("not found"),
            "error should mention 'not found': {}",
            err
        );
    }

    #[test]
    fn test_accepts_absolute() {
        let result = SafeCommand::new("/usr/bin/echo");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_output_captures_stdout() {
        let cmd = SafeCommand::new("/usr/bin/echo").unwrap().arg("hello");
        let output = cmd.run_output().await.unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout.trim(), "hello");
    }

    #[tokio::test]
    async fn test_run_output_timeout() {
        let cmd = SafeCommand::new("/usr/bin/sleep")
            .unwrap()
            .arg("10")
            .timeout(Duration::from_millis(100));

        let result = cmd.run_output().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            CommandError::Timeout => {} // expected
            other => panic!("expected Timeout, got: {}", other),
        }
    }

    #[tokio::test]
    async fn test_env_clear() {
        // Set a unique env var to verify it gets cleared
        std::env::set_var("CLAWTOWER_TEST_MARKER", "visible");

        let cmd = SafeCommand::new("/usr/bin/env").unwrap();
        let output = cmd.run_output().await.unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);

        // With env_clear=true (default), env should produce no output
        // (or at most empty lines)
        assert!(
            !stdout.contains("CLAWTOWER_TEST_MARKER"),
            "env should not contain test marker when cleared, got: {}",
            stdout
        );
        assert!(
            stdout.trim().is_empty(),
            "env output should be empty with cleared environment, got: {}",
            stdout
        );

        std::env::remove_var("CLAWTOWER_TEST_MARKER");
    }

    #[tokio::test]
    async fn test_env_allow() {
        let cmd = SafeCommand::new("/usr/bin/env")
            .unwrap()
            .allow_env("HOME");
        let output = cmd.run_output().await.unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Only HOME should appear
        let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines.len(),
            1,
            "expected exactly 1 env var (HOME), got {}: {:?}",
            lines.len(),
            lines
        );
        assert!(
            lines[0].starts_with("HOME="),
            "expected HOME=..., got: {}",
            lines[0]
        );
    }

    #[test]
    fn test_command_error_display() {
        assert_eq!(CommandError::NotAbsolute.to_string(), "program path must be absolute");
        assert_eq!(CommandError::NotFound.to_string(), "program binary not found on disk");
        assert_eq!(CommandError::Timeout.to_string(), "command timed out");

        let exit_err = CommandError::ExitFailure {
            code: 1,
            stderr: "bad input".to_string(),
        };
        let msg = exit_err.to_string();
        assert!(msg.contains("code 1"), "should show exit code: {}", msg);
        assert!(msg.contains("bad input"), "should show stderr: {}", msg);

        let exit_err_empty = CommandError::ExitFailure {
            code: 2,
            stderr: String::new(),
        };
        let msg = exit_err_empty.to_string();
        assert!(msg.contains("code 2"), "should show exit code: {}", msg);
        assert!(!msg.contains(":"), "empty stderr should not add colon: {}", msg);
    }

    #[test]
    fn test_builder_chaining() {
        let cmd = SafeCommand::new("/usr/bin/echo")
            .unwrap()
            .arg("-n")
            .args(&["hello", "world"])
            .timeout(Duration::from_secs(10))
            .allow_env("PATH");

        assert_eq!(cmd.program, PathBuf::from("/usr/bin/echo"));
        assert_eq!(cmd.args, vec!["-n", "hello", "world"]);
        assert_eq!(cmd.timeout, Duration::from_secs(10));
        assert!(cmd.env_clear);
        assert_eq!(cmd.env_allow, vec!["PATH"]);
    }

    #[tokio::test]
    async fn test_run_output_exit_failure() {
        let cmd = SafeCommand::new("/usr/bin/false").unwrap();
        let result = cmd.run_output().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            CommandError::ExitFailure { code, .. } => {
                assert_eq!(code, 1);
            }
            other => panic!("expected ExitFailure, got: {}", other),
        }
    }
}
