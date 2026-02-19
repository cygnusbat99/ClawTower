// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! ClawTower — Tamper-proof security watchdog for AI agents.
//!
//! This is the main entry point. It handles CLI argument parsing, privilege
//! escalation, config loading, and delegates to the [`orchestrator`] for
//! the long-lived watchdog runtime.
//!
//! The architecture is a channel pipeline:
//! Sources → raw_tx → Aggregator → alert_tx → TUI/headless + slack_tx → Slack

mod admin;
mod agent_profile;
mod alerts;
mod aggregator;
mod app_state;
mod apparmor;
mod capabilities;
mod agent_envelope;
mod cli;
mod correlator;
mod detect;
mod export;
mod memory_sentinel;
mod orchestrator;
mod process_cage;
mod api;
mod audit_chain;
mod auth_hooks;
mod auditd;
mod behavior;
mod cloud;
mod cognitive;
mod compliance;
mod config;
mod config_merge;
mod sentinel;
mod falco;
mod firewall;
mod identity;
mod journald;
mod logtamper;
mod netpolicy;
mod network;
mod openclaw_config;
mod policy;
mod prompt_firewall;
mod proxy;
mod runtime;
mod safe_cmd;
mod safe_io;
mod safe_match;
mod safe_tail;
mod samhain;
mod scanner;
mod sources;
mod forensics;
mod seccomp;
mod barnacle;
mod slack;
mod tui;
mod response;
mod update;
mod util;

#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod adversarial_tests;
#[cfg(test)]
mod benchmarks;

use anyhow::Result;
use config::Config;
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    // Auth FIRST, before any async runtime
    cli::ensure_root();

    // Now start tokio and run the app
    tokio::runtime::Runtime::new()?.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(|s| s.as_str()).unwrap_or("run");
    let rest_args: Vec<String> = args.iter().skip(2).cloned().collect();

    // Dispatch CLI subcommands (install, scan, harden, etc.)
    if cli::dispatch_subcommand(subcommand, &rest_args, &args).await? {
        return Ok(());
    }

    // ── Watchdog startup ────────────────────────────────────────────────────
    let run_args: Vec<&String> = if subcommand == "run" {
        rest_args.iter().collect()
    } else {
        args.iter().skip(1).collect()
    };

    let config_path = run_args.iter()
        .find(|a| !a.starts_with("--"))
        .map(|s| PathBuf::from(s.as_str()))
        .unwrap_or_else(|| PathBuf::from("/etc/clawtower/config.toml"));

    let headless = run_args.iter().any(|a| a.as_str() == "--headless")
        || unsafe { libc::isatty(0) == 0 };

    let profile_name: Option<String> = run_args.iter().find_map(|a| {
        a.strip_prefix("--profile=").map(|s| s.to_string())
    });

    // If running in TUI mode, stop the background service to avoid port/socket conflicts
    if !headless {
        let service_was_running = std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "clawtower"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if service_was_running {
            eprintln!("Stopping clawtower service for TUI mode...");
            let _ = std::process::Command::new("sudo")
                .args(["systemctl", "stop", "clawtower"])
                .status();
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        if service_was_running {
            std::env::set_var("CLAWTOWER_RESTART_SERVICE", "1");
        }
    }

    let config_d = config_path.parent()
        .unwrap_or(Path::new("/etc/clawtower"))
        .join("config.d");

    let profile_path: Option<PathBuf> = profile_name.as_ref().map(|name| {
        let system_path = PathBuf::from(format!("/etc/clawtower/profiles/{}.toml", name));
        if system_path.exists() { system_path }
        else { PathBuf::from(format!("profiles/{}.toml", name)) }
    });

    let config = Config::load_with_profile_and_overrides(
        &config_path,
        profile_path.as_deref(),
        &config_d,
    )?;
    if let Some(ref name) = profile_name {
        eprintln!("Config loaded with profile '{}' (overlays from {})", name, config_d.display());
    } else {
        eprintln!("Config loaded (with overlays from {})", config_d.display());
    }

    // Build state and hand off to orchestrator
    let (state, receivers) = app_state::AppState::build(config, config_path, profile_name, headless);
    orchestrator::run_watchdog(state, receivers).await
}
