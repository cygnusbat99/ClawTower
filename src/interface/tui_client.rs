// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! TUI client mode — connects to a running ClawTower service's API instead of
//! starting local monitoring sources.
//!
//! When the headless service is already running with an accessible API, the TUI
//! enters client mode: it creates the same channels/stores that [`tui::run_tui`]
//! expects, but feeds them from background HTTP polling tasks.
//!
//! ```text
//! Normal mode:  Sources → Aggregator → alert_tx → run_tui()
//! Client mode:  API polling tasks → alert_tx → run_tui()
//! ```

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::{DateTime, FixedOffset, Local};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::core::alerts::{Alert, Severity};
use crate::config::Config;
use crate::core::response::{
    ContainmentAction, PendingAction, PendingStatus, ResponseMode, ResponseRequest,
};
use crate::scanner::{ScanResult, ScanStatus};
use crate::tui;

// ── Public entry points ─────────────────────────────────────────────────────

/// Probe the service API to check if it's reachable (2s timeout).
pub async fn service_api_reachable(bind: &str, port: u16) -> bool {
    let url = format!("http://{}:{}/api/health", bind, port);
    let client = match Client::builder().timeout(Duration::from_secs(2)).build() {
        Ok(c) => c,
        Err(_) => return false,
    };
    client
        .get(&url)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Run the TUI in client mode, polling the running service's API.
pub async fn run_client_tui(config: &Config, config_path: PathBuf) -> Result<()> {
    let connect_addr = if config.api.bind == "0.0.0.0" {
        "127.0.0.1"
    } else {
        &config.api.bind
    };
    let base_url = format!("http://{}:{}", connect_addr, config.api.port);
    let auth_token = config.api.auth_token.clone();

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // Create the same channels/stores that run_tui() expects
    let (alert_tx, alert_rx) = mpsc::channel::<Alert>(1000);
    let pending_actions = crate::core::response::new_shared_pending();
    let scan_results = crate::scanner::new_shared_scan_results();
    let (response_tx, response_rx) = mpsc::channel::<ResponseRequest>(100);

    // Spawn background polling tasks
    spawn_alert_poller(
        client.clone(),
        base_url.clone(),
        auth_token.clone(),
        alert_tx.clone(),
    );
    spawn_pending_poller(
        client.clone(),
        base_url.clone(),
        auth_token.clone(),
        pending_actions.clone(),
    );
    spawn_scan_poller(
        client.clone(),
        base_url.clone(),
        auth_token.clone(),
        scan_results.clone(),
    );
    spawn_approval_bridge(client, base_url, auth_token, response_rx);

    // Synthetic startup alert
    let _ = alert_tx
        .send(Alert::new(
            Severity::Info,
            "system",
            "TUI connected in client mode (service running)",
        ))
        .await;

    tui::run_tui(
        alert_rx,
        Some(config_path),
        pending_actions,
        Some(response_tx),
        Some(scan_results),
        None,
        None,
    )
    .await
}

// ── API deserialization structs ─────────────────────────────────────────────

#[derive(Deserialize)]
struct ApiAlert {
    ts: String,
    severity: String,
    source: String,
    message: String,
}

#[derive(Deserialize)]
struct ApiPendingAction {
    id: String,
    threat_source: String,
    threat_message: String,
    severity: String,
    mode: ResponseMode,
    actions: Vec<String>,
    playbook: Option<String>,
    status: PendingStatus,
    age_seconds: u64,
}

#[derive(Deserialize)]
struct ApiScanResult {
    category: String,
    status: String,
    details: String,
    timestamp: String,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Build a GET request with optional Bearer auth.
fn authed_get(client: &Client, url: &str, auth_token: &str) -> reqwest::RequestBuilder {
    let req = client.get(url);
    if auth_token.is_empty() {
        req
    } else {
        req.bearer_auth(auth_token)
    }
}

/// Parse a containment action display string back into the enum.
fn parse_action_string(s: &str) -> Option<ContainmentAction> {
    if s == "revoke_api_keys" {
        return Some(ContainmentAction::RevokeApiKeys);
    }
    if s == "lock_clawsudo" {
        return Some(ContainmentAction::LockClawsudo);
    }
    if let Some(rest) = s.strip_prefix("kill_process(pid=") {
        let pid: u32 = rest.strip_suffix(')')?.parse().ok()?;
        return Some(ContainmentAction::KillProcess { pid });
    }
    if let Some(rest) = s.strip_prefix("suspend_process(pid=") {
        let pid: u32 = rest.strip_suffix(')')?.parse().ok()?;
        return Some(ContainmentAction::SuspendProcess { pid });
    }
    if let Some(rest) = s.strip_prefix("drop_network(uid=") {
        let uid: u32 = rest.strip_suffix(')')?.parse().ok()?;
        return Some(ContainmentAction::DropNetwork { uid });
    }
    if s.starts_with("freeze_filesystem(") {
        return Some(ContainmentAction::FreezeFilesystem { paths: vec![] });
    }
    None
}

fn api_pending_to_pending_action(api: ApiPendingAction) -> PendingAction {
    PendingAction {
        id: api.id,
        threat_source: api.threat_source,
        threat_message: api.threat_message,
        severity: Severity::from_str(&api.severity),
        mode: api.mode,
        actions: api
            .actions
            .iter()
            .filter_map(|s| parse_action_string(s))
            .collect(),
        playbook: api.playbook,
        created_at: Instant::now()
            .checked_sub(Duration::from_secs(api.age_seconds))
            .unwrap_or_else(Instant::now),
        timeout: Duration::from_secs(120),
        status: api.status,
    }
}

fn api_scan_to_scan_result(api: ApiScanResult) -> ScanResult {
    let status = match api.status.as_str() {
        "Pass" => ScanStatus::Pass,
        "Fail" => ScanStatus::Fail,
        _ => ScanStatus::Warn,
    };
    let mut result = ScanResult::new(&api.category, status, &api.details);
    if let Ok(ts) = DateTime::parse_from_rfc3339(&api.timestamp) {
        result.timestamp = ts.with_timezone(&Local);
    }
    result
}

// ── Background polling tasks ────────────────────────────────────────────────

fn spawn_alert_poller(
    client: Client,
    base_url: String,
    auth_token: String,
    alert_tx: mpsc::Sender<Alert>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        let mut last_seen_ts: Option<DateTime<FixedOffset>> = None;
        let mut consecutive_failures: u32 = 0;
        let mut disconnected = false;

        loop {
            interval.tick().await;

            let url = format!("{}/api/alerts", base_url);
            let resp = authed_get(&client, &url, &auth_token).send().await;

            match resp {
                Ok(r) if r.status().is_success() => {
                    if disconnected {
                        disconnected = false;
                        let _ = alert_tx
                            .send(Alert::new(
                                Severity::Info,
                                "client",
                                "Connection to ClawTower API restored",
                            ))
                            .await;
                    }
                    consecutive_failures = 0;

                    if let Ok(alerts) = r.json::<Vec<ApiAlert>>().await {
                        for api_alert in &alerts {
                            if let Ok(ts) = DateTime::parse_from_rfc3339(&api_alert.ts) {
                                if last_seen_ts.map(|last| ts > last).unwrap_or(true) {
                                    let alert = Alert::new(
                                        Severity::from_str(&api_alert.severity),
                                        &api_alert.source,
                                        &api_alert.message,
                                    );
                                    let _ = alert_tx.send(alert).await;
                                    last_seen_ts = Some(ts);
                                }
                            }
                        }
                    }
                }
                _ => {
                    consecutive_failures += 1;
                    if consecutive_failures >= 3 && !disconnected {
                        disconnected = true;
                        let _ = alert_tx
                            .send(Alert::new(
                                Severity::Warning,
                                "client",
                                "Connection to ClawTower API lost (retrying...)",
                            ))
                            .await;
                    }
                }
            }
        }
    });
}

fn spawn_pending_poller(
    client: Client,
    base_url: String,
    auth_token: String,
    pending_store: crate::core::response::SharedPendingActions,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;

            let url = format!("{}/api/pending", base_url);
            let resp = authed_get(&client, &url, &auth_token).send().await;

            if let Ok(r) = resp {
                if r.status().is_success() {
                    if let Ok(items) = r.json::<Vec<ApiPendingAction>>().await {
                        let actions: Vec<PendingAction> =
                            items.into_iter().map(api_pending_to_pending_action).collect();
                        let mut store = pending_store.lock().await;
                        *store = actions;
                    }
                }
            }
        }
    });
}

fn spawn_scan_poller(
    client: Client,
    base_url: String,
    auth_token: String,
    scan_store: crate::scanner::SharedScanResults,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;

            let url = format!("{}/api/scans", base_url);
            let resp = authed_get(&client, &url, &auth_token).send().await;

            if let Ok(r) = resp {
                if r.status().is_success() {
                    if let Ok(items) = r.json::<Vec<ApiScanResult>>().await {
                        let results: Vec<ScanResult> =
                            items.into_iter().map(api_scan_to_scan_result).collect();
                        let mut store = scan_store.lock().await;
                        *store = results;
                    }
                }
            }
        }
    });
}

fn spawn_approval_bridge(
    client: Client,
    base_url: String,
    auth_token: String,
    mut response_rx: mpsc::Receiver<ResponseRequest>,
) {
    tokio::spawn(async move {
        while let Some(req) = response_rx.recv().await {
            if let ResponseRequest::Resolve {
                id,
                approved,
                by,
                message,
                surface: _,
            } = req
            {
                let action = if approved { "approve" } else { "deny" };
                let url = format!("{}/api/pending/{}/{}", base_url, id, action);
                let body = serde_json::json!({ "by": by, "message": message });
                let mut req_builder = client.post(&url);
                if !auth_token.is_empty() {
                    req_builder = req_builder.bearer_auth(&auth_token);
                }
                let _ = req_builder.json(&body).send().await;
            }
        }
    });
}
