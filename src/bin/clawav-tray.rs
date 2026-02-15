use ksni::menu::*;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const POLL_INTERVAL: Duration = Duration::from_secs(10);
const API_BASE: &str = "http://127.0.0.1:18791";

#[derive(Debug, Clone, Default)]
struct TrayState {
    running: bool,
    paused: bool,
    alerts_critical: u32,
    alerts_warning: u32,
    alerts_total: u32,
    last_scan_mins: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct StatusResponse {
    #[serde(default)]
    paused: Option<bool>,
    #[serde(default)]
    alerts_critical: Option<u32>,
    #[serde(default)]
    alerts_warning: Option<u32>,
    #[serde(default)]
    alerts_total: Option<u32>,
    #[serde(default)]
    last_scan_epoch: Option<i64>,
}

/// Load embedded lobster PNG and convert RGBA → ARGB32 for ksni
fn lobster_icon() -> ksni::Icon {
    let png_bytes = include_bytes!("../../assets/lobster.png");
    let decoder = png::Decoder::new(std::io::Cursor::new(png_bytes));
    let mut reader = decoder.read_info().expect("PNG decode");
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).expect("PNG frame");
    let width = info.width as i32;
    let height = info.height as i32;

    let mut argb = vec![0u8; (width * height * 4) as usize];
    for i in 0..(width * height) as usize {
        let si = i * 4;
        argb[si] = buf[si + 3];     // A
        argb[si + 1] = buf[si];     // R
        argb[si + 2] = buf[si + 1]; // G
        argb[si + 3] = buf[si + 2]; // B
    }

    ksni::Icon { width, height, data: argb }
}

/// Run a command via pkexec (polkit GUI password prompt)
fn run_elevated(args: &[&str]) {
    let mut cmd = Command::new("pkexec");
    cmd.args(args);
    match cmd.status() {
        Ok(s) if s.success() => eprintln!("Elevated command succeeded: {:?}", args),
        Ok(s) => eprintln!("Elevated command failed ({}): {:?}", s, args),
        Err(e) => eprintln!("Failed to launch pkexec: {e}"),
    }
}

struct ClawAVTray {
    state: Arc<Mutex<TrayState>>,
}

impl ksni::Tray for ClawAVTray {
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![lobster_icon()]
    }

    fn title(&self) -> String {
        "ClawAV".into()
    }

    fn id(&self) -> String {
        "clawav-tray".into()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        let st = self.state.lock().unwrap();
        let status = if !st.running {
            "Stopped"
        } else if st.paused {
            "Paused"
        } else {
            "Running"
        };
        ksni::ToolTip {
            title: format!("ClawAV v{VERSION} — {status}"),
            description: format!("Alerts: {}", st.alerts_total),
            ..Default::default()
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let st = self.state.lock().unwrap();
        let status = if !st.running {
            "Stopped"
        } else if st.paused {
            "Paused"
        } else {
            "Running"
        };
        let last_scan = match st.last_scan_mins {
            Some(m) => format!("{m} min ago"),
            None => "N/A".into(),
        };
        let alert_label = if st.alerts_critical > 0 {
            format!("Alerts: {} ({} critical)", st.alerts_total, st.alerts_critical)
        } else {
            format!("Alerts: {}", st.alerts_total)
        };

        let pause_label = if st.paused {
            "Resume Monitoring \u{1f513}"
        } else {
            "Pause Monitoring \u{1f513}"
        };

        vec![
            // --- Status section ---
            StandardItem {
                label: format!("ClawAV v{VERSION} — {status}"),
                enabled: false,
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: alert_label,
                enabled: false,
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: format!("Last Scan: {last_scan}"),
                enabled: false,
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            // --- Actions ---
            StandardItem {
                label: "Open TUI".into(),
                activate: Box::new(|_| {
                    let _ = Command::new("x-terminal-emulator")
                        .args(["-e", "clawav"])
                        .spawn()
                        .or_else(|_| {
                            Command::new("lxterminal")
                                .args(["-e", "clawav"])
                                .spawn()
                        });
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Open Dashboard".into(),
                activate: Box::new(|_| {
                    let _ = Command::new("xdg-open").arg(API_BASE).spawn();
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Run Scan Now".into(),
                activate: Box::new(|_| {
                    thread::spawn(|| {
                        let _ = Client::new()
                            .post(format!("{API_BASE}/api/scan"))
                            .timeout(Duration::from_secs(5))
                            .send();
                    });
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            // --- Elevated actions (require password via pkexec) ---
            StandardItem {
                label: pause_label.into(),
                activate: Box::new(|_| {
                    thread::spawn(|| {
                        run_elevated(&["clawav-ctl", "toggle-pause"]);
                    });
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit \u{1f513}".into(),
                activate: Box::new(|_| {
                    thread::spawn(|| {
                        run_elevated(&["systemctl", "stop", "clawav"]);
                        std::process::exit(0);
                    });
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

fn poll_status(client: &Client, state: &Arc<Mutex<TrayState>>) {
    let health_ok = client
        .get(format!("{API_BASE}/api/health"))
        .timeout(Duration::from_secs(5))
        .send()
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    if !health_ok {
        let mut st = state.lock().unwrap();
        *st = TrayState::default();
        return;
    }

    let status: Option<StatusResponse> = client
        .get(format!("{API_BASE}/api/status"))
        .timeout(Duration::from_secs(5))
        .send()
        .ok()
        .and_then(|r| r.json().ok());

    let mut st = state.lock().unwrap();
    st.running = true;
    if let Some(s) = status {
        st.paused = s.paused.unwrap_or(false);
        st.alerts_critical = s.alerts_critical.unwrap_or(0);
        st.alerts_warning = s.alerts_warning.unwrap_or(0);
        st.alerts_total = s.alerts_total.unwrap_or(0);
        st.last_scan_mins = s.last_scan_epoch.map(|epoch| {
            let now = chrono::Utc::now().timestamp();
            ((now - epoch).max(0) / 60) as u64
        });
    }
}

fn main() {
    eprintln!("ClawAV Tray v{VERSION} starting...");

    let state = Arc::new(Mutex::new(TrayState::default()));
    let poll_state = Arc::clone(&state);

    // Background poller
    thread::spawn(move || {
        let client = Client::new();
        loop {
            poll_status(&client, &poll_state);
            thread::sleep(POLL_INTERVAL);
        }
    });

    let service = ksni::TrayService::new(ClawAVTray { state });
    if let Err(e) = service.run() {
        eprintln!("TrayService failed: {e}");
        std::process::exit(1);
    }
}
