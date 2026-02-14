use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::alerts::{Alert, Severity};

/// Shared alert store — thread-safe ring buffer
pub struct AlertRingBuffer {
    buf: VecDeque<Alert>,
    max: usize,
}

impl AlertRingBuffer {
    pub fn new(max: usize) -> Self {
        Self {
            buf: VecDeque::with_capacity(max),
            max,
        }
    }

    pub fn push(&mut self, alert: Alert) {
        if self.buf.len() >= self.max {
            self.buf.pop_front();
        }
        self.buf.push_back(alert);
    }

    pub fn last_n(&self, n: usize) -> Vec<&Alert> {
        self.buf.iter().rev().take(n).collect::<Vec<_>>().into_iter().rev().collect()
    }

    pub fn count_by_source(&self) -> std::collections::HashMap<String, usize> {
        let mut m = std::collections::HashMap::new();
        for a in &self.buf {
            *m.entry(a.source.clone()).or_insert(0) += 1;
        }
        m
    }

    pub fn count_by_severity(&self) -> (usize, usize, usize) {
        let (mut info, mut warn, mut crit) = (0, 0, 0);
        for a in &self.buf {
            match a.severity {
                Severity::Info => info += 1,
                Severity::Warning => warn += 1,
                Severity::Critical => crit += 1,
            }
        }
        (info, warn, crit)
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }
}

pub type SharedAlertStore = Arc<Mutex<AlertRingBuffer>>;

pub fn new_shared_store(max: usize) -> SharedAlertStore {
    Arc::new(Mutex::new(AlertRingBuffer::new(max)))
}

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
    uptime_seconds: u64,
    version: &'static str,
    modules: Modules,
}

#[derive(Serialize)]
struct Modules {
    auditd: bool,
    network: bool,
    behavior: bool,
    firewall: bool,
}

#[derive(Serialize)]
struct AlertJson {
    ts: String,
    severity: String,
    source: String,
    message: String,
}

#[derive(Serialize)]
struct SecurityResponse {
    uptime_seconds: u64,
    total_alerts: usize,
    alerts_by_severity: SeverityCounts,
    alerts_by_source: std::collections::HashMap<String, usize>,
}

#[derive(Serialize)]
struct SeverityCounts {
    info: usize,
    warning: usize,
    critical: usize,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn json_response(status: StatusCode, body: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .body(Body::from(body))
        .unwrap()
}

async fn handle(
    req: Request<Body>,
    store: SharedAlertStore,
    start_time: Instant,
) -> Result<Response<Body>, Infallible> {
    let resp = match req.uri().path() {
        "/" => {
            let html = r#"<!DOCTYPE html><html><head><title>ClawAV</title></head><body>
<h1>&#128737; ClawAV is running</h1>
<ul>
<li><a href="/api/status">/api/status</a> — System status</li>
<li><a href="/api/alerts">/api/alerts</a> — Recent alerts</li>
<li><a href="/api/security">/api/security</a> — Security posture</li>
</ul></body></html>"#;
            Response::builder()
                .header("Content-Type", "text/html")
                .body(Body::from(html))
                .unwrap()
        }
        "/api/status" => {
            let resp = StatusResponse {
                status: "running",
                uptime_seconds: start_time.elapsed().as_secs(),
                version: "0.3.0",
                modules: Modules {
                    auditd: true,
                    network: true,
                    behavior: true,
                    firewall: true,
                },
            };
            json_response(StatusCode::OK, serde_json::to_string(&resp).unwrap())
        }
        "/api/alerts" => {
            let store = store.lock().await;
            let alerts: Vec<AlertJson> = store
                .last_n(100)
                .into_iter()
                .map(|a| AlertJson {
                    ts: a.timestamp.to_rfc3339(),
                    severity: a.severity.to_string(),
                    source: a.source.clone(),
                    message: a.message.clone(),
                })
                .collect();
            json_response(StatusCode::OK, serde_json::to_string(&alerts).unwrap())
        }
        "/api/security" => {
            let store = store.lock().await;
            let (info, warn, crit) = store.count_by_severity();
            let resp = SecurityResponse {
                uptime_seconds: start_time.elapsed().as_secs(),
                total_alerts: store.len(),
                alerts_by_severity: SeverityCounts {
                    info,
                    warning: warn,
                    critical: crit,
                },
                alerts_by_source: store.count_by_source(),
            };
            json_response(StatusCode::OK, serde_json::to_string(&resp).unwrap())
        }
        _ => {
            let err = ErrorResponse {
                error: "not found".to_string(),
            };
            json_response(StatusCode::NOT_FOUND, serde_json::to_string(&err).unwrap())
        }
    };
    Ok(resp)
}

pub async fn run_api_server(bind: &str, port: u16, store: SharedAlertStore) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;
    let start_time = Instant::now();

    let make_svc = make_service_fn(move |_conn| {
        let store = store.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle(req, store.clone(), start_time)
            }))
        }
    });

    eprintln!("API server listening on {}", addr);
    Server::bind(&addr).serve(make_svc).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::{Alert, Severity};

    #[test]
    fn test_ring_buffer_capacity() {
        let mut buf = AlertRingBuffer::new(1000);
        for i in 0..1001 {
            buf.push(Alert::new(Severity::Info, "test", &format!("msg {}", i)));
        }
        assert_eq!(buf.len(), 1000);
        // Oldest (msg 0) should be dropped, first should be msg 1
        let alerts = buf.last_n(1000);
        assert_eq!(alerts[0].message, "msg 1");
        assert_eq!(alerts[999].message, "msg 1000");
    }

    #[test]
    fn test_alert_json_serialization() {
        let alert = Alert::new(Severity::Critical, "auditd", "privilege escalation detected");
        let json_alert = AlertJson {
            ts: alert.timestamp.to_rfc3339(),
            severity: alert.severity.to_string(),
            source: alert.source.clone(),
            message: alert.message.clone(),
        };
        let json = serde_json::to_string(&json_alert).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["severity"], "CRIT");
        assert_eq!(parsed["source"], "auditd");
        assert_eq!(parsed["message"], "privilege escalation detected");
        assert!(parsed["ts"].as_str().is_some());
    }

    #[test]
    fn test_count_by_severity() {
        let mut buf = AlertRingBuffer::new(100);
        buf.push(Alert::new(Severity::Info, "a", "x"));
        buf.push(Alert::new(Severity::Warning, "b", "y"));
        buf.push(Alert::new(Severity::Critical, "c", "z"));
        buf.push(Alert::new(Severity::Info, "d", "w"));
        let (info, warn, crit) = buf.count_by_severity();
        assert_eq!(info, 2);
        assert_eq!(warn, 1);
        assert_eq!(crit, 1);
    }
}
