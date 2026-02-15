use anyhow::{bail, Context, Result};
use std::env;

const BASE: &str = "http://127.0.0.1:18791";

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");

    let client = reqwest::blocking::Client::new();

    match cmd {
        "status" => {
            let resp = client
                .get(format!("{BASE}/api/status"))
                .send()
                .context("failed to reach clawav daemon")?;
            let body: serde_json::Value = resp.json().context("invalid JSON from daemon")?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        "toggle-pause" => {
            let resp = client
                .post(format!("{BASE}/api/pause/toggle"))
                .send()
                .context("failed to reach clawav daemon")?;
            let body = resp.text().context("failed to read response")?;
            eprintln!("{body}");
        }
        "stop" => {
            let _resp = client
                .post(format!("{BASE}/api/shutdown"))
                .send()
                .context("failed to reach clawav daemon")?;
            eprintln!("shutdown requested");
        }
        other => {
            bail!("unknown command: {other:?}\nUsage: clawav-ctl <status|toggle-pause|stop>");
        }
    }

    Ok(())
}
