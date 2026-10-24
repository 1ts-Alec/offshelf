//! HTTP client for oshelfd: signs every request with the device key and
//! checks the Pi's signature on every buffered response.

use std::io::Read;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context};
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use oshelf_core::auth;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
/// Largest response body read into memory (a full page of log entries).
const MAX_BODY: u64 = 40 << 20;

pub struct Client {
    /// Switchable: the Mac app moves between home and tunnel addresses.
    base: RwLock<String>,
    last_ts: std::sync::Mutex<i64>,
    device_id: [u8; 16],
    key: SigningKey,
    server_key: VerifyingKey,
    agent: ureq::Agent,
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::from_slice(&self.body)?)
    }

    pub fn ok(self) -> anyhow::Result<Self> {
        if (200..300).contains(&self.status) {
            return Ok(self);
        }
        let msg = self
            .json()
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_owned))
            .unwrap_or_else(|| String::from_utf8_lossy(&self.body).into_owned());
        bail!("server answered {}: {msg}", self.status)
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(10))
        .timeout_read(std::time::Duration::from_secs(120))
        .build()
}

/// Sends a request and collects the reply whatever its status.
fn send(
    agent: &ureq::Agent,
    method: &str,
    url: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> anyhow::Result<Reply> {
    let mut req = agent.request(method, url);
    for (k, v) in headers {
        req = req.set(k, v);
    }
    let res = match req.send_bytes(body) {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(anyhow!(e).context(format!("{method} {url}"))),
    };
    let status = res.status();
    let headers = res
        .headers_names()
        .into_iter()
        .filter_map(|n| res.header(&n).map(|v| (n.clone(), v.to_string())))
        .collect();
    let mut body = Vec::new();
    res.into_reader().take(MAX_BODY).read_to_end(&mut body)?;
    Ok(Reply { status, headers, body })
}

/// Unsigned call used only for pairing and health.
pub fn post_json(base: &str, path: &str, value: &serde_json::Value) -> anyhow::Result<Reply> {
    send(
        &agent(),
        "POST",
        &format!("{}{path}", base.trim_end_matches('/')),
        &[("content-type", "application/json".into())],
        value.to_string().as_bytes(),
    )
}

impl Client {
    pub fn new(base: &str, device_id: [u8; 16], key: SigningKey, server_key: VerifyingKey) -> Self {
        Self {
            base: RwLock::new(base.trim_end_matches('/').to_string()),
            last_ts: std::sync::Mutex::new(0),
            device_id,
            key,
            server_key,
            agent: agent(),
        }
    }

    pub fn base(&self) -> String {
        self.base.read().expect("base lock").clone()
    }

    /// Points later requests at another address of the same Pi. Responses
    /// are still checked against the pinned server key.
    pub fn set_base(&self, base: &str) {
        *self.base.write().expect("base lock") = base.trim_end_matches('/').to_string();
    }

    fn authorization(&self, method: &str, path: &str, body: &[u8]) -> ([u8; 64], String) {
        // Strictly increasing per client: two identical requests in the same
        // millisecond would otherwise carry the same signature, and the Pi
        // rejects the second as a replay.
        let ts = {
            let mut last = self.last_ts.lock().expect("ts lock");
            *last = now_ms().max(*last + 1);
            *last
        };
        let sig = auth::sign_request(&self.key, method, path, ts, body);
        let header = format!(
            "{} device={}, ts={ts}, sig={}",
            auth::SCHEME,
            hex::encode(self.device_id),
            B64.encode(sig)
        );
        (sig, header)
    }

    /// Signed GET whose body is read as it arrives (the event stream).
    /// `idle` bounds the wait for each read, so a dead link shows up.
    pub fn get_stream(&self, path: &str, idle: std::time::Duration) -> anyhow::Result<Box<dyn Read + Send>> {
        let (_, authorization) = self.authorization("GET", path, &[]);
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(10))
            .timeout_read(idle)
            .build();
        let url = format!("{}{path}", self.base());
        match agent.get(&url).set("authorization", &authorization).call() {
            Ok(r) => Ok(Box::new(r.into_reader())),
            Err(ureq::Error::Status(code, _)) => bail!("server answered {code} for {path}"),
            Err(e) => Err(anyhow!(e).context(format!("GET {url}"))),
        }
    }

    /// Signed request. `streamed` replies (ranged chunk reads) carry no
    /// server signature; their contents are checked against chunk ids.
    fn call(
        &self,
        method: &str,
        path: &str,
        extra: &[(&str, String)],
        body: &[u8],
        streamed: bool,
    ) -> anyhow::Result<Reply> {
        let (sig, authorization) = self.authorization(method, path, body);
        let mut headers = vec![("authorization", authorization)];
        headers.extend(extra.iter().cloned());
        let reply = send(&self.agent, method, &format!("{}{path}", self.base()), &headers, body)?;
        if reply.status == 401 {
            return reply.ok();
        }
        if !streamed {
            let server_sig: [u8; 64] = reply
                .header("x-oshelf-sig")
                .and_then(|v| B64.decode(v).ok())
                .and_then(|v| v.try_into().ok())
                .context("response from the Pi is not signed")?;
            if !auth::verify_response(&self.server_key, &sig, reply.status, &reply.body, &server_sig) {
                bail!("response signature doesn't match the Pi this device paired with");
            }
        }
        Ok(reply)
    }

    pub fn get(&self, path: &str) -> anyhow::Result<Reply> {
        self.call("GET", path, &[], &[], false)
    }

    pub fn get_streamed(&self, path: &str) -> anyhow::Result<Reply> {
        self.call("GET", path, &[], &[], true)
    }

    pub fn post(&self, path: &str, headers: &[(&str, String)], body: &[u8]) -> anyhow::Result<Reply> {
        self.call("POST", path, headers, body, false)
    }

    pub fn post_json(&self, path: &str, v: &serde_json::Value) -> anyhow::Result<Reply> {
        self.post(
            path,
            &[("content-type", "application/json".into())],
            v.to_string().as_bytes(),
        )
    }

    pub fn put(&self, path: &str, headers: &[(&str, String)], body: &[u8]) -> anyhow::Result<Reply> {
        self.call("PUT", path, headers, body, false)
    }

    pub fn delete(&self, path: &str) -> anyhow::Result<Reply> {
        self.call("DELETE", path, &[], &[], false)
    }
}

/// Splits a framed body (`u32le len || bytes`, repeated).
pub fn frames(mut body: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    while !body.is_empty() {
        anyhow::ensure!(body.len() >= 4, "truncated frame");
        let len = u32::from_le_bytes(body[0..4].try_into().expect("4 bytes")) as usize;
        anyhow::ensure!(body.len() >= 4 + len, "truncated frame");
        out.push(body[4..4 + len].to_vec());
        body = &body[4 + len..];
    }
    Ok(out)
}

/// Splits framed log entries (`u64le revision || u32le len || bytes`).
pub fn log_frames(mut body: &[u8]) -> anyhow::Result<Vec<(u64, Vec<u8>)>> {
    let mut out = Vec::new();
    while !body.is_empty() {
        anyhow::ensure!(body.len() >= 12, "truncated log frame");
        let rev = u64::from_le_bytes(body[0..8].try_into().expect("8 bytes"));
        let len = u32::from_le_bytes(body[8..12].try_into().expect("4 bytes")) as usize;
        anyhow::ensure!(body.len() >= 12 + len, "truncated log frame");
        out.push((rev, body[12..12 + len].to_vec()));
        body = &body[12 + len..];
    }
    Ok(out)
}
