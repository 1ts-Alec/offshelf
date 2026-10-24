//! Keeping the tree live and the link healthy: the revision event stream,
//! host selection by Wi-Fi network with ordered fallback, health checks,
//! and the periodic cache trim and auto offload.

use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oshelf_core::manifest::{Kind, Node, ROOT};

use crate::activity::Kind as EventKind;
use crate::engine::{human, now_ns, Engine};
use crate::settings::{Host, OffloadOrder};

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// The Pi sends a keep-alive every 15 s; three missed means the link is gone.
const STREAM_IDLE: Duration = Duration::from_secs(45);
const HEALTH_EVERY: Duration = Duration::from_secs(15);
const MAINTAIN_EVERY: Duration = Duration::from_secs(60);

/// Free and total bytes on the volume holding `path`.
pub fn disk_space(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is a valid C string and s a properly sized out parameter.
    if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let bs = s.f_bsize as u64;
    Some((s.f_bavail as u64 * bs, s.f_blocks as u64 * bs))
}

/// Times an unsigned health check against `url`.
pub fn probe(url: &str) -> Option<Duration> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(PROBE_TIMEOUT)
        .timeout(PROBE_TIMEOUT)
        .build();
    let t = Instant::now();
    agent
        .get(&format!("{}/v1/health", url.trim_end_matches('/')))
        .call()
        .ok()
        .map(|_| t.elapsed())
}

/// Hosts in the order to try them on Wi-Fi `ssid`: hosts whose rules match
/// first, then everything else down the list. Falling back to non-matching
/// hosts keeps the shelf reachable when the network name is unknown (no
/// Wi-Fi, or no permission to read it).
pub fn host_order(hosts: &[Host], ssid: Option<&str>) -> Vec<Host> {
    let matches = |h: &Host| ssid.is_some_and(|s| h.ssids.iter().any(|x| x == s));
    let mut out: Vec<Host> = hosts.iter().filter(|h| matches(h)).cloned().collect();
    out.extend(hosts.iter().filter(|h| !matches(h)).cloned());
    out
}

impl Engine {
    fn hosts(&self) -> Vec<Host> {
        let hosts = self.settings.lock().expect("settings").hosts.clone();
        if hosts.is_empty() {
            vec![Host {
                name: "Home".into(),
                url: self.config.server_url.clone(),
                ssids: vec![],
            }]
        } else {
            hosts
        }
    }

    pub fn set_hosts(&self, hosts: Vec<Host>) {
        let mut s = self.settings.lock().expect("settings");
        s.hosts = hosts;
        s.save();
    }

    /// Tells the engine which Wi-Fi network the Mac is on (`None` when not
    /// on Wi-Fi) and switches hosts if the rules say so.
    pub fn set_network(&self, ssid: Option<String>) {
        let changed = {
            let mut l = self.link.lock().expect("link");
            let c = l.ssid != ssid;
            l.ssid = ssid;
            c
        };
        if changed {
            self.select_host();
        }
    }

    /// Picks the first reachable host for the current network and points
    /// the client at it. The tree is re-verified after a switch.
    pub fn select_host(&self) -> bool {
        let ssid = self.link.lock().expect("link").ssid.clone();
        for h in host_order(&self.hosts(), ssid.as_deref()) {
            let Some(rtt) = probe(&h.url) else { continue };
            let previous = self.client.base();
            self.client.set_base(&h.url);
            {
                let mut l = self.link.lock().expect("link");
                l.host = h.url.clone();
                l.host_name = h.name.clone();
                l.latency_ms = Some(rtt.as_millis() as u32);
            }
            if previous != h.url.trim_end_matches('/') {
                let how = match &ssid {
                    Some(s) if h.ssids.contains(s) => format!("Joined {s}"),
                    _ => "Using the fallback address".into(),
                };
                self.activity
                    .push(EventKind::Switched, &format!("Switched to {}", h.name), &how);
            }
            return true;
        }
        false
    }

    fn mark_online(&self) {
        let mut l = self.link.lock().expect("link");
        if !l.online {
            self.activity.push(
                EventKind::Online,
                &format!(
                    "Back on {}",
                    if l.host_name.is_empty() {
                        "your shelf"
                    } else {
                        &l.host_name
                    }
                ),
                "Tree verified",
            );
        }
        l.online = true;
        l.error = None;
        l.last_verified_ms = now_ns() / 1_000_000;
    }

    fn verify(&self) -> anyhow::Result<()> {
        let pulled = self.refresh()?;
        self.mark_online();
        if pulled > 0 {
            tracing::debug!("pulled {pulled} changes");
        }
        Ok(())
    }

    /// Follows the revision stream until it drops.
    fn follow_events(&self) -> anyhow::Result<()> {
        let stream = self.client.get_stream("/v1/events", STREAM_IDLE)?;
        // The first event is the current head; catch up to it before
        // anything is served as live.
        self.verify()?;
        for line in BufReader::new(stream).lines() {
            let line = line?;
            let Some(data) = line.strip_prefix("data:") else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(data.trim()) else {
                continue;
            };
            let rev = v["revision"].as_u64().unwrap_or(0);
            if rev > self.view().revision {
                self.verify()?;
            } else {
                self.mark_online();
            }
        }
        anyhow::bail!("event stream closed")
    }

    pub fn spawn_sync(self: &Arc<Self>) {
        let me = Arc::downgrade(self);
        std::thread::Builder::new()
            .name("oshelf-events".into())
            .spawn(move || {
                let mut backoff = Duration::from_secs(1);
                loop {
                    let Some(e) = me.upgrade() else { return };
                    let started = Instant::now();
                    if e.select_host() {
                        if let Err(err) = e.follow_events() {
                            tracing::info!("event stream: {err:#}");
                            e.note_offline(&err);
                        }
                    } else {
                        e.note_offline(&anyhow::anyhow!("no host answered"));
                    }
                    if started.elapsed() > Duration::from_secs(30) {
                        backoff = Duration::from_secs(1);
                    }
                    drop(e);
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(20));
                }
            })
            .expect("spawn events thread");

        let me = Arc::downgrade(self);
        std::thread::Builder::new()
            .name("oshelf-health".into())
            .spawn(move || {
                let mut last_maintain = Instant::now();
                loop {
                    std::thread::sleep(HEALTH_EVERY);
                    let Some(e) = me.upgrade() else { return };
                    e.health_check();
                    if last_maintain.elapsed() >= MAINTAIN_EVERY {
                        last_maintain = Instant::now();
                        e.maintain();
                    }
                }
            })
            .expect("spawn health thread");
    }

    /// A signed head check: measures latency and catches a stale tree.
    pub fn health_check(&self) {
        let t = Instant::now();
        match self.client.get("/v1/manifest/head").and_then(|r| r.ok()?.json()) {
            Ok(head) => {
                let ms = t.elapsed().as_millis() as u32;
                self.link.lock().expect("link").latency_ms = Some(ms);
                let rev = head["revision"].as_u64().unwrap_or(0);
                if rev != self.view().revision {
                    if let Err(err) = self.verify() {
                        self.note_offline(&err);
                    }
                } else {
                    self.mark_online();
                }
            }
            Err(err) => {
                self.note_offline(&err);
                // Maybe we moved networks without being told: try the list.
                self.select_host();
            }
        }
    }

    /// Cache trim and auto offload.
    pub fn maintain(&self) {
        let freed = self.trim_cache();
        if freed > 0 {
            tracing::info!("trimmed {} from the streaming cache", human(freed));
        }
        self.auto_offload();
    }

    /// Below the free space threshold, drops this Mac's copies of unpinned
    /// files (oldest opened or biggest first) until back above it.
    pub fn auto_offload(&self) -> u64 {
        let (on, pct, order) = {
            let s = self.settings.lock().expect("settings");
            (s.auto_offload, s.threshold_pct, s.offload_order)
        };
        if !on {
            return 0;
        }
        let Some((free, total)) = disk_space(&self.staging) else {
            return 0;
        };
        let want = total / 100 * u64::from(pct) + total / 50;
        if free >= total / 100 * u64::from(pct) {
            return 0;
        }
        let mut need = want.saturating_sub(free);
        let keep = self.pinned_chunks();
        let v = self.view();
        let mut files: Vec<&Node> = v
            .tree
            .walk(&ROOT)
            .into_iter()
            .filter(|n| n.kind == Kind::File && self.cache.cached_bytes(&n.chunks) > 0)
            .filter(|n| !n.chunks.iter().any(|c| keep.contains(c)))
            .collect();
        match order {
            OffloadOrder::Oldest => files.sort_by_key(|n| self.cache.last_used(&n.chunks)),
            OffloadOrder::Biggest => files.sort_by_key(|n| std::cmp::Reverse(self.cache.cached_bytes(&n.chunks))),
        }
        let (mut freed, mut count) = (0, 0);
        for f in files {
            if need == 0 {
                break;
            }
            let got: u64 = f.chunks.iter().map(|c| self.cache.remove(c)).sum();
            freed += got;
            count += 1;
            need = need.saturating_sub(got);
        }
        if freed > 0 {
            self.activity.push(
                EventKind::Offloaded,
                &format!("Auto offload freed {}", human(freed)),
                &format!("Low on space · {count} files offloaded"),
            );
        }
        freed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(name: &str, ssids: &[&str]) -> Host {
        Host {
            name: name.into(),
            url: format!("http://{name}"),
            ssids: ssids.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn ssid_rules_then_fallback() {
        let hosts = vec![
            h("home", &["Home-5G", "Home-2G"]),
            h("studio", &["Studio"]),
            h("away", &[]),
        ];
        let names = |v: Vec<Host>| v.into_iter().map(|h| h.name).collect::<Vec<_>>();
        assert_eq!(names(host_order(&hosts, Some("Home-2G"))), ["home", "studio", "away"]);
        assert_eq!(names(host_order(&hosts, Some("Studio"))), ["studio", "home", "away"]);
        assert_eq!(names(host_order(&hosts, Some("Cafe"))), ["home", "studio", "away"]);
        assert_eq!(names(host_order(&hosts, None)), ["home", "studio", "away"]);
    }
}
