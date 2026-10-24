//! What the Activity tab and the menu bar show: recent events, plus live
//! streaming and upload progress.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use oshelf_core::manifest::Id;

const KEEP: usize = 200;
/// Window over which the streaming rate is measured.
const RATE_WINDOW: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Uploaded,
    Pinned,
    Offloaded,
    Switched,
    Synced,
    Conflict,
    Offline,
    Online,
    Error,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub kind: Kind,
    pub title: String,
    pub detail: String,
    pub time_ms: i64,
}

/// A file being read through the mount right now.
#[derive(Debug, Clone)]
pub struct Streaming {
    pub id: Id,
    pub name: String,
    pub size: u64,
    /// Sealed bytes fetched for it since it was opened.
    pub fetched: u64,
    last: Instant,
}

#[derive(Default)]
pub struct Activity {
    events: Mutex<VecDeque<Event>>,
    streaming: Mutex<Vec<Streaming>>,
    samples: Mutex<VecDeque<(Instant, u64)>>,
}

impl Activity {
    pub fn push(&self, kind: Kind, title: &str, detail: &str) {
        tracing::info!("{title}: {detail}");
        let mut e = self.events.lock().expect("events");
        e.push_front(Event {
            kind,
            title: title.into(),
            detail: detail.into(),
            time_ms: crate::engine::now_ns() / 1_000_000,
        });
        e.truncate(KEEP);
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().expect("events").iter().cloned().collect()
    }

    pub fn streamed(&self, id: &Id, name: &str, size: u64, bytes: u64, _took: Duration) {
        let now = Instant::now();
        let mut s = self.streaming.lock().expect("streaming");
        match s.iter_mut().find(|f| f.id == *id) {
            Some(f) => {
                f.fetched += bytes;
                f.last = now;
            }
            None => s.push(Streaming {
                id: *id,
                name: name.into(),
                size,
                fetched: bytes,
                last: now,
            }),
        }
        self.samples.lock().expect("samples").push_back((now, bytes));
    }

    /// Files read in the last few seconds and the combined rate in bytes/s.
    pub fn streaming(&self) -> (Vec<Streaming>, u64) {
        let now = Instant::now();
        let mut s = self.streaming.lock().expect("streaming");
        s.retain(|f| now.duration_since(f.last) < Duration::from_secs(10));
        let mut samples = self.samples.lock().expect("samples");
        while samples
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) > RATE_WINDOW)
        {
            samples.pop_front();
        }
        let bytes: u64 = samples.iter().map(|(_, b)| b).sum();
        (s.clone(), bytes / RATE_WINDOW.as_secs())
    }
}
