use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const DEFAULT_TTL: Duration = Duration::from_secs(60);
const DEFAULT_CAPACITY: usize = 8_192;

pub struct LineageCache {
    inner: Mutex<LineageInner>,
    ttl: Duration,
    capacity: usize,
}

struct LineageInner {
    entries: HashMap<u32, (u32, Instant)>,
    order: VecDeque<(u32, Instant)>,
}

impl LineageCache {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            inner: Mutex::new(LineageInner {
                entries: HashMap::new(),
                order: VecDeque::new(),
            }),
            ttl,
            capacity,
        }
    }

    pub async fn record_fork(&self, child: u32, parent: u32) {
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        guard.entries.insert(child, (parent, now));
        guard.order.push_back((child, now));
        guard.purge(now, self.ttl, self.capacity);
    }

    pub async fn lookup(&self, pid: u32) -> Option<u32> {
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        guard.purge(now, self.ttl, self.capacity);
        guard.entries.get(&pid).map(|(parent, _)| *parent)
    }
}

impl Default for LineageCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_CAPACITY)
    }
}

impl LineageInner {
    fn purge(&mut self, now: Instant, ttl: Duration, capacity: usize) {
        while let Some(&(pid, recorded_at)) = self.order.front() {
            let mut remove_entry = false;
            let expired = now.duration_since(recorded_at) > ttl;
            let over_capacity = self.entries.len() > capacity;

            match self.entries.get(&pid) {
                Some((_, current_ts)) if *current_ts == recorded_at => {
                    if expired || over_capacity {
                        self.entries.remove(&pid);
                        remove_entry = true;
                    }
                }
                Some(_) => {
                    // stale queue entry for a newer timestamp; drop queue entry only
                    remove_entry = true;
                }
                None => {
                    remove_entry = true;
                }
            }

            if !remove_entry {
                // Entry still valid and capacity satisfied
                break;
            }

            self.order.pop_front();
        }

        while self.entries.len() > capacity {
            if let Some((pid, recorded_at)) = self.order.pop_front()
                && let Some((_, current_ts)) = self.entries.get(&pid)
                && *current_ts == recorded_at
            {
                self.entries.remove(&pid);
            } else {
                break;
            }
        }
    }
}
