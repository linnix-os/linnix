#[cfg(feature = "fake-events")]
use crate::{PERCENT_MILLI_UNKNOWN, ProcessEvent, ProcessEventWire, handler::HandlerList};
#[cfg(feature = "fake-events")]
use axum::response::sse::Event;
#[cfg(feature = "fake-events")]
use clap::ValueEnum;
use linnix_ai_ebpf_common::{EventType, FileIoEvent, NetEvent, SyscallEvent};
#[cfg(feature = "fake-events")]
use rand::Rng;
#[cfg(feature = "fake-events")]
use std::convert::Infallible; // for Result<Event, Infallible>
#[cfg(feature = "fake-events")]
use std::sync::Arc;
#[cfg(feature = "fake-events")]
use tokio::time::{Duration, sleep};

#[cfg(feature = "fake-events")]
use futures_util::StreamExt; // provides .map() on streams

#[cfg(feature = "fake-events")]
#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FakeEvent {
    Net(NetEvent),
    FileIo(FileIoEvent),
    Syscall(SyscallEvent),
}

#[cfg(feature = "fake-events")]
fn generate(max_bytes: u64) -> FakeEvent {
    let mut rng = rand::thread_rng();
    match rng.gen_range(0..3) {
        0 => FakeEvent::Net(NetEvent {
            pid: rng.r#gen::<u32>(), // <- raw identifier
            bytes: rng.gen_range(0..max_bytes),
        }),
        1 => FakeEvent::FileIo(FileIoEvent {
            pid: rng.r#gen::<u32>(),
            bytes: rng.gen_range(0..max_bytes),
        }),
        _ => FakeEvent::Syscall(SyscallEvent {
            pid: rng.r#gen::<u32>(),
            syscall: rng.gen_range(0..400),
        }),
    }
}

#[cfg(feature = "fake-events")]
pub fn stream() -> impl futures_util::Stream<Item = FakeEvent> {
    let rate: u64 = std::env::var("FAKE_EVENT_RATE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let max_bytes: u64 = std::env::var("FAKE_EVENT_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024);

    // Avoid 0ms intervals (Tokio panics). Clamp to at least 1ms.
    let period = if rate == 0 {
        std::time::Duration::from_millis(1000)
    } else {
        std::cmp::max(
            std::time::Duration::from_millis(1),
            std::time::Duration::from_secs_f64(1.0 / rate as f64),
        )
    };

    tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(period))
        .map(move |_| generate(max_bytes))
}

#[cfg(feature = "fake-events")]
pub fn sse_stream() -> impl futures_util::Stream<Item = Result<Event, Infallible>> {
    // If available in your axum version, prefer json_data to avoid manual stringify:
    // stream().map(|ev| Ok(Event::default().json_data(&ev).unwrap()))
    stream().map(|ev| Ok(Event::default().data(serde_json::to_string(&ev).unwrap())))
}

#[cfg(feature = "fake-events")]
#[derive(Clone, ValueEnum, Debug)]
#[value(rename_all = "kebab-case")]
pub enum DemoProfile {
    ForkStorm,
    ShortJobs,
    RunawayTree,
}

#[cfg(feature = "fake-events")]
fn build_event(
    pid: u32,
    ppid: u32,
    ty: EventType,
    seq: u64,
    cpu: Option<f32>,
    mem: Option<f32>,
) -> ProcessEvent {
    let mut comm = [0u8; 16];
    let name = b"demo";
    comm[..name.len()].copy_from_slice(name);
    let base = ProcessEventWire {
        pid,
        ppid,
        uid: 0,
        gid: 0,
        event_type: ty as u32,
        ts_ns: 0,
        seq,
        comm,
        exit_time_ns: 0,
        cpu_pct_milli: PERCENT_MILLI_UNKNOWN,
        mem_pct_milli: PERCENT_MILLI_UNKNOWN,
        data: 0,
        data2: 0,
        aux: 0,
        aux2: 0,
    };
    let mut event = ProcessEvent::new(base);
    event.set_cpu_percent(cpu);
    event.set_mem_percent(mem);
    event
}

#[cfg(feature = "fake-events")]
async fn demo_fork_storm(handlers: Arc<HandlerList>, cap: u64) {
    let count = cap.min(50);
    let interval = Duration::from_secs_f64(1.0 / cap.max(1) as f64);
    for i in 0..count {
        let ev = build_event(2000 + i as u32, 1000, EventType::Fork, i, None, None);
        handlers.on_event(&ev).await;
        sleep(interval).await;
    }
}

#[cfg(feature = "fake-events")]
async fn demo_short_jobs(handlers: Arc<HandlerList>, cap: u64) {
    let count = cap.min(20);
    let interval = Duration::from_secs_f64(1.0 / cap.max(1) as f64);
    for i in 0..count {
        let pid = 3000 + i as u32;
        let exec = build_event(pid, 0, EventType::Exec, i, None, None);
        handlers.on_event(&exec).await;
        sleep(Duration::from_millis(100)).await;
        let exit = build_event(pid, 0, EventType::Exit, i + 1000, None, None);
        handlers.on_event(&exit).await;
        sleep(interval).await;
    }
}

#[cfg(feature = "fake-events")]
async fn demo_runaway_tree(handlers: Arc<HandlerList>, _cap: u64) {
    let ev = build_event(4000, 0, EventType::Exec, 0, Some(90.0), Some(512.0));
    handlers.on_event(&ev).await;
    sleep(Duration::from_secs(2)).await;
    let ev2 = build_event(4001, 4000, EventType::Fork, 1, Some(95.0), Some(512.0));
    handlers.on_event(&ev2).await;
}

#[cfg(feature = "fake-events")]
pub async fn run_demo(profile: DemoProfile, handlers: Arc<HandlerList>, cap: u64) {
    match profile {
        DemoProfile::ForkStorm => demo_fork_storm(handlers, cap).await,
        DemoProfile::ShortJobs => demo_short_jobs(handlers, cap).await,
        DemoProfile::RunawayTree => demo_runaway_tree(handlers, cap).await,
    }
}

#[cfg(all(test, feature = "fake-events"))]
mod tests {
    use super::*;
    use crate::alerts::RuleEngine;
    use crate::handler::HandlerList;
    use crate::metrics::Metrics;
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tokio::time::{self, Duration};
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn generates_some_events() {
        let mut s = stream();
        if let Some(_ev) = s.next().await {
            // okay
        } else {
            panic!("no fake event generated");
        }
    }

    #[tokio::test]
    async fn demo_profiles_trigger_once() {
        time::pause();
        let rules = "- name: fork_storm\n  detector: forks_per_sec\n  threshold: 3\n  duration: 1\n  severity: high\n  cooldown: 5\n- name: short_jobs\n  detector: exec_rate\n  regex: .+\n  rate_per_min: 5\n  median_lifetime: 2\n  severity: low\n  cooldown: 5\n- name: runaway_tree\n  detector: subtree_cpu_pct\n  threshold: 50\n  duration: 1\n  severity: high\n  cooldown: 5\n";
        let file = NamedTempFile::new().unwrap();
        tokio::fs::write(file.path(), rules).await.unwrap();
        let metrics = Arc::new(Metrics::new());
        let engine = RuleEngine::from_path(
            file.path().to_str().unwrap(),
            "/dev/null".into(),
            false,
            Arc::clone(&metrics),
        )
        .unwrap();
        let tx = engine.broadcaster();
        let mut list = HandlerList::new();
        list.register(engine);
        let handlers = Arc::new(list);
        let mut rx = tx.subscribe();
        let cap = 5;
        for (profile, rule) in [
            (DemoProfile::ForkStorm, "fork_storm"),
            (DemoProfile::ShortJobs, "short_jobs"),
            (DemoProfile::RunawayTree, "runaway_tree"),
        ] {
            let h = tokio::spawn(run_demo(profile.clone(), Arc::clone(&handlers), cap));
            time::advance(Duration::from_secs(1)).await;
            h.await.unwrap();
            let alert = rx.recv().await.unwrap();
            assert_eq!(alert.rule, rule);
            assert!(rx.try_recv().is_err());
            let h2 = tokio::spawn(run_demo(profile, Arc::clone(&handlers), cap));
            time::advance(Duration::from_secs(1)).await;
            h2.await.unwrap();
            assert!(rx.try_recv().is_err(), "cooldown works");
            time::advance(Duration::from_secs(5)).await;
        }
    }
}
