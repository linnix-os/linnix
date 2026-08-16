//! The daemon's `/system` payload, and how it is put to the model.
//!
//! This mirrors `cognitod`'s `SystemSnapshot` field for field. That matters
//! more than it looks: serde drops anything the local struct does not declare,
//! silently and without error, so a partial copy here is indistinguishable from
//! a daemon that never sent the data. The reasoner spent its life analysing CPU
//! and memory *usage* while every pressure figure the daemon emitted was
//! discarded at deserialisation.

use serde::Deserialize;

/// One system snapshot as served by `GET /system`.
///
/// Field-for-field with the daemon's own `SystemSnapshot`; see the module note
/// for why the copy has to stay complete.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SystemSnapshot {
    pub timestamp: u64,
    pub cpu_percent: f32,
    pub mem_percent: f32,
    pub load_avg: [f32; 3],
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    /// % of the last 10s at least one task stalled waiting for CPU.
    pub psi_cpu_some_avg10: f32,
    /// % of the last 10s at least one task stalled waiting for memory.
    pub psi_memory_some_avg10: f32,
    /// % of the last 10s *every* runnable task stalled on memory.
    pub psi_memory_full_avg10: f32,
    /// % of the last 10s at least one task stalled on I/O.
    pub psi_io_some_avg10: f32,
    /// % of the last 10s *every* runnable task stalled on I/O.
    pub psi_io_full_avg10: f32,
}

impl SystemSnapshot {
    /// The snapshot as the model should see it.
    ///
    /// Labelled rather than `{:#?}`-dumped: the Debug form names fields
    /// `psi_cpu_some_avg10`, which tells a model nothing about what the number
    /// means or how it differs from `cpu_percent`. The units and the reading of
    /// pressure-versus-usage are stated because the whole point of shipping
    /// these figures is that they change the conclusion.
    pub fn render_for_prompt(&self) -> String {
        format!(
            "System snapshot (unix timestamp {ts}):\n  \
             CPU usage:     {cpu:.1}%\n  \
             Memory usage:  {mem:.1}%\n  \
             Load average:  {l1:.2}, {l5:.2}, {l15:.2}\n  \
             Disk:          {dr} read, {dw} written\n  \
             Network:       {nrx} received, {ntx} sent\n\
             \n\
             Pressure stall information (PSI) — percentage of the last 10 seconds \
             spent stalled waiting for a resource:\n  \
             CPU, some tasks stalled:     {pcpu:.1}%\n  \
             Memory, some tasks stalled:  {pmem_some:.1}%\n  \
             Memory, all tasks stalled:   {pmem_full:.1}%\n  \
             I/O, some tasks stalled:     {pio_some:.1}%\n  \
             I/O, all tasks stalled:      {pio_full:.1}%\n\
             \n\
             PSI measures time spent blocked waiting for a resource, which the usage \
             figures above cannot show. High CPU usage with low CPU pressure is a machine \
             being used efficiently; moderate usage with high pressure means tasks are \
             queueing and work is being delayed. Weigh the pressure figures accordingly, \
             and say so when usage and pressure disagree.",
            ts = self.timestamp,
            cpu = self.cpu_percent,
            mem = self.mem_percent,
            l1 = self.load_avg[0],
            l5 = self.load_avg[1],
            l15 = self.load_avg[2],
            dr = human_bytes(self.disk_read_bytes),
            dw = human_bytes(self.disk_write_bytes),
            nrx = human_bytes(self.net_rx_bytes),
            ntx = human_bytes(self.net_tx_bytes),
            pcpu = self.psi_cpu_some_avg10,
            pmem_some = self.psi_memory_some_avg10,
            pmem_full = self.psi_memory_full_avg10,
            pio_some = self.psi_io_some_avg10,
            pio_full = self.psi_io_full_avg10,
        )
    }

    /// The highest pressure figure and what it was, for the terminal summary.
    ///
    /// One line, because the summary sits above the model's analysis and is
    /// there to let a reader see at a glance whether the machine was stalling —
    /// not to reproduce every counter.
    pub fn peak_pressure(&self) -> (&'static str, f32) {
        [
            ("CPU", self.psi_cpu_some_avg10),
            ("memory", self.psi_memory_some_avg10),
            ("memory (all tasks)", self.psi_memory_full_avg10),
            ("I/O", self.psi_io_some_avg10),
            ("I/O (all tasks)", self.psi_io_full_avg10),
        ]
        .into_iter()
        .fold(
            ("none", 0.0),
            |acc, item| if item.1 > acc.1 { item } else { acc },
        )
    }
}

fn human_bytes(bytes: u64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{:.1} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else {
        format!("{:.1} KB", b / 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `/system` body exactly as the daemon serialises it. If the daemon
    /// grows a field this fixture goes stale, but the failure this pins is the
    /// one that actually happened: fields present on the wire and absent here.
    const DAEMON_PAYLOAD: &str = r#"{
        "timestamp": 1700000000,
        "cpu_percent": 41.5,
        "mem_percent": 62.0,
        "load_avg": [4.1, 3.8, 2.9],
        "disk_read_bytes": 13001000,
        "disk_write_bytes": 3200000,
        "net_rx_bytes": 8600000,
        "net_tx_bytes": 1150000,
        "psi_cpu_some_avg10": 75.2,
        "psi_memory_some_avg10": 3.1,
        "psi_memory_full_avg10": 0.4,
        "psi_io_some_avg10": 12.7,
        "psi_io_full_avg10": 0.2
    }"#;

    #[test]
    fn every_pressure_figure_survives_deserialisation() {
        let snapshot: SystemSnapshot = serde_json::from_str(DAEMON_PAYLOAD).unwrap();

        // Asserted individually rather than as a struct comparison so a
        // dropped field names itself instead of failing as one opaque diff.
        assert_eq!(snapshot.psi_cpu_some_avg10, 75.2);
        assert_eq!(snapshot.psi_memory_some_avg10, 3.1);
        assert_eq!(snapshot.psi_memory_full_avg10, 0.4);
        assert_eq!(snapshot.psi_io_some_avg10, 12.7);
        assert_eq!(snapshot.psi_io_full_avg10, 0.2);
        assert_eq!(snapshot.disk_read_bytes, 13_001_000);
        assert_eq!(snapshot.net_tx_bytes, 1_150_000);
    }

    #[test]
    fn the_prompt_carries_the_pressure_the_usage_hides() {
        let snapshot: SystemSnapshot = serde_json::from_str(DAEMON_PAYLOAD).unwrap();
        let prompt = snapshot.render_for_prompt();

        // The scenario the project exists to catch: moderate usage, severe
        // stall. Both numbers have to reach the model for it to be able to
        // tell them apart.
        assert!(prompt.contains("41.5%"), "usage missing: {prompt}");
        assert!(prompt.contains("75.2%"), "CPU pressure missing: {prompt}");
        assert!(prompt.contains("12.7%"), "I/O pressure missing: {prompt}");
        assert!(
            prompt.to_lowercase().contains("pressure"),
            "the prompt must say what the figures are: {prompt}"
        );
    }

    #[test]
    fn peak_pressure_names_the_worst_resource() {
        let snapshot: SystemSnapshot = serde_json::from_str(DAEMON_PAYLOAD).unwrap();
        assert_eq!(snapshot.peak_pressure(), ("CPU", 75.2));

        // A machine under no pressure must not name a resource, or the summary
        // reads as a finding when there is nothing to find.
        let calm = SystemSnapshot::default();
        assert_eq!(calm.peak_pressure(), ("none", 0.0));
    }

    #[test]
    fn byte_counts_render_at_a_readable_scale() {
        assert_eq!(human_bytes(512), "0.5 KB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }
}
