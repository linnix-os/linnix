#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RssProbeMode {
    CoreSignal,
    CoreMm,
    Tracepoint,
    Disabled,
}

impl RssProbeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RssProbeMode::CoreSignal => "core:signal",
            RssProbeMode::CoreMm => "core:mm",
            RssProbeMode::Tracepoint => "tracepoint:mm/rss_stat",
            RssProbeMode::Disabled => "disabled",
        }
    }

    pub fn metric_value(self) -> u8 {
        match self {
            RssProbeMode::Disabled => 0,
            RssProbeMode::CoreSignal => 1,
            RssProbeMode::CoreMm => 2,
            RssProbeMode::Tracepoint => 3,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProbeState {
    pub rss_probe: RssProbeMode,
    pub btf_available: bool,
}

impl ProbeState {
    pub const fn disabled() -> Self {
        Self {
            rss_probe: RssProbeMode::Disabled,
            btf_available: false,
        }
    }
}
