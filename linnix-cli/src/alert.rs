use colored::*;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
pub struct Alert {
    pub rule: String,
    pub severity: Severity,
    pub message: String,
    pub host: String,
}

impl Alert {
    pub fn pretty(&self, color: bool) -> String {
        let sev = match self.severity {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        };
        let sev_colored = if color {
            match self.severity {
                Severity::Info => sev.normal().to_string(),
                Severity::Low => sev.blue().to_string(),
                Severity::Medium => sev.yellow().to_string(),
                Severity::High => sev.red().bold().to_string(),
            }
        } else {
            sev.to_string()
        };
        format!(
            "[{sev_colored}] {} - {} ({})",
            self.rule, self.message, self.host
        )
    }
}
