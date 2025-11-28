//! Notification handlers for external alerting systems

mod apprise;
mod slack;

pub use apprise::AppriseNotifier;
pub use slack::SlackNotifier;
