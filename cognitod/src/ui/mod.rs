/// UI Dashboard module for embedded web interface
///
/// Serves a single-page application with real-time process monitoring,
/// alert visualization, and system metrics.
use axum::response::{Html, IntoResponse};

/// Embedded dashboard HTML
const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// Serve the main dashboard page
pub async fn dashboard_handler() -> impl IntoResponse {
    Html(DASHBOARD_HTML)
}
