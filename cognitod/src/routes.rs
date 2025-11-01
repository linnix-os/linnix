use axum::{Router, response::Json, routing::get};
use serde::Serialize;
use std::sync::Arc;

use crate::context::ContextStore;

#[derive(Serialize)]
#[allow(dead_code)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    comm: String,
}

#[allow(dead_code)]
pub fn routes(ctx: Arc<ContextStore>) -> Router {
    Router::new().route(
        "/processes",
        get({
            let ctx = Arc::clone(&ctx);
            move || async move {
                let snapshots = ctx.snapshot();
                let data: Vec<ProcessInfo> = snapshots
                    .into_iter()
                    .map(|e| ProcessInfo {
                        pid: e.pid,
                        ppid: e.ppid,
                        uid: e.uid,
                        gid: e.gid,
                        comm: String::from_utf8_lossy(&e.comm)
                            .trim_end_matches('\0')
                            .to_string(),
                    })
                    .collect();
                Json(data)
            }
        }),
    )
}
