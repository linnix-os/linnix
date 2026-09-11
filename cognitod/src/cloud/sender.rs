//! HTTPS sender for sealed batches.
//!
//! POSTs gzip-compressed batch bytes with bearer auth. Response handling
//! follows schema §10 exactly:
//!
//! | Status      | Meaning                  | Action                              |
//! |-------------|--------------------------|-------------------------------------|
//! | 200 / 202   | accepted (202) or dup (200) | delete local batch               |
//! | 409         | key reused, body differs | quarantine + local diagnostic, no retry |
//! | 413 / 422   | invalid request          | quarantine, do not loop             |
//! | other 4xx   | client error             | quarantine, do not loop             |
//! | 429 / 5xx   | transient                | exponential backoff + jitter, honor `Retry-After` |
//! | transport error | network failure      | same as transient                     |
//!
//! Batch bytes are immutable across retries: the same sealed bytes and the
//! same idempotency key go out every attempt. The bearer token is never
//! logged and is redacted from `Debug`.

use std::io::Write as _;
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;

/// What to do after attempting a POST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendDecision {
    /// 200/202: drop the local batch.
    Acked,
    /// 409/413/422/other 4xx: move to quarantine, never retry.
    Quarantine { reason: String },
    /// 429/5xx/network error: keep spooled, retry after `retry_after`.
    Retry { retry_after: Duration },
}

/// Classify an HTTP status into a send decision (pure, unit-tested).
pub fn classify_status(status: u16) -> SendDecision {
    match status {
        200 | 202 => SendDecision::Acked,
        409 => SendDecision::Quarantine {
            reason: "409: idempotency key reused with a different body".to_string(),
        },
        413 => SendDecision::Quarantine {
            reason: "413: batch exceeds edge body limits".to_string(),
        },
        422 => SendDecision::Quarantine {
            reason: "422: edge rejected the batch as a schema violation".to_string(),
        },
        429 => SendDecision::Retry {
            retry_after: BACKOFF_BASE,
        },
        500..=599 => SendDecision::Retry {
            retry_after: BACKOFF_BASE,
        },
        _ => SendDecision::Quarantine {
            reason: format!("{status}: unexpected client error; not retrying"),
        },
    }
}

/// Base delay for the first retry; doubles per consecutive failure.
pub const BACKOFF_BASE: Duration = Duration::from_secs(5);
/// Upper bound for any single backoff.
pub const BACKOFF_MAX: Duration = Duration::from_secs(300);

/// Exponential backoff with ±25% jitter. `failures` counts consecutive
/// retryable failures; resets on any ack. Jitter comes from a cheap
/// time-based xorshift — no RNG dependency needed for this.
pub fn backoff_delay(failures: u32) -> Duration {
    let exp = failures.min(6);
    let base = BACKOFF_BASE
        .as_secs()
        .saturating_mul(1 << exp)
        .min(BACKOFF_MAX.as_secs());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    // xorshift64* on the timestamp for jitter in [-25%, +25%].
    let mut x = nanos.wrapping_add(0x9E3779B97F4A7C15).max(1);
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    let jitter_pct = (x % 51) as i64 - 25; // -25..=25
    let adjusted = (base as i64 * (100 + jitter_pct) / 100).max(1) as u64;
    Duration::from_secs(adjusted)
}

/// Parse a `Retry-After` header: delta-seconds, else `None` (HTTP dates are
/// not worth the parsing dependency for a hint the backoff already covers).
pub fn parse_retry_after(value: Option<&str>) -> Option<Duration> {
    value?.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// Extract `Retry-After` for retryable statuses: 429 and 5xx (schema §10:
/// "honor Retry-After" — a `503 Retry-After: 120` must not fall back to the
/// shorter local backoff). Pure, unit-tested.
fn retry_after_for(status: u16, headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    if status != 429 && !(500..=599).contains(&status) {
        return None;
    }
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_retry_after(Some(v)))
}

pub fn gzip_body(bytes: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(bytes).expect("gzip into memory cannot fail");
    enc.finish().expect("gzip finish cannot fail")
}

pub struct Sender {
    client: reqwest::Client,
    endpoint: String,
    token: String,
}

impl Sender {
    pub fn new(endpoint: String, token: String) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            endpoint,
            token,
        })
    }

    /// POST one sealed batch. Returns the decision; the caller owns the
    /// spool mutation (remove / quarantine / backoff).
    pub async fn post_batch(&self, bytes: &[u8]) -> SendDecision {
        let body = gzip_body(bytes);
        let response = self
            .client
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .header("Content-Encoding", "gzip")
            .bearer_auth(&self.token)
            .body(body)
            .send()
            .await;
        match response {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let retry_after = retry_after_for(status, resp.headers());
                match classify_status(status) {
                    SendDecision::Retry { .. } => SendDecision::Retry {
                        retry_after: retry_after.unwrap_or(BACKOFF_BASE),
                    },
                    other => other,
                }
            }
            Err(e) => {
                log::warn!("[cloud] batch POST failed: {e}; will retry with backoff");
                SendDecision::Retry {
                    retry_after: BACKOFF_BASE,
                }
            }
        }
    }
}

// The token must never appear in logs or panic messages.
impl std::fmt::Debug for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sender")
            .field("endpoint", &self.endpoint)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_table() {
        assert_eq!(classify_status(200), SendDecision::Acked);
        assert_eq!(classify_status(202), SendDecision::Acked);
        assert!(matches!(
            classify_status(409),
            SendDecision::Quarantine { .. }
        ));
        assert!(matches!(
            classify_status(413),
            SendDecision::Quarantine { .. }
        ));
        assert!(matches!(
            classify_status(422),
            SendDecision::Quarantine { .. }
        ));
        assert!(matches!(
            classify_status(400),
            SendDecision::Quarantine { .. }
        ));
        assert!(matches!(classify_status(429), SendDecision::Retry { .. }));
        assert!(matches!(classify_status(500), SendDecision::Retry { .. }));
        assert!(matches!(classify_status(503), SendDecision::Retry { .. }));
    }

    #[test]
    fn backoff_grows_and_caps_with_jitter_bounds() {
        let d0 = backoff_delay(0);
        assert!(d0 >= Duration::from_secs(3) && d0 <= Duration::from_secs(7));
        let d6 = backoff_delay(6);
        assert!(d6 <= BACKOFF_MAX + Duration::from_secs(75));
        let d99 = backoff_delay(99);
        assert!(d99 <= BACKOFF_MAX + Duration::from_secs(75));
    }

    #[test]
    fn retry_after_parses_delta_seconds() {
        assert_eq!(
            parse_retry_after(Some("120")),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            parse_retry_after(Some("  5 ")),
            Some(Duration::from_secs(5))
        );
        assert_eq!(parse_retry_after(None), None);
        assert_eq!(parse_retry_after(Some("not-a-number")), None);
    }

    fn headers_with_retry_after(value: &str) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    #[test]
    fn retry_after_honored_on_429_and_5xx_only() {
        let headers = headers_with_retry_after("120");
        let empty = reqwest::header::HeaderMap::new();
        // 429 and retryable 5xx honor the header...
        assert_eq!(
            retry_after_for(429, &headers),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            retry_after_for(503, &headers),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            retry_after_for(500, &headers),
            Some(Duration::from_secs(120))
        );
        // ...a missing header falls back to the caller's backoff...
        assert_eq!(retry_after_for(503, &empty), None);
        // ...and non-retryable statuses never honor it.
        assert_eq!(retry_after_for(200, &headers), None);
        assert_eq!(retry_after_for(409, &headers), None);
        assert_eq!(retry_after_for(400, &headers), None);
    }

    #[test]
    fn gzip_round_trips() {
        let body = br#"{"events": []}"#;
        let gz = gzip_body(body);
        assert_ne!(gz, body);
        let mut dec = flate2::read::GzDecoder::new(&gz[..]);
        let mut out = Vec::new();
        use std::io::Read as _;
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, body);
    }

    #[test]
    fn sender_debug_redacts_token() {
        let s = Sender::new("https://example/v1".to_string(), "sekrit".to_string()).unwrap();
        let rendered = format!("{:?}", s);
        assert!(!rendered.contains("sekrit"));
        assert!(rendered.contains("https://example/v1"));
    }
}
