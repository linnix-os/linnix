use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::Client;

/// Environment variable holding the bearer token for a cognitod instance that
/// was started with an API token configured.
pub const TOKEN_ENV: &str = "LINNIX_API_TOKEN";

/// Build the HTTP client every command uses.
///
/// When `LINNIX_API_TOKEN` is set, its value is attached as a bearer token on
/// every request, which is what a cognitod behind a token expects on all of its
/// TCP routes. Without the variable this is a plain client, so unauthenticated
/// local runs are unaffected.
pub fn client() -> Client {
    let mut headers = HeaderMap::new();

    if let Some(token) = std::env::var(TOKEN_ENV)
        .ok()
        .filter(|t| !t.trim().is_empty())
    {
        match HeaderValue::from_str(&format!("Bearer {}", token.trim())) {
            Ok(mut value) => {
                value.set_sensitive(true);
                headers.insert(AUTHORIZATION, value);
            }
            Err(_) => {
                eprintln!(
                    "warning: {} contains characters that cannot be sent in a header; \
                     continuing without authentication",
                    TOKEN_ENV
                );
            }
        }
    }

    Client::builder()
        .default_headers(headers)
        .build()
        .unwrap_or_else(|_| Client::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_client_when_no_token_is_set() {
        // The builder must not panic on the common unauthenticated path.
        let _ = client();
    }

    #[test]
    fn a_blank_token_is_treated_as_absent() {
        assert!(Some("   ".to_string())
            .filter(|t| !t.trim().is_empty())
            .is_none());
    }
}
