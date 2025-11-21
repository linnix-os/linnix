use anyhow::{Context, Result, anyhow};
use reqwest::{Client, Url};
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;

const INSIGHT_GRAMMAR: &str = r#"root ::= "{" space "\"class\"" space ":" space class space "," space "\"confidence\"" space ":" space confidence space "," space "\"why\"" space ":" space string space "," space "\"actions\"" space ":" space actions space "}"
class ::= "\"fork_storm\"" | "\"cpu_spin\"" | "\"memory_leak\"" | "\"runaway_tree\"" | "\"short_lived_jobs\"" | "\"unknown\""
confidence ::= "0." [0-9] [0-9]? | "1.0"
string ::= "\"" [^\"]* "\""
actions ::= "[" space (string (space "," space string)*)? space "]"
space ::= [ \t\n]*"#;

#[derive(Clone)]
pub struct ChatMessage {
    pub role: &'static str,
    pub content: String,
}

#[derive(Clone)]
pub struct IlmClient {
    client: Client,
    endpoint: Url,
    timeout: Duration,
}

impl IlmClient {
    pub fn new(endpoint: &str, timeout: Duration) -> Result<Self> {
        let endpoint = Url::parse(endpoint).context("invalid ILM endpoint URL")?;
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .context("failed to build reqwest client")?;
        Ok(Self {
            client,
            endpoint,
            timeout,
        })
    }

    pub async fn check_health(&self) -> Result<()> {
        let mut url = self.endpoint.clone();
        url.set_path("/v1/models");
        url.set_query(None);
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .context("health request failed")?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!("health check returned status {}", resp.status()))
        }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub async fn chat(&self, messages: &[ChatMessage]) -> Result<String> {
        if messages.is_empty() {
            return Err(anyhow!("chat requires at least one message"));
        }
        let payload = build_request(messages);
        let resp = self
            .client
            .post(self.endpoint.clone())
            .json(&payload)
            .send()
            .await
            .context("chat request failed")?;
        if !resp.status().is_success() {
            return Err(anyhow!("chat request status {}", resp.status()));
        }
        let value: Value = resp.json().await.context("failed to parse chat response")?;
        extract_message(&value)
    }
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    temperature: f32,
    max_tokens: u32,
    stream: bool,
    messages: Vec<MessagePayload<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grammar: Option<&'a str>,
}

#[derive(Serialize)]
struct MessagePayload<'a> {
    role: &'a str,
    content: &'a str,
}

fn build_request(messages: &[ChatMessage]) -> ChatRequest<'_> {
    let payload = messages
        .iter()
        .map(|m| MessagePayload {
            role: m.role,
            content: m.content.as_str(),
        })
        .collect();
    ChatRequest {
        model: "local-sre-llm",
        temperature: 0.0,
        max_tokens: 48,
        stream: false,
        messages: payload,
        grammar: Some(INSIGHT_GRAMMAR),
    }
}

fn extract_message(value: &Value) -> Result<String> {
    let choices = value
        .get("choices")
        .and_then(|c| c.as_array())
        .ok_or_else(|| anyhow!("completion missing choices array"))?;
    let first = choices
        .first()
        .ok_or_else(|| anyhow!("completion choices empty"))?;
    let message = first
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| anyhow!("completion missing message content"))?;
    Ok(message.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grammar_is_valid_gbnf() {
        assert!(INSIGHT_GRAMMAR.contains("root ::="));
        assert!(INSIGHT_GRAMMAR.contains("class ::="));
        assert!(INSIGHT_GRAMMAR.contains("confidence ::="));
        assert!(INSIGHT_GRAMMAR.contains("actions ::="));
    }

    #[test]
    fn test_request_includes_grammar() {
        let msg = ChatMessage {
            role: "user",
            content: "test".to_string(),
        };
        let messages = [msg];
        let req = build_request(&messages);
        assert_eq!(req.grammar, Some(INSIGHT_GRAMMAR));
    }
}
