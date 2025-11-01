#![allow(dead_code)]

use crate::config::{Config, OfflineGuard};
use crate::metrics::Metrics;
use dashmap::DashMap;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering}; // Add this import
use std::time::Duration;

const TAG_CACHE_PATH: &str = "tag_cache.json.gz";
const TAG_CACHE_MAX_ENTRIES: usize = 10_000;
const TAG_CACHE_USE_GZIP: bool = true;

pub static TAG_CACHE: Lazy<DashMap<String, Vec<String>>> = Lazy::new(DashMap::new);
static TAG_CACHE_DIRTY: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));
static TAG_HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .timeout(Duration::from_secs(6))
        .build()
        .expect("failed to build reqwest client for LLM tagging")
});
static TAG_ENDPOINT: Lazy<String> = Lazy::new(|| {
    env::var("LLM_TAG_ENDPOINT")
        .or_else(|_| env::var("LLM_ENDPOINT"))
        .unwrap_or_else(|_| Config::load().reasoner.endpoint)
});
static TAG_MODEL: Lazy<String> = Lazy::new(|| {
    env::var("LLM_TAG_MODEL")
        .or_else(|_| env::var("LLM_MODEL"))
        .unwrap_or_else(|_| "local-sre-llm".to_string())
});
static TAG_API_KEY: Lazy<Option<String>> = Lazy::new(|| {
    env::var("LLM_API_KEY")
        .ok()
        .or_else(|| env::var("OPENAI_API_KEY").ok())
});

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatMessageContent,
}

#[derive(Deserialize)]
struct ChatMessageContent {
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

/// Asynchronously queries the configured LLM endpoint to get semantic tags for a process command name.
/// Returns a Vec<String> of tags like "package_manager", "network_tool", etc.
pub async fn llm_tags_for_comm(
    comm: &str,
    metrics: Arc<Metrics>,
    offline: Arc<OfflineGuard>,
) -> anyhow::Result<Vec<String>> {
    if !offline.check("llm_tagging") {
        return Ok(vec!["offline".to_string()]);
    }
    // Check cache first
    let key = comm.trim().to_lowercase();

    if let Some(tags) = TAG_CACHE.get(&key) {
        return Ok(tags.clone());
    }

    let prompt = format!(
        "Command: {comm}\nReturn a JSON array of 1-3 lowercase snake_case tags describing what this command typically does (e.g., \"package_manager\", \"network_tool\"). Respond with JSON only and nothing else."
    );

    let req_body = ChatRequest {
        model: TAG_MODEL.clone(),
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: "You classify Linux command names into semantic categories. Respond with a JSON array of lowercase snake_case tags. Output JSON only, no prose, no code fences, no explanations.".to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: prompt,
            },
        ],
        temperature: Some(0.0),
        max_tokens: Some(48),
        stream: Some(false),
    };

    let client = &*TAG_HTTP_CLIENT;
    let mut request = client.post(TAG_ENDPOINT.as_str()).json(&req_body);
    if let Some(key) = TAG_API_KEY.as_ref() {
        request = request.bearer_auth(key);
    }

    let response = match request.send().await {
        Ok(resp) => resp,
        Err(err) => {
            metrics
                .tag_failures_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(anyhow::anyhow!("LLM tagging request failed: {err}"));
        }
    };

    if !response.status().is_success() {
        metrics
            .tag_failures_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(anyhow::anyhow!(
            "LLM tagging request returned status {}",
            response.status()
        ));
    }

    let body = match response.text().await {
        Ok(body) => body,
        Err(err) => {
            metrics
                .tag_failures_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(anyhow::anyhow!("Failed to read LLM response body: {err}"));
        }
    };

    let tags = match parse_tag_response(&body) {
        Ok(tags) => tags,
        Err(err) => {
            metrics
                .tag_failures_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(err);
        }
    };

    // Insert into cache
    log::debug!("[tagger] cached tags for '{comm}': {tags:?}");
    insert_tag_cache(key.clone(), tags.clone());

    Ok(tags)
}

/// Load the tag cache from disk at startup.
pub fn load_tag_cache_from_disk() {
    if !Path::new(TAG_CACHE_PATH).exists() {
        log::info!("[tagger] No tag cache file found, starting fresh");
        return;
    }
    let file = match File::open(TAG_CACHE_PATH) {
        Ok(f) => f,
        Err(e) => {
            log::warn!("[tagger] Failed to open tag cache: {e}");
            return;
        }
    };
    let mut reader: Box<dyn Read> = if TAG_CACHE_USE_GZIP {
        Box::new(GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    let mut data = String::new();
    if let Err(e) = reader.read_to_string(&mut data) {
        log::warn!("[tagger] Failed to read tag cache: {e}");
        return;
    }
    match serde_json::from_str::<std::collections::HashMap<String, Vec<String>>>(&data) {
        Ok(map) => {
            TAG_CACHE.clear();
            for (k, v) in map {
                TAG_CACHE.insert(k, v);
            }
            log::info!(
                "[tagger] Loaded tag cache from disk ({} entries)",
                TAG_CACHE.len()
            );
        }
        Err(e) => {
            log::warn!("[tagger] Failed to parse tag cache: {e}");
        }
    }
}

/// Save the tag cache to disk.
pub fn save_tag_cache_to_disk() {
    if !TAG_CACHE_DIRTY.swap(false, Ordering::Relaxed) {
        return;
    }
    let map: std::collections::HashMap<_, _> = TAG_CACHE
        .iter()
        .map(|kv| (kv.key().clone(), kv.value().clone()))
        .collect();
    let json = match serde_json::to_string_pretty(&map) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("[tagger] Failed to serialize tag cache: {e}");
            return;
        }
    };
    let path = tag_cache_path();
    let tmp_path = path.with_extension("tmp");
    let file = match std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600) // Set permissions to 0600
        .open(&tmp_path)
    {
        Ok(f) => f,
        Err(e) => {
            log::warn!("[tagger] Failed to create tag cache file: {e}");
            return;
        }
    };
    let result = if TAG_CACHE_USE_GZIP {
        let mut encoder = GzEncoder::new(file, Compression::default());
        encoder
            .write_all(json.as_bytes())
            .and_then(|_| encoder.finish().map(|_| ()))
    } else {
        let mut writer = file;
        writer.write_all(json.as_bytes())
    };
    if let Err(e) = result {
        log::warn!("[tagger] Failed to write tag cache: {e}");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp_path, &path) {
        log::warn!("[tagger] Failed to rename tag cache file: {e}");
    }
}

// Use this function to insert tags, enforcing the size and dirty flag
pub fn insert_tag_cache(comm: String, tags: Vec<String>) {
    if TAG_CACHE.len() >= TAG_CACHE_MAX_ENTRIES && !TAG_CACHE.contains_key(&comm) {
        log::warn!(
            "[tagger] Tag cache full ({TAG_CACHE_MAX_ENTRIES} entries), skipping insert for '{comm}'"
        );
        return;
    }
    TAG_CACHE.insert(comm, tags);
    TAG_CACHE_DIRTY.store(true, Ordering::Relaxed);
}

fn tag_cache_path() -> std::path::PathBuf {
    use std::env;
    let base = env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let mut home = env::var_os("HOME")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| ".".into());
            home.push(".cache");
            home
        });
    let mut path = base;
    path.push("linnix");
    std::fs::create_dir_all(&path).ok();
    path.push(if TAG_CACHE_USE_GZIP {
        "tag_cache.json.gz"
    } else {
        "tag_cache.json"
    });
    path
}

fn parse_tag_response(body: &str) -> anyhow::Result<Vec<String>> {
    if let Ok(chat_resp) = serde_json::from_str::<ChatResponse>(body)
        && let Some(choice) = chat_resp.choices.first() {
            return parse_tag_content(&choice.message.content);
        }
    parse_tag_content(body)
}

fn parse_tag_content(content: &str) -> anyhow::Result<Vec<String>> {
    let trimmed = content.trim();
    let normalized = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .map(|s| s.trim())
        .and_then(|s| s.strip_suffix("```").map(|s| s.trim()))
        .unwrap_or(trimmed);
    serde_json::from_str(normalized).map_err(|e| {
        anyhow::anyhow!("Failed to parse LLM tags JSON: {e}\nLLM output: {normalized}")
    })
}
