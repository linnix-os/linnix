use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Clone)]
struct DocumentEntry {
    snippet: String,
    weights: HashMap<String, f32>,
}

#[derive(Clone)]
pub struct KbIndex {
    docs: Vec<DocumentEntry>,
    doc_freq: HashMap<String, usize>,
    total_docs: usize,
}

impl KbIndex {
    pub fn from_dir(dir: &Path, max_docs: usize, max_doc_bytes: usize) -> io::Result<Self> {
        if max_docs == 0 {
            return Ok(Self::empty());
        }
        if !dir.exists() {
            return Ok(Self::empty());
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if !is_kb_file(&path) {
                continue;
            }
            entries.push(path);
        }
        entries.sort();

        let mut docs = Vec::new();
        let mut doc_freq: HashMap<String, usize> = HashMap::new();
        for path in entries.into_iter().take(max_docs) {
            if let Ok(doc) = load_document(&path, max_doc_bytes) {
                update_doc_freq(&mut doc_freq, &doc.weights);
                docs.push(doc);
            }
        }

        Ok(Self {
            total_docs: docs.len(),
            docs,
            doc_freq,
        })
    }

    pub fn query(&self, query: &str, k: usize) -> Vec<(f32, String)> {
        if self.total_docs == 0 || k == 0 {
            return Vec::new();
        }
        let query_tokens = tokenize(query);
        if query_tokens.is_empty() {
            return Vec::new();
        }
        let query_weights = term_weights(&query_tokens);
        let mut scores = Vec::new();
        for doc in &self.docs {
            let mut score = 0.0_f32;
            for (token, q_weight) in &query_weights {
                if let Some(d_weight) = doc.weights.get(token) {
                    let idf = self.idf(token);
                    score += q_weight * d_weight * idf * idf;
                }
            }
            if score > 0.0 {
                scores.push((score, doc.snippet.clone()));
            }
        }
        scores.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        scores.truncate(k);
        scores
    }

    pub fn is_empty(&self) -> bool {
        self.total_docs == 0
    }

    fn empty() -> Self {
        Self {
            docs: Vec::new(),
            doc_freq: HashMap::new(),
            total_docs: 0,
        }
    }

    fn idf(&self, token: &str) -> f32 {
        let df = self.doc_freq.get(token).copied().unwrap_or(0) as f32;
        let total = self.total_docs.max(1) as f32;
        ((total + 1.0) / (df + 1.0)).ln() + 1.0
    }
}

fn is_kb_file(path: &Path) -> bool {
    match path.extension().and_then(|s| s.to_str()) {
        Some(ext) => matches!(ext.to_ascii_lowercase().as_str(), "md" | "txt"),
        None => false,
    }
}

fn load_document(path: &Path, max_doc_bytes: usize) -> io::Result<DocumentEntry> {
    let raw = fs::read(path)?;
    let slice = if max_doc_bytes > 0 {
        &raw[..raw.len().min(max_doc_bytes)]
    } else {
        &raw[..]
    };
    let text = String::from_utf8_lossy(slice).to_string();
    let tokens = tokenize(&text);
    if tokens.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "document contains no tokens",
        ));
    }
    let weights = term_weights(&tokens);
    let snippet = build_snippet(&text);
    Ok(DocumentEntry { snippet, weights })
}

fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        let ascii = if ch.is_ascii() {
            ch.to_ascii_lowercase()
        } else {
            ' '
        };
        if ascii.is_ascii_alphanumeric() {
            current.push(ascii);
        } else if !current.is_empty() {
            tokens.push(current.clone());
            current.clear();
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn term_weights(tokens: &[String]) -> HashMap<String, f32> {
    let mut counts: HashMap<String, f32> = HashMap::new();
    for token in tokens {
        *counts.entry(token.clone()).or_insert(0.0) += 1.0;
    }
    let total = tokens.len() as f32;
    if total == 0.0 {
        return counts;
    }
    for value in counts.values_mut() {
        *value /= total;
    }
    counts
}

fn update_doc_freq(doc_freq: &mut HashMap<String, usize>, weights: &HashMap<String, f32>) {
    let mut seen = HashSet::new();
    for token in weights.keys() {
        if seen.insert(token.clone()) {
            *doc_freq.entry(token.clone()).or_insert(0) += 1;
        }
    }
}

fn build_snippet(text: &str) -> String {
    let mut words = Vec::new();
    for word in text.split_whitespace().take(120) {
        words.push(word);
    }
    let mut snippet = words.join(" ");
    if snippet.len() > 512 {
        snippet.truncate(512);
    }
    snippet
}
