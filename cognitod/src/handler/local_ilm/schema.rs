use jsonschema::{Draft, JSONSchema};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InsightClass {
    ForkStorm,
    ShortJobFlood,
    RunawayTree,
    CpuSpin,
    IoSaturation,
    OomRisk,
    Normal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Insight {
    pub class: InsightClass,
    pub confidence: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_process: Option<String>,
    pub why: String,
    #[serde(default)]
    pub actions: Vec<String>,
}

impl Insight {
    fn validate_ranges(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.confidence) {
            return Err(format!("confidence {} out of range", self.confidence));
        }
        if self.why.len() > 160 {
            return Err(format!("why too long ({} bytes)", self.why.len()));
        }
        if self.actions.len() > 3 {
            return Err(format!("too many actions: {}", self.actions.len()));
        }
        if let Some(proc_name) = &self.primary_process
            && proc_name.trim().is_empty()
        {
            return Err("primary_process must not be empty when present".to_string());
        }
        for action in &self.actions {
            if action.trim().is_empty() {
                return Err("actions must not contain empty entries".to_string());
            }
            if action.len() > 160 {
                return Err("actions must be reasonably short".to_string());
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_ranges()
    }
}

fn sanitize_payload(raw: &str) -> Result<String, String> {
    let mut text = raw.trim();
    for prefix in [
        "Response:",
        "response:",
        "Answer:",
        "answer:",
        "Output:",
        "output:",
    ] {
        if let Some(rest) = text.strip_prefix(prefix) {
            text = rest.trim_start();
        }
    }
    for prefix in ["```json", "```JSON", "```"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            text = rest.trim_start();
        }
    }
    if let Some(rest) = text.strip_suffix("```") {
        text = rest.trim_end();
    }
    if text.is_empty() {
        return Err("empty insight payload".to_string());
    }
    Ok(text.to_string())
}

pub fn parse_and_validate(raw: &str) -> Result<Insight, String> {
    let cleaned = sanitize_payload(raw)?;
    log::debug!("[local-ilm] parsing cleaned insight payload: {}", cleaned);
    deserialize_insight(&cleaned)
}

pub fn insight_json_schema() -> &'static Value {
    &INSIGHT_SCHEMA_JSON
}

pub fn insight_schema_validator() -> &'static JSONSchema {
    &INSIGHT_SCHEMA_VALIDATOR
}

fn deserialize_insight(cleaned: &str) -> Result<Insight, String> {
    if let Some(value) = extract_object(cleaned) {
        return value_to_insight(value);
    }
    Err("invalid JSON insight payload: unable to parse insight object".to_string())
}

fn extract_object(text: &str) -> Option<Value> {
    // attempt direct parse
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        return object_from_value(value);
    }
    // attempt streaming first value
    let mut stream = serde_json::Deserializer::from_str(text).into_iter::<Value>();
    if let Some(Ok(value)) = stream.next()
        && let Some(obj) = object_from_value(value.clone())
    {
        return Some(obj);
    }
    // fallback to substring between braces
    if let (Some(start), Some(end)) = (text.find('{'), text.rfind('}'))
        && end >= start
    {
        let slice = &text[start..=end];
        if let Ok(value) = serde_json::from_str::<Value>(slice) {
            return object_from_value(value);
        }
    }
    None
}

fn object_from_value(value: Value) -> Option<Value> {
    match value {
        Value::Object(_) => Some(value),
        Value::Array(arr) => arr.into_iter().find_map(|v| match v {
            Value::Object(_) => Some(v),
            _ => None,
        }),
        _ => None,
    }
}

fn value_to_insight(value: Value) -> Result<Insight, String> {
    match value {
        Value::Object(mut map) => {
            normalize_class(&mut map);
            normalize_confidence(&mut map);
            normalize_primary_process(&mut map);
            normalize_why(&mut map);
            normalize_actions(&mut map);
            let normalized = Value::Object(map);
            validate_against_schema(&normalized)?;
            serde_json::from_value::<Insight>(normalized)
                .map_err(|err| format!("invalid JSON insight payload: {err}"))
                .and_then(|insight| {
                    insight.validate()?;
                    Ok(insight)
                })
        }
        _ => Err("invalid JSON insight payload: expected JSON object".to_string()),
    }
}

fn normalize_class(map: &mut Map<String, Value>) {
    const ALLOWED: [&str; 7] = [
        "fork_storm",
        "short_job_flood",
        "runaway_tree",
        "cpu_spin",
        "io_saturation",
        "oom_risk",
        "normal",
    ];
    let raw = map
        .remove("class")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();
    let normalized = raw.trim().replace(['-', ' '], "_").to_lowercase();
    let class = if ALLOWED.contains(&normalized.as_str()) {
        normalized
    } else {
        "normal".to_string()
    };
    map.insert("class".to_string(), Value::String(class));
}

fn normalize_confidence(map: &mut Map<String, Value>) {
    let value = map.remove("confidence");
    let mut confidence = match value {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.trim().parse::<f64>().unwrap_or(0.0),
        Some(v) => v.as_f64().unwrap_or(0.0),
        None => 0.0,
    };
    if !confidence.is_finite() {
        confidence = 0.0;
    }
    confidence = confidence.clamp(0.0, 1.0);
    let number = Number::from_f64(confidence).unwrap_or_else(|| Number::from_f64(0.0).unwrap());
    map.insert("confidence".to_string(), Value::Number(number));
}

fn normalize_primary_process(map: &mut Map<String, Value>) {
    let value = map.remove("primary_process").unwrap_or(Value::Null);
    let normalized = match value {
        Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty()
                || trimmed.eq_ignore_ascii_case("primary_process_value")
                || trimmed.eq_ignore_ascii_case("none")
            {
                Value::Null
            } else {
                Value::String(trimmed.to_string())
            }
        }
        Value::Null => Value::Null,
        _ => Value::Null,
    };
    map.insert("primary_process".to_string(), normalized);
}

fn normalize_why(map: &mut Map<String, Value>) {
    let value = map.remove("why");
    let mut why = match value {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(v) => v.to_string(),
        None => String::new(),
    };
    if why.is_empty()
        || why.eq_ignore_ascii_case("WHY_TEXT")
        || why.eq_ignore_ascii_case("placeholder")
    {
        why = "Insufficient telemetry to classify window".to_string();
    }
    if why.len() > 120 {
        why.truncate(120);
    }
    map.insert("why".to_string(), Value::String(why));
}

fn normalize_actions(map: &mut Map<String, Value>) {
    let value = map.remove("actions");
    let mut actions = Vec::new();
    match value {
        Some(Value::Array(items)) => {
            for item in items {
                if let Some(s) = item.as_str() {
                    let action = s.trim();
                    if action.is_empty()
                        || action.eq_ignore_ascii_case("ACTION_VALUES")
                        || action.eq_ignore_ascii_case("placeholder")
                    {
                        continue;
                    }
                    actions.push(Value::String(action.to_string()));
                    if actions.len() == 3 {
                        break;
                    }
                }
            }
        }
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("ACTION_VALUES") {
                actions.push(Value::String(trimmed.to_string()));
            }
        }
        _ => {}
    }
    map.insert("actions".to_string(), Value::Array(actions));
}

fn validate_against_schema(value: &Value) -> Result<(), String> {
    if let Err(errors) = insight_schema_validator().validate(value) {
        let reasons = errors.map(|e| e.to_string()).collect::<Vec<_>>().join("; ");
        return Err(format!(
            "invalid JSON insight payload: schema violation: {reasons}"
        ));
    }
    Ok(())
}

impl InsightClass {
    pub fn triggers_alert(&self) -> bool {
        matches!(
            self,
            InsightClass::ForkStorm | InsightClass::ShortJobFlood | InsightClass::RunawayTree
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            InsightClass::ForkStorm => "fork_storm",
            InsightClass::ShortJobFlood => "short_job_flood",
            InsightClass::RunawayTree => "runaway_tree",
            InsightClass::CpuSpin => "cpu_spin",
            InsightClass::IoSaturation => "io_saturation",
            InsightClass::OomRisk => "oom_risk",
            InsightClass::Normal => "normal",
        }
    }
}

static INSIGHT_SCHEMA_JSON: Lazy<Value> = Lazy::new(|| {
    serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Insight",
        "type": "object",
        "additionalProperties": false,
        "required": ["class", "confidence", "primary_process", "why", "actions"],
        "properties": {
            "class": {
                "type": "string",
                "enum": [
                    "fork_storm",
                    "short_job_flood",
                    "runaway_tree",
                    "cpu_spin",
                    "io_saturation",
                    "oom_risk",
                    "normal"
                ]
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0
            },
            "primary_process": {
                "oneOf": [
                    { "type": "null" },
                    {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 120
                    }
                ]
            },
            "why": {
                "type": "string",
                "minLength": 1,
                "maxLength": 120
            },
            "actions": {
                "type": "array",
                "maxItems": 3,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 160
                }
            }
        }
    })
});

static INSIGHT_SCHEMA_VALIDATOR: Lazy<JSONSchema> = Lazy::new(|| {
    JSONSchema::options()
        .with_draft(Draft::Draft7)
        .compile(&INSIGHT_SCHEMA_JSON)
        .expect("compile insight schema")
});

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn schema_accepts_valid_payload() {
        let payload = json!({
            "class": "cpu_spin",
            "confidence": 0.72,
            "primary_process": "java",
            "why": "cpu usage pegged across sample window",
            "actions": [
                "capture stack traces for pid 1234",
                "throttle offending workload"
            ]
        });
        validate_against_schema(&payload).expect("schema should accept valid payload");
        let parsed = parse_and_validate(&payload.to_string()).expect("payload parses");
        assert!(parsed.confidence > 0.0);
        assert_eq!(parsed.class, InsightClass::CpuSpin);
        assert_eq!(parsed.actions.len(), 2);
    }

    #[test]
    fn schema_rejects_unknown_fields() {
        let payload = json!({
            "class": "normal",
            "confidence": 0.5,
            "primary_process": null,
            "why": "no anomaly detected",
            "actions": [],
            "extra": "nope"
        });
        let err = parse_and_validate(&payload.to_string()).expect_err("unknown field should fail");
        assert!(
            err.contains("schema violation") || err.contains("unknown field"),
            "unexpected error message: {err}"
        );
    }
}
