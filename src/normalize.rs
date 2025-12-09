use anyhow::Result;
use serde_json::Value;

#[allow(dead_code)]
pub fn canonicalize_json(v: &Value) -> Result<String> {
    Ok(serde_json::to_string(v)?)
}
