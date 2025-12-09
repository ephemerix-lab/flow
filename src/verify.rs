use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};
use zip::ZipArchive;

pub async fn verify_bundle(
    bundle: &str,
    policy_path: Option<&str>,
    require_signature: bool,
) -> Result<()> {
    let tempdir = tempfile::tempdir()?;
    unpack_bundle(bundle, tempdir.path(), require_signature)?;
    let manifest_path = tempdir.path().join("manifest.json");
    if !manifest_path.exists() {
        bail!("manifest.json missing from bundle");
    }

    let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    if require_signature && manifest.signature.is_none() {
        bail!("signature required but bundle signature missing");
    }

    let canonical_entries = load_entries(&tempdir.path().join("canonical"))?;
    let resolved = cross_check_manifest(&manifest, tempdir.path())?;
    let resolved_map: BTreeMap<_, _> = resolved
        .into_iter()
        .map(|entry| (entry.id.clone(), entry))
        .collect();
    for id in resolved_map.keys() {
        if !canonical_entries.contains_key(id) {
            bail!("canonical entry {} missing from canonical files", id);
        }
    }

    if let Some(policy_file) = policy_path {
        let policy = load_policy(policy_file)?;
        apply_policy(&policy, &canonical_entries, &resolved_map)?;
    }
    Ok(())
}

fn unpack_bundle(bundle: &str, dest: &Path, require_signature: bool) -> Result<()> {
    let file = File::open(bundle).with_context(|| format!("reading bundle {bundle}"))?;
    let mut archive = ZipArchive::new(file)?;
    if require_signature {
        let mut has_sig = false;
        for i in 0..archive.len() {
            let name = archive.by_index(i)?.name().to_string();
            if name == "sig/manifest.sig" {
                has_sig = true;
                break;
            }
        }
        if !has_sig {
            bail!("--require-signature set but sig/manifest.sig missing");
        }
    }

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = dest.join(file.mangled_name());

        if file.name().ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }
    Ok(())
}

fn cross_check_manifest(manifest: &Manifest, base: &Path) -> Result<Vec<ResolvedEntry>> {
    let mut needs_requests = false;
    let mut needs_responses = false;
    let mut needs_canonical = false;
    let mut resolved = Vec::new();

    for entry in &manifest.entries {
        let request_path = base.join(&entry.request_ref);
        let response_path = base.join(&entry.response_ref);
        let canonical_path = base.join(&entry.canonical_ref);

        needs_requests |= entry.request_ref.starts_with("requests/");
        needs_responses |= entry.response_ref.starts_with("responses/");
        needs_canonical |= entry.canonical_ref.starts_with("canonical/");

        ensure_file(&request_path)?;
        ensure_file(&response_path)?;
        ensure_file(&canonical_path)?;
        resolved.push(ResolvedEntry {
            id: entry.id.clone(),
            request_path,
            response_path,
            canonical_path,
        });
    }

    if needs_canonical {
        ensure_dir(base.join("canonical"))?;
    }
    if needs_requests {
        ensure_dir(base.join("requests"))?;
    }
    if needs_responses {
        ensure_dir(base.join("responses"))?;
    }
    let sig_dir = base.join("sig");
    if sig_dir.exists() {
        ensure_dir(sig_dir)?;
    }

    Ok(resolved)
}

fn ensure_dir(path: PathBuf) -> Result<()> {
    if path.is_dir() {
        Ok(())
    } else {
        bail!("required directory {} missing", path.display())
    }
}

fn ensure_file(path: &Path) -> Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        bail!("expected file {} missing", path.display())
    }
}

fn load_entries(canon_dir: &Path) -> Result<BTreeMap<String, CanonicalEntry>> {
    let mut map = BTreeMap::new();
    if !canon_dir.exists() {
        return Ok(map);
    }
    for entry in fs::read_dir(canon_dir)? {
        let entry = entry?;
        if !entry.path().is_file() {
            continue;
        }
        let reader = BufReader::new(File::open(entry.path())?);
        for line in reader.lines() {
            let line = line?;
            let record: CanonicalEntry = serde_json::from_str(&line)?;
            map.insert(record.id.clone(), record);
        }
    }
    Ok(map)
}

fn load_policy(path: &str) -> Result<VerifyPolicy> {
    let contents = fs::read_to_string(path)?;
    let policy: VerifyPolicy = serde_yaml::from_str(&contents)?;
    Ok(policy)
}

fn apply_policy(
    policy: &VerifyPolicy,
    canonical: &BTreeMap<String, CanonicalEntry>,
    resolved: &BTreeMap<String, ResolvedEntry>,
) -> Result<()> {
    if let Some(status) = &policy.status {
        verify_status(status, canonical, resolved)?;
    }
    if let Some(headers) = &policy.headers {
        verify_headers(headers, resolved)?;
    }
    if let Some(json) = &policy.json {
        if json.equal {
            verify_json_equal(json, canonical, resolved)?;
        }
    }
    if let Some(timing) = &policy.timing {
        if let Some(max_latency) = timing.max_latency_ms {
            let _unused = max_latency; // TODO: implement timing checks
        }
    }
    Ok(())
}

fn verify_status(
    config: &StatusPolicy,
    entries: &BTreeMap<String, CanonicalEntry>,
    resolved: &BTreeMap<String, ResolvedEntry>,
) -> Result<()> {
    if config.allow.is_empty() {
        return Ok(());
    }
    let allowed: BTreeSet<_> = config.allow.iter().cloned().collect();
    for id in resolved.keys() {
        if let Some(entry) = entries.get(id) {
            if let Some(status) = entry.res.get("status").and_then(|s| s.as_i64()) {
                if !allowed.contains(&(status as i32)) {
                    bail!("status {} for entry {} not in allow list", status, entry.id);
                }
            }
        } else {
            bail!("missing canonical data for entry {id}");
        }
    }
    Ok(())
}

fn verify_headers(
    config: &HeadersPolicy,
    resolved: &BTreeMap<String, ResolvedEntry>,
) -> Result<()> {
    if config.require.is_empty() {
        return Ok(());
    }
    for (id, entry) in resolved {
        let content = fs::read(&entry.response_path)?;
        let header_end = content
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|idx| idx + 4)
            .unwrap_or(content.len());
        let header_text = String::from_utf8_lossy(&content[..header_end]).to_lowercase();
        for needle in &config.require {
            if !header_text.contains(&needle.to_lowercase()) {
                bail!(
                    "response {} missing required header fragment '{}'; headers: {}",
                    id,
                    needle,
                    header_text.lines().take(5).collect::<Vec<_>>().join("\\n")
                );
            }
        }
    }
    Ok(())
}

fn verify_json_equal(
    policy: &JsonPolicy,
    entries: &BTreeMap<String, CanonicalEntry>,
    resolved: &BTreeMap<String, ResolvedEntry>,
) -> Result<()> {
    let mut ids = resolved.keys();
    let Some(first_id) = ids.next() else {
        return Ok(());
    };
    let baseline_id = first_id.clone();
    let Some(first_entry_raw) = entries.get(first_id) else {
        bail!("missing canonical data for entry {baseline_id}");
    };
    let mut first_entry = first_entry_raw.clone();
    scrub_entry(&mut first_entry, &policy.ignore_fields);

    for id in ids {
        let Some(entry) = entries.get(id) else {
            bail!("missing canonical data for entry {id}");
        };
        let mut other = entry.clone();
        scrub_entry(&mut other, &policy.ignore_fields);
        if other.req != first_entry.req || other.res != first_entry.res {
            bail!(
                "canonical mismatch between entries {} and {}",
                baseline_id,
                id
            );
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct Manifest {
    entries: Vec<ManifestEntry>,
    signature: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ManifestEntry {
    #[allow(dead_code)]
    id: String,
    request_ref: String,
    response_ref: String,
    canonical_ref: String,
}

#[derive(Clone, Debug, Deserialize)]
struct CanonicalEntry {
    id: String,
    req: serde_json::Value,
    res: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct VerifyPolicy {
    #[serde(default)]
    status: Option<StatusPolicy>,
    #[serde(default)]
    headers: Option<HeadersPolicy>,
    #[serde(default)]
    json: Option<JsonPolicy>,
    #[serde(default)]
    timing: Option<TimingPolicy>,
}

#[derive(Debug, Deserialize)]
struct StatusPolicy {
    #[serde(default)]
    allow: Vec<i32>,
}

#[derive(Debug, Deserialize)]
struct HeadersPolicy {
    #[serde(default)]
    require: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct JsonPolicy {
    #[serde(default)]
    equal: bool,
    #[serde(default)]
    ignore_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TimingPolicy {
    #[serde(default)]
    max_latency_ms: Option<u64>,
}

#[derive(Clone, Debug)]
struct ResolvedEntry {
    id: String,
    #[allow(dead_code)]
    request_path: PathBuf,
    response_path: PathBuf,
    #[allow(dead_code)]
    canonical_path: PathBuf,
}

fn scrub_entry(entry: &mut CanonicalEntry, ignore_fields: &[String]) {
    for pattern in ignore_fields {
        if let Some(rest) = pattern.strip_prefix("req.") {
            drop_field(&mut entry.req, rest);
        } else if let Some(rest) = pattern.strip_prefix("res.") {
            drop_field(&mut entry.res, rest);
        } else {
            drop_field(&mut entry.req, pattern);
            drop_field(&mut entry.res, pattern);
        }
    }
}

fn drop_field(value: &mut Value, path: &str) {
    let cleaned = path.trim_matches('/');
    if cleaned.is_empty() {
        return;
    }
    let segments: Vec<&str> = cleaned
        .split(['.', '/'])
        .filter(|s| !s.is_empty())
        .collect();
    if segments.is_empty() {
        return;
    }
    remove_segments(value, &segments);
}

fn remove_segments(value: &mut Value, segments: &[&str]) {
    if segments.is_empty() {
        return;
    }
    if let Value::Object(map) = value {
        if segments.len() == 1 {
            map.remove(segments[0]);
        } else if let Some(next) = map.get_mut(segments[0]) {
            remove_segments(next, &segments[1..]);
        }
    }
}
