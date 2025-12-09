use anyhow::Result;
use assert_cmd::Command as AssertCommand;
use serde_json::json;
use std::{fs, path::Path};
use tempfile::tempdir;

#[test]
fn deterministic_pack_produces_identical_archives() -> Result<()> {
    let tmp = tempdir()?;
    let shot = tmp.path().join("shot");
    create_fake_shot(&shot)?;

    let first = tmp.path().join("bundle1.zip");
    let second = tmp.path().join("bundle2.zip");

    let flow_bin = assert_cmd::cargo::cargo_bin!("flow").to_path_buf();
    AssertCommand::new(flow_bin.clone())
        .arg("pack")
        .arg("--in")
        .arg(&shot)
        .arg("--out")
        .arg(&first)
        .arg("--deterministic")
        .assert()
        .success();

    AssertCommand::new(flow_bin)
        .arg("pack")
        .arg("--in")
        .arg(&shot)
        .arg("--out")
        .arg(&second)
        .arg("--deterministic")
        .assert()
        .success();

    let a = fs::read(&first)?;
    let b = fs::read(&second)?;
    assert_eq!(a, b, "bundles differ despite deterministic flag");
    Ok(())
}

fn create_fake_shot(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir.join("requests"))?;
    fs::create_dir_all(dir.join("responses"))?;
    fs::create_dir_all(dir.join("canonical"))?;
    fs::create_dir_all(dir.join("proofs"))?;
    fs::create_dir_all(dir.join("sig"))?;

    fs::write(
        dir.join("requests/000001.req"),
        b"GET / HTTP/1.1\r\nHost: example\r\n\r\n",
    )?;
    fs::write(
        dir.join("responses/000001.res"),
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    )?;
    let canonical = json!({
        "id": "000001",
        "ts": "1970-01-01T00:00:00Z",
        "req": {"method": "GET", "host": "example", "path": "/"},
        "res": {"status": 200}
    });
    fs::write(
        dir.join("canonical/000001.jsonl"),
        canonical.to_string() + "\n",
    )?;
    fs::write(dir.join("proofs/chain.ndjson"), "{\"id\":\"000001\"}\n")?;

    let manifest = json!({
        "version": "1.1",
        "created_at": "1970-01-01T00:00:00Z",
        "tool": {
            "name": "flow",
            "version": "1.1.0"
        },
        "capture": {
            "mode": "proxy",
            "listener": "127.0.0.1:8080",
            "filters": {"include": [], "exclude": []}
        },
        "entries": [{
            "id": "000001",
            "request_ref": "requests/000001.req",
            "response_ref": "responses/000001.res",
            "canonical_ref": "canonical/000001.jsonl"
        }],
        "integrity": {"chain_b3": "TODO"},
        "signature": null
    });
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}
