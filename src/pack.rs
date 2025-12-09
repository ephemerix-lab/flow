use anyhow::{bail, Context, Result};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use zip::write::{ExtendedFileOptions, FileOptions};

pub async fn pack_shot(
    input: &str,
    output: &str,
    _sign_pem: Option<&str>,
    deterministic: bool,
) -> Result<()> {
    let base = Path::new(input);
    if !base.exists() {
        bail!("input shot directory {input} does not exist");
    }

    let file = File::create(output)?;
    let mut zip = zip::ZipWriter::new(file);
    let mut opts: FileOptions<'static, ExtendedFileOptions> = FileOptions::default();
    if deterministic {
        opts = opts
            .last_modified_time(zip::DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).unwrap());
    }

    let files = collect_files(base)?;
    if files.is_empty() {
        bail!("no files found to pack under {input}");
    }

    for (rel, path) in files {
        zip.start_file(rel, opts.clone())?;
        zip.write_all(&fs::read(&path)?)?;
    }
    zip.finish()?;
    Ok(())
}

fn collect_files(base: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut files = Vec::new();
    let manifest = base.join("manifest.json");
    if !manifest.is_file() {
        bail!("manifest.json not found at {}", manifest.display());
    }
    files.push((rel_path(&manifest, base)?, manifest));

    let proofs = base.join("proofs/chain.ndjson");
    if proofs.is_file() {
        files.push((rel_path(&proofs, base)?, proofs));
    }

    for dir in ["requests", "responses", "canonical", "sig"] {
        let dir_path = base.join(dir);
        if dir_path.is_dir() {
            collect_dir(&dir_path, base, &mut files)?;
        }
    }

    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn collect_dir(dir: &Path, base: &Path, files: &mut Vec<(String, PathBuf)>) -> Result<()> {
    for entry in
        fs::read_dir(dir).with_context(|| format!("reading directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_dir(&path, base, files)?;
        } else if path.is_file() {
            files.push((rel_path(&path, base)?, path));
        }
    }
    Ok(())
}

fn rel_path(path: &Path, base: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(base)
        .with_context(|| format!("{} is outside {}", path.display(), base.display()))?;
    Ok(rel.to_string_lossy().replace('\\', "/"))
}
