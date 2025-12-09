use anyhow::{bail, Result};

pub async fn cmd_record(
    out: String,
    proxy: String,
    include: Vec<String>,
    exclude: Vec<String>,
    max_size: u64,
    intercept: bool,
    exit_after: Option<usize>,
) -> Result<()> {
    crate::capture::run_proxy_capture(
        &out, &proxy, &include, &exclude, max_size, intercept, exit_after,
    )
    .await
}
pub async fn cmd_pack(
    input: String,
    output: String,
    sign: Option<String>,
    deterministic: bool,
) -> Result<()> {
    crate::pack::pack_shot(&input, &output, sign.as_deref(), deterministic).await
}
pub async fn cmd_verify(
    bundle: String,
    policy: Option<String>,
    require_signature: bool,
) -> Result<()> {
    crate::verify::verify_bundle(&bundle, policy.as_deref(), require_signature).await
}
pub async fn cmd_replay(_bundle: String, _map: Vec<String>, _concurrency: usize) -> Result<()> {
    not_yet_implemented("replay")
}
pub async fn cmd_diff(_a: String, _b: String) -> Result<()> {
    not_yet_implemented("diff")
}
pub async fn cmd_gen_cert(_cn: String) -> Result<()> {
    not_yet_implemented("gen-cert")
}
pub async fn cmd_redact(_policy: String, _input: String) -> Result<()> {
    not_yet_implemented("redact")
}

fn not_yet_implemented(name: &str) -> Result<()> {
    bail!("{name} subcommand is not yet implemented")
}
