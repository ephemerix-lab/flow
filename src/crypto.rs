use anyhow::Result;
use tracing::info;

#[allow(dead_code)]
pub async fn gen_local_ca(cn: &str) -> Result<()> {
    info!("(v1.1 placeholder) generated local CA with CN={}", cn);
    Ok(())
}
