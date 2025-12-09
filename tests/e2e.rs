use anyhow::{bail, Context, Result};
use assert_cmd::Command as AssertCommand;
use std::{
    fs,
    io::Read,
    net::TcpStream,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

const SERVER_PORT: u16 = 39111;
const PROXY_PORT: u16 = 48111;

#[test]
fn record_pack_verify_end_to_end() -> Result<()> {
    let keep_tmp = std::env::var("FLOW_TEST_KEEP_TMP").is_ok();
    let tmp = tempfile::Builder::new().prefix("flow-e2e").tempdir()?;
    let tmp_path = tmp.path().to_path_buf();
    println!("e2e tmp dir: {}", tmp_path.display());
    let server_root = tmp_path.join("server");
    fs::create_dir_all(&server_root)?;
    fs::write(
        server_root.join("index.html"),
        "<html><body>hello</body></html>",
    )?;

    let mut server = spawn_python_server(&server_root)?;
    wait_for_port(SERVER_PORT, Duration::from_secs(5))?;

    let shot_dir = tmp_path.join("shot1");
    let flow_bin = assert_cmd::cargo::cargo_bin!("flow").to_path_buf();
    let mut record = Command::new(flow_bin.clone())
        .arg("record")
        .arg("--out")
        .arg(&shot_dir)
        .arg("--proxy")
        .arg(format!(":{PROXY_PORT}"))
        .arg("--include")
        .arg(format!("localhost:{SERVER_PORT}"))
        .arg("--exit-after")
        .arg("1")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn flow record")?;
    wait_for_port(PROXY_PORT, Duration::from_secs(5))?;

    if let Err(err) = run_curl_proxy_request() {
        let logs = stop_child_with_logs(&mut record);
        terminate_child(&mut server);
        return Err(err.context(format!("flow stderr:\n{}", logs)));
    }
    wait_for_capture(&shot_dir, Duration::from_secs(5))?;

    wait_for_child(&mut record, Duration::from_secs(10))?;
    terminate_child(&mut server);

    let bundle = tmp_path.join("flow.bundle.zip");
    AssertCommand::new(flow_bin.clone())
        .arg("pack")
        .arg("--in")
        .arg(&shot_dir)
        .arg("--out")
        .arg(&bundle)
        .arg("--deterministic")
        .assert()
        .success();

    AssertCommand::new(flow_bin.clone())
        .arg("verify")
        .arg(&bundle)
        .arg("--policy")
        .arg("examples/verify.yaml")
        .assert()
        .success();

    if keep_tmp {
        let _ = tmp.keep();
    }
    Ok(())
}

fn spawn_python_server(root: &Path) -> Result<std::process::Child> {
    let candidates = [
        PythonCandidate {
            program: "python3",
            version_args: &["--version"],
            server_prefix: &[],
        },
        PythonCandidate {
            program: "python",
            version_args: &["--version"],
            server_prefix: &[],
        },
        PythonCandidate {
            program: "py",
            version_args: &["-3", "--version"],
            server_prefix: &["-3"],
        },
    ];

    for cand in candidates {
        if Command::new(cand.program)
            .args(cand.version_args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
        {
            let mut args: Vec<String> = cand.server_prefix.iter().map(|s| s.to_string()).collect();
            args.push("-m".into());
            args.push("http.server".into());
            args.push(SERVER_PORT.to_string());
            return Command::new(cand.program)
                .args(&args)
                .current_dir(root)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .context("failed to spawn python http.server");
        }
    }
    bail!("python interpreter not found (tried python3, python, py)");
}

fn wait_for_port(port: u16, timeout: Duration) -> Result<()> {
    let addr = format!("127.0.0.1:{port}");
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(&addr).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("timed out waiting for {}", addr);
}

fn run_curl_proxy_request() -> Result<()> {
    let status = Command::new("curl")
        .args([
            "-sS",
            "-x",
            &format!("http://127.0.0.1:{PROXY_PORT}"),
            &format!("http://localhost:{SERVER_PORT}/"),
        ])
        .stdout(Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(code) => bail!("curl exited with status {}", code),
        Err(err) => bail!("failed to run curl: {err}"),
    }
}

fn wait_for_child(child: &mut std::process::Child, timeout: Duration) -> Result<()> {
    if child.wait_timeout(timeout)?.is_none() {
        let logs = stop_child_with_logs(child);
        if logs.is_empty() {
            bail!("process did not exit within {:?}", timeout);
        } else {
            bail!(
                "process did not exit within {:?}. stderr:\n{}",
                timeout,
                logs
            );
        }
    }
    Ok(())
}

fn terminate_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn stop_child_with_logs(child: &mut std::process::Child) -> String {
    let _ = child.kill();
    let _ = child.wait();
    let mut buf = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut buf);
    }
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut buf);
    }
    buf
}

fn wait_for_capture(shot: &Path, timeout: Duration) -> Result<()> {
    let requests_dir = shot.join("requests");
    let start = Instant::now();
    while start.elapsed() < timeout {
        if requests_dir.exists() {
            if let Ok(mut entries) = fs::read_dir(&requests_dir) {
                if entries.next().is_some() {
                    return Ok(());
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!(
        "no captured requests written to {} within {:?}",
        requests_dir.display(),
        timeout
    );
}

struct PythonCandidate {
    program: &'static str,
    version_args: &'static [&'static str],
    server_prefix: &'static [&'static str],
}
