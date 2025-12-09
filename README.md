# Flow v1.1

Flow is a deterministic HTTP **record → pack → verify** engine for debugging API and AI pipelines. It captures traffic through a proxy, produces cryptographically provable bundles, and replays/verifies them for reproducible runs. TLS intercept stays off by default; CONNECT tunnels only expose metadata, not encrypted payloads.

## Why Flow?
- Catch regressions early with deterministic, replayable HTTP bundles.
- Debug flaky API/LLM pipelines without re-hitting external services.
- Ship cryptographic proof trails for compliance and handoffs.
- Swap between live capture and offline verification with the same CLI.

## Features
- Live HTTP/1.1 proxy capture (no TLS intercept; CONNECT metadata only).
- Deterministic packing with stable hashes via `--deterministic`.
- Policy-based verification (see `examples/verify.yaml`) and redaction support.
- Replay support for captured sessions.
- Minimal dependencies; ships as a single binary.

## Install
- Download the latest binary from GitHub Releases and place it on your `PATH`.
- Or build from source: `cargo build --release` (binary at `target/release/flow`).

## Quickstart (copy/paste)
In one shell start a simple server:
```bash
python3 -m http.server 9000
```
In another shell, record → pack → verify:
```bash
RUST_LOG=info cargo run -- record --out shot1 --proxy :8080 --include localhost:9000
curl -x http://127.0.0.1:8080 http://localhost:9000/
cargo run -- pack --in shot1 --out flow.bundle.zip --deterministic
cargo run -- verify flow.bundle.zip --policy examples/verify.yaml
```
For HTTPS, route through CONNECT (metadata only, payloads stay encrypted):
```bash
curl -x http://127.0.0.1:8080 https://example.com/ -k
```

## Project layout
```
src/{cli,capture,normalize,pack,replay,verify,crypto,util}/*.rs
schemas/{manifest_v1.json,verify_v1.json}
examples/{verify.yaml,redact.yaml}
tests/{e2e.rs,determinism.rs}
.github/workflows/ci.yml
```

## Release process
1. Ensure `cargo fmt`, `cargo clippy --all-targets --all-features`, and `cargo test --all` pass.
2. Build optimized binaries for each platform: `cargo build --release`.
3. Package each binary as `flow-{os}-{arch}.tar.gz` (for example `flow-linux-x86_64.tar.gz`) using `tar -czf <archive> -C target/release flow{.exe}` and compute `sha256` files.
4. Tag the release (`git tag v1.1.0 && git push origin v1.1.0`); GitHub Actions uploads tarballs and hashes for the tag.
5. Update `CHANGELOG.md` with a brief summary for the release.
