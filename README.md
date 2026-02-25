# netprofiler_lite

Small, shareable object-storage throughput benchmark.

- End-user download runs require no credentials (public-readable objects only).
- Defaults (object sizing + grading thresholds) are informed by field experience and conversations with HPC/AI researchers.
- Roadmap: evolve toward saturating an entire cluster (not just one host).

## Quickstart

Prebuilt binary (fastest):

```bash
os="$(uname -s)"; arch="$(uname -m)"
case "${os}-${arch}" in
  Linux-x86_64) asset="netprofiler_lite-linux-x86_64.tar.gz" ;;
  Darwin-x86_64) asset="netprofiler_lite-macos-x86_64.tar.gz" ;;
  Darwin-arm64) asset="netprofiler_lite-macos-arm64.tar.gz" ;;
  *) echo "unsupported: ${os}-${arch}"; exit 1 ;;
esac

base="https://github.com/kennethdsheridan/netprofiler_lite/releases/latest/download"
curl -fsSL -O "${base}/${asset}" -O "${base}/${asset}.sha256"
shasum -a 256 -c "${asset}.sha256" 2>/dev/null || sha256sum -c "${asset}.sha256"
tar -xzf "${asset}"

./netprofiler_lite
```

Nix:

```bash
nix run --accept-flake-config .#bench
```

Non-Nix (Rust toolchain):

```bash
curl https://sh.rustup.rs -sSf | sh -s -- -y
source "$HOME/.cargo/env"

cargo build --release
./target/release/netprofiler_lite
```

## Docs

- Table of contents:
- Nix setup: `docs/nix.md`
- Usage (CLI flags, config, backends, credentials, troubleshooting): `docs/usage.md`
- Preseeding objects (maintainers): `docs/preseed.md`
- Releases (download + tag-based releases): `docs/release.md`
