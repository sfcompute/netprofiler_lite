# netprofiler_lite

Small, shareable object-storage network benchmark.

Goals:
- Compare multi-region object storage throughput from a host.
- Support AWS S3 and Cloudflare R2 (S3-compatible) without requiring `aws` CLI.
- Keep the code small and vendor-neutral.

Notes on defaults:
- The default object size / object count / concurrency settings are chosen based on industry experience
  and conversations with researchers working in the HPC and AI space.
- The letter-grade thresholds are calibrated to reflect commonly discussed performance tiers for
  multi-Gbps networking in those environments.

This tool is designed to be shared so others can reproduce and compare object-storage throughput
results without distributing proprietary binaries.

Roadmap note:
- This is intended to evolve into a benchmark that can saturate an entire cluster (not just a
  single host), while keeping the same "no-credentials for end-users" distribution model.

## No Credentials Required (Partner Runs)

If you are an end-user running the benchmark:
- You do NOT need AWS or R2 credentials.
- You do NOT need `aws` CLI.
- You ONLY need public-readable test objects (provided by the benchmark maintainer).

Credentialed operations are maintainer-only:
- `--ensure` (create/check/seed objects) requires credentials.
- Upload tests require credentials.

## Partner quickstart (recommended)

0) Install Nix (Determininate Systems, non-interactive)

```bash
sudo curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix \
  | sh -s -- install --no-confirm

. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
```

1) Run with Nix (recommended)

Print help:

```bash
nix run --accept-flake-config . -- --help
```

Run the default public endpoints (copy/paste):

```bash
nix run --accept-flake-config .#bench
```

If you are running from GitHub (no checkout required):

```bash
nix run --accept-flake-config github:kennethdsheridan/netprofiler_lite#bench
```

Note: this repo sets `nixConfig.extra-substituters`. Nix will prompt unless you pass
`--accept-flake-config` (as shown) or set `accept-flake-config = true` in your Nix config
(`~/.config/nix/nix.conf` or `/etc/nix/nix.conf`).

## Releases

Prebuilt binaries are published for:
- Linux x86_64
- macOS (x86_64 and arm64)

Create a release by pushing a tag like `v0.1.0`.

2) Or build with Rust toolchain

```bash
cargo build --release
./target/release/netprofiler_lite --help
```

3) Configure backends (optional)

Edit `netprofiler_lite.toml` and set `backends = [...]`.

- S3: `"bucket:region"` (maintainer seeds the bucket + makes objects public-read)
- Cloudflare R2 (public): use the bucket *public origin* as `"https://pub-<id>.r2.dev"` (no creds)

3) Run

```bash
./result/bin/netprofiler_lite
# or
./target/release/netprofiler_lite
```

The binary reads `./netprofiler_lite.toml` automatically when present. CLI flags override config.

Copy/paste run command (same defaults as `.#bench`):

```bash
./target/release/netprofiler_lite \
  --backends "sf-netprofiler-lite-public-6f9c2e-eun1:eu-north-1,sf-netprofiler-lite-public-6f9c2e-euc1:eu-central-1,sf-netprofiler-lite-public-6f9c2e-usw2:us-west-2,sf-netprofiler-lite-public-6f9c2e-use1:us-east-1,https://pub-0323b6896e3e42cb8971495d2f9a2370.r2.dev,https://pub-c02404be13b644a1874a29231dfbe0d2.r2.dev" \
  --direction download \
  --concurrency 256 \
  --duration 15 \
  --prefix data-8m \
  --file-count 100 \
  --file-size-mb 8
```

## CLI shape

There are no subcommands. Everything is a top-level flag:

```bash
./target/release/netprofiler_lite --backends "bkt:us-west-2,https://pub-....r2.dev" --duration 60
```

## Maintainer Preseed

Maintainers: see `docs/preseed.md`.

## Backends

Comma-separated specs:

- S3: `bucket:region` (e.g. `my-bkt:eu-north-1`)
- R2: `r2:bucket:account_id` or `r2:bucket` (uses `R2_ACCOUNT_ID`)
- Public HTTP origin: `https://...`
  - Use this for CloudFront (`https://d111111abcdef8.cloudfront.net`) or Cloudflare public R2 (`https://pub-xxxx.r2.dev`).

## Credentials

End-users: you can skip this section.

For end-user download runs, do NOT set any credentials; just run with public backends.

S3 (AWS):
- Prefers env vars:
  - `AWS_ACCESS_KEY_ID`
  - `AWS_SECRET_ACCESS_KEY`
  - optional: `AWS_SESSION_TOKEN`
- Also supports standard shared credentials:
  - `~/.aws/credentials` (respects `AWS_PROFILE` / `AWS_DEFAULT_PROFILE`)
  - optional: `AWS_SHARED_CREDENTIALS_FILE`

Seeder docs: `docs/preseed.md`.

R2:
- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `R2_ACCOUNT_ID` (if not provided in backend spec)

Note: make sure you're using the intended Cloudflare account id. You can force it when seeding:

```bash
export R2_ACCOUNT_ID=751a8d4a9f0608f2aa7758b0e8cdd7c1
```

R2 public access + seeding details: `docs/preseed.md`.

If you don't have credentials:
- You can still run `--direction download` as long as the objects are public-read.
- Omit `--ensure` (it requires credentials to check/create/seed).

Tip: if you need `aws configure`, run it inside the Nix dev shell:

```bash
nix develop --accept-flake-config -c aws configure
```

## Typical run (download)

```bash
./target/release/netprofiler_lite
```

This reads `netprofiler_lite.toml` automatically (if present). CLI args override config.

Override just one thing (example):

```bash
./target/release/netprofiler_lite --duration 60
```

If objects are missing: ask the maintainer to seed them (see `docs/preseed.md`).

Output formats:
- `--output human` (default)
- `--output json`
- `--output csv`
- `--output toml`

Report file:
- By default, a TOML report is written to `netprofiler_lite_report.toml`.
- Override with `--report-toml path/to/report.toml` or disable with `--no-report-toml`.
