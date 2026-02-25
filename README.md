# netprofiler_lite

Small, shareable object-storage network benchmark for datacenter providers.

Goals:
- Compare multi-region object storage throughput from a host.
- Support AWS S3 and Cloudflare R2 (S3-compatible) without requiring `aws` CLI.
- Keep the code small and vendor-neutral.

This is intended to be shared with providers (e.g. NDG) to reproduce observed results
without distributing any proprietary binaries or internal agent code.

## No Credentials Required (Partner Runs)

If you are a partner/end-user running the benchmark:
- You do NOT need AWS or R2 credentials.
- You do NOT need `aws` CLI.
- You ONLY need public-readable test objects (provided by SF Compute).

Credentialed operations are maintainer-only:
- `--ensure` (create/check/seed objects) requires credentials.
- Upload tests require credentials.

## Partner quickstart (recommended)

1) Build with Nix (deterministic):

```bash
nix build --accept-flake-config
./result/bin/netprofiler_lite --help
```

Or build with Rust toolchain:

```bash
cargo build --release
./target/release/netprofiler_lite --help
```

2) Configure backends

Edit `netprofiler_lite.toml` and set `backends = [...]`.

- S3: `"bucket:region"` (SF Compute seeds the bucket + makes objects public-read)
- Cloudflare R2 (public): use the bucket *public origin* as `"https://pub-<id>.r2.dev"` (no creds)

3) Run

```bash
./result/bin/netprofiler_lite
# or
./target/release/netprofiler_lite
```

The binary reads `./netprofiler_lite.toml` automatically when present. CLI flags override config.

## CLI shape

There are no subcommands. Everything is a top-level flag:

```bash
./target/release/netprofiler_lite --backends "bkt:us-west-2,https://pub-....r2.dev" --duration 60
```

## Preseed artifacts (SF Compute side)

Use this to seed S3/R2 objects so partners can run download benchmarks without credentials.

Run with Nix + Doppler (no secrets written to disk):

```bash

# Optional: set explicit bucket names.
# If omitted, the seeder defaults to globally-unique names based on your AWS account id.
# You can override the base name via NETPROFILER_BUCKET_BASE.
# export NETPROFILER_BUCKET_BASE=netprofiler-lite
# export BUCKET_EUN1=...
# export BUCKET_EUC1=...
# export BUCKET_USW2=...
# export BUCKET_USE1=...

export R2_BUCKET=...            # optional (single bucket)
export R2_BUCKET_BASE=sf-netprofiler-lite-r2   # optional; seeds two buckets: -us and -eu
# or explicitly:
# export R2_BUCKET_US=sf-netprofiler-lite-r2-us
# export R2_BUCKET_EU=sf-netprofiler-lite-r2-eu
export PREFIX=data-8m
export FILE_COUNT=100
export FILE_SIZE_MB=8

nix develop --accept-flake-config -c doppler run --project cloudflare --config prd -- \
  bash ./scripts/seed_artifacts.sh
```

Seeding speed knobs:
- `SEED_CONCURRENCY=16` (default): parallel uploads per bucket/region
- `SEED_MODE=overwrite` (default): always upload objects (fastest)
- `SEED_MODE=skip-existing`: HEAD objects first and only upload missing
- `SEED_SKIP_IF_PRESENT=1` (default): if `${PREFIX}.0` and `${PREFIX}.(file_count-1)` exist, skip uploading objects

Or as a flake app:

```bash
nix run .#seed --accept-flake-config
```

## Backends

Comma-separated specs:

- S3: `bucket:region` (e.g. `my-bkt:eu-north-1`)
- R2: `r2:bucket:account_id` or `r2:bucket` (uses `R2_ACCOUNT_ID`)
- Public HTTP origin: `https://...`
  - Use this for CloudFront (`https://d111111abcdef8.cloudfront.net`) or Cloudflare public R2 (`https://pub-xxxx.r2.dev`).

## Credentials

Partners/end-users: you can skip this section.

For partner download runs, do NOT set any credentials; just run with public backends.

S3 (AWS):
- Prefers env vars:
  - `AWS_ACCESS_KEY_ID`
  - `AWS_SECRET_ACCESS_KEY`
  - optional: `AWS_SESSION_TOKEN`
- Also supports standard shared credentials:
  - `~/.aws/credentials` (respects `AWS_PROFILE` / `AWS_DEFAULT_PROFILE`)
  - optional: `AWS_SHARED_CREDENTIALS_FILE`

Seeder precedence:
- By default, `scripts/seed_artifacts.sh` prefers `~/.aws/credentials` over env vars.
- To force env vars to win, set `AWS_ENV_OVERRIDE=1`.

R2:
- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `R2_ACCOUNT_ID` (if not provided in backend spec)

Note: make sure you're using the intended Cloudflare account id. You can force it when seeding:

```bash
export R2_ACCOUNT_ID=751a8d4a9f0608f2aa7758b0e8cdd7c1
```

R2 public access (for partner no-credential download tests):
- Cloudflare Dashboard -> R2 -> Buckets -> select bucket
- Enable "Public access" (creates an `r2.dev` URL)
- For partner runs (no credentials), prefer using the public origin backend:
  - Add the bucket's public origin to `backends` as `https://pub-<id>.r2.dev`
  - `netprofiler_lite` will request `https://pub-<id>.r2.dev/<key>`

Note: `r2:bucket:account_id` backends are for authenticated access (R2_* env vars).

R2 US vs EU:
- Cloudflare R2 is globally distributed by default.
- To enforce an EU-only or US-only data boundary, create the bucket with the desired
  jurisdiction / data localization setting in the Cloudflare UI.

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

If objects are missing, you can seed them:

```bash
./target/release/netprofiler_lite \
  --backends "bkt-eun1:eu-north-1,bkt-usw2:us-west-2" \
  --ensure
```

Output formats:
- `--output human` (default)
- `--output json`
- `--output csv`
- `--output toml`

Report file:
- By default, a TOML report is written to `netprofiler_lite_report.toml`.
- Override with `--report-toml path/to/report.toml` or disable with `--no-report-toml`.
