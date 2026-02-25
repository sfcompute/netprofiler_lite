# Preseeding Test Objects (Maintainers)

Partners/end-users should not need any credentials to run download benchmarks.
This document is for SF Compute maintainers who seed objects and make them public-readable.

## What This Does

- Creates S3 buckets (if missing) and uploads the test objects.
- Uploads objects to Cloudflare R2 buckets.
- Leaves partners with public-readable URLs so they can run download tests with no credentials.

## Run (Nix + Doppler)

Run with Nix + Doppler so secrets are not written to disk:

```bash
# Optional: set explicit bucket names.
# If omitted, the seeder defaults to globally-unique names based on your AWS account id.
# You can override the base name via NETPROFILER_BUCKET_BASE.
# export NETPROFILER_BUCKET_BASE=netprofiler-lite
# export BUCKET_EUN1=...
# export BUCKET_EUC1=...
# export BUCKET_USW2=...
# export BUCKET_USE1=...

export R2_BUCKET=...                        # optional (single bucket)
export R2_BUCKET_BASE=sf-netprofiler-lite-r2 # optional; seeds two buckets: -us and -eu
# or explicitly:
# export R2_BUCKET_US=sf-netprofiler-lite-r2-us
# export R2_BUCKET_EU=sf-netprofiler-lite-r2-eu

export PREFIX=data-8m
export FILE_COUNT=100
export FILE_SIZE_MB=8

nix develop --accept-flake-config -c doppler run --project cloudflare --config prd -- \
  bash ./scripts/seed_artifacts.sh
```

Or as a flake app:

```bash
nix run .#seed --accept-flake-config
```

## Seeding Speed Knobs

- `SEED_CONCURRENCY=16` (default): parallel uploads per bucket/region
- `SEED_MODE=overwrite` (default): always upload objects (fastest)
- `SEED_MODE=skip-existing`: HEAD objects first and only upload missing
- `SEED_SKIP_IF_PRESENT=1` (default): if `${PREFIX}.0` and `${PREFIX}.(file_count-1)` exist, skip uploading objects

## Credentials (Seeder)

S3 (AWS):
- Prefers env vars:
  - `AWS_ACCESS_KEY_ID`
  - `AWS_SECRET_ACCESS_KEY`
  - optional: `AWS_SESSION_TOKEN`
- Also supports shared credentials:
  - `~/.aws/credentials` (respects `AWS_PROFILE` / `AWS_DEFAULT_PROFILE`)
  - optional: `AWS_SHARED_CREDENTIALS_FILE`

Seeder precedence:
- By default, `scripts/seed_artifacts.sh` prefers `~/.aws/credentials` over env vars.
- To force env vars to win, set `AWS_ENV_OVERRIDE=1`.

R2:
- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `R2_ACCOUNT_ID` (if not provided in backend spec)

If you need `aws configure`, run it inside the Nix dev shell:

```bash
nix develop --accept-flake-config -c aws configure
```

## Cloudflare R2 Public Access (Partner Downloads)

To enable anonymous downloads for partners:

- Cloudflare Dashboard -> R2 -> Buckets -> select bucket
- Enable "Public access" (creates an `r2.dev` URL)
- Partners should use the bucket's public origin as an HTTP backend:
  - `https://pub-<id>.r2.dev`
  - `netprofiler_lite` will request `https://pub-<id>.r2.dev/<key>`

Note: `r2:bucket:account_id` backends are for authenticated access (R2_* env vars).

## R2 US vs EU

- Cloudflare R2 is globally distributed by default.
- To enforce an EU-only or US-only data boundary, create the bucket with the desired
  jurisdiction / data localization setting in the Cloudflare UI.
