# Preseeding Test Objects (Maintainers)

Partners/end-users should not need any credentials to run download benchmarks.
This document is for maintainers who seed objects and make them public-readable.

Tip: If you want `nix run .#bench` to include S3 without hardcoding bucket names in the repo,
tell users to export `NETPROFILER_S3_BUCKET_EUN1/EUC1/USW2/USE1` and then run the bench app.

## What This Does

- Creates S3 buckets (if missing) and uploads the test objects.
- Uploads objects to Cloudflare R2 buckets.
- Leaves partners with public-readable URLs so they can run download tests with no credentials.

## Default Bucket Names

The distribution defaults (used by `netprofiler_lite.toml` and `nix run .#bench`) are:

- `sf-netprofiler-lite-public-6f9c2e-eun1` (eu-north-1)
- `sf-netprofiler-lite-public-6f9c2e-euc1` (eu-central-1)
- `sf-netprofiler-lite-public-6f9c2e-usw2` (us-west-2)
- `sf-netprofiler-lite-public-6f9c2e-use1` (us-east-1)

If you need to change these, set `NETPROFILER_BUCKET_BASE` during seeding and update the defaults.

## Run (Nix + Doppler)

Run with Nix + Doppler so secrets are not written to disk:

```bash
# Optional: set explicit bucket names.
# If omitted, the seeder uses the distribution default base name.
# To override, set:
# export NETPROFILER_BUCKET_BASE=sf-netprofiler-lite-public-<suffix>
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

Or run the flake app (recommended for maintainers):

```bash
nix develop --accept-flake-config -c doppler run --project cloudflare --config prd -- \
  nix run --accept-flake-config .#seed
```

Expected output highlights:
- The seeder will load AWS creds from `~/.aws/credentials` (and will auto-select the only profile
  if `default` is missing keys).
- It will print the buckets it is using/creating, e.g.:
  - `BUCKET_EUN1=sf-netprofiler-lite-public-6f9c2e-eun1`
  - `BUCKET_EUC1=sf-netprofiler-lite-public-6f9c2e-euc1`
  - `BUCKET_USW2=sf-netprofiler-lite-public-6f9c2e-usw2`
  - `BUCKET_USE1=sf-netprofiler-lite-public-6f9c2e-use1`
- It will create missing buckets and upload `${PREFIX}.0..${PREFIX}.(FILE_COUNT-1)`.

Or as a flake app:

```bash
nix run .#seed --accept-flake-config
```

Note: this repo sets `nixConfig.extra-substituters`. Nix will prompt unless you pass
`--accept-flake-config` (as shown) or set `accept-flake-config = true` in your Nix config
(`~/.config/nix/nix.conf` or `/etc/nix/nix.conf`).

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
