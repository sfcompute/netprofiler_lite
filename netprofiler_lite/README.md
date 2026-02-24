# netprofiler_lite

Small, shareable object-storage network benchmark for datacenter providers.

Goals:
- Compare multi-region object storage throughput from a host.
- Support AWS S3 and Cloudflare R2 (S3-compatible) without requiring `aws` CLI.
- Keep the code small and vendor-neutral.

This is intended to be shared with providers (e.g. NDG) to reproduce observed results
without distributing any proprietary binaries or internal agent code.

## Deterministic dev env (recommended)

Install Determinate Nix:

```bash
curl -L https://install.determinate.systems/nix | sh -s -- install
```

Open a new shell, then:

```bash
cd netprofiler_lite
nix develop --accept-flake-config
```

Inside the dev shell:

```bash
cargo build --release
./target/release/netprofiler_lite --help
```

You can also build and run via Nix:

```bash
nix build --accept-flake-config
./result/bin/netprofiler_lite --help
```

## Preseed artifacts (SF Compute side)

Use this to seed S3/R2 objects so partners can run download benchmarks without credentials.

Run with Nix + Doppler (no secrets written to disk):

```bash
cd netprofiler_lite

# Optional: set explicit bucket names.
# If omitted, the seeder defaults to globally-unique names based on your AWS account id.
# You can override the base name via NETPROFILER_BUCKET_BASE.
# export NETPROFILER_BUCKET_BASE=netprofiler-lite
# export BUCKET_EUN1=...
# export BUCKET_EUC1=...
# export BUCKET_USW2=...
# export BUCKET_USE1=...

export R2_BUCKET=...            # optional
export PREFIX=data-8m
export FILE_COUNT=100
export FILE_SIZE_MB=8

nix develop --accept-flake-config -c doppler run --project cloudflare --config prd -- \
  bash ./scripts/seed_artifacts.sh
```

Or as a flake app:

```bash
cd netprofiler_lite
nix run .#seed --accept-flake-config
```

## Backends

Comma-separated specs:

- S3: `bucket:region` (e.g. `my-bkt:eu-north-1`)
- R2: `r2:bucket:account_id` or `r2:bucket` (uses `R2_ACCOUNT_ID`)

## Credentials

S3 (AWS):
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- optional: `AWS_SESSION_TOKEN`

R2:
- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `R2_ACCOUNT_ID` (if not provided in backend spec)

If you don't have credentials:
- You can still run `--direction download` as long as the objects are public-read.
- Omit `--ensure` (it requires credentials to check/create/seed).

## Typical run (download)

```bash
./target/release/netprofiler_lite compare \
  --backends "bkt-eun1:eu-north-1,bkt-usw2:us-west-2,bkt-use1:us-east-1,bkt-euc1:eu-central-1" \
  --direction download \
  --concurrency 256 \
  --duration 30 \
  --prefix data-8m \
  --file-count 100 \
  --file-size-mb 8
```

If objects are missing, you can seed them:

```bash
./target/release/netprofiler_lite compare \
  --backends "bkt-eun1:eu-north-1,bkt-usw2:us-west-2" \
  --ensure
```

Output formats:
- `--output human` (default)
- `--output json`
- `--output csv`
