# Usage Notes

This doc contains details that are intentionally kept out of the README.

Nix setup: [docs/nix.md](nix.md).

## CLI

There are no subcommands. Everything is a top-level flag.

Common flags:
- `--backends "..."`
- `--direction download|upload|both`
- `--concurrency N`
- `--duration SECONDS`
- `--prefix data-8m`
- `--file-count N`
- `--file-size-mb N`
- `--output human|json|csv|toml`

Config:
- If `./netprofiler_lite.toml` exists, it is read automatically.
- CLI flags override config values.

## Backends

Backend specs are comma-separated:

- S3: `bucket:region` (example: `my-bkt:eu-north-1`)
- R2 (authenticated): `r2:bucket:account_id` or `r2:bucket` (uses `R2_ACCOUNT_ID`)
- Public HTTP origin: `https://...`
  - Use this for CloudFront (`https://d111111abcdef8.cloudfront.net`) or Cloudflare public R2 (`https://pub-xxxx.r2.dev`).

## Credentials

End-users running download-only benchmarks against public objects should NOT set credentials.

Upload tests and `--ensure` require credentials.

S3 (AWS):
- Env:
  - `AWS_ACCESS_KEY_ID`
  - `AWS_SECRET_ACCESS_KEY`
  - optional: `AWS_SESSION_TOKEN`
- Shared credentials file:
  - `~/.aws/credentials` (respects `AWS_PROFILE` / `AWS_DEFAULT_PROFILE`)
  - optional: `AWS_SHARED_CREDENTIALS_FILE`

R2:
- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `R2_ACCOUNT_ID` (if not provided in backend spec)

## Troubleshooting

- `HTTP 429` / very low `ok%`: your endpoint is rate-limiting. Reduce `--concurrency` or use a different backend.
- `preflight GET failed ... 404`: objects were not seeded (or not public). Ask the maintainer to run preseeding.
