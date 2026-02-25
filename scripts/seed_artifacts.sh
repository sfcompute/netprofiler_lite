#!/usr/bin/env bash
# Seed and (optionally) publish benchmark artifacts for netprofiler_lite.
#
# Run this on the SF Compute side so partners can benchmark without credentials
# (anonymous download mode) after objects are made public.

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

need aws
need dd
need curl
need head
need tr

# Speed knobs
# - SEED_CONCURRENCY: parallelism per bucket/region
# - SEED_MODE:
#     overwrite     -> always upload objects (fastest; safe for one-off preseeding)
#     skip-existing -> HEAD each object and only upload if missing
SEED_CONCURRENCY="${SEED_CONCURRENCY:-16}"
SEED_MODE="${SEED_MODE:-overwrite}"
# If the bucket already appears to have the artifacts (prefix.0 and prefix.(file_count-1)),
# skip uploading objects for that bucket.
SEED_SKIP_IF_PRESENT="${SEED_SKIP_IF_PRESENT:-1}"

sanitize_no_newlines() {
  # Drop CR/LF characters (common when secrets are copied with trailing newline)
  # shellcheck disable=SC2001
  printf '%s' "$1" | tr -d '\r\n'
}

load_aws_creds_from_shared_file() {
  # If AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY aren't set, try to source them
  # from AWS_SHARED_CREDENTIALS_FILE or ~/.aws/credentials.
  #
  # This avoids surprises when running via `nix run` where users expect their
  # standard shared credentials file to be honored.
  #
  # Precedence:
  # - By default, shared credentials file wins ("look there first").
  # - If you need env vars to override the file, set AWS_ENV_OVERRIDE=1.

  trim() {
    local s="$1"
    # leading
    s="${s#"${s%%[!$' \t\r\n']*}"}"
    # trailing
    s="${s%"${s##*[!$' \t\r\n']}"}"
    printf '%s' "$s"
  }

  local profile credfile home
  profile="${AWS_PROFILE:-${AWS_DEFAULT_PROFILE:-default}}"

  if [[ -n "${AWS_SHARED_CREDENTIALS_FILE:-}" ]]; then
    credfile="$AWS_SHARED_CREDENTIALS_FILE"
  else
    home="${HOME:-/root}"
    credfile="${home%/}/.aws/credentials"
  fi

  [[ -n "${credfile}" ]] || return 0
  [[ -f "${credfile}" ]] || {
    echo "WARN: AWS shared credentials not found at $credfile (profile=$profile)" >&2
    return 0
  }

  # Parse minimal INI: find [profile] section and read keys.
  local in_section=0 line key val
  local profiles_seen=""
  local ak="" sk="" st=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line%%;*}"
    line="$(trim "$line")"
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^\[(.*)\]$ ]]; then
      if [[ -z "$profiles_seen" ]]; then
        profiles_seen="${BASH_REMATCH[1]}"
      else
        profiles_seen="${profiles_seen},${BASH_REMATCH[1]}"
      fi
      if [[ "${BASH_REMATCH[1]}" == "$profile" ]]; then
        in_section=1
      else
        in_section=0
      fi
      continue
    fi
    (( in_section == 1 )) || continue
    [[ "$line" == *"="* ]] || continue
    key="${line%%=*}"
    val="${line#*=}"
    key="$(trim "$key")"
    val="$(trim "$val")"
    key="${key,,}"
    # Strip simple quotes
    val="${val%\"}"; val="${val#\"}"
    val="${val%\'}"; val="${val#\'}"

    case "$key" in
      aws_access_key_id|access_key_id) ak="$val" ;;
      aws_secret_access_key|secret_access_key) sk="$val" ;;
      aws_session_token|session_token) st="$val" ;;
    esac
  done <"$credfile"

  if [[ -n "$ak" && -n "$sk" ]]; then
    if [[ "${AWS_ENV_OVERRIDE:-0}" == "1" && -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
      echo "INFO: Using AWS creds from environment (AWS_ENV_OVERRIDE=1)" >&2
      return 0
    else
      export AWS_ACCESS_KEY_ID="$ak"
      export AWS_SECRET_ACCESS_KEY="$sk"
      if [[ -n "$st" ]]; then
        export AWS_SESSION_TOKEN="$st"
      fi
      echo "INFO: Loaded AWS creds from $credfile (profile=$profile)" >&2
    fi
  else
    echo "WARN: No static keys found in $credfile (profile=$profile)" >&2
    if [[ -n "$profiles_seen" ]]; then
      echo "WARN: Profiles present in $credfile: $profiles_seen" >&2
      echo "WARN: Set AWS_PROFILE to one of those profile names." >&2
    fi
  fi
}

load_aws_creds_from_shared_file

PREFIX="${PREFIX:-data-8m}"
FILE_COUNT="${FILE_COUNT:-100}"
FILE_SIZE_MB="${FILE_SIZE_MB:-8}"

# Set these for the 4-backend NDG run.
BUCKET_EUN1="${BUCKET_EUN1:-}"
BUCKET_EUC1="${BUCKET_EUC1:-}"
BUCKET_USW2="${BUCKET_USW2:-}"
BUCKET_USE1="${BUCKET_USE1:-}"

R2_BUCKET="${R2_BUCKET:-}"
R2_BUCKET_BASE="${R2_BUCKET_BASE:-${R2_BUCKET}}"
R2_BUCKET_US="${R2_BUCKET_US:-}"
R2_BUCKET_EU="${R2_BUCKET_EU:-}"
R2_ACCOUNT_ID="${R2_ACCOUNT_ID:-}"

# Allow using Doppler Cloudflare secret names directly.
R2_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID:-${CLOUDFLARE_R2_ACCESS_ID:-}}"
R2_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY:-${CLOUDFLARE_R2_SECRET_ACCESS_KEY:-}}"
R2_ACCOUNT_ID="${R2_ACCOUNT_ID:-${CLOUDFLARE_R2_ACCOUNT_ID:-}}"
R2_ACCESS_KEY_ID="$(sanitize_no_newlines "${R2_ACCESS_KEY_ID:-}")"
R2_SECRET_ACCESS_KEY="$(sanitize_no_newlines "${R2_SECRET_ACCESS_KEY:-}")"
R2_ACCOUNT_ID="$(sanitize_no_newlines "${R2_ACCOUNT_ID:-}")"

# If both are present (explicit + Doppler), require they match.
if [[ -n "${CLOUDFLARE_R2_ACCOUNT_ID:-}" && -n "${R2_ACCOUNT_ID:-}" ]]; then
  if [[ "$(sanitize_no_newlines "${CLOUDFLARE_R2_ACCOUNT_ID}")" != "${R2_ACCOUNT_ID}" ]]; then
    die "R2 account id mismatch: R2_ACCOUNT_ID=${R2_ACCOUNT_ID} CLOUDFLARE_R2_ACCOUNT_ID=${CLOUDFLARE_R2_ACCOUNT_ID}"
  fi
fi

if [[ -n "$R2_BUCKET_BASE" ]]; then
  if [[ -z "$R2_BUCKET_US" ]]; then R2_BUCKET_US="${R2_BUCKET_BASE}-us"; fi
  if [[ -z "$R2_BUCKET_EU" ]]; then R2_BUCKET_EU="${R2_BUCKET_BASE}-eu"; fi
fi

publish_s3_policy() {
  local bucket="$1"
  local policy

  policy=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadBenchmarkObjects",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::${bucket}/${PREFIX}.*"]
    }
  ]
}
EOF
)

  aws s3api put-public-access-block \
    --bucket "$bucket" \
    --public-access-block-configuration \
      BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false \
    >/dev/null

  aws s3api put-bucket-policy --bucket "$bucket" --policy "$policy" >/dev/null
}

verify_s3_public_get() {
  # args: bucket region key
  local bucket="$1" region="$2" key="$3"
  local url
  if [[ "$region" == "us-east-1" ]]; then
    url="https://${bucket}.s3.amazonaws.com/${key}"
  else
    url="https://${bucket}.s3.${region}.amazonaws.com/${key}"
  fi

  local code
  code="$(curl -sS -o /dev/null -I -w '%{http_code}' --connect-timeout 5 --max-time 20 "$url" || echo 000)"
  case "$code" in
    200|206|301|302|307|308)
      echo "INFO: Public S3 OK: $url (HTTP $code)" >&2
      ;;
    403)
      die "Public S3 check failed (403) for $url. Likely causes: account-level Block Public Access, bucket default KMS encryption, or policy not applied."
      ;;
    404)
      die "Public S3 check failed (404) for $url. Object missing: ${key}"
      ;;
    000)
      die "Public S3 check failed (no response) for $url. Check DNS/egress/firewall."
      ;;
    *)
      die "Public S3 check failed (HTTP $code) for $url"
      ;;
  esac
}

ensure_s3_bucket() {
  local bucket="$1" region="$2"

  if aws s3api head-bucket --bucket "$bucket" >/dev/null 2>&1; then
    local loc
    loc=$(aws s3api get-bucket-location --bucket "$bucket" --output text 2>/dev/null || true)
    case "$loc" in
      None|NONE|null|NULL|"") loc="us-east-1";;
    esac
    [[ "$loc" == "$region" ]] || die "S3 bucket region mismatch: $bucket configured=$region actual=$loc"
    return 0
  fi

  echo "Creating S3 bucket: $bucket ($region)"
  if [[ "$region" == "us-east-1" ]]; then
    aws s3api create-bucket --bucket "$bucket" >/dev/null
  else
    aws s3api create-bucket \
      --bucket "$bucket" \
      --region "$region" \
      --create-bucket-configuration "LocationConstraint=$region" \
      >/dev/null
  fi
}

seed_objects_s3() {
  local bucket="$1" region="$2" payload_path="$3"

  if [[ "$SEED_SKIP_IF_PRESENT" == "1" ]]; then
    local first last
    first="${PREFIX}.0"
    last="${PREFIX}.$((FILE_COUNT-1))"
    if aws s3api head-object --bucket "$bucket" --key "$first" --region "$region" >/dev/null 2>&1 \
      && aws s3api head-object --bucket "$bucket" --key "$last" --region "$region" >/dev/null 2>&1; then
      echo "Skipping object seeding for $bucket ($region): artifacts already present" >&2
      return 0
    fi
  fi

  export PREFIX FILE_COUNT
  case "$SEED_MODE" in
    overwrite|skip-existing) ;;
    *) die "Invalid SEED_MODE: $SEED_MODE (use overwrite or skip-existing)";;
  esac

  seq 0 $((FILE_COUNT-1)) | xargs -n 1 -P "$SEED_CONCURRENCY" bash -c '
    set -euo pipefail
    i="$1"
    key="${PREFIX}.${i}"
    if [[ "'$SEED_MODE'" == "skip-existing" ]]; then
      if aws s3api head-object --bucket "'$bucket'" --key "$key" --region "'$region'" >/dev/null 2>&1; then
        exit 0
      fi
    fi
    aws s3api put-object --bucket "'$bucket'" --key "$key" --body "'$payload_path'" --region "'$region'" >/dev/null
  ' _
}

ensure_r2_bucket() {
  local bucket="$1" account_id="$2"
  local endpoint="https://${account_id}.r2.cloudflarestorage.com"

  AWS_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID:?set R2_ACCESS_KEY_ID (or CLOUDFLARE_R2_ACCESS_ID)}" \
  AWS_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY:?set R2_SECRET_ACCESS_KEY (or CLOUDFLARE_R2_SECRET_ACCESS_KEY)}" \
  AWS_SESSION_TOKEN="" \
  AWS_REGION="auto" \
  aws --endpoint-url "$endpoint" s3api head-bucket --bucket "$bucket" >/dev/null 2>&1 \
    && return 0

  echo "Creating R2 bucket: $bucket (account_id=$account_id)"
  AWS_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID:?}" \
  AWS_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY:?}" \
  AWS_SESSION_TOKEN="" \
  AWS_REGION="auto" \
  aws --endpoint-url "$endpoint" s3api create-bucket --bucket "$bucket" >/dev/null
}

seed_objects_r2() {
  local bucket="$1" account_id="$2" payload_path="$3"
  local endpoint="https://${account_id}.r2.cloudflarestorage.com"

  : "${R2_ACCESS_KEY_ID:?missing R2_ACCESS_KEY_ID}"
  : "${R2_SECRET_ACCESS_KEY:?missing R2_SECRET_ACCESS_KEY}"
  export PREFIX FILE_COUNT R2_ACCESS_KEY_ID R2_SECRET_ACCESS_KEY

  if [[ "$SEED_SKIP_IF_PRESENT" == "1" ]]; then
    local first last
    first="${PREFIX}.0"
    last="${PREFIX}.$((FILE_COUNT-1))"
    if AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID" \
       AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY" \
       AWS_SESSION_TOKEN="" \
       AWS_REGION="auto" \
       aws --endpoint-url "$endpoint" s3api head-object --bucket "$bucket" --key "$first" >/dev/null 2>&1 \
      && AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID" \
         AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY" \
         AWS_SESSION_TOKEN="" \
         AWS_REGION="auto" \
         aws --endpoint-url "$endpoint" s3api head-object --bucket "$bucket" --key "$last" >/dev/null 2>&1; then
      echo "Skipping object seeding for r2:$bucket: artifacts already present" >&2
      return 0
    fi
  fi
  case "$SEED_MODE" in
    overwrite|skip-existing) ;;
    *) die "Invalid SEED_MODE: $SEED_MODE (use overwrite or skip-existing)";;
  esac

  seq 0 $((FILE_COUNT-1)) | xargs -n 1 -P "$SEED_CONCURRENCY" bash -c '
    set -euo pipefail
    i="$1"
    key="${PREFIX}.${i}"
    if [[ "'$SEED_MODE'" == "skip-existing" ]]; then
      if AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID" \
         AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY" \
         AWS_SESSION_TOKEN="" \
         AWS_REGION="auto" \
         aws --endpoint-url "'$endpoint'" s3api head-object --bucket "'$bucket'" --key "$key" >/dev/null 2>&1; then
        exit 0
      fi
    fi
    AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID" \
    AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY" \
    AWS_SESSION_TOKEN="" \
    AWS_REGION="auto" \
    aws --endpoint-url "'$endpoint'" s3api put-object --bucket "'$bucket'" --key "$key" --body "'$payload_path'" >/dev/null
  ' _
}

publish_r2_policy_best_effort() {
  local bucket="$1" account_id="$2"
  local endpoint="https://${account_id}.r2.cloudflarestorage.com"
  local policy
  policy=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadBenchmarkObjects",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::${bucket}/${PREFIX}.*"]
    }
  ]
}
EOF
)

  AWS_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID:?}" \
  AWS_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY:?}" \
  AWS_SESSION_TOKEN="" \
  AWS_REGION="auto" \
  aws --endpoint-url "$endpoint" s3api put-bucket-policy --bucket "$bucket" --policy "$policy" >/dev/null \
    || {
      echo "WARN: failed to apply R2 public policy via S3 API; configure public access in Cloudflare if needed." >&2
      return 0
    }
}

payload="/tmp/netprofiler-payload-${FILE_SIZE_MB}mb.bin"
if [[ ! -f "$payload" ]]; then
  echo "Creating local payload: ${payload} (${FILE_SIZE_MB}MB)"
  dd if=/dev/zero of="$payload" bs=1048576 count="$FILE_SIZE_MB" status=none
fi

bucket_defaults() {
  # Default to a random suffix to avoid leaking AWS account ids and to avoid
  # global name collisions.
  random_suffix() {
    LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8
  }

  # Allow overriding the base name if desired (to keep stable buckets).
  local base
  base="${NETPROFILER_BUCKET_BASE:-netprofiler-lite-$(random_suffix)}"

  if [[ -z "$BUCKET_EUN1" ]]; then BUCKET_EUN1="${base}-eun1"; fi
  if [[ -z "$BUCKET_EUC1" ]]; then BUCKET_EUC1="${base}-euc1"; fi
  if [[ -z "$BUCKET_USW2" ]]; then BUCKET_USW2="${base}-usw2"; fi
  if [[ -z "$BUCKET_USE1" ]]; then BUCKET_USE1="${base}-use1"; fi
}

bucket_defaults

echo "Using buckets:"
echo "  BUCKET_EUN1=$BUCKET_EUN1"
echo "  BUCKET_EUC1=$BUCKET_EUC1"
echo "  BUCKET_USW2=$BUCKET_USW2"
echo "  BUCKET_USE1=$BUCKET_USE1"

echo "For nix run .#bench with S3, export:" >&2
echo "  export NETPROFILER_S3_BUCKET_EUN1=$BUCKET_EUN1" >&2
echo "  export NETPROFILER_S3_BUCKET_EUC1=$BUCKET_EUC1" >&2
echo "  export NETPROFILER_S3_BUCKET_USW2=$BUCKET_USW2" >&2
echo "  export NETPROFILER_S3_BUCKET_USE1=$BUCKET_USE1" >&2

[[ -n "$BUCKET_EUN1" ]] || die "BUCKET_EUN1 not set"
[[ -n "$BUCKET_EUC1" ]] || die "BUCKET_EUC1 not set"
[[ -n "$BUCKET_USW2" ]] || die "BUCKET_USW2 not set"
[[ -n "$BUCKET_USE1" ]] || die "BUCKET_USE1 not set"

echo "Seeding S3 buckets..."
ensure_s3_bucket "$BUCKET_EUN1" "eu-north-1"
seed_objects_s3 "$BUCKET_EUN1" "eu-north-1" "$payload"
publish_s3_policy "$BUCKET_EUN1"

ensure_s3_bucket "$BUCKET_EUC1" "eu-central-1"
seed_objects_s3 "$BUCKET_EUC1" "eu-central-1" "$payload"
publish_s3_policy "$BUCKET_EUC1"

ensure_s3_bucket "$BUCKET_USW2" "us-west-2"
seed_objects_s3 "$BUCKET_USW2" "us-west-2" "$payload"
publish_s3_policy "$BUCKET_USW2"

ensure_s3_bucket "$BUCKET_USE1" "us-east-1"
seed_objects_s3 "$BUCKET_USE1" "us-east-1" "$payload"
publish_s3_policy "$BUCKET_USE1"

echo "S3 done."

if [[ -n "$R2_BUCKET_US" || -n "$R2_BUCKET_EU" ]]; then
  [[ -n "$R2_ACCOUNT_ID" ]] || die "Set R2_ACCOUNT_ID (or CLOUDFLARE_R2_ACCOUNT_ID) when using R2 buckets"
  : "${R2_ACCESS_KEY_ID:?set R2_ACCESS_KEY_ID (or CLOUDFLARE_R2_ACCESS_ID)}"
  : "${R2_SECRET_ACCESS_KEY:?set R2_SECRET_ACCESS_KEY (or CLOUDFLARE_R2_SECRET_ACCESS_KEY)}"

  if [[ -n "$R2_BUCKET_US" ]]; then
    echo "Seeding R2 (US) bucket..."
    ensure_r2_bucket "$R2_BUCKET_US" "$R2_ACCOUNT_ID"
    seed_objects_r2 "$R2_BUCKET_US" "$R2_ACCOUNT_ID" "$payload"
    publish_r2_policy_best_effort "$R2_BUCKET_US" "$R2_ACCOUNT_ID"
  fi

  if [[ -n "$R2_BUCKET_EU" ]]; then
    echo "Seeding R2 (EU) bucket..."
    ensure_r2_bucket "$R2_BUCKET_EU" "$R2_ACCOUNT_ID"
    seed_objects_r2 "$R2_BUCKET_EU" "$R2_ACCOUNT_ID" "$payload"
    publish_r2_policy_best_effort "$R2_BUCKET_EU" "$R2_ACCOUNT_ID"
  fi

  echo "R2 done."
fi

echo
echo "Artifacts seeded:"
echo "  prefix=${PREFIX} file_count=${FILE_COUNT} file_size_mb=${FILE_SIZE_MB}"
echo "  S3 eu-north-1:   ${BUCKET_EUN1}"
echo "  S3 eu-central-1: ${BUCKET_EUC1}"
echo "  S3 us-west-2:    ${BUCKET_USW2}"
echo "  S3 us-east-1:    ${BUCKET_USE1}"
if [[ -n "$R2_BUCKET_US" ]]; then
  echo "  R2 (US):          ${R2_BUCKET_US} (account_id=${R2_ACCOUNT_ID})"
  echo "    public URL (r2.dev): https://${R2_BUCKET_US}.r2.dev/${PREFIX}.0"
fi
if [[ -n "$R2_BUCKET_EU" ]]; then
  echo "  R2 (EU):          ${R2_BUCKET_EU} (account_id=${R2_ACCOUNT_ID})"
  echo "    public URL (r2.dev): https://${R2_BUCKET_EU}.r2.dev/${PREFIX}.0"
fi
