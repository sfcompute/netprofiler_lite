#!/usr/bin/env bash
# NDG reproducible object-storage network benchmark (S3/R2)
#
# This is a bash-only reproduction of the download saturation test.
# It uses awscli for presigning and curl for high-concurrency transfers.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ndg_object_storage_benchmark.sh \
    --backends "bucket-usw2:us-west-2,bucket-use1:us-east-1,r2:my-r2:ACCOUNT" \
    [--ensure] \
    [--direction download|upload|both] \
    [--prefix data-8m] \
    [--file-count 100] \
    [--file-size-mb 8] \
    [--concurrency 256] \
    [--duration 30] \
    [--output human|csv]

EOF
}

die() { echo "ERROR: $*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

GRADE() {
  local gbps="$1"
  awk -v g="$gbps" 'BEGIN {
    if (g >= 10.0) print "A+";
    else if (g >= 5.0) print "A";
    else if (g >= 2.0) print "B";
    else if (g >= 1.0) print "C";
    else print "D";
  }'
}

NOW_ISO() {
  if date -Iseconds >/dev/null 2>&1; then date -Iseconds; else date '+%Y-%m-%dT%H:%M:%S%z'; fi
}

TMPDIR_ROOT="${TMPDIR:-/tmp}"
WORKDIR="$(mktemp -d "${TMPDIR_ROOT%/}/ndg-netprof.XXXXXX")"
cleanup() { rm -rf "$WORKDIR" 2>/dev/null || true; }
trap cleanup EXIT

BACKENDS=""
DIRECTION="download"
PREFIX="data-8m"
FILE_COUNT=100
FILE_SIZE_MB=8
CONCURRENCY=256
DURATION=30
OUTPUT="human"
ENSURE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backends) BACKENDS="${2:-}"; shift 2 ;;
    --direction) DIRECTION="${2:-}"; shift 2 ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --file-count) FILE_COUNT="${2:-}"; shift 2 ;;
    --file-size-mb) FILE_SIZE_MB="${2:-}"; shift 2 ;;
    --concurrency) CONCURRENCY="${2:-}"; shift 2 ;;
    --duration) DURATION="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    --ensure) ENSURE=1; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown arg: $1" ;;
  esac
done

[[ -n "$BACKENDS" ]] || { usage; die "--backends is required"; }

case "$DIRECTION" in
  download|upload|both) ;;
  *) die "--direction must be download, upload, or both";;
esac

case "$OUTPUT" in
  human|csv) ;;
  *) die "--output must be human or csv";;
esac

need_cmd aws
need_cmd curl
need_cmd awk
need_cmd mktemp
need_cmd date
need_cmd dd

BACKEND_LIST_FILE="$WORKDIR/backends.txt"
printf '%s' "$BACKENDS" | tr ',' '\n' | awk 'NF{print $0}' >"$BACKEND_LIST_FILE"

RESULTS_CSV="$WORKDIR/results.csv"
echo "timestamp,backend_type,name,bucket,region_or_account,direction,concurrency,duration_s,file_count,file_size_mb,bytes,transfers,successes,throughput_gbps,grade" >"$RESULTS_CSV"

presign_get_url() {
  local btype="$1" bucket="$2" region="$3" key="$4"
  local expires
  expires=$(( DURATION + 900 ))

  case "$btype" in
    s3)
      AWS_REGION="$region" aws s3 presign "s3://$bucket/$key" --expires-in "$expires"
      ;;
    r2)
      local account_id="$region"
      local endpoint="https://${account_id}.r2.cloudflarestorage.com"
      AWS_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID:?R2_ACCESS_KEY_ID required for r2}" \
      AWS_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY:?R2_SECRET_ACCESS_KEY required for r2}" \
      AWS_REGION="auto" \
      aws --endpoint-url "$endpoint" s3 presign "s3://$bucket/$key" --expires-in "$expires"
      ;;
    *) return 2;;
  esac
}

download_saturate() {
  local btype="$1" name="$2" bucket="$3" region="$4"

  local url_file="$WORKDIR/${name}.urls"
  : >"$url_file"

  local i key url
  for ((i=0; i<FILE_COUNT; i++)); do
    key="${PREFIX}.${i}"
    url="$(presign_get_url "$btype" "$bucket" "$region" "$key")" || die "presign failed for $name $key"
    printf '%s\n' "$url" >>"$url_file"
  done

  local first_url
  first_url="$(awk 'NR==1{print; exit}' "$url_file")"
  [[ -n "$first_url" ]] || die "no URLs generated for $name"

  local code
  code="$(curl -sS -o /dev/null -I -w '%{http_code}' --connect-timeout 5 --max-time 30 "$first_url" || echo 000)"
  case "$code" in
    2*|3*) ;;
    403) die "$name preflight failed (403). Check credentials/policy for $bucket";;
    404) die "$name preflight failed (404). Expected objects like ${PREFIX}.0 to exist in $bucket";;
    000) die "$name preflight failed (no response). Check DNS/route/firewall";;
    *) die "$name preflight failed (HTTP $code)";;
  esac

  local fifo="$WORKDIR/${name}.fifo"
  local sumfile="$WORKDIR/${name}.sum"
  mkfifo "$fifo"
  awk '{bytes+=$1; n+=1; ok+=$2} END{printf("%d %d %d\n", bytes, n, ok)}' <"$fifo" >"$sumfile" &
  local awk_pid=$!

  local start_epoch end_epoch
  start_epoch="$(date +%s)"
  end_epoch=$(( start_epoch + DURATION ))

  local active=0 idx=0
  local urls_count
  urls_count="$FILE_COUNT"

  while :; do
    local now
    now="$(date +%s)"
    if (( now >= end_epoch )); then
      break
    fi
    if (( active >= CONCURRENCY )); then
      wait -n 2>/dev/null || true
      active=$(( active - 1 ))
      continue
    fi

    local line
    line=$(( (idx % urls_count) + 1 ))
    url="$(awk -v n="$line" 'NR==n{print; exit}' "$url_file")"
    idx=$(( idx + 1 ))

    (
      local out http bytes ok
      out="$(curl -sS -o /dev/null --http1.1 -w '%{http_code} %{size_download}\n' \
        --connect-timeout 5 --max-time 120 "$url" 2>/dev/null || printf '000 0\n')"
      http="${out%% *}"
      bytes="${out#* }"
      ok=0
      [[ "$http" == 2* ]] && ok=1
      case "$bytes" in ''|*[!0-9]*) bytes=0;; esac
      printf '%s %s\n' "$bytes" "$ok" >"$fifo"
    ) &
    active=$(( active + 1 ))
  done

  while (( active > 0 )); do
    wait -n 2>/dev/null || true
    active=$(( active - 1 ))
  done

  wait "$awk_pid" 2>/dev/null || true

  local end_actual elapsed
  end_actual="$(date +%s)"
  elapsed=$(( end_actual - start_epoch ))
  (( elapsed > 0 )) || elapsed=1

  local bytes_total transfers successes
  read -r bytes_total transfers successes <"$sumfile"
  local throughput_gbps
  throughput_gbps="$(awk -v b="$bytes_total" -v s="$elapsed" 'BEGIN{printf("%.6f", (b*8)/(s*1000000000.0))}')"
  local grade
  grade="$(GRADE "$throughput_gbps")"

  local ts
  ts="$(NOW_ISO)"
  echo "${ts},${btype},${name},${bucket},${region},download,${CONCURRENCY},${DURATION},${FILE_COUNT},${FILE_SIZE_MB},${bytes_total},${transfers},${successes},${throughput_gbps},${grade}" >>"$RESULTS_CSV"
}

parse_backend() {
  local spec="$1"
  local IFS=':'
  read -r a b c _extra <<<"$spec"

  if [[ "$a" == "r2" || "$a" == "R2" ]]; then
    [[ -n "$b" ]] || die "Invalid r2 spec: $spec"
    local bucket="$b"
    local account_id="${c:-${R2_ACCOUNT_ID:-}}"
    [[ -n "$account_id" ]] || die "R2 account_id missing for $spec (set R2_ACCOUNT_ID or use r2:bucket:account_id)"
    echo "r2 r2-${bucket} ${bucket} ${account_id}"
    return
  fi

  if [[ "$a" == "s3" || "$a" == "S3" ]]; then
    [[ -n "$b" && -n "$c" ]] || die "Invalid s3 spec: $spec (use s3:bucket:region)"
    echo "s3 s3-${b}-${c} ${b} ${c}"
    return
  fi

  local bucket="$a"
  local region="${b:-${AWS_REGION:-us-west-2}}"
  [[ -n "$bucket" ]] || die "Invalid backend spec: $spec"
  echo "s3 s3-${bucket}-${region} ${bucket} ${region}"
}

while IFS= read -r spec; do
  [[ -n "$spec" ]] || continue
  read -r btype name bucket region <<<"$(parse_backend "$spec")"
  download_saturate "$btype" "$name" "$bucket" "$region"
done <"$BACKEND_LIST_FILE"

if [[ "$OUTPUT" == "csv" ]]; then
  cat "$RESULTS_CSV"
  exit 0
fi

echo
echo "== Results"
echo "Config: direction=$DIRECTION concurrency=$CONCURRENCY duration=${DURATION}s prefix=$PREFIX file_count=$FILE_COUNT file_size_mb=$FILE_SIZE_MB"
echo

awk -F',' '
  NR==1 { next }
  {
    printf("%-10s %-28s %-12s %10.3f Gbps  grade=%-2s  ok=%s/%s  bytes=%s\n",
      $6, $3, $2, $14, $15, $13, $12, $11)
  }
' "$RESULTS_CSV" | sort
