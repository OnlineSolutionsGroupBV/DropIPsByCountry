#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON:-python}"
DATA_DIR="${DATA_DIR:-data}"
SOURCE_CSV="${SOURCE_CSV:-$DATA_DIR/country_asn.csv}"
OUTPUT="${FAST_GEO_RANGES:-$DATA_DIR/fast_geo_ranges.tsv}"
TOKEN="${IPINFO_TOKEN:-}"
CURL_INSECURE="${CURL_INSECURE:-0}"
FORCE_DOWNLOAD="${FORCE_DOWNLOAD:-0}"
MAX_SOURCE_AGE_HOURS="${MAX_SOURCE_AGE_HOURS:-24}"
MIN_SOURCE_BYTES="${MIN_SOURCE_BYTES:-1000000}"

mkdir -p "$DATA_DIR"

source_is_recent_enough() {
  if [ "$FORCE_DOWNLOAD" = "1" ]; then
    return 1
  fi
  if [ ! -f "$SOURCE_CSV" ]; then
    return 1
  fi
  size=$(wc -c < "$SOURCE_CSV" | tr -d ' ')
  if [ "$size" -lt "$MIN_SOURCE_BYTES" ]; then
    return 1
  fi
  now=$(date +%s)
  mtime=$(stat -c %Y "$SOURCE_CSV" 2>/dev/null || stat -f %m "$SOURCE_CSV")
  age_hours=$(( (now - mtime) / 3600 ))
  [ "$age_hours" -le "$MAX_SOURCE_AGE_HOURS" ]
}

if [ -n "$TOKEN" ] && ! source_is_recent_enough; then
  TMP_GZ="$SOURCE_CSV.gz.tmp"
  CURL_ARGS=(-L)
  if [ "$CURL_INSECURE" = "1" ]; then
    CURL_ARGS+=(-k)
  fi
  curl "${CURL_ARGS[@]}" "https://ipinfo.io/data/free/country_asn.csv.gz?token=$TOKEN" -o "$TMP_GZ"
  gzip -dc "$TMP_GZ" > "$SOURCE_CSV.tmp"
  mv "$SOURCE_CSV.tmp" "$SOURCE_CSV"
  rm -f "$TMP_GZ"
elif [ -n "$TOKEN" ]; then
  echo "Using recent source CSV: $SOURCE_CSV"
fi

if [ ! -f "$SOURCE_CSV" ]; then
  echo "ERROR: source CSV not found: $SOURCE_CSV" >&2
  echo "Set SOURCE_CSV=/path/to/ipinfo_lite.csv or IPINFO_TOKEN=..." >&2
  exit 1
fi

"$PYTHON_BIN" build_fast_geo_ranges.py --input "$SOURCE_CSV" --output "$OUTPUT"
