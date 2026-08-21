#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON:-python}"
DATA_DIR="${DATA_DIR:-data}"
SOURCE_CSV="${SOURCE_CSV:-$DATA_DIR/country_asn.csv}"
OUTPUT="${FAST_GEO_RANGES:-$DATA_DIR/fast_geo_ranges.tsv}"
TOKEN="${IPINFO_TOKEN:-}"

mkdir -p "$DATA_DIR"

if [ -n "$TOKEN" ]; then
  TMP_GZ="$SOURCE_CSV.gz.tmp"
  curl -L "https://ipinfo.io/data/free/country_asn.csv.gz?token=$TOKEN" -o "$TMP_GZ"
  gzip -dc "$TMP_GZ" > "$SOURCE_CSV.tmp"
  mv "$SOURCE_CSV.tmp" "$SOURCE_CSV"
  rm -f "$TMP_GZ"
fi

if [ ! -f "$SOURCE_CSV" ]; then
  echo "ERROR: source CSV not found: $SOURCE_CSV" >&2
  echo "Set SOURCE_CSV=/path/to/ipinfo_lite.csv or IPINFO_TOKEN=..." >&2
  exit 1
fi

"$PYTHON_BIN" build_fast_geo_ranges.py --input "$SOURCE_CSV" --output "$OUTPUT"
