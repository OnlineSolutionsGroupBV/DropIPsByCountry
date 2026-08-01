#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON:-python}"
TARGET_PREFIX="${TARGET_PREFIX:-24}"
MIN_HITS="${MIN_HITS:-1}"
COUNTRY_CODES="${COUNTRY_CODES:-$("$PYTHON_BIN" -c 'import country_policy; print(country_policy.default_country_codes_csv())')}"
AGG_SOURCE="${AGG_SOURCE:-geo}"
INPUT_FILE="${INPUT_FILE:-input.txt}"
OUTPUT_FILE="${OUTPUT_FILE:-aggregated_generiek_subnets.json}"
APPLY="${APPLY:-1}"
CHECK_EXISTING="${CHECK_EXISTING:-0}"
SUDO_FLAG="${SUDO_FLAG:---sudo}"

if [ ! -f "$INPUT_FILE" ]; then
  echo "ERROR: input file not found: $INPUT_FILE" >&2
  exit 1
fi

if [ "$INPUT_FILE" != "input.txt" ]; then
  cp "$INPUT_FILE" input.txt
fi

"$PYTHON_BIN" parse_ips.py

AGG_ARGS=(
  --source "$AGG_SOURCE"
  --target-prefix "$TARGET_PREFIX"
  --min-hits "$MIN_HITS"
  --output "$OUTPUT_FILE"
)

if [ "$AGG_SOURCE" = "geo" ]; then
  "$PYTHON_BIN" get_ip_country.py
  AGG_ARGS+=(--input geo_data.json --filter-ips-file output.txt)
elif [ "$AGG_SOURCE" = "ips" ]; then
  AGG_ARGS+=(--input output.txt)
else
  echo "ERROR: AGG_SOURCE must be 'ips' or 'geo'" >&2
  exit 1
fi

if [ "$AGG_SOURCE" = "geo" ]; then
  AGG_ARGS+=(--country-codes "$COUNTRY_CODES")
fi

"$PYTHON_BIN" aggregate_generiek_subnets.py "${AGG_ARGS[@]}"
"$PYTHON_BIN" cache_crawler_ips.py --cache-dir ip_cache
"$PYTHON_BIN" audit_generiek_subnets.py --input "$OUTPUT_FILE" --allowlist ip_cache/allowlist_cidrs.json --country-codes "$COUNTRY_CODES" --fail-on-country-mismatch

if [ "$CHECK_EXISTING" = "1" ]; then
  "$PYTHON_BIN" find_bad_ufw_rules.py --allowlist ip_cache/allowlist_cidrs.json --output bad_ufw_rules.json --country-codes "$COUNTRY_CODES" $SUDO_FLAG
  "$PYTHON_BIN" clean_bad_ufw_rules.py --input bad_ufw_rules.json $SUDO_FLAG --dry-run
  if [ "$APPLY" = "1" ]; then
    "$PYTHON_BIN" clean_bad_ufw_rules.py --input bad_ufw_rules.json $SUDO_FLAG
  fi
else
  echo "Skipping existing UFW audit. Run with CHECK_EXISTING=1 for one-time cleanup."
fi

BLOCK_ARGS=(
  --input "$OUTPUT_FILE"
  --country-codes "$COUNTRY_CODES"
)

if [ "$CHECK_EXISTING" = "1" ]; then
  BLOCK_ARGS+=(--check-bad-rules)
fi

if [ "$APPLY" != "1" ]; then
  BLOCK_ARGS+=(--dry-run)
fi

if [ -n "$SUDO_FLAG" ]; then
  BLOCK_ARGS+=($SUDO_FLAG)
fi

"$PYTHON_BIN" block_generiek_subnet.py "${BLOCK_ARGS[@]}"

if [ "$APPLY" != "1" ]; then
  echo "Dry-run complete. Re-run with APPLY=1 to add the planned UFW rules."
fi
