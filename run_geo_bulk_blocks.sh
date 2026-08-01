#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON:-python}"
INPUT_FILE="${INPUT_FILE:-geo_data.json}"
OUTPUT_FILE="${OUTPUT_FILE:-aggregated_geo_bulk_subnets.json}"
TARGET_PREFIX="${TARGET_PREFIX:-24}"
MIN_HITS="${MIN_HITS:-1}"
COUNTRY_CODES="${COUNTRY_CODES:-$("$PYTHON_BIN" -c 'import country_policy; print(country_policy.default_country_codes_csv())')}"
APPLY="${APPLY:-1}"
CHECK_EXISTING="${CHECK_EXISTING:-1}"
SUDO_FLAG="${SUDO_FLAG:---sudo}"

if [ ! -f "$INPUT_FILE" ]; then
  echo "ERROR: geo data file not found: $INPUT_FILE" >&2
  exit 1
fi

"$PYTHON_BIN" aggregate_generiek_subnets.py \
  --source geo \
  --input "$INPUT_FILE" \
  --country-codes "$COUNTRY_CODES" \
  --target-prefix "$TARGET_PREFIX" \
  --min-hits "$MIN_HITS" \
  --output "$OUTPUT_FILE"

"$PYTHON_BIN" cache_crawler_ips.py --cache-dir ip_cache
"$PYTHON_BIN" audit_generiek_subnets.py --input "$OUTPUT_FILE" --allowlist ip_cache/allowlist_cidrs.json --country-codes "$COUNTRY_CODES"

if [ "$CHECK_EXISTING" = "1" ]; then
  "$PYTHON_BIN" find_bad_ufw_rules.py --allowlist ip_cache/allowlist_cidrs.json --output bad_ufw_rules.json --country-codes "$COUNTRY_CODES" $SUDO_FLAG
  "$PYTHON_BIN" clean_bad_ufw_rules.py --input bad_ufw_rules.json $SUDO_FLAG --dry-run
  if [ "$APPLY" = "1" ]; then
    "$PYTHON_BIN" clean_bad_ufw_rules.py --input bad_ufw_rules.json $SUDO_FLAG
  fi
else
  echo "Skipping existing UFW audit. Set CHECK_EXISTING=1 to include cleanup."
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
