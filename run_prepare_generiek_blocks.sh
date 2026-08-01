#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON:-python}"
TARGET_PREFIX="${TARGET_PREFIX:-24}"
MIN_HITS="${MIN_HITS:-1}"
COUNTRY_CODES="${COUNTRY_CODES:-}"
INPUT_FILE="${INPUT_FILE:-input.txt}"
OUTPUT_FILE="${OUTPUT_FILE:-aggregated_generiek_subnets.json}"
APPLY="${APPLY:-1}"
SUDO_FLAG="${SUDO_FLAG:---sudo}"

if [ ! -f "$INPUT_FILE" ]; then
  echo "ERROR: input file not found: $INPUT_FILE" >&2
  exit 1
fi

if [ "$INPUT_FILE" != "input.txt" ]; then
  cp "$INPUT_FILE" input.txt
fi

"$PYTHON_BIN" parse_ips.py
"$PYTHON_BIN" get_ip_country.py

AGG_ARGS=(
  --target-prefix "$TARGET_PREFIX"
  --min-hits "$MIN_HITS"
  --output "$OUTPUT_FILE"
)

if [ -n "$COUNTRY_CODES" ]; then
  AGG_ARGS+=(--country-codes "$COUNTRY_CODES")
fi

"$PYTHON_BIN" aggregate_generiek_subnets.py "${AGG_ARGS[@]}"
"$PYTHON_BIN" cache_crawler_ips.py --cache-dir ip_cache
"$PYTHON_BIN" audit_generiek_subnets.py --input "$OUTPUT_FILE" --allowlist ip_cache/allowlist_cidrs.json --fail-on-overlap
"$PYTHON_BIN" find_bad_ufw_rules.py --allowlist ip_cache/allowlist_cidrs.json --output bad_ufw_rules.json $SUDO_FLAG
"$PYTHON_BIN" clean_bad_ufw_rules.py --input bad_ufw_rules.json $SUDO_FLAG --dry-run

BLOCK_ARGS=(
  --input "$OUTPUT_FILE"
  --check-bad-rules
  --dry-run
)

if [ -n "$SUDO_FLAG" ]; then
  BLOCK_ARGS+=($SUDO_FLAG)
fi

"$PYTHON_BIN" block_generiek_subnet.py "${BLOCK_ARGS[@]}"

if [ "$APPLY" = "1" ]; then
  APPLY_ARGS=(
    --input "$OUTPUT_FILE"
    --check-bad-rules
  )
  if [ -n "$SUDO_FLAG" ]; then
    APPLY_ARGS+=($SUDO_FLAG)
  fi
  "$PYTHON_BIN" block_generiek_subnet.py "${APPLY_ARGS[@]}"
else
  echo "Dry-run complete. Re-run with APPLY=1 to add the planned UFW rules."
fi
