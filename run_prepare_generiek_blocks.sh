#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON:-python}"
POLICY_MODE="${POLICY_MODE:-1}"
TARGET_PREFIX="${TARGET_PREFIX:-24}"
MIN_HITS="${MIN_HITS:-1}"
COUNTRY_CODES="${COUNTRY_CODES:-$("$PYTHON_BIN" -c 'import country_policy; print(country_policy.default_country_codes_csv())')}"
AGG_SOURCE="${AGG_SOURCE:-geo}"
INPUT_FILE="${INPUT_FILE:-input.txt}"
OUTPUT_FILE="${OUTPUT_FILE:-aggregated_generiek_subnets.json}"
APPLY="${APPLY:-1}"
CHECK_EXISTING="${CHECK_EXISTING:-0}"
SUDO_FLAG="${SUDO_FLAG:---sudo}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RUN_DIR="${RUN_DIR:-runs/$RUN_ID}"

snapshot_if_exists() {
  src="$1"
  dest="$2"
  if [ -e "$src" ]; then
    cp "$src" "$RUN_DIR/$dest"
  fi
}

write_summary() {
  {
    echo "run_id=$RUN_ID"
    echo "run_dir=$RUN_DIR"
    echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "python=$PYTHON_BIN"
    echo "policy_mode=$POLICY_MODE"
    echo "target_prefix=$TARGET_PREFIX"
    echo "min_hits=$MIN_HITS"
    echo "country_codes=$COUNTRY_CODES"
    echo "agg_source=$AGG_SOURCE"
    echo "input_file=$INPUT_FILE"
    echo "output_file=$OUTPUT_FILE"
    echo "apply=$APPLY"
    echo "check_existing=$CHECK_EXISTING"
    echo "sudo_flag=$SUDO_FLAG"
    if [ -f output.txt ]; then
      echo "parsed_ip_lines=$(wc -l < output.txt | tr -d ' ')"
    fi
    if [ -f "$OUTPUT_FILE" ]; then
      echo "candidate_subnet_lines=$(grep -c '\"' "$OUTPUT_FILE" 2>/dev/null || true)"
    fi
  } > "$RUN_DIR/summary.txt"
}

if [ ! -f "$INPUT_FILE" ]; then
  echo "ERROR: input file not found: $INPUT_FILE" >&2
  exit 1
fi

mkdir -p "$RUN_DIR"
snapshot_if_exists "$INPUT_FILE" "input_raw.txt"

if [ "$INPUT_FILE" != "input.txt" ]; then
  cp "$INPUT_FILE" input.txt
fi

"$PYTHON_BIN" parse_ips.py
snapshot_if_exists input.txt "input_effective.txt"
snapshot_if_exists output.txt "output_ips.txt"

AGG_ARGS=(
  --source "$AGG_SOURCE"
  --target-prefix "$TARGET_PREFIX"
  --min-hits "$MIN_HITS"
  --output "$OUTPUT_FILE"
)

if [ "$AGG_SOURCE" = "geo" ]; then
  "$PYTHON_BIN" get_ip_country.py
  AGG_ARGS+=(--input geo_data.json --filter-ips-file output.txt)
  if [ "$POLICY_MODE" = "1" ]; then
    "$PYTHON_BIN" recommend_country_prefixes.py --geo-data geo_data.json --country-codes "$COUNTRY_CODES"
    "$PYTHON_BIN" recommend_provider_subnets.py --geo-data geo_data.json --country-codes "$COUNTRY_CODES"
    AGG_ARGS+=(--policy-mode --country-policy-file country_prefix_recommendations.json --provider-policy-file provider_subnet_recommendations.json)
  fi
elif [ "$AGG_SOURCE" = "ips" ]; then
  AGG_ARGS+=(--input output.txt)
  if [ "$POLICY_MODE" = "1" ]; then
    echo "WARNING: POLICY_MODE=1 only applies to AGG_SOURCE=geo. Using legacy prefix mode for raw IP source." >&2
  fi
else
  echo "ERROR: AGG_SOURCE must be 'ips' or 'geo'" >&2
  exit 1
fi

if [ "$AGG_SOURCE" = "geo" ]; then
  AGG_ARGS+=(--country-codes "$COUNTRY_CODES")
fi

"$PYTHON_BIN" aggregate_generiek_subnets.py "${AGG_ARGS[@]}"
snapshot_if_exists "$OUTPUT_FILE" "$(basename "$OUTPUT_FILE")"
snapshot_if_exists generiek_country_report.json "generiek_country_report.json"
snapshot_if_exists generiek_blocked_candidate_ips.txt "generiek_blocked_candidate_ips.txt"
snapshot_if_exists generiek_allowed_non_target_ips.txt "generiek_allowed_non_target_ips.txt"
snapshot_if_exists country_prefix_recommendations.txt "country_prefix_recommendations.txt"
snapshot_if_exists country_prefix_recommendations.json "country_prefix_recommendations.json"
snapshot_if_exists country_prefix_plan.sh "country_prefix_plan.sh"
snapshot_if_exists provider_subnet_recommendations.txt "provider_subnet_recommendations.txt"
snapshot_if_exists provider_dangerous_subnets.txt "provider_dangerous_subnets.txt"
snapshot_if_exists provider_subnet_recommendations.json "provider_subnet_recommendations.json"
snapshot_if_exists provider_subnet_candidates.json "provider_subnet_candidates.json"
"$PYTHON_BIN" cache_crawler_ips.py --cache-dir ip_cache
snapshot_if_exists ip_cache/allowlist_cidrs.json "allowlist_cidrs.json"
"$PYTHON_BIN" audit_generiek_subnets.py --input "$OUTPUT_FILE" --allowlist ip_cache/allowlist_cidrs.json --country-codes "$COUNTRY_CODES"

if [ "$CHECK_EXISTING" = "1" ]; then
  "$PYTHON_BIN" find_bad_ufw_rules.py --allowlist ip_cache/allowlist_cidrs.json --output bad_ufw_rules.json --country-codes "$COUNTRY_CODES" $SUDO_FLAG
  snapshot_if_exists bad_ufw_rules.json "bad_ufw_rules.json"
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
write_summary

if [ "$APPLY" != "1" ]; then
  echo "Dry-run complete. Re-run with APPLY=1 to add the planned UFW rules."
fi
echo "Run snapshot saved to $RUN_DIR"
