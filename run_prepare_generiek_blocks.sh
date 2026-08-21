#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON:-python}"
POLICY_MODE="${POLICY_MODE:-1}"
MERGE_PROVIDER_CANDIDATES="${MERGE_PROVIDER_CANDIDATES:-0}"
TARGET_PREFIX="${TARGET_PREFIX:-24}"
MIN_HITS="${MIN_HITS:-1}"
COUNTRY_CODES="${COUNTRY_CODES:-$("$PYTHON_BIN" -c 'import country_policy; print(country_policy.default_country_codes_csv())')}"
AGG_SOURCE="${AGG_SOURCE:-geo}"
INPUT_FILE="${INPUT_FILE:-input.txt}"
OUTPUT_FILE="${OUTPUT_FILE:-aggregated_generiek_subnets.json}"
APPLY="${APPLY:-1}"
CHECK_EXISTING="${CHECK_EXISTING:-0}"
SUDO_FLAG="${SUDO_FLAG:---sudo}"
FAST_GEO_LOOKUP="${FAST_GEO_LOOKUP:-0}"
FAST_GEO_RANGES="${FAST_GEO_RANGES:-data/fast_geo_ranges.tsv}"
FAST_GEO_WRITE_UNKNOWN="${FAST_GEO_WRITE_UNKNOWN:-0}"
SKIP_GEO_FETCH="${SKIP_GEO_FETCH:-0}"
FAST_UFW_APPLY="${FAST_UFW_APPLY:-0}"
UFW_USER_RULES="${UFW_USER_RULES:-}"
ALLOW_EMPTY_INPUT="${ALLOW_EMPTY_INPUT:-0}"
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
    echo "merge_provider_candidates=$MERGE_PROVIDER_CANDIDATES"
    echo "target_prefix=$TARGET_PREFIX"
    echo "min_hits=$MIN_HITS"
    echo "country_codes=$COUNTRY_CODES"
    echo "agg_source=$AGG_SOURCE"
    echo "input_file=$INPUT_FILE"
    echo "output_file=$OUTPUT_FILE"
    echo "apply=$APPLY"
    echo "check_existing=$CHECK_EXISTING"
    echo "sudo_flag=$SUDO_FLAG"
    echo "fast_geo_lookup=$FAST_GEO_LOOKUP"
    echo "fast_geo_ranges=$FAST_GEO_RANGES"
    echo "skip_geo_fetch=$SKIP_GEO_FETCH"
    echo "fast_ufw_apply=$FAST_UFW_APPLY"
    echo "ufw_user_rules=$UFW_USER_RULES"
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
PARSED_IP_LINES=$(wc -l < output.txt | tr -d ' ')
if [ "$PARSED_IP_LINES" -eq 0 ] && [ "$ALLOW_EMPTY_INPUT" != "1" ]; then
  snapshot_if_exists input.txt "input_effective.txt"
  snapshot_if_exists output.txt "output_ips.txt"
  write_summary
  echo "ERROR: parsed 0 IPs from $INPUT_FILE. Refusing to continue with an empty block plan." >&2
  echo "Set ALLOW_EMPTY_INPUT=1 only for an intentional empty dry-run." >&2
  exit 2
fi
snapshot_if_exists input.txt "input_effective.txt"
snapshot_if_exists output.txt "output_ips.txt"

if [ "$FAST_GEO_LOOKUP" = "1" ]; then
  FAST_GEO_ARGS=(
    --input output.txt
    --geo-data geo_data.json
    --ranges "$FAST_GEO_RANGES"
  )
  if [ "$FAST_GEO_WRITE_UNKNOWN" = "1" ]; then
    FAST_GEO_ARGS+=(--write-unknown)
  fi
  "$PYTHON_BIN" fast_geo_lookup.py "${FAST_GEO_ARGS[@]}"
  snapshot_if_exists geo_data.json "geo_data_after_fast_lookup.json"
fi

AGG_ARGS=(
  --source "$AGG_SOURCE"
  --target-prefix "$TARGET_PREFIX"
  --min-hits "$MIN_HITS"
  --output "$OUTPUT_FILE"
)

if [ "$AGG_SOURCE" = "geo" ]; then
  if [ "$SKIP_GEO_FETCH" = "1" ]; then
    echo "Skipping get_ip_country.py because SKIP_GEO_FETCH=1."
  else
    "$PYTHON_BIN" get_ip_country.py
  fi
  AGG_ARGS+=(--input geo_data.json --filter-ips-file output.txt)
  if [ "$POLICY_MODE" = "1" ]; then
    "$PYTHON_BIN" recommend_country_prefixes.py --geo-data geo_data.json --country-codes "$COUNTRY_CODES"
    "$PYTHON_BIN" recommend_provider_subnets.py --geo-data geo_data.json --country-codes "$COUNTRY_CODES"
    AGG_ARGS+=(--policy-mode --country-policy-file country_prefix_recommendations.json)
    if [ "$MERGE_PROVIDER_CANDIDATES" = "1" ]; then
      AGG_ARGS+=(--provider-policy-file provider_subnet_recommendations.json)
    fi
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

if [ "$FAST_UFW_APPLY" = "1" ]; then
  if [ -z "$UFW_USER_RULES" ]; then
    if [ -f /lib/ufw/user.rules ]; then
      UFW_USER_RULES="/lib/ufw/user.rules"
    elif [ -f /etc/ufw/user.rules ]; then
      UFW_USER_RULES="/etc/ufw/user.rules"
    else
      echo "ERROR: FAST_UFW_APPLY=1 but UFW_USER_RULES was not set and no default user.rules file was found." >&2
      exit 1
    fi
  fi
  FAST_UFW_ARGS=(
    --input "$OUTPUT_FILE"
    --user-rules "$UFW_USER_RULES"
    --blocked-file blocked_generiek_ips.txt
    --allowlist ip_cache/allowlist_cidrs.json
    --geo-data geo_data.json
    --country-codes "$COUNTRY_CODES"
  )
  if [ -n "$SUDO_FLAG" ]; then
    FAST_UFW_ARGS+=(--sudo)
  fi
  if [ "$APPLY" = "1" ]; then
    FAST_UFW_ARGS+=(--apply --reload)
  else
    FAST_UFW_ARGS+=(--dry-run --output-preview "$RUN_DIR/user.rules.preview")
  fi
  "$PYTHON_BIN" fast_apply_ufw_user_rules.py "${FAST_UFW_ARGS[@]}"
else
  "$PYTHON_BIN" block_generiek_subnet.py "${BLOCK_ARGS[@]}"
fi
write_summary

if [ "$APPLY" != "1" ]; then
  echo "Dry-run complete. Re-run with APPLY=1 to add the planned UFW rules."
fi
echo "Run snapshot saved to $RUN_DIR"
