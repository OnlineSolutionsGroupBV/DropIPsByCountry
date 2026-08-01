#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON:-python}"
COUNTRY_CODES="${COUNTRY_CODES:-$("$PYTHON_BIN" -c 'import country_policy; print(country_policy.default_country_codes_csv())')}"
SUDO_FLAG="${SUDO_FLAG:---sudo}"
ALLOWLIST="${ALLOWLIST:-ip_cache/allowlist_cidrs.json}"
OUTPUT="${OUTPUT:-bad_ufw_rules.json}"
APPLY_CLEAN="${APPLY_CLEAN:-0}"

"$PYTHON_BIN" cache_crawler_ips.py --cache-dir ip_cache
"$PYTHON_BIN" find_bad_ufw_rules.py --allowlist "$ALLOWLIST" --output "$OUTPUT" --country-codes "$COUNTRY_CODES" $SUDO_FLAG
"$PYTHON_BIN" clean_bad_ufw_rules.py --input "$OUTPUT" $SUDO_FLAG --dry-run

if [ "$APPLY_CLEAN" = "1" ]; then
  "$PYTHON_BIN" clean_bad_ufw_rules.py --input "$OUTPUT" $SUDO_FLAG
else
  echo "Dry-run only. Re-run with APPLY_CLEAN=1 to delete the reported existing UFW rules."
fi
