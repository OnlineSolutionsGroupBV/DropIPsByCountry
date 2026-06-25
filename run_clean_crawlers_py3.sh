#!/usr/bin/env bash
set -euo pipefail

python3 cache_crawler_ips.py --cache-dir ip_cache
python3 find_bad_ufw_rules.py --allowlist ip_cache/allowlist_cidrs.json --output bad_ufw_rules.json --sudo

CLEAN_ARGS=()
if [ "${DRY_RUN:-0}" = "1" ]; then
  CLEAN_ARGS+=(--dry-run)
fi

python3 clean_bad_ufw_rules.py --input bad_ufw_rules.json --sudo "${CLEAN_ARGS[@]}"
