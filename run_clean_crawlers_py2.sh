#!/usr/bin/env bash
set -euo pipefail

python cache_crawler_ips.py --cache-dir ip_cache
python find_bad_ufw_rules.py --allowlist ip_cache/allowlist_cidrs.json --output bad_ufw_rules.json --sudo
python clean_bad_ufw_rules.py --input bad_ufw_rules.json --sudo
