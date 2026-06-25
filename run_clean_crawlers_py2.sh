#!/usr/bin/env bash
set -euo pipefail

if [ -n "${PYTHON2:-}" ]; then
  PYTHON_BIN="$PYTHON2"
elif command -v python2 >/dev/null 2>&1; then
  PYTHON_BIN="python2"
else
  PYTHON_BIN="python"
fi

"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info[0] == 2 else 1)' || {
  echo "ERROR: Python 2 is required. Set PYTHON2=/path/to/python2 if needed." >&2
  exit 1
}

"$PYTHON_BIN" cache_crawler_ips.py --cache-dir ip_cache
"$PYTHON_BIN" find_bad_ufw_rules.py --allowlist ip_cache/allowlist_cidrs.json --output bad_ufw_rules.json --sudo
"$PYTHON_BIN" clean_bad_ufw_rules.py --input bad_ufw_rules.json --sudo
