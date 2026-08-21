#!/usr/bin/env bash
set -euo pipefail

export FAST_GEO_LOOKUP="${FAST_GEO_LOOKUP:-1}"
export SKIP_GEO_FETCH="${SKIP_GEO_FETCH:-1}"
export FAST_UFW_APPLY="${FAST_UFW_APPLY:-1}"
export FAST_GEO_RANGES="${FAST_GEO_RANGES:-data/fast_geo_ranges.tsv}"
export INPUT_FILE="${INPUT_FILE:-input.txt}"

FETCH_SERVER_STATUS="${FETCH_SERVER_STATUS:-1}"
SERVER_STATUS_URL="${SERVER_STATUS_URL:-http://127.0.0.1/server-status}"
SERVER_STATUS_HOST="${SERVER_STATUS_HOST:-www.nieuwejobs.com}"
CURL_BIN="${CURL_BIN:-curl}"
RESTART_APACHE="${RESTART_APACHE:-1}"
APACHE_RESTART_CMD="${APACHE_RESTART_CMD:-service apache2 restart}"

if [ "$FETCH_SERVER_STATUS" = "1" ]; then
  tmp_status="${INPUT_FILE}.tmp-$$"
  "$CURL_BIN" -fsS "$SERVER_STATUS_URL" -H "Host: $SERVER_STATUS_HOST" -o "$tmp_status"
  mv "$tmp_status" "$INPUT_FILE"
  echo "Fetched server status into $INPUT_FILE from $SERVER_STATUS_URL with Host: $SERVER_STATUS_HOST"
fi

./run_prepare_generiek_blocks.sh

if [ "$RESTART_APACHE" = "1" ]; then
  echo "Restarting Apache with: $APACHE_RESTART_CMD"
  $APACHE_RESTART_CMD
fi
