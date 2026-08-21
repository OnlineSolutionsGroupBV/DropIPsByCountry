#!/usr/bin/env bash
set -euo pipefail

export FAST_GEO_LOOKUP="${FAST_GEO_LOOKUP:-1}"
export SKIP_GEO_FETCH="${SKIP_GEO_FETCH:-1}"
export FAST_UFW_APPLY="${FAST_UFW_APPLY:-1}"
export FAST_GEO_RANGES="${FAST_GEO_RANGES:-data/fast_geo_ranges.tsv}"

./run_prepare_generiek_blocks.sh
