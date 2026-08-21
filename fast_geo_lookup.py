#!/usr/bin/env python
from __future__ import print_function

import argparse
import json
import os
import re
import time

from local_ip_country import atomic_write_json, load_ranges, lookup_ip, row_to_geo_details


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def read_ips(path):
    ips = []
    seen = set()
    with open(path, "rb") as f:
        for raw in f:
            text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
            for ip in IPV4_RE.findall(text):
                if ip not in seen:
                    ips.append(ip)
                    seen.add(ip)
    return ips


def load_geo_data(path):
    if not os.path.exists(path):
        return {}
    with open(path, "rb") as f:
        try:
            return json.load(f)
        except ValueError:
            return {}


def unknown_details():
    return {
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "org": "Unknown",
        "loc": "Unknown",
        "source": "local_miss",
        "lookup_updated_at": int(time.time()),
    }


def update_geo_data(input_path, geo_data_path, ranges_path, write_unknown=False, refresh_existing=False):
    start_time = time.time()
    ips = read_ips(input_path)
    geo_data = load_geo_data(geo_data_path)
    starts, ranges = load_ranges(ranges_path)

    cache_hits = 0
    local_hits = 0
    local_misses = 0
    updated = 0

    for ip in ips:
        if ip in geo_data and not refresh_existing:
            cache_hits += 1
            continue
        row = None
        try:
            row = lookup_ip(ip, starts, ranges)
        except Exception:
            row = None
        if row:
            geo_data[ip] = row_to_geo_details(row)
            local_hits += 1
            updated += 1
        else:
            local_misses += 1
            if write_unknown:
                geo_data[ip] = unknown_details()
                updated += 1

    if updated:
        atomic_write_json(geo_data_path, geo_data)

    return {
        "input_ips": len(ips),
        "cache_hits": cache_hits,
        "local_hits": local_hits,
        "local_misses": local_misses,
        "updated": updated,
        "elapsed_seconds": time.time() - start_time,
    }


def main():
    parser = argparse.ArgumentParser(description="Update geo_data.json from local fast geo ranges without external API calls.")
    parser.add_argument("--input", default="output.txt")
    parser.add_argument("--geo-data", default="geo_data.json")
    parser.add_argument("--ranges", default=os.path.join("data", "fast_geo_ranges.tsv"))
    parser.add_argument("--write-unknown", action="store_true")
    parser.add_argument("--refresh-existing", action="store_true")
    args = parser.parse_args()

    stats = update_geo_data(
        args.input,
        args.geo_data,
        args.ranges,
        write_unknown=args.write_unknown,
        refresh_existing=args.refresh_existing,
    )
    print("Fast geo lookup complete")
    print("Input IPs:", stats["input_ips"])
    print("Cache hits:", stats["cache_hits"])
    print("Local hits:", stats["local_hits"])
    print("Local misses:", stats["local_misses"])
    print("Updated geo_data rows:", stats["updated"])
    print("Elapsed seconds: %.3f" % stats["elapsed_seconds"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
