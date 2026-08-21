#!/usr/bin/env python
from __future__ import print_function

import argparse
import json

import fast_geo_lookup
from local_ip_country import load_ranges, lookup_ip


def compare(input_path, geo_data_path, ranges_path, sample=0):
    ips = fast_geo_lookup.read_ips(input_path)
    if sample:
        ips = ips[:sample]
    geo_data = fast_geo_lookup.load_geo_data(geo_data_path)
    starts, ranges = load_ranges(ranges_path)

    compared = 0
    missing_existing = 0
    local_misses = 0
    mismatches = []
    matches = 0

    for ip in ips:
        existing = geo_data.get(ip)
        if not existing:
            missing_existing += 1
            continue
        row = lookup_ip(ip, starts, ranges)
        if not row:
            local_misses += 1
            continue
        compared += 1
        existing_country = existing.get("country", "Unknown").upper()
        local_country = row.get("country", "Unknown").upper()
        if existing_country == local_country:
            matches += 1
        else:
            mismatches.append((ip, existing_country, local_country, row.get("network", "")))

    return {
        "input_ips": len(ips),
        "compared": compared,
        "matches": matches,
        "missing_existing": missing_existing,
        "local_misses": local_misses,
        "mismatches": mismatches,
    }


def main():
    parser = argparse.ArgumentParser(description="Compare existing geo_data.json country values with local fast range lookup.")
    parser.add_argument("--input", default="output.txt")
    parser.add_argument("--geo-data", default="geo_data.json")
    parser.add_argument("--ranges", default="data/fast_geo_ranges.tsv")
    parser.add_argument("--sample", type=int, default=0)
    parser.add_argument("--json-output", default="")
    args = parser.parse_args()

    result = compare(args.input, args.geo_data, args.ranges, args.sample)
    print("Input IPs:", result["input_ips"])
    print("Compared:", result["compared"])
    print("Matches:", result["matches"])
    print("Missing existing geo_data:", result["missing_existing"])
    print("Local misses:", result["local_misses"])
    print("Mismatches:", len(result["mismatches"]))
    for ip, existing_country, local_country, network in result["mismatches"][:20]:
        print("%s existing=%s local=%s network=%s" % (ip, existing_country, local_country, network))
    if args.json_output:
        with open(args.json_output, "w") as f:
            json.dump(result, f, indent=2, sort_keys=True)
        print("Wrote:", args.json_output)
    return 0 if not result["mismatches"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
