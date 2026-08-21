#!/usr/bin/env python
from __future__ import print_function

import argparse
import collections
import json
import os
import re
import sys

from local_ip_country import load_ranges, lookup_ip, row_to_geo_details, to_text


REQUEST_RE = re.compile(r"\s((?:\d{1,3}\.){3}\d{1,3})\s+(\S+:\d+)\s+([A-Z]+)\s+(\S+)")


def read_text(path):
    with open(path, "rb") as f:
        return to_text(f.read())


def load_json(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, "rb") as f:
        try:
            return json.load(f)
        except ValueError:
            return {}


def parse_rows(text, min_categories):
    rows = []
    for line in text.splitlines():
        match = REQUEST_RE.search(line)
        if not match:
            continue
        ip, vhost, method, url = match.groups()
        category_count = url.count("categories=")
        if category_count < min_categories:
            continue
        rows.append({
            "ip": ip,
            "vhost": vhost,
            "method": method,
            "url": url,
            "category_count": category_count,
        })
    return rows


def geo_for_ip(ip, geo_data, range_index):
    details = geo_data.get(ip)
    if details:
        return details
    if not range_index:
        return {"country": "Missing", "org": "Missing"}
    starts, ranges = range_index
    row = lookup_ip(ip, starts, ranges)
    if not row:
        return {"country": "Missing", "org": "Missing"}
    return row_to_geo_details(row)


def summarize(rows, geo_data, range_index):
    by_country = collections.Counter()
    by_provider = collections.Counter()
    by_vhost = collections.Counter()
    examples_by_country = collections.defaultdict(list)
    examples_by_provider = collections.defaultdict(list)
    unique_ips = set()

    for row in rows:
        ip = row["ip"]
        unique_ips.add(ip)
        details = geo_for_ip(ip, geo_data, range_index)
        country = to_text(details.get("country", "Missing")).upper()
        org = to_text(details.get("org", "Missing"))
        by_country[country] += 1
        by_provider[org] += 1
        by_vhost[row["vhost"]] += 1
        example = "%s %s %s" % (ip, row["vhost"], row["url"][:140])
        if len(examples_by_country[country]) < 5:
            examples_by_country[country].append(example)
        if len(examples_by_provider[org]) < 5:
            examples_by_provider[org].append(example)

    return {
        "rows": len(rows),
        "unique_ips": len(unique_ips),
        "by_country": by_country,
        "by_provider": by_provider,
        "by_vhost": by_vhost,
        "examples_by_country": examples_by_country,
        "examples_by_provider": examples_by_provider,
    }


def print_counter(title, counter, examples, limit):
    print(title)
    for key, count in counter.most_common(limit):
        print("  %s | %d" % (key, count))
        for example in examples.get(key, [])[:3]:
            print("    %s" % example)


def main():
    parser = argparse.ArgumentParser(description="Analyze Apache server-status requests with repeated categories= parameters.")
    parser.add_argument("--input", default="input.txt")
    parser.add_argument("--geo-data", default="geo_data.json")
    parser.add_argument("--ranges", default=os.path.join("data", "fast_geo_ranges.tsv"))
    parser.add_argument("--min-categories", type=int, default=3)
    parser.add_argument("--limit", type=int, default=30)
    args = parser.parse_args()

    if args.min_categories < 1:
        print("ERROR: --min-categories must be at least 1", file=sys.stderr)
        return 1
    text = read_text(args.input)
    rows = parse_rows(text, args.min_categories)
    geo_data = load_json(args.geo_data)
    range_index = None
    if args.ranges and os.path.exists(args.ranges):
        range_index = load_ranges(args.ranges)

    stats = summarize(rows, geo_data, range_index)
    print("Input:", args.input)
    print("Min categories:", args.min_categories)
    print("Matching request rows:", stats["rows"])
    print("Unique IPs:", stats["unique_ips"])
    print_counter("Countries:", stats["by_country"], stats["examples_by_country"], args.limit)
    print_counter("Providers:", stats["by_provider"], stats["examples_by_provider"], args.limit)
    print_counter("VHosts:", stats["by_vhost"], {}, args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
