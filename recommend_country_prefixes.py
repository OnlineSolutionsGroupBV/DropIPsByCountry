#!/usr/bin/env python
from __future__ import print_function

import argparse
import collections
import json
import os
import sys

from country_policy import default_country_codes, effective_country_codes

try:
    text_type = unicode  # Py2
except NameError:
    text_type = str


try:
    import ipaddress as _ip

    def ip_network(value, strict=False):
        return _ip.ip_network(text_type(value), strict=strict)

except ImportError:
    try:
        import ipaddr as _ip
    except ImportError:
        _ip = None

    def ip_network(value, strict=False):
        if _ip is None:
            raise ImportError("Missing ipaddress/ipaddr module")
        return _ip.IPNetwork(text_type(value))


DEFAULT_PREFIXES = [24, 22, 20, 18, 16]


def parse_prefixes(value):
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def parse_country_codes(value):
    if not value:
        return default_country_codes()
    return effective_country_codes([part.strip().upper() for part in value.split(",") if part.strip()])


def load_geo_data(path):
    with open(path, "r") as f:
        return json.load(f)


def network_for_ip(ip, prefix):
    return text_type(ip_network("%s/%d" % (ip, prefix), strict=False))


def country_for_details(details):
    country = details.get("country", "Unknown")
    if country is None:
        country = "Unknown"
    return text_type(country).upper()


def collect_country_ips(geo_data, country_codes):
    wanted = set(country_codes)
    countries = collections.defaultdict(set)
    for ip, details in geo_data.items():
        country = country_for_details(details)
        if country in wanted:
            countries[country].add(ip)
    return countries


def prefix_stats_for_ips(ips, prefix):
    counts = collections.Counter(network_for_ip(ip, prefix) for ip in ips)
    if not counts:
        return {
            "prefix": prefix,
            "networks": 0,
            "max_hits": 0,
            "networks_2_plus": 0,
            "networks_3_plus": 0,
            "networks_5_plus": 0,
            "networks_10_plus": 0,
            "top": [],
        }
    return {
        "prefix": prefix,
        "networks": len(counts),
        "max_hits": max(counts.values()),
        "networks_2_plus": sum(1 for count in counts.values() if count >= 2),
        "networks_3_plus": sum(1 for count in counts.values() if count >= 3),
        "networks_5_plus": sum(1 for count in counts.values() if count >= 5),
        "networks_10_plus": sum(1 for count in counts.values() if count >= 10),
        "top": [{"cidr": cidr, "hits": hits} for cidr, hits in counts.most_common(10)],
    }


def recommend_for_country(total_ips, stats_by_prefix):
    if total_ips >= 100 and stats_by_prefix[16]["networks_10_plus"]:
        return {"target_prefix": 16, "min_hits": 10, "reason": "100+ IPs and at least one /16 has 10+ observed IPs"}
    if total_ips >= 50 and stats_by_prefix[18]["networks_5_plus"]:
        return {"target_prefix": 18, "min_hits": 5, "reason": "50+ IPs and at least one /18 has 5+ observed IPs"}
    if total_ips >= 25 and stats_by_prefix[20]["networks_3_plus"]:
        return {"target_prefix": 20, "min_hits": 3, "reason": "25+ IPs and at least one /20 has 3+ observed IPs"}
    if stats_by_prefix[24]["networks_2_plus"]:
        return {"target_prefix": 24, "min_hits": 2, "reason": "at least one /24 has 2+ observed IPs"}
    return {"target_prefix": 32, "min_hits": 1, "reason": "traffic is too distributed for safe subnet aggregation"}


def build_recommendations(geo_data, country_codes, prefixes):
    country_ips = collect_country_ips(geo_data, country_codes)
    rows = []
    for country in sorted(country_ips.keys()):
        ips = country_ips[country]
        stats_by_prefix = {}
        for prefix in prefixes:
            stats_by_prefix[prefix] = prefix_stats_for_ips(ips, prefix)
        for required in DEFAULT_PREFIXES:
            if required not in stats_by_prefix:
                stats_by_prefix[required] = prefix_stats_for_ips(ips, required)
        recommendation = recommend_for_country(len(ips), stats_by_prefix)
        rows.append({
            "country": country,
            "observed_ips": len(ips),
            "recommendation": recommendation,
            "prefix_stats": [stats_by_prefix[prefix] for prefix in prefixes],
        })
    rows.sort(key=lambda row: (-row["observed_ips"], row["country"]))
    return rows


def write_json(path, rows):
    with open(path, "w") as f:
        json.dump({"countries": rows}, f, indent=2, sort_keys=True)


def write_text(path, rows):
    with open(path, "w") as f:
        f.write("Country prefix recommendations\n")
        f.write("==============================\n\n")
        f.write("Country | observed IPs | recommendation | min_hits | reason\n")
        for row in rows:
            rec = row["recommendation"]
            f.write("%s | %d | /%d | %d | %s\n" % (
                row["country"],
                row["observed_ips"],
                rec["target_prefix"],
                rec["min_hits"],
                rec["reason"],
            ))
        f.write("\nDetails\n")
        f.write("-------\n")
        for row in rows:
            f.write("\n%s (%d observed IPs)\n" % (row["country"], row["observed_ips"]))
            for stat in row["prefix_stats"]:
                f.write("  /%d networks=%d max_hits=%d n>=2=%d n>=3=%d n>=5=%d n>=10=%d\n" % (
                    stat["prefix"],
                    stat["networks"],
                    stat["max_hits"],
                    stat["networks_2_plus"],
                    stat["networks_3_plus"],
                    stat["networks_5_plus"],
                    stat["networks_10_plus"],
                ))
                for top in stat["top"][:3]:
                    f.write("    %s hits=%d\n" % (top["cidr"], top["hits"]))


def write_shell_plan(path, rows):
    with open(path, "w") as f:
        f.write("# Review before running. Each line uses the recommended prefix/min_hits for one country.\n")
        for row in rows:
            rec = row["recommendation"]
            f.write("COUNTRY_CODES=%s TARGET_PREFIX=%d MIN_HITS=%d APPLY=0 bash run_geo_bulk_blocks.sh\n" % (
                row["country"],
                rec["target_prefix"],
                rec["min_hits"],
            ))


def build_parser():
    parser = argparse.ArgumentParser(description="Recommend per-country subnet prefix and min_hits settings from geo_data.json.")
    parser.add_argument("--geo-data", default="geo_data.json")
    parser.add_argument("--country-codes", default="")
    parser.add_argument("--prefixes", default="24,22,20,18,16")
    parser.add_argument("--json-output", default="country_prefix_recommendations.json")
    parser.add_argument("--text-output", default="country_prefix_recommendations.txt")
    parser.add_argument("--shell-output", default="country_prefix_plan.sh")
    return parser


def main():
    if _ip is None:
        print("ERROR: Missing ipaddress module. Install one of: pip install ipaddress or pip install ipaddr", file=sys.stderr)
        return 1

    args = build_parser().parse_args()
    if not os.path.exists(args.geo_data):
        print("ERROR: geo data not found: %s" % args.geo_data, file=sys.stderr)
        return 1

    geo_data = load_geo_data(args.geo_data)
    country_codes = parse_country_codes(args.country_codes)
    prefixes = parse_prefixes(args.prefixes)
    rows = build_recommendations(geo_data, country_codes, prefixes)
    write_json(args.json_output, rows)
    write_text(args.text_output, rows)
    write_shell_plan(args.shell_output, rows)

    print("Countries:", len(rows))
    print("Wrote:", args.text_output)
    print("Wrote:", args.json_output)
    print("Wrote:", args.shell_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
