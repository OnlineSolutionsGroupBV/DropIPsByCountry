#!/usr/bin/env python
from __future__ import print_function

import argparse
import codecs
import collections
import json
import os
import re
import sys

from country_policy import default_country_codes, effective_country_codes, is_safe_provider

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


ASN_RE = re.compile(r"\b(AS\d+)\b")
def parse_country_codes(value):
    if not value:
        return default_country_codes()
    return effective_country_codes([part.strip().upper() for part in value.split(",") if part.strip()])


def parse_prefixes(value):
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def to_country(details):
    value = details.get("country", "Unknown")
    if value is None:
        value = "Unknown"
    return text_type(value).upper()


def to_org(details):
    value = details.get("org", "Unknown")
    if value is None:
        value = "Unknown"
    return text_type(value)


def org_key(org):
    match = ASN_RE.search(org)
    if match:
        return match.group(1) + " " + org.split(match.group(1), 1)[1].strip()
    return org


def network_for_ip(ip, prefix):
    return text_type(ip_network("%s/%d" % (ip, prefix), strict=False))


def blocked_size(prefix):
    return 2 ** (32 - prefix)


def collect_groups(geo_data, country_codes):
    wanted = set(country_codes)
    groups = collections.defaultdict(list)
    for ip, details in geo_data.items():
        country = to_country(details)
        if country not in wanted:
            continue
        org = org_key(to_org(details))
        groups[(country, org)].append(ip)
    return groups


def prefix_counts(ips, prefix):
    return collections.Counter(network_for_ip(ip, prefix) for ip in ips)


def choose_recommendation(observed_ips, stats, min_provider_ips):
    if observed_ips < min_provider_ips:
        return {"decision": "LOW_EVIDENCE", "target_prefix": 32, "min_hits": 1, "reason": "provider has too few observed IPs"}
    if stats[16]["networks_10_plus"]:
        return {"decision": "CANDIDATE", "target_prefix": 16, "min_hits": 10, "reason": "provider has 10+ observed IPs in a /16"}
    if stats[18]["networks_5_plus"]:
        return {"decision": "CANDIDATE", "target_prefix": 18, "min_hits": 5, "reason": "provider has 5+ observed IPs in a /18"}
    if stats[20]["networks_3_plus"]:
        return {"decision": "CANDIDATE", "target_prefix": 20, "min_hits": 3, "reason": "provider has 3+ observed IPs in a /20"}
    if stats[24]["networks_2_plus"]:
        return {"decision": "CANDIDATE", "target_prefix": 24, "min_hits": 2, "reason": "provider has 2+ observed IPs in a /24"}
    return {"decision": "EXACT_IP_ONLY", "target_prefix": 32, "min_hits": 1, "reason": "provider traffic is distributed across subnets"}


def stats_for_prefixes(ips, prefixes):
    result = {}
    for prefix in prefixes:
        counts = prefix_counts(ips, prefix)
        result[prefix] = {
            "prefix": prefix,
            "networks": len(counts),
            "max_hits": max(counts.values()) if counts else 0,
            "networks_2_plus": sum(1 for count in counts.values() if count >= 2),
            "networks_3_plus": sum(1 for count in counts.values() if count >= 3),
            "networks_5_plus": sum(1 for count in counts.values() if count >= 5),
            "networks_10_plus": sum(1 for count in counts.values() if count >= 10),
            "top": [{"cidr": cidr, "hits": hits} for cidr, hits in counts.most_common(10)],
        }
    return result


def candidate_cidrs_for_recommendation(ips, recommendation):
    prefix = recommendation["target_prefix"]
    min_hits = recommendation["min_hits"]
    counts = prefix_counts(ips, prefix)
    return [cidr for cidr, hits in counts.items() if hits >= min_hits]


def candidate_details_for_recommendation(ips, recommendation):
    prefix = recommendation["target_prefix"]
    min_hits = recommendation["min_hits"]
    counts = prefix_counts(ips, prefix)
    examples = collections.defaultdict(list)
    for ip in sorted(ips):
        cidr = network_for_ip(ip, prefix)
        if len(examples[cidr]) < 8:
            examples[cidr].append(ip)
    rows = []
    for cidr, hits in counts.items():
        if hits < min_hits:
            continue
        rows.append({
            "cidr": cidr,
            "hits": hits,
            "blocks_ips": blocked_size(prefix),
            "example_ips": examples[cidr],
        })
    rows.sort(key=lambda row: (-row["hits"], row["cidr"]))
    return rows


def risk_score(row):
    rec = row["recommendation"]
    if rec["decision"] != "CANDIDATE":
        return 0
    prefix_weight = {16: 50, 18: 35, 20: 22, 24: 12, 32: 1}.get(rec["target_prefix"], 1)
    return row["observed_ips"] + prefix_weight + (len(row["candidate_cidrs"]) * 5)


def build_recommendations(geo_data, country_codes, prefixes, min_provider_ips):
    required_prefixes = sorted(set(prefixes + [24, 20, 18, 16]))
    rows = []
    for (country, org), ips in collect_groups(geo_data, country_codes).items():
        stats = stats_for_prefixes(ips, required_prefixes)
        recommendation = choose_recommendation(len(ips), stats, min_provider_ips)
        if is_safe_provider(org):
            recommendation = {
                "decision": "SKIP_SAFE_PROVIDER",
                "target_prefix": 32,
                "min_hits": 1,
                "reason": "provider name matches crawler/search allowlist provider",
            }
        candidate_details = []
        if recommendation["decision"] == "CANDIDATE":
            candidate_details = candidate_details_for_recommendation(ips, recommendation)
        candidates = [item["cidr"] for item in candidate_details]
        rows.append({
            "country": country,
            "org": org,
            "observed_ips": len(ips),
            "recommendation": recommendation,
            "candidate_cidrs": sorted(candidates),
            "candidate_details": candidate_details,
            "prefix_stats": [stats[prefix] for prefix in prefixes],
            "example_ips": sorted(ips)[:10],
        })
    rows.sort(key=lambda row: (
        row["recommendation"]["decision"] != "CANDIDATE",
        -risk_score(row),
        -row["observed_ips"],
        row["country"],
        row["org"],
    ))
    return rows


def write_json(path, rows):
    with open(path, "w") as f:
        json.dump({"providers": rows}, f, indent=2, sort_keys=True)


def write_candidates(path, rows):
    cidrs = []
    seen = set()
    for row in rows:
        for cidr in row["candidate_cidrs"]:
            if cidr not in seen:
                cidrs.append(cidr)
                seen.add(cidr)
    with open(path, "w") as f:
        json.dump(cidrs, f, indent=2, sort_keys=True)


def write_text(path, rows, max_rows):
    with codecs.open(path, "w", encoding="utf-8") as f:
        f.write("Provider subnet recommendations\n")
        f.write("===============================\n\n")
        f.write("Country | observed IPs | decision | prefix | min_hits | org | candidates | reason\n")
        for row in rows[:max_rows]:
            rec = row["recommendation"]
            f.write("%s | %d | %s | /%d | %d | %s | %d | %s\n" % (
                row["country"],
                row["observed_ips"],
                rec["decision"],
                rec["target_prefix"],
                rec["min_hits"],
                row["org"],
                len(row["candidate_cidrs"]),
                rec["reason"],
            ))
            for cidr in row["candidate_cidrs"][:5]:
                f.write("  candidate %s blocks=%d\n" % (cidr, blocked_size(rec["target_prefix"])))
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


def write_danger_text(path, rows, max_rows):
    candidates = [row for row in rows if row["recommendation"]["decision"] == "CANDIDATE"]
    total_subnets = sum(len(row["candidate_cidrs"]) for row in candidates)
    total_observed_ips = sum(row["observed_ips"] for row in candidates)
    with codecs.open(path, "w", encoding="utf-8") as f:
        f.write("Dangerous provider subnet candidates\n")
        f.write("====================================\n\n")
        f.write("Providers with candidate blocks: %d\n" % len(candidates))
        f.write("Candidate subnets: %d\n" % total_subnets)
        f.write("Observed IPs behind these providers: %d\n" % total_observed_ips)
        f.write("Machine blocklist: provider_subnet_candidates.json\n\n")
        f.write("Criteria: provider must be in target country list, not protected by country policy, not a known safe crawler/provider name, and enough IPs must cluster inside the recommended prefix.\n\n")

        for index, row in enumerate(candidates[:max_rows], 1):
            rec = row["recommendation"]
            f.write("%d. %s | %s\n" % (index, row["country"], row["org"]))
            f.write("   risk_score: %d\n" % risk_score(row))
            f.write("   observed_ips: %d\n" % row["observed_ips"])
            f.write("   recommendation: /%d with min_hits=%d\n" % (rec["target_prefix"], rec["min_hits"]))
            f.write("   reason: %s\n" % rec["reason"])
            f.write("   provider_example_ips: %s\n" % ", ".join(row["example_ips"][:8]))
            f.write("   candidate_subnets:\n")
            for detail in row["candidate_details"]:
                f.write("     - %s hits=%d blocks_ips=%d examples=%s\n" % (
                    detail["cidr"],
                    detail["hits"],
                    detail["blocks_ips"],
                    ", ".join(detail["example_ips"]),
                ))
            f.write("   prefix_stats:\n")
            for stat in row["prefix_stats"]:
                f.write("     /%d networks=%d max_hits=%d n>=2=%d n>=3=%d n>=5=%d n>=10=%d\n" % (
                    stat["prefix"],
                    stat["networks"],
                    stat["max_hits"],
                    stat["networks_2_plus"],
                    stat["networks_3_plus"],
                    stat["networks_5_plus"],
                    stat["networks_10_plus"],
                ))
            f.write("\n")


def build_parser():
    parser = argparse.ArgumentParser(description="Recommend provider/ASN-specific subnet blocks from geo_data.json.")
    parser.add_argument("--geo-data", default="geo_data.json")
    parser.add_argument("--country-codes", default="")
    parser.add_argument("--prefixes", default="24,20,18,16")
    parser.add_argument("--min-provider-ips", type=int, default=3)
    parser.add_argument("--text-output", default="provider_subnet_recommendations.txt")
    parser.add_argument("--danger-output", default="provider_dangerous_subnets.txt")
    parser.add_argument("--json-output", default="provider_subnet_recommendations.json")
    parser.add_argument("--candidates-output", default="provider_subnet_candidates.json")
    parser.add_argument("--max-rows", type=int, default=200)
    return parser


def main():
    if _ip is None:
        print("ERROR: Missing ipaddress module. Install one of: pip install ipaddress or pip install ipaddr", file=sys.stderr)
        return 1
    args = build_parser().parse_args()
    if not os.path.exists(args.geo_data):
        print("ERROR: geo data not found: %s" % args.geo_data, file=sys.stderr)
        return 1
    rows = build_recommendations(
        load_json(args.geo_data),
        parse_country_codes(args.country_codes),
        parse_prefixes(args.prefixes),
        args.min_provider_ips,
    )
    write_text(args.text_output, rows, args.max_rows)
    write_danger_text(args.danger_output, rows, args.max_rows)
    write_json(args.json_output, rows)
    write_candidates(args.candidates_output, rows)
    print("Providers:", len(rows))
    print("Wrote:", args.text_output)
    print("Wrote:", args.danger_output)
    print("Wrote:", args.json_output)
    print("Wrote:", args.candidates_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
