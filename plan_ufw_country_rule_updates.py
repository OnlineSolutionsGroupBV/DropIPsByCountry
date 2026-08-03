#!/usr/bin/env python
from __future__ import print_function

import argparse
import codecs
import collections
import json
import os
import re
import subprocess
import sys

from country_policy import PROTECTED_COUNTRY_CODES
from block_generiek_subnet import (
    ip_network,
    is_subnet_of,
    load_allowlist_networks,
    network_sort_key,
    network_version,
    networks_overlap,
    to_text,
)


UFW_NUMBERED_RE = re.compile(r"^\[\s*(\d+)\]\s+(.*)$")


def read_text(path):
    with open(path, "rb") as f:
        data = f.read()
    if isinstance(data, bytes):
        return data.decode("utf-8")
    return data


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def run_ufw_status(sudo):
    cmd = ["ufw", "status", "numbered"]
    if sudo:
        cmd = ["sudo"] + cmd
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        if isinstance(err, bytes):
            err = err.decode("utf-8")
        raise RuntimeError("ufw status failed: %s" % err)
    if isinstance(out, bytes):
        out = out.decode("utf-8")
    return out


def parse_ufw_deny_rules(status_text):
    rules = []
    for line in status_text.splitlines():
        line = line.strip()
        match = UFW_NUMBERED_RE.match(line)
        if not match:
            continue
        if "DENY IN" not in line:
            continue
        source = line.split("DENY IN", 1)[1].strip()
        if not source:
            continue
        value = source.split()[0]
        try:
            if "/" not in value:
                value += "/32"
            net = ip_network(value, strict=False)
        except ValueError:
            continue
        if network_version(net) != 4:
            continue
        rules.append({
            "num": int(match.group(1)),
            "line": line,
            "cidr": to_text(net),
            "network": net,
        })
    return rules


def load_recommendations(path):
    data = load_json(path)
    rows = data.get("countries", [])
    result = {}
    for row in rows:
        country = to_text(row.get("country", "")).upper()
        rec = row.get("recommendation", {})
        if not country or "target_prefix" not in rec:
            continue
        result[country] = {
            "target_prefix": int(rec.get("target_prefix")),
            "min_hits": int(rec.get("min_hits", 1)),
            "reason": rec.get("reason", ""),
        }
    return result


def geo_ip_network(ip):
    return ip_network("%s/32" % ip, strict=False)


def country_for_details(details):
    country = details.get("country", "Unknown")
    if country is None:
        country = "Unknown"
    return to_text(country).upper()


def org_for_details(details):
    org = details.get("org", "Unknown")
    if org is None:
        org = "Unknown"
    return to_text(org)


def geo_sources_in_network(net, geo_data):
    rows = []
    for ip, details in geo_data.items():
        try:
            ip_net = geo_ip_network(ip)
        except ValueError:
            continue
        if network_version(ip_net) != network_version(net):
            continue
        if not is_subnet_of(ip_net, net):
            continue
        rows.append({
            "ip": ip,
            "country": country_for_details(details),
            "org": org_for_details(details),
        })
    rows.sort(key=lambda row: row["ip"])
    return rows


def network_for_ip_prefix(ip, prefix):
    return ip_network("%s/%d" % (ip, prefix), strict=False)


def blocked_size(net):
    return 2 ** (32 - net.prefixlen)


def overlaps_any(net, networks):
    overlaps = []
    for other in networks:
        if networks_overlap(net, other):
            overlaps.append(to_text(other))
    return overlaps


def country_counts(sources):
    counts = collections.Counter(row["country"] for row in sources)
    return [{"country": country, "ips": count} for country, count in counts.most_common()]


def provider_counts(sources):
    counts = collections.Counter(row["org"] for row in sources)
    return [{"org": org, "ips": count} for org, count in counts.most_common(8)]


def safe_examples(sources, max_examples):
    return ["%s %s %s" % (row["ip"], row["country"], row["org"]) for row in sources[:max_examples]]


def build_country_ip_index(geo_data):
    index = collections.defaultdict(list)
    for ip, details in geo_data.items():
        country = country_for_details(details)
        index[country].append(ip)
    return index


def country_hits_in_network(country_ips, net):
    hits = []
    for ip in country_ips:
        try:
            ip_net = geo_ip_network(ip)
        except ValueError:
            continue
        if is_subnet_of(ip_net, net):
            hits.append(ip)
    return sorted(hits)


def classify_rule(rule, geo_data, recommendations, allowlist, country_ip_index, max_examples):
    old_net = rule["network"]
    sources = geo_sources_in_network(old_net, geo_data)
    base = {
        "num": rule["num"],
        "line": rule["line"],
        "old_cidr": rule["cidr"],
        "old_blocks_ips": blocked_size(old_net),
        "source_count": len(sources),
        "country_counts": country_counts(sources),
        "provider_counts": provider_counts(sources),
        "examples": safe_examples(sources, max_examples),
    }

    if not sources:
        base.update({"action": "SKIP_NO_EVIDENCE", "reason": "no geo_data IPs found inside existing UFW rule"})
        return base

    old_overlap = overlaps_any(old_net, allowlist)
    if old_overlap:
        base.update({
            "action": "SKIP_EXISTING_ALLOWLIST_OVERLAP",
            "reason": "existing rule overlaps crawler/search allowlist; review with bad UFW audit before replacing",
            "allowlist_overlaps": old_overlap[:5],
        })
        return base

    countries = set(row["country"] for row in sources)
    if countries & set(PROTECTED_COUNTRY_CODES):
        base.update({"action": "SKIP_PROTECTED_COUNTRY", "reason": "existing rule contains protected country evidence"})
        return base

    if len(countries) != 1:
        base.update({"action": "SKIP_MIXED_COUNTRIES", "reason": "existing rule contains multiple countries in geo_data"})
        return base

    country = list(countries)[0]
    base["country"] = country
    if country not in recommendations:
        base.update({"action": "SKIP_NO_RECOMMENDATION", "reason": "country is not present in country recommendation file"})
        return base

    rec = recommendations[country]
    target_prefix = rec["target_prefix"]
    min_hits = rec["min_hits"]
    candidate_by_cidr = {}
    for source in sources:
        try:
            new_net = network_for_ip_prefix(source["ip"], target_prefix)
        except ValueError:
            continue
        cidr = to_text(new_net)
        if cidr not in candidate_by_cidr:
            candidate_by_cidr[cidr] = new_net

    kept = []
    skipped_candidates = []
    for cidr, new_net in sorted(candidate_by_cidr.items(), key=lambda item: network_sort_key(item[1])):
        country_hits = country_hits_in_network(country_ip_index.get(country, []), new_net)
        if len(country_hits) < min_hits:
            skipped_candidates.append({
                "cidr": cidr,
                "reason": "below recommended min_hits",
                "hits": len(country_hits),
                "min_hits": min_hits,
            })
            continue
        overlap = overlaps_any(new_net, allowlist)
        if overlap:
            skipped_candidates.append({
                "cidr": cidr,
                "reason": "allowlist overlap",
                "hits": len(country_hits),
                "overlaps": overlap[:5],
            })
            continue
        candidate_sources = geo_sources_in_network(new_net, geo_data)
        candidate_countries = set(row["country"] for row in candidate_sources)
        if candidate_countries - set([country]):
            skipped_candidates.append({
                "cidr": cidr,
                "reason": "new subnet contains non-target country evidence",
                "hits": len(country_hits),
                "country_counts": country_counts(candidate_sources),
            })
            continue
        kept.append({
            "cidr": cidr,
            "hits": len(country_hits),
            "blocks_ips": blocked_size(new_net),
            "example_ips": country_hits[:max_examples],
        })

    base["recommendation"] = {
        "target_prefix": target_prefix,
        "min_hits": min_hits,
        "reason": rec.get("reason", ""),
    }
    base["new_cidrs"] = kept
    base["skipped_candidates"] = skipped_candidates

    old_cidrs = set([rule["cidr"]])
    new_cidrs = set(item["cidr"] for item in kept)
    if not kept:
        base.update({"action": "SKIP_NO_SAFE_REPLACEMENT", "reason": "all recommended replacement CIDRs were skipped"})
    elif old_cidrs == new_cidrs:
        base.update({"action": "KEEP", "reason": "existing rule already matches recommendation"})
    else:
        base.update({"action": "REPLACE", "reason": "existing rule can be replaced by recommended country subnet(s)"})
    return base


def build_plan(status_text, geo_data, recommendations, allowlist, max_examples):
    rules = parse_ufw_deny_rules(status_text)
    country_ip_index = build_country_ip_index(geo_data)
    analyzed = [
        classify_rule(rule, geo_data, recommendations, allowlist, country_ip_index, max_examples)
        for rule in rules
    ]
    replace_rules = [row for row in analyzed if row["action"] == "REPLACE"]
    add_by_cidr = {}
    for row in replace_rules:
        for item in row["new_cidrs"]:
            add_by_cidr[item["cidr"]] = item
    add_rules = [add_by_cidr[cidr] for cidr in sorted(add_by_cidr.keys(), key=lambda c: network_sort_key(ip_network(c, strict=False)))]
    delete_rules = [{
        "num": row["num"],
        "old_cidr": row["old_cidr"],
        "line": row["line"],
        "country": row.get("country", "Unknown"),
    } for row in replace_rules]
    delete_rules.sort(key=lambda row: row["num"], reverse=True)
    summary = collections.Counter(row["action"] for row in analyzed)
    return {
        "summary": dict(summary),
        "rules_parsed": len(rules),
        "delete_rules": delete_rules,
        "add_rules": add_rules,
        "rules": analyzed,
    }


def write_json(path, plan):
    with open(path, "w") as f:
        json.dump(plan, f, indent=2, sort_keys=True)


def write_text(path, plan, max_rules):
    with codecs.open(path, "w", encoding="utf-8") as f:
        f.write("UFW country rule update plan\n")
        f.write("============================\n\n")
        f.write("Parsed deny rules: %d\n" % plan["rules_parsed"])
        for action, count in sorted(plan["summary"].items()):
            f.write("%s: %d\n" % (action, count))
        f.write("Rules to delete: %d\n" % len(plan["delete_rules"]))
        f.write("Rules to add: %d\n\n" % len(plan["add_rules"]))

        if plan["delete_rules"] or plan["add_rules"]:
            f.write("Apply order\n")
            f.write("-----------\n")
            for row in plan["delete_rules"]:
                f.write("delete #%d %s %s\n" % (row["num"], row["old_cidr"], row["country"]))
            for row in plan["add_rules"]:
                f.write("add %s hits=%d blocks_ips=%d\n" % (row["cidr"], row["hits"], row["blocks_ips"]))
            f.write("\n")

        f.write("Rule analysis\n")
        f.write("-------------\n")
        for row in plan["rules"][:max_rules]:
            f.write("\n[%d] %s\n" % (row["num"], row["old_cidr"]))
            f.write("  action: %s\n" % row["action"])
            f.write("  reason: %s\n" % row["reason"])
            f.write("  source_count: %d\n" % row["source_count"])
            if row.get("country"):
                f.write("  country: %s\n" % row["country"])
            if row.get("recommendation"):
                rec = row["recommendation"]
                f.write("  recommendation: /%d min_hits=%d (%s)\n" % (
                    rec["target_prefix"],
                    rec["min_hits"],
                    rec["reason"],
                ))
            if row["country_counts"]:
                f.write("  countries: %s\n" % ", ".join("%s=%d" % (item["country"], item["ips"]) for item in row["country_counts"]))
            if row["provider_counts"]:
                f.write("  providers: %s\n" % ", ".join("%s=%d" % (item["org"], item["ips"]) for item in row["provider_counts"]))
            for item in row.get("new_cidrs", []):
                f.write("  new: %s hits=%d blocks_ips=%d examples=%s\n" % (
                    item["cidr"],
                    item["hits"],
                    item["blocks_ips"],
                    ", ".join(item["example_ips"]),
                ))
            for item in row.get("skipped_candidates", []):
                f.write("  skipped: %s %s\n" % (item["cidr"], item["reason"]))


def build_parser():
    parser = argparse.ArgumentParser(description="Plan safe replacements for existing UFW DENY rules using country prefix recommendations.")
    parser.add_argument("--recommendations", default="country_prefix_recommendations.json")
    parser.add_argument("--geo-data", default="geo_data.json")
    parser.add_argument("--allowlist", default=os.path.join("ip_cache", "allowlist_cidrs.json"))
    parser.add_argument("--ufw-status-file", help="Read UFW status from a file instead of running ufw")
    parser.add_argument("--sudo", action="store_true", help="Use sudo for ufw status")
    parser.add_argument("--output", default="ufw_country_update_plan.txt")
    parser.add_argument("--json-output", default="ufw_country_update_plan.json")
    parser.add_argument("--max-examples", type=int, default=8)
    parser.add_argument("--max-rules", type=int, default=500)
    return parser


def main():
    args = build_parser().parse_args()
    try:
        if args.ufw_status_file:
            status_text = read_text(args.ufw_status_file)
        else:
            status_text = run_ufw_status(args.sudo)
        if not os.path.exists(args.geo_data):
            raise RuntimeError("geo data not found: %s" % args.geo_data)
        if not os.path.exists(args.recommendations):
            raise RuntimeError("recommendations not found: %s" % args.recommendations)
        geo_data = load_json(args.geo_data)
        recommendations = load_recommendations(args.recommendations)
        allowlist = load_allowlist_networks(args.allowlist)
        plan = build_plan(status_text, geo_data, recommendations, allowlist, args.max_examples)
        write_text(args.output, plan, args.max_rules)
        write_json(args.json_output, plan)
        print("Parsed deny rules:", plan["rules_parsed"])
        print("Rules to delete:", len(plan["delete_rules"]))
        print("Rules to add:", len(plan["add_rules"]))
        print("Wrote:", args.output)
        print("Wrote:", args.json_output)
        return 0
    except (IOError, ValueError, RuntimeError, ImportError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
