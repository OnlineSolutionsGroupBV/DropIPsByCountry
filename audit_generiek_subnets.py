#!/usr/bin/env python
from __future__ import print_function

import argparse
import collections
import json
import os
import sys

try:
    import ipaddress as _ip

    def ip_address(value):
        return _ip.ip_address(value)

    def ip_network(value, strict=False):
        return _ip.ip_network(value, strict=strict)

except ImportError:
    try:
        import ipaddr as _ip
    except ImportError:
        _ip = None

    def ip_address(value):
        if _ip is None:
            raise ImportError("Missing ipaddress/ipaddr module")
        return _ip.IPAddress(value)

    def ip_network(value, strict=False):
        if _ip is None:
            raise ImportError("Missing ipaddress/ipaddr module")
        return _ip.IPNetwork(value)


def net_version(net):
    return net.version


def net_prefixlen(net):
    return net.prefixlen


def net_first_int(net):
    value = getattr(net, "network_address", None)
    if value is None:
        value = net.network
    return int(value)


def net_last_int(net):
    value = getattr(net, "broadcast_address", None)
    if value is None:
        value = net.broadcast
    return int(value)


def networks_overlap(left, right):
    if net_version(left) != net_version(right):
        return False
    return net_first_int(left) <= net_last_int(right) and net_first_int(right) <= net_last_int(left)


def network_sort_key(net):
    return (net_version(net), net_first_int(net), net_prefixlen(net))


def load_network_list(path):
    with open(path, "r") as f:
        data = json.load(f)

    if isinstance(data, dict):
        raw_values = data.get("cidrs", data.keys())
    elif isinstance(data, list):
        raw_values = data
    else:
        raise RuntimeError("Expected %s to contain a JSON list or object" % path)

    networks = []
    invalid = []
    seen = set()
    for value in raw_values:
        try:
            net = ip_network(str(value).strip(), strict=False)
        except ValueError as exc:
            invalid.append((value, str(exc)))
            continue
        key = str(net)
        if key not in seen:
            networks.append(net)
            seen.add(key)

    networks.sort(key=network_sort_key)
    return networks, invalid


def load_geo_counts(path, candidates):
    if not path or not os.path.exists(path):
        return {}, {}

    prefix_lengths = sorted(set(net_prefixlen(net) for net in candidates if net_version(net) == 4))
    candidate_keys = set(str(net) for net in candidates)
    counts = {}
    examples = {}

    with open(path, "r") as f:
        geo_data = json.load(f)

    for ip, details in geo_data.items():
        try:
            addr = ip_address(ip)
        except ValueError:
            continue
        if getattr(addr, "version", 4) != 4:
            continue

        for prefix in prefix_lengths:
            net = ip_network("%s/%d" % (ip, prefix), strict=False)
            key = str(net)
            if key not in candidate_keys:
                continue
            counts[key] = counts.get(key, 0) + 1
            if key not in examples:
                examples[key] = []
            if len(examples[key]) < 3:
                examples[key].append("%s %s %s" % (ip, details.get("country", "?"), details.get("org", "?")))

    return counts, examples


def find_overlaps(candidates, allowlist):
    overlaps = []
    for candidate in candidates:
        for allowed in allowlist:
            if networks_overlap(candidate, allowed):
                overlaps.append((candidate, allowed))
    overlaps.sort(key=lambda item: (network_sort_key(item[0]), network_sort_key(item[1])))
    return overlaps


def build_parser():
    parser = argparse.ArgumentParser(
        description="Audit generated generic subnets before adding UFW deny rules."
    )
    parser.add_argument("--input", default="aggregated_generiek_subnets.json")
    parser.add_argument("--geo-data", default="geo_data.json")
    parser.add_argument("--allowlist", default=os.path.join("ip_cache", "allowlist_cidrs.json"))
    parser.add_argument("--max-examples", type=int, default=30)
    parser.add_argument("--fail-on-overlap", action="store_true")
    return parser


def main():
    if _ip is None:
        print("ERROR: Missing ipaddress module. Install one of: pip install ipaddress or pip install ipaddr", file=sys.stderr)
        return 1

    args = build_parser().parse_args()
    candidates, invalid = load_network_list(args.input)
    prefix_counts = collections.Counter(net_prefixlen(net) for net in candidates)

    print("Input:", args.input)
    print("Candidate subnets:", len(candidates))
    print("Invalid values:", len(invalid))
    if invalid:
        for value, error in invalid[:args.max_examples]:
            print("  invalid %s: %s" % (value, error))
        if len(invalid) > args.max_examples:
            print("  ... %d more invalid value(s)" % (len(invalid) - args.max_examples))

    print("Prefix distribution:")
    for prefix, count in sorted(prefix_counts.items()):
        print("  /%d: %d" % (prefix, count))

    source_counts, source_examples = load_geo_counts(args.geo_data, candidates)
    if source_counts:
        one_hit = sum(1 for net in candidates if source_counts.get(str(net), 0) == 1)
        print("Subnets backed by exactly 1 source IP:", one_hit)
        broad_one_hit = [
            net for net in candidates
            if net_version(net) == 4 and net_prefixlen(net) < 24 and source_counts.get(str(net), 0) == 1
        ]
        print("Broad subnets (< /24) backed by exactly 1 source IP:", len(broad_one_hit))
        for net in broad_one_hit[:args.max_examples]:
            print("  %s from %s" % (net, "; ".join(source_examples.get(str(net), []))))
        if len(broad_one_hit) > args.max_examples:
            print("  ... %d more broad one-hit subnet(s)" % (len(broad_one_hit) - args.max_examples))

    allowlist = []
    allow_invalid = []
    if args.allowlist and os.path.exists(args.allowlist):
        allowlist, allow_invalid = load_network_list(args.allowlist)
    else:
        print("Allowlist: missing %s" % args.allowlist)
        print("Run: python cache_crawler_ips.py --cache-dir ip_cache")

    if allow_invalid:
        print("Invalid allowlist values:", len(allow_invalid))

    overlaps = find_overlaps(candidates, allowlist)
    print("Allowlist CIDRs:", len(allowlist))
    print("Candidate/allowlist overlaps:", len(overlaps))
    for candidate, allowed in overlaps[:args.max_examples]:
        detail = ""
        if source_examples.get(str(candidate)):
            detail = " source: %s" % "; ".join(source_examples[str(candidate)])
        print("  BLOCK %s overlaps ALLOW %s%s" % (candidate, allowed, detail))
    if len(overlaps) > args.max_examples:
        print("  ... %d more overlap(s)" % (len(overlaps) - args.max_examples))

    if overlaps and args.fail_on_overlap:
        return 2
    if invalid:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
