#!/usr/bin/env python
from __future__ import print_function

import argparse
import json
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


DEFAULT_COUNTRY_CODES = [
    "CN", "BR", "IQ", "TR", "UZ", "IN", "SA", "VE", "RU", "KE", "BD",
    "AR", "JO", "PK", "MA", "ZA", "UA", "EC", "AZ", "UY", "MX", "PY",
    "KZ", "AE", "NP", "CO", "JM", "PH", "NI", "SY", "HK", "IR", "PS",
    "OM", "DZ", "SN", "BY", "TN", "GE", "ID", "RS", "AM", "AL", "SG",
    "MM", "ET", "LB", "MY", "VN", "BH", "TH", "US",
]


def parse_country_codes(value):
    return [code.strip().upper() for code in value.split(",") if code.strip()]


def network_sort_key(value):
    net = ip_network(value, strict=False)
    first = getattr(net, "network_address", None)
    if first is None:
        first = net.network
    return (net.version, int(first), net.prefixlen)


def build_subnets(geo_data, country_codes, target_prefix, min_hits):
    country_set = set(country_codes)
    counts = {}
    selected_ips = 0

    for ip, details in geo_data.items():
        if details.get("country") not in country_set:
            continue
        try:
            addr = ip_address(ip)
        except ValueError:
            continue
        if getattr(addr, "version", 4) != 4:
            continue

        selected_ips += 1
        network = ip_network("%s/%d" % (ip, target_prefix), strict=False)
        key = str(network)
        counts[key] = counts.get(key, 0) + 1

    subnets = [net for net, count in counts.items() if count >= min_hits]
    subnets.sort(key=network_sort_key)
    return selected_ips, subnets


def build_parser():
    parser = argparse.ArgumentParser(
        description="Aggregate selected country IPs from geo_data.json into IPv4 CIDR ranges."
    )
    parser.add_argument("--input", default="geo_data.json")
    parser.add_argument("--output", default="aggregated_generiek_subnets.json")
    parser.add_argument(
        "--country-codes",
        default=",".join(DEFAULT_COUNTRY_CODES),
        help="Comma-separated countries to include. Default includes US.",
    )
    parser.add_argument(
        "--target-prefix",
        type=int,
        default=24,
        help="IPv4 prefix to generate. Use 24 by default; use 16 only after audit.",
    )
    parser.add_argument(
        "--min-hits",
        type=int,
        default=1,
        help="Only output a subnet if at least this many source IPs fall inside it.",
    )
    return parser


def main():
    if _ip is None:
        print("ERROR: Missing ipaddress module. Install one of: pip install ipaddress or pip install ipaddr", file=sys.stderr)
        return 1

    args = build_parser().parse_args()
    if args.target_prefix < 1 or args.target_prefix > 32:
        print("ERROR: --target-prefix must be between 1 and 32", file=sys.stderr)
        return 1
    if args.min_hits < 1:
        print("ERROR: --min-hits must be at least 1", file=sys.stderr)
        return 1

    with open(args.input, "r") as f:
        geo_data = json.load(f)

    country_codes = parse_country_codes(args.country_codes)
    selected_ips, subnets = build_subnets(geo_data, country_codes, args.target_prefix, args.min_hits)

    with open(args.output, "w") as f:
        json.dump(subnets, f, indent=4)

    print("Selected IPs:", selected_ips)
    print("Generated subnets:", len(subnets))
    print("Target prefix:", args.target_prefix)
    print("Output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
