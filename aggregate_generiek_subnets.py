#!/usr/bin/env python
from __future__ import print_function

import argparse
import codecs
import collections
import json
import re
import sys

from country_policy import DEFAULT_COUNTRY_CODES, effective_country_codes

try:
    text_type = unicode  # Py2
except NameError:
    text_type = str

try:
    binary_type = bytes
except NameError:
    binary_type = str


def to_text(value):
    if isinstance(value, text_type):
        return value
    if isinstance(value, binary_type):
        return value.decode("utf-8")
    return text_type(value)


try:
    import ipaddress as _ip

    def ip_address(value):
        return _ip.ip_address(to_text(value))

    def ip_network(value, strict=False):
        return _ip.ip_network(to_text(value), strict=strict)

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


def parse_country_codes(value):
    return effective_country_codes([code.strip().upper() for code in value.split(",") if code.strip()])


def network_sort_key(value):
    net = ip_network(value, strict=False)
    first = getattr(net, "network_address", None)
    if first is None:
        first = net.network
    return (net.version, int(first), net.prefixlen)


def parse_ips_from_text(text):
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    ips = []
    seen = set()
    for value in ip_pattern.findall(text):
        try:
            addr = ip_address(value)
        except ValueError:
            continue
        if getattr(addr, "version", 4) != 4:
            continue
        key = str(addr)
        if key not in seen:
            ips.append(key)
            seen.add(key)
    return ips


def geo_country(details):
    return to_text(details.get("country", "Unknown")).upper()


def geo_detail_line(ip, details):
    return "%s %s %s %s %s" % (
        ip,
        geo_country(details),
        details.get("region", "Unknown"),
        details.get("city", "Unknown"),
        details.get("org", "Unknown"),
    )


def build_subnets_from_ips(ips, target_prefix, min_hits):
    counts = {}
    selected_ips = 0

    for ip in ips:
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


def build_subnets_from_geo(geo_data, country_codes, target_prefix, min_hits, source_ips=None):
    country_set = set(country_codes)
    source_ip_set = set(source_ips) if source_ips is not None else None
    ips = []

    for ip, details in geo_data.items():
        if source_ip_set is not None and ip not in source_ip_set:
            continue
        if details.get("country") not in country_set:
            continue
        ips.append(ip)

    return build_subnets_from_ips(ips, target_prefix, min_hits)


def build_country_report(geo_data, country_codes, source_ips=None):
    country_set = set(country_codes)
    ip_list = list(source_ips) if source_ips is not None else sorted(geo_data.keys())
    report = {
        "target_country_codes": sorted(country_set),
        "total_ips": len(ip_list),
        "blocked_ips": [],
        "allowed_ips": [],
        "missing_geo_ips": [],
        "countries": {},
    }

    country_counts = collections.defaultdict(lambda: {"total": 0, "blocked": 0, "allowed": 0})

    for ip in ip_list:
        details = geo_data.get(ip)
        if not details:
            report["missing_geo_ips"].append(ip)
            continue

        country = geo_country(details)
        blocked = country in country_set
        row = {
            "ip": ip,
            "country": country,
            "region": details.get("region", "Unknown"),
            "city": details.get("city", "Unknown"),
            "org": details.get("org", "Unknown"),
        }

        country_counts[country]["total"] += 1
        if blocked:
            report["blocked_ips"].append(row)
            country_counts[country]["blocked"] += 1
        else:
            report["allowed_ips"].append(row)
            country_counts[country]["allowed"] += 1

    for country, counts in country_counts.items():
        report["countries"][country] = dict(counts)

    return report


def write_ip_detail_file(path, rows):
    with codecs.open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write("%s %s %s %s %s\n" % (
                row["ip"],
                row["country"],
                row["region"],
                row["city"],
                row["org"],
            ))


def print_country_report(report):
    print("Country statistics:")
    print("  Country | Total | Blocked | Allowed")
    for country, counts in sorted(report["countries"].items()):
        print("  %s | %d | %d | %d" % (
            country,
            counts.get("total", 0),
            counts.get("blocked", 0),
            counts.get("allowed", 0),
        ))
    print("Blocked IPs:", len(report["blocked_ips"]))
    print("Allowed IPs:", len(report["allowed_ips"]))
    print("Missing geo IPs:", len(report["missing_geo_ips"]))


def build_parser():
    parser = argparse.ArgumentParser(
        description="Aggregate selected country IPs from geo_data.json into IPv4 CIDR ranges."
    )
    parser.add_argument("--input", default="geo_data.json")
    parser.add_argument(
        "--source",
        choices=["geo", "ips"],
        default="geo",
        help="Read --input as geo_data.json country data or as raw IP/text input.",
    )
    parser.add_argument(
        "--filter-ips-file",
        help="When --source=geo, only aggregate geo_data entries whose IP appears in this raw IP/text file.",
    )
    parser.add_argument("--output", default="aggregated_generiek_subnets.json")
    parser.add_argument("--report-output", default="generiek_country_report.json")
    parser.add_argument("--blocked-ips-output", default="generiek_blocked_candidate_ips.txt")
    parser.add_argument("--allowed-ips-output", default="generiek_allowed_non_target_ips.txt")
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

    if args.source == "geo":
        with open(args.input, "r") as f:
            geo_data = json.load(f)
        country_codes = parse_country_codes(args.country_codes)
        source_ips = None
        if args.filter_ips_file:
            with open(args.filter_ips_file, "r") as f:
                source_ips = parse_ips_from_text(f.read())
        selected_ips, subnets = build_subnets_from_geo(
            geo_data,
            country_codes,
            args.target_prefix,
            args.min_hits,
            source_ips=source_ips,
        )
        report = build_country_report(geo_data, country_codes, source_ips=source_ips)
        with open(args.report_output, "w") as f:
            json.dump(report, f, indent=4, sort_keys=True)
        write_ip_detail_file(args.blocked_ips_output, report["blocked_ips"])
        write_ip_detail_file(args.allowed_ips_output, report["allowed_ips"])
    else:
        with open(args.input, "r") as f:
            selected_ips, subnets = build_subnets_from_ips(
                parse_ips_from_text(f.read()),
                args.target_prefix,
                args.min_hits,
            )

    with open(args.output, "w") as f:
        json.dump(subnets, f, indent=4)

    print("Selected IPs:", selected_ips)
    print("Generated subnets:", len(subnets))
    print("Source:", args.source)
    print("Target prefix:", args.target_prefix)
    print("Output:", args.output)
    if args.source == "geo":
        print("Report:", args.report_output)
        print("Blocked candidate IPs:", args.blocked_ips_output)
        print("Allowed non-target IPs:", args.allowed_ips_output)
        print_country_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
