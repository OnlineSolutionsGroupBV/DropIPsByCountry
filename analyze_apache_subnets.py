#!/usr/bin/env python
from __future__ import print_function

import argparse
import collections
import gzip
import json
import os
import re
import sys

try:
    text_type = unicode  # Py2
except NameError:
    text_type = str

try:
    binary_type = bytes
except NameError:
    binary_type = str


IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
REQUEST_RE = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+[^"]*)?"\s+(?P<status>\d{3}|-)')
DEFAULT_EXTENSIONS = (".log", ".log.1", ".txt", ".gz")


def to_text(value):
    if isinstance(value, text_type):
        return value
    if isinstance(value, binary_type):
        return value.decode("utf-8", "replace")
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
        return _ip.IPAddress(to_text(value))

    def ip_network(value, strict=False):
        if _ip is None:
            raise ImportError("Missing ipaddress/ipaddr module")
        return _ip.IPNetwork(to_text(value))


def parse_country_codes(value):
    return set(code.strip().upper() for code in value.split(",") if code.strip())


def is_ipv4(value):
    if not IPV4_RE.match(value):
        return False
    try:
        addr = ip_address(value)
    except ValueError:
        return False
    return getattr(addr, "version", 4) == 4


def network_for_ip(ip, prefix):
    return str(ip_network("%s/%d" % (ip, prefix), strict=False))


def blocked_size(prefix):
    return 2 ** (32 - prefix)


def infer_site_from_path(path):
    name = os.path.basename(path)
    for suffix in (".gz", ".log", ".log.1", ".txt"):
        if name.endswith(suffix):
            name = name[:-len(suffix)]
    return name or "unknown"


def iter_log_paths(log_dir, include_gz=True):
    paths = []
    for root, _dirs, files in os.walk(log_dir):
        for name in files:
            path = os.path.join(root, name)
            if name.endswith(".gz") and not include_gz:
                continue
            if name.endswith(DEFAULT_EXTENSIONS) or "access" in name:
                paths.append(path)
    return sorted(paths)


def open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rb")
    return open(path, "rb")


def parse_log_line(line, fallback_site):
    line = to_text(line).rstrip("\n")
    if " [" not in line:
        return None

    left = line.split(" [", 1)[0]
    tokens = left.split()
    if not tokens:
        return None

    site = fallback_site
    ip = None
    if is_ipv4(tokens[0]):
        ip = tokens[0]
    elif len(tokens) > 1 and is_ipv4(tokens[1]):
        site = tokens[0]
        ip = tokens[1]
    else:
        return None

    match = REQUEST_RE.search(line)
    method = match.group("method") if match else "-"
    url = match.group("url") if match else "-"
    status = match.group("status") if match else "-"
    return {
        "ip": ip,
        "site": site,
        "method": method,
        "url": url.split("?", 1)[0].split("#", 1)[0],
        "status": status,
    }


def load_geo_data(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def country_for_ip(geo_data, ip):
    details = geo_data.get(ip, {})
    return to_text(details.get("country", "Unknown")).upper()


def add_top(counter, key, limit=8):
    counter[key] += 1
    if len(counter) > limit * 4:
        for old_key, _count in counter.most_common()[:-limit * 2]:
            del counter[old_key]


def analyze_logs(paths, geo_data, target_countries, subnet_prefixes):
    totals = {
        "files": len(paths),
        "lines": 0,
        "matched": 0,
        "unique_ips": set(),
    }
    ips = {}
    subnets = {}

    for path in paths:
        site_from_file = infer_site_from_path(path)
        with open_log(path) as handle:
            for line in handle:
                totals["lines"] += 1
                parsed = parse_log_line(line, site_from_file)
                if not parsed:
                    continue
                totals["matched"] += 1
                ip = parsed["ip"]
                totals["unique_ips"].add(ip)
                country = country_for_ip(geo_data, ip)
                is_target = country in target_countries

                if ip not in ips:
                    ips[ip] = {
                        "ip": ip,
                        "country": country,
                        "target_country": is_target,
                        "requests": 0,
                        "sites": collections.Counter(),
                        "urls": collections.Counter(),
                        "statuses": collections.Counter(),
                    }
                ips[ip]["requests"] += 1
                add_top(ips[ip]["sites"], parsed["site"])
                add_top(ips[ip]["urls"], parsed["url"])
                add_top(ips[ip]["statuses"], parsed["status"])

                for prefix in subnet_prefixes:
                    key = network_for_ip(ip, prefix)
                    if key not in subnets:
                        subnets[key] = {
                            "cidr": key,
                            "prefix": prefix,
                            "would_block_ips": blocked_size(prefix),
                            "requests": 0,
                            "unique_ips": set(),
                            "target_unique_ips": set(),
                            "non_target_unique_ips": set(),
                            "countries": collections.Counter(),
                            "sites": collections.Counter(),
                            "top_ips": collections.Counter(),
                        }
                    item = subnets[key]
                    item["requests"] += 1
                    item["unique_ips"].add(ip)
                    if is_target:
                        item["target_unique_ips"].add(ip)
                    else:
                        item["non_target_unique_ips"].add(ip)
                    add_top(item["countries"], country)
                    add_top(item["sites"], parsed["site"])
                    add_top(item["top_ips"], ip)

    return totals, ips, subnets


def counter_to_list(counter, limit=10):
    return [{"value": key, "count": count} for key, count in counter.most_common(limit)]


def serialize_ip(item):
    return {
        "ip": item["ip"],
        "country": item["country"],
        "target_country": item["target_country"],
        "requests": item["requests"],
        "sites": counter_to_list(item["sites"]),
        "urls": counter_to_list(item["urls"]),
        "statuses": counter_to_list(item["statuses"]),
    }


def classify_subnet(item, min_requests, min_unique_ips):
    non_target = len(item["non_target_unique_ips"])
    target = len(item["target_unique_ips"])
    if non_target:
        return "REVIEW_NON_TARGET_PRESENT"
    if target >= min_unique_ips and item["requests"] >= min_requests:
        return "CANDIDATE"
    if target:
        return "LOW_EVIDENCE"
    return "NO_TARGET_IPS"


def serialize_subnet(item, min_requests, min_unique_ips):
    unique_ips = len(item["unique_ips"])
    target_unique = len(item["target_unique_ips"])
    result = {
        "cidr": item["cidr"],
        "prefix": item["prefix"],
        "would_block_ips": item["would_block_ips"],
        "observed_unique_ips": unique_ips,
        "target_unique_ips": target_unique,
        "non_target_unique_ips": len(item["non_target_unique_ips"]),
        "requests": item["requests"],
        "decision": classify_subnet(item, min_requests, min_unique_ips),
        "countries": counter_to_list(item["countries"]),
        "sites": counter_to_list(item["sites"]),
        "top_ips": counter_to_list(item["top_ips"]),
    }
    return result


def build_report(totals, ips, subnets, target_countries, min_requests, min_unique_ips):
    ip_rows = sorted(
        [serialize_ip(item) for item in ips.values()],
        key=lambda row: (-row["requests"], row["ip"]),
    )
    subnet_rows = sorted(
        [serialize_subnet(item, min_requests, min_unique_ips) for item in subnets.values()],
        key=lambda row: (
            row["decision"] != "CANDIDATE",
            row["prefix"],
            -row["requests"],
            -row["observed_unique_ips"],
            row["cidr"],
        ),
    )
    return {
        "summary": {
            "files": totals["files"],
            "lines": totals["lines"],
            "matched": totals["matched"],
            "unique_ips": len(totals["unique_ips"]),
            "missing_geo_ips": len([row for row in ip_rows if row["country"] == "UNKNOWN"]),
            "target_country_codes": sorted(target_countries),
            "min_requests": min_requests,
            "min_unique_ips": min_unique_ips,
        },
        "top_ips": ip_rows,
        "subnets": subnet_rows,
    }


def write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def write_text_report(path, report, max_rows):
    with open(path, "w") as f:
        summary = report["summary"]
        f.write("Apache subnet analysis\n")
        f.write("======================\n\n")
        f.write("Files: %d\n" % summary["files"])
        f.write("Lines: %d\n" % summary["lines"])
        f.write("Matched lines: %d\n" % summary["matched"])
        f.write("Unique IPs: %d\n" % summary["unique_ips"])
        f.write("Target countries: %s\n\n" % ",".join(summary["target_country_codes"]))

        f.write("Subnet options\n")
        f.write("--------------\n")
        f.write("CIDR | decision | requests | observed IPs | target IPs | non-target IPs | would block | countries | sites\n")
        for row in report["subnets"][:max_rows]:
            countries = ",".join("%s:%s" % (c["value"], c["count"]) for c in row["countries"])
            sites = ",".join("%s:%s" % (s["value"], s["count"]) for s in row["sites"])
            f.write("%s | %s | %d | %d | %d | %d | %d | %s | %s\n" % (
                row["cidr"],
                row["decision"],
                row["requests"],
                row["observed_unique_ips"],
                row["target_unique_ips"],
                row["non_target_unique_ips"],
                row["would_block_ips"],
                countries,
                sites,
            ))

        f.write("\nTop IPs\n")
        f.write("-------\n")
        f.write("IP | country | target | requests | sites | urls\n")
        for row in report["top_ips"][:max_rows]:
            sites = ",".join("%s:%s" % (s["value"], s["count"]) for s in row["sites"])
            urls = ",".join("%s:%s" % (u["value"], u["count"]) for u in row["urls"])
            f.write("%s | %s | %s | %d | %s | %s\n" % (
                row["ip"],
                row["country"],
                "yes" if row["target_country"] else "no",
                row["requests"],
                sites,
                urls,
            ))


def write_candidates(path, report):
    with open(path, "w") as f:
        for row in report["subnets"]:
            if row["decision"] == "CANDIDATE":
                f.write("%s\n" % row["cidr"])


def write_ip_lists(ips_output, missing_geo_output, report):
    with open(ips_output, "w") as f:
        for row in sorted(report["top_ips"], key=lambda item: item["ip"]):
            f.write("%s\n" % row["ip"])
    with open(missing_geo_output, "w") as f:
        for row in sorted(report["top_ips"], key=lambda item: item["ip"]):
            if row["country"] == "UNKNOWN":
                f.write("%s\n" % row["ip"])


def build_parser():
    parser = argparse.ArgumentParser(
        description="Analyze Apache access logs across many niche sites and report IP/subnet blocking candidates."
    )
    parser.add_argument("--log-dir", default="/var/log/apache2")
    parser.add_argument("--geo-data", default="geo_data.json")
    parser.add_argument("--country-codes", default="CN,IN")
    parser.add_argument("--prefixes", default="32,24,16", help="Comma-separated IPv4 prefixes to report.")
    parser.add_argument("--min-requests", type=int, default=100)
    parser.add_argument("--min-unique-ips", type=int, default=3)
    parser.add_argument("--json-output", default="apache_subnet_report.json")
    parser.add_argument("--text-output", default="apache_subnet_report.txt")
    parser.add_argument("--candidates-output", default="apache_subnet_candidates.txt")
    parser.add_argument("--ips-output", default="apache_log_ips.txt")
    parser.add_argument("--missing-geo-output", default="apache_missing_geo_ips.txt")
    parser.add_argument("--max-report-rows", type=int, default=200)
    parser.add_argument("--no-gz", action="store_true", help="Skip .gz rotated logs.")
    return parser


def main():
    if _ip is None:
        print("ERROR: Missing ipaddress module. Install one of: pip install ipaddress or pip install ipaddr", file=sys.stderr)
        return 1

    args = build_parser().parse_args()
    if not os.path.isdir(args.log_dir):
        print("ERROR: log directory not found: %s" % args.log_dir, file=sys.stderr)
        return 1

    prefixes = [int(p.strip()) for p in args.prefixes.split(",") if p.strip()]
    for prefix in prefixes:
        if prefix < 1 or prefix > 32:
            print("ERROR: invalid prefix: %s" % prefix, file=sys.stderr)
            return 1

    paths = iter_log_paths(args.log_dir, include_gz=not args.no_gz)
    geo_data = load_geo_data(args.geo_data)
    target_countries = parse_country_codes(args.country_codes)
    totals, ips, subnets = analyze_logs(paths, geo_data, target_countries, prefixes)
    report = build_report(totals, ips, subnets, target_countries, args.min_requests, args.min_unique_ips)

    write_json(args.json_output, report)
    write_text_report(args.text_output, report, args.max_report_rows)
    write_candidates(args.candidates_output, report)
    write_ip_lists(args.ips_output, args.missing_geo_output, report)

    print("Files:", report["summary"]["files"])
    print("Matched lines:", report["summary"]["matched"])
    print("Unique IPs:", report["summary"]["unique_ips"])
    print("Missing geo IPs:", report["summary"]["missing_geo_ips"])
    print("Wrote:", args.json_output)
    print("Wrote:", args.text_output)
    print("Wrote:", args.candidates_output)
    print("Wrote:", args.ips_output)
    print("Wrote:", args.missing_geo_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
