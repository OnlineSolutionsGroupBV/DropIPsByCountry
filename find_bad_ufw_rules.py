#!/usr/bin/env python
from __future__ import print_function
import argparse
try:
    import ipaddress as _ip
    def ip_network(value, strict=False):
        return _ip.ip_network(value, strict=strict)
    def net_version(net):
        return net.version
    def net_is_subnet_of(a, b):
        return a.subnet_of(b)
    def net_first_int(net):
        return int(net.network_address)
    def net_last_int(net):
        return int(net.broadcast_address)
except ImportError:
    try:
        import ipaddr as _ip
    except ImportError:
        _ip = None
    def ip_network(value, strict=False):
        if _ip is None:
            raise ImportError("Missing ipaddress/ipaddr module")
        return _ip.IPNetwork(value)
    def net_version(net):
        return net.version
    def net_is_subnet_of(a, b):
        if _ip is None:
            raise ImportError("Missing ipaddress/ipaddr module")
        if a.version != b.version:
            return False
        return a.network >= b.network and a.broadcast <= b.broadcast
    def net_first_int(net):
        return int(net.network)
    def net_last_int(net):
        return int(net.broadcast)
import json
import os
import re
import subprocess

from country_policy import DEFAULT_COUNTRY_CODES, effective_country_codes


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
IPV6_RE = re.compile(r"\b[0-9a-fA-F:]{2,}(?:/\d{1,3})?\b")
def load_allowlist(path):
    with open(path, "r") as f:
        data = json.load(f)
    cidrs = data.get("cidrs", [])
    nets = []
    for c in cidrs:
        try:
            nets.append(ip_network(c, strict=False))
        except ValueError:
            continue
    return nets


def load_geo_data(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def parse_country_codes(value):
    return set(effective_country_codes([code.strip().upper() for code in value.split(",") if code.strip()]))


def run_ufw_status(sudo):
    cmd = ["ufw", "status", "numbered"]
    if sudo:
        cmd = ["sudo"] + cmd
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError("ufw status failed: %s" % (err.decode("utf-8") if isinstance(err, bytes) else err))
    if isinstance(out, bytes):
        out = out.decode("utf-8")
    return out


def extract_ips(line):
    found = []
    for m in IPV4_RE.findall(line):
        try:
            if "/" in m:
                found.append(ip_network(m, strict=False))
            else:
                found.append(ip_network(m + "/32"))
        except ValueError:
            continue
    for m in IPV6_RE.findall(line):
        try:
            if "/" in m:
                found.append(ip_network(m, strict=False))
            else:
                found.append(ip_network(m + "/128"))
        except ValueError:
            continue
    return found


def net_overlaps(a, b):
    if net_version(a) != net_version(b):
        return False
    return net_first_int(a) <= net_last_int(b) and net_first_int(b) <= net_last_int(a)


def is_blocking_allowed(candidate, allowlist):
    # Flag exact allowlist blocks and broad deny rules that cover part of an
    # allowlisted crawler range.
    for allow in allowlist:
        if net_overlaps(candidate, allow):
            return True
    return False


def find_non_target_sources(candidate, geo_data, country_codes, max_examples):
    found = []
    for ip, details in geo_data.items():
        country = details.get("country", "Unknown")
        if country:
            country = country.upper()
        if country in country_codes:
            continue
        try:
            ip_net = ip_network(ip + "/32", strict=False)
        except ValueError:
            continue
        if net_version(candidate) != net_version(ip_net):
            continue
        if net_is_subnet_of(ip_net, candidate):
            found.append("%s %s %s" % (ip, country, details.get("org", "Unknown")))
            if len(found) >= max_examples:
                break
    return found


def main():
    if _ip is None:
        print("ERROR: Missing ipaddress module. Install one of: pip install ipaddress (Py2 backport) or pip install ipaddr")
        return 1
    parser = argparse.ArgumentParser()
    parser.add_argument("--allowlist", default=os.path.join("ip_cache", "allowlist_cidrs.json"))
    parser.add_argument("--output", default="bad_ufw_rules.json")
    parser.add_argument("--sudo", action="store_true", help="Use sudo for ufw status")
    parser.add_argument("--geo-data", default="geo_data.json")
    parser.add_argument("--country-codes", default=",".join(DEFAULT_COUNTRY_CODES))
    parser.add_argument("--skip-country-check", action="store_true")
    parser.add_argument("--max-country-examples", type=int, default=10)
    args = parser.parse_args()

    allowlist = load_allowlist(args.allowlist)
    geo_data = load_geo_data(args.geo_data)
    country_codes = parse_country_codes(args.country_codes)

    status = run_ufw_status(args.sudo)
    bad_rules = []

    for line in status.splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        m = re.match(r"^\[\s*(\d+)\]\s+(.*)$", line)
        if not m:
            continue
        num = int(m.group(1))
        rest = m.group(2)
        candidates = extract_ips(rest)
        bad = []
        reasons = []
        for c in candidates:
            if is_blocking_allowed(c, allowlist):
                bad.append(str(c))
                reasons.append({
                    "type": "allowlist_overlap",
                    "cidr": str(c),
                })
            if not args.skip_country_check:
                non_target_sources = find_non_target_sources(
                    c,
                    geo_data,
                    country_codes,
                    args.max_country_examples,
                )
                if non_target_sources:
                    if str(c) not in bad:
                        bad.append(str(c))
                    reasons.append({
                        "type": "country_mismatch",
                        "cidr": str(c),
                        "examples": non_target_sources,
                    })
        if bad:
            bad_rules.append({"num": num, "line": line, "cidrs": bad, "reasons": reasons})

    with open(args.output, "w") as f:
        json.dump({"count": len(bad_rules), "rules": bad_rules}, f, indent=2)

    print("Found %d bad rule(s). Wrote %s" % (len(bad_rules), args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
