#!/usr/bin/env python
from __future__ import print_function

import argparse
import json
import os
import re
import subprocess
import sys

try:
    import ipaddress as _ip

    def ip_network(value, strict=False):
        return _ip.ip_network(value, strict=strict)

    def network_version(net):
        return net.version

    def is_subnet_of(candidate, existing):
        return candidate.subnet_of(existing)

except ImportError:
    try:
        import ipaddr as _ip
    except ImportError:
        _ip = None

    def ip_network(value, strict=False):
        if _ip is None:
            raise ImportError("Missing ipaddress/ipaddr module")
        return _ip.IPNetwork(value)

    def network_version(net):
        return net.version

    def is_subnet_of(candidate, existing):
        if candidate.version != existing.version:
            return False
        return candidate.network >= existing.network and candidate.broadcast <= existing.broadcast


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
IPV6_RE = re.compile(r"\b[0-9a-fA-F:]*:[0-9a-fA-F:]+(?:/\d{1,3})?\b")


def read_text(path):
    with open(path, "rb") as f:
        data = f.read()
    if isinstance(data, bytes):
        return data.decode("utf-8")
    return data


def load_candidate_networks(path):
    if not os.path.exists(path):
        raise RuntimeError("Input file not found: %s" % path)

    with open(path, "r") as f:
        data = json.load(f)

    if isinstance(data, dict):
        raw_values = list(data.keys())
    elif isinstance(data, list):
        raw_values = data
    else:
        raise RuntimeError("Expected %s to contain a JSON list or object" % path)

    networks = []
    seen = set()
    for value in raw_values:
        try:
            net = ip_network(str(value).strip(), strict=False)
        except ValueError:
            print("Skipping invalid CIDR/IP in %s: %s" % (path, value), file=sys.stderr)
            continue
        key = str(net)
        if key not in seen:
            networks.append(net)
            seen.add(key)

    return networks


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


def networks_from_text(text):
    networks = []
    for value in IPV4_RE.findall(text):
        try:
            if "/" in value:
                networks.append(ip_network(value, strict=False))
            else:
                networks.append(ip_network(value + "/32", strict=False))
        except ValueError:
            continue
    for value in IPV6_RE.findall(text):
        try:
            if "/" in value:
                networks.append(ip_network(value, strict=False))
            else:
                networks.append(ip_network(value + "/128", strict=False))
        except ValueError:
            continue
    return networks


def parse_ufw_denies(status_text):
    denied = []
    for line in status_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("["):
            continue
        if "DENY IN" not in stripped:
            continue
        for net in networks_from_text(stripped):
            denied.append(net)
    return denied


def is_covered_by_existing_rule(candidate, existing_rules):
    for existing in existing_rules:
        if network_version(candidate) != network_version(existing):
            continue
        if existing.prefixlen > candidate.prefixlen:
            continue
        if is_subnet_of(candidate, existing):
            return True
    return False


def plan_new_rules(candidates, existing_rules):
    exact_existing = set(str(net) for net in existing_rules)
    existing_by_version_prefix = {}
    for net in existing_rules:
        existing_by_version_prefix.setdefault(network_version(net), {}).setdefault(net.prefixlen, []).append(net)

    planned = []
    for candidate in candidates:
        if str(candidate) in exact_existing:
            continue
        version_rules = existing_by_version_prefix.get(network_version(candidate), {})
        possible_covers = []
        for prefix in range(0, candidate.prefixlen + 1):
            possible_covers.extend(version_rules.get(prefix, []))
        if not is_covered_by_existing_rule(candidate, possible_covers):
            planned.append(candidate)
    return planned


def run_bad_rule_check(args):
    cmd = [
        sys.executable or "python",
        "find_bad_ufw_rules.py",
        "--allowlist",
        args.allowlist,
        "--output",
        args.bad_rules_output,
    ]
    if args.sudo:
        cmd.append("--sudo")

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if isinstance(out, bytes):
        out = out.decode("utf-8")
    if isinstance(err, bytes):
        err = err.decode("utf-8")

    if proc.returncode != 0:
        raise RuntimeError("find_bad_ufw_rules.py failed: %s" % (err or out))

    with open(args.bad_rules_output, "r") as f:
        data = json.load(f)
    count = int(data.get("count", 0))
    if count:
        raise RuntimeError(
            "Found %d bad UFW rule(s) in %s. Run clean_bad_ufw_rules.py before adding new blocks."
            % (count, args.bad_rules_output)
        )
    print(out.strip())


def apply_ufw_rule(network, sudo):
    cmd = ["ufw", "insert", "1", "deny", "from", str(network)]
    if sudo:
        cmd = ["sudo"] + cmd
    proc = subprocess.Popen(cmd)
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError("ufw insert failed for %s" % network)


def append_tracking_file(path, networks):
    existing = set()
    if os.path.exists(path):
        with open(path, "r") as f:
            existing = set(line.strip() for line in f if line.strip())

    with open(path, "a") as f:
        for net in networks:
            value = str(net)
            if value not in existing:
                f.write(value + "\n")
                existing.add(value)


def reload_ufw(sudo):
    cmd = ["ufw", "reload"]
    if sudo:
        cmd = ["sudo"] + cmd
    proc = subprocess.Popen(cmd)
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError("ufw reload failed")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Block generic aggregated subnets with UFW, skipping rules already present in live UFW."
    )
    parser.add_argument("--input", default="aggregated_generiek_subnets.json")
    parser.add_argument("--blocked-file", default="blocked_generiek_ips.txt")
    parser.add_argument("--sudo", action="store_true", help="Use sudo for ufw commands")
    parser.add_argument("--dry-run", action="store_true", help="Print changes without modifying UFW or tracking file")
    parser.add_argument("--show-all", action="store_true", help="Print every planned addition")
    parser.add_argument("--max-preview", type=int, default=50, help="Number of planned additions to preview")
    parser.add_argument("--no-reload", action="store_true", help="Do not run ufw reload after adding rules")
    parser.add_argument("--ufw-status-file", help="Read UFW status from a file instead of running ufw")
    parser.add_argument("--check-bad-rules", action="store_true", help="Run find_bad_ufw_rules.py before adding rules")
    parser.add_argument("--allowlist", default=os.path.join("ip_cache", "allowlist_cidrs.json"))
    parser.add_argument("--bad-rules-output", default="bad_ufw_rules.json")
    return parser


def main():
    if _ip is None:
        print("ERROR: Missing ipaddress module. Install one of: pip install ipaddress or pip install ipaddr")
        return 1

    args = build_parser().parse_args()

    try:
        candidates = load_candidate_networks(args.input)
        if args.check_bad_rules:
            run_bad_rule_check(args)

        if args.ufw_status_file:
            status_text = read_text(args.ufw_status_file)
        else:
            status_text = run_ufw_status(args.sudo)

        existing_rules = parse_ufw_denies(status_text)
        to_add = plan_new_rules(candidates, existing_rules)

        print("Candidate subnets: %d" % len(candidates))
        print("Existing UFW deny rules parsed: %d" % len(existing_rules))
        print("New UFW rules to add: %d" % len(to_add))

        if to_add:
            print("Planned additions:")
            preview = to_add if args.show_all else to_add[:args.max_preview]
            for net in preview:
                print("  ufw insert 1 deny from %s" % net)
            remaining = len(to_add) - len(preview)
            if remaining > 0:
                print("  ... %d more. Use --show-all to print every planned rule." % remaining)

        if args.dry_run:
            print("Dry-run only. No UFW rules changed.")
            return 0

        added = []
        for net in to_add:
            apply_ufw_rule(net, args.sudo)
            print("Blocked subnet: %s" % net)
            added.append(net)

        append_tracking_file(args.blocked_file, added)

        if added and not args.no_reload:
            reload_ufw(args.sudo)

        print("Done. Added %d new UFW rule(s)." % len(added))
        return 0
    except (IOError, ValueError, RuntimeError, ImportError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
