#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import re
import subprocess
from typing import Iterable, List, Tuple


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
IPV6_RE = re.compile(r"\b[0-9a-fA-F:]{2,}(?:/\d{1,3})?\b")


def load_allowlist(path: str) -> List[ipaddress._BaseNetwork]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    cidrs = data.get("cidrs", [])
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    return nets


def run_ufw_status(sudo: bool) -> str:
    cmd = ["ufw", "status", "numbered"]
    if sudo:
        cmd = ["sudo"] + cmd
    proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return proc.stdout


def extract_ips(line: str) -> List[ipaddress._BaseNetwork]:
    found: List[ipaddress._BaseNetwork] = []
    for m in IPV4_RE.findall(line):
        try:
            if "/" in m:
                found.append(ipaddress.ip_network(m, strict=False))
            else:
                found.append(ipaddress.ip_network(m + "/32"))
        except ValueError:
            continue
    for m in IPV6_RE.findall(line):
        try:
            if "/" in m:
                found.append(ipaddress.ip_network(m, strict=False))
            else:
                found.append(ipaddress.ip_network(m + "/128"))
        except ValueError:
            continue
    return found


def is_blocking_allowed(candidate: ipaddress._BaseNetwork, allowlist: List[ipaddress._BaseNetwork]) -> bool:
    # Only flag rules that are entirely within an allowlist range.
    for allow in allowlist:
        if candidate.version != allow.version:
            continue
        try:
            if candidate.subnet_of(allow):
                return True
        except AttributeError:
            # Py<3.7 compatibility fallback (not expected here)
            if allow.supernet_of(candidate):
                return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allowlist", default=os.path.join("ip_cache", "allowlist_cidrs.json"))
    parser.add_argument("--output", default="bad_ufw_rules.json")
    parser.add_argument("--sudo", action="store_true", help="Use sudo for ufw status")
    args = parser.parse_args()

    allowlist = load_allowlist(args.allowlist)

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
        for c in candidates:
            if is_blocking_allowed(c, allowlist):
                bad.append(str(c))
        if bad:
            bad_rules.append({"num": num, "line": line, "cidrs": bad})

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"count": len(bad_rules), "rules": bad_rules}, f, indent=2)

    print(f"Found {len(bad_rules)} bad rule(s). Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
