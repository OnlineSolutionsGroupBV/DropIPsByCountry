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
import json
import os
import re
import subprocess


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


def is_blocking_allowed(candidate, allowlist):
    # Only flag rules that are entirely within an allowlist range.
    for allow in allowlist:
        if net_version(candidate) != net_version(allow):
            continue
        if net_is_subnet_of(candidate, allow):
            return True
    return False


def main():
    if _ip is None:
        print("ERROR: Missing ipaddress module. Install one of: pip install ipaddress (Py2 backport) or pip install ipaddr")
        return 1
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

    with open(args.output, "w") as f:
        json.dump({"count": len(bad_rules), "rules": bad_rules}, f, indent=2)

    print("Found %d bad rule(s). Wrote %s" % (len(bad_rules), args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
