#!/usr/bin/env python
from __future__ import print_function
import argparse
import json
import os
import re
import time
try:
    import ipaddress as _ip
    def ip_network(value, strict=False):
        return _ip.ip_network(value, strict=strict)
    def ip_address(value):
        return _ip.ip_address(value)
    def net_to_str(net):
        return str(net)
except ImportError:
    try:
        import ipaddr as _ip
    except ImportError:
        _ip = None
    def ip_network(value, strict=False):
        if _ip is None:
            raise ImportError("Missing ipaddress/ipaddr module")
        return _ip.IPNetwork(value)
    def ip_address(value):
        if _ip is None:
            raise ImportError("Missing ipaddress/ipaddr module")
        return _ip.IPAddress(value)
    def net_to_str(net):
        return str(net)

try:
    # Py3
    from urllib.request import Request, urlopen
except ImportError:
    # Py2
    from urllib2 import Request, urlopen


SOURCES = {
    "openai_gptbot": "https://openai.com/gptbot.json",
    "googlebot": "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
    "google_special": "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json",
    "google_user_triggered": "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json",
    "google_user_triggered_google": "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json",
}


CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b[0-9a-fA-F:]*:[0-9a-fA-F:]+(?:/\d{1,3})?\b")

try:
    text_type = unicode  # Py2
except NameError:
    text_type = str


def fetch_json(url):
    req = Request(url, headers={"User-Agent": "DropIPsByCountry/1.0"})
    resp = urlopen(req, timeout=30)
    try:
        data = resp.read()
    finally:
        try:
            resp.close()
        except Exception:
            pass
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return json.loads(data)


def _to_text(value):
    if isinstance(value, text_type):
        return value
    try:
        return value.decode("utf-8")
    except Exception:
        try:
            return value.decode("latin-1")
        except Exception:
            return text_type(value)


def extract_prefixes(obj):
    prefixes = set()

    def add_candidate(value):
        try:
            net = ip_network(value, strict=False)
        except ValueError:
            return
        prefixes.add(net_to_str(net))

    def walk(item):
        if isinstance(item, dict):
            for k, v in item.items():
                if k in ("ipv4Prefix", "ipv6Prefix", "ip_prefix", "ipPrefix", "prefix"):
                    if isinstance(v, (str, text_type)):
                        add_candidate(_to_text(v))
                else:
                    walk(v)
        elif isinstance(item, list):
            for v in item:
                walk(v)
        elif isinstance(item, (str, text_type)):
            text = _to_text(item)
            for m in CIDR_RE.findall(text):
                add_candidate(m)
            for m in IPV4_RE.findall(text):
                try:
                    ip_address(m)
                except ValueError:
                    continue
                prefixes.add(net_to_str(ip_network(m + "/32")))
            for m in IPV6_RE.findall(text):
                try:
                    if "/" in m:
                        ip_network(m, strict=False)
                    else:
                        ip_address(m)
                except ValueError:
                    continue
                if "/" in m:
                    prefixes.add(net_to_str(ip_network(m, strict=False)))
                else:
                    prefixes.add(net_to_str(ip_network(m + "/128")))

    walk(obj)

    return sorted(prefixes, key=lambda s: (":" in s, s))


def load_cached(path, max_age_days):
    if not os.path.exists(path):
        return None
    age = time.time() - os.path.getmtime(path)
    if age > max_age_days * 86400:
        return None
    try:
        f = open(path, "r")
    except TypeError:
        f = open(path, "r")
    with f:
        return json.load(f)


def main():
    if _ip is None:
        print("ERROR: Missing ipaddress module. Install one of: pip install ipaddress (Py2 backport) or pip install ipaddr")
        return 1
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-dir", default="ip_cache", help="Cache directory")
    parser.add_argument("--max-age-days", type=int, default=7, help="Max cache age in days")
    parser.add_argument("--force", action="store_true", help="Force refresh")
    args = parser.parse_args()

    try:
        os.makedirs(args.cache_dir)
    except OSError:
        pass

    combined = set()
    meta = {"updated_at": int(time.time()), "sources": {}}

    for name, url in SOURCES.items():
        cache_path = os.path.join(args.cache_dir, "%s.json" % name)
        data = None
        if not args.force:
            data = load_cached(cache_path, args.max_age_days)
        if data is None:
            data = fetch_json(url)
            with open(cache_path, "w") as f:
                json.dump(data, f, indent=2, sort_keys=True)
            meta["sources"][name] = {"url": url, "cached": False}
        else:
            meta["sources"][name] = {"url": url, "cached": True}

        prefixes = extract_prefixes(data)
        combined.update(prefixes)

    allowlist = sorted(combined, key=lambda s: (":" in s, s))
    allowlist_path = os.path.join(args.cache_dir, "allowlist_cidrs.json")
    with open(allowlist_path, "w") as f:
        json.dump({"updated_at": meta["updated_at"], "cidrs": allowlist}, f, indent=2)

    meta_path = os.path.join(args.cache_dir, "allowlist_meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    print("Cached %d CIDRs to %s" % (len(allowlist), allowlist_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
