#!/usr/bin/env python3
import argparse
import json
import os
import re
import time
import urllib.request
from typing import Iterable, List, Set
import ipaddress


SOURCES = {
    "openai_gptbot": "https://openai.com/gptbot.json",
    "googlebot": "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
    "google_special": "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json",
    "google_user_triggered": "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json",
    "google_user_triggered_google": "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json",
}


CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b[0-9a-fA-F:]{2,}(?:/\d{1,3})?\b")


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "DropIPsByCountry/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read().decode("utf-8")
    return json.loads(data)


def extract_prefixes(obj: object) -> List[str]:
    prefixes: Set[str] = set()

    def add_candidate(value: str) -> None:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return
        prefixes.add(str(net))

    def walk(item: object) -> None:
        if isinstance(item, dict):
            for k, v in item.items():
                if k in ("ipv4Prefix", "ipv6Prefix", "ip_prefix", "ipPrefix", "prefix"):
                    if isinstance(v, str):
                        add_candidate(v)
                else:
                    walk(v)
        elif isinstance(item, list):
            for v in item:
                walk(v)
        elif isinstance(item, str):
            for m in CIDR_RE.findall(item):
                add_candidate(m)

    walk(obj)

    # If a source publishes plain IPs (no CIDR), convert to /32 or /128
    for text in json.dumps(obj).split():
        for m in IPV4_RE.findall(text):
            try:
                ipaddress.ip_address(m)
            except ValueError:
                continue
            prefixes.add(str(ipaddress.ip_network(m + "/32")))
        for m in IPV6_RE.findall(text):
            try:
                if "/" in m:
                    ipaddress.ip_network(m, strict=False)
                else:
                    ipaddress.ip_address(m)
            except ValueError:
                continue
            if "/" in m:
                prefixes.add(str(ipaddress.ip_network(m, strict=False)))
            else:
                prefixes.add(str(ipaddress.ip_network(m + "/128")))

    return sorted(prefixes, key=lambda s: (":" in s, s))


def load_cached(path: str, max_age_days: int) -> dict | None:
    if not os.path.exists(path):
        return None
    age = time.time() - os.path.getmtime(path)
    if age > max_age_days * 86400:
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-dir", default="ip_cache", help="Cache directory")
    parser.add_argument("--max-age-days", type=int, default=7, help="Max cache age in days")
    parser.add_argument("--force", action="store_true", help="Force refresh")
    args = parser.parse_args()

    os.makedirs(args.cache_dir, exist_ok=True)

    combined: Set[str] = set()
    meta = {"updated_at": int(time.time()), "sources": {}}

    for name, url in SOURCES.items():
        cache_path = os.path.join(args.cache_dir, f"{name}.json")
        data = None
        if not args.force:
            data = load_cached(cache_path, args.max_age_days)
        if data is None:
            data = fetch_json(url)
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
            meta["sources"][name] = {"url": url, "cached": False}
        else:
            meta["sources"][name] = {"url": url, "cached": True}

        prefixes = extract_prefixes(data)
        combined.update(prefixes)

    allowlist = sorted(combined, key=lambda s: (":" in s, s))
    allowlist_path = os.path.join(args.cache_dir, "allowlist_cidrs.json")
    with open(allowlist_path, "w", encoding="utf-8") as f:
        json.dump({"updated_at": meta["updated_at"], "cidrs": allowlist}, f, indent=2)

    meta_path = os.path.join(args.cache_dir, "allowlist_meta.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"Cached {len(allowlist)} CIDRs to {allowlist_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
