#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse
import datetime as dt
import io
import json
import os
import re
import sys

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<dt>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+[^"]+"\s+\d{3}\s+\S+\s+"[^"]*"\s+"[^"]*"'
)


def load_db(path):
    if not os.path.exists(path):
        return {"dates": {}, "updated_at": None}
    if os.path.getsize(path) == 0:
        return {"dates": {}, "updated_at": None}
    with io.open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except ValueError:
            return {"dates": {}, "updated_at": None}


def save_db(path, data):
    data["updated_at"] = dt.datetime.utcnow().isoformat() + "Z"
    # In Python 2 json.dump writes byte str, so use binary mode.
    with open(path, "wb") as f:
        json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=True)


def parse_date(date_str):
    # Example: "01/Feb/2026:06:25:43 +0100"
    parts = date_str.split()
    main = parts[0]
    parsed = dt.datetime.strptime(main, "%d/%b/%Y:%H:%M:%S")
    return parsed.date().isoformat()


def normalize_url(url):
    # Strip query string and fragment for generic stats.
    return url.split("?", 1)[0].split("#", 1)[0]


def ensure_date_bucket(db, date_key):
    dates = db["dates"]
    if date_key not in dates:
        dates[date_key] = {
            "total_requests": 0,
            "urls": {},
            "ips": {},
            "ip_urls": {},
        }
    return dates[date_key]


def add_count(counter, key, amount=1):
    counter[key] = counter.get(key, 0) + amount


def add_ip_url(bucket, ip, url):
    if "ip_urls" not in bucket:
        bucket["ip_urls"] = {}
    ip_urls = bucket["ip_urls"]
    if ip not in ip_urls:
        ip_urls[ip] = {}
    add_count(ip_urls[ip], url)


def parse_logs(log_paths, db, show_errors=False):
    parsed_lines = 0
    matched_lines = 0
    for log_path in log_paths:
        with io.open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parsed_lines += 1
                match = LOG_PATTERN.match(line)
                if not match:
                    if show_errors:
                        sys.stderr.write("No match: {}\n".format(line.rstrip("\n")))
                    continue
                matched_lines += 1
                date_key = parse_date(match.group("dt"))
                url = normalize_url(match.group("url"))
                ip = match.group("ip")

                bucket = ensure_date_bucket(db, date_key)
                bucket["total_requests"] += 1
                add_count(bucket["urls"], url)
                add_count(bucket["ips"], ip)
                add_ip_url(bucket, ip, url)
    return parsed_lines, matched_lines


def is_static_url(url):
    static_prefixes = ("/static/", "/media/", "/assets/")
    static_exts = (
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
        ".mp4", ".mp3", ".webm", ".ogg", ".pdf",
    )
    if url == "/favicon.ico":
        return True
    if url.startswith(static_prefixes):
        return True
    lower_url = url.lower()
    return lower_url.endswith(static_exts)


def report(db, date_key=None, top_urls=20, top_ips=20, include_static=False, per_ip_urls=5):
    dates = db.get("dates", {})
    if not dates:
        print("No data in database.")
        return 0

    if date_key is None:
        print("Available dates:")
        for key in sorted(dates.keys()):
            print("  {}: {} requests".format(key, dates[key].get("total_requests", 0)))
        print("Use --date YYYY-MM-DD to show details.")
        return 0

    if date_key not in dates:
        print("Date not found: {}".format(date_key))
        print("Available dates: {}".format(", ".join(sorted(dates.keys()))))
        return 1

    bucket = dates[date_key]
    print("Date: {}".format(date_key))
    print("Total requests: {}".format(bucket.get("total_requests", 0)))

    urls = bucket.get("urls", {})
    ips = bucket.get("ips", {})
    ip_urls = bucket.get("ip_urls", {})

    print("\nTop URLs:")
    shown = 0
    for url, count in sorted(urls.items(), key=lambda x: x[1], reverse=True):
        if not include_static and is_static_url(url):
            continue
        print("  {}  {}".format(count, url))
        shown += 1
        if shown >= top_urls:
            break
    if shown == 0:
        print("  (no non-static URLs found)")

    print("\nTop IPs:")
    shown_ips = 0
    for ip, count in sorted(ips.items(), key=lambda x: x[1], reverse=True):
        print("  {}  {}".format(count, ip))
        if per_ip_urls > 0:
            urls_for_ip = ip_urls.get(ip, {})
            shown_urls = 0
            for url, ucount in sorted(urls_for_ip.items(), key=lambda x: x[1], reverse=True):
                if not include_static and is_static_url(url):
                    continue
                print("      {}  {}".format(ucount, url))
                shown_urls += 1
                if shown_urls >= per_ip_urls:
                    break
            if shown_urls == 0:
                print("      (no non-static URLs found)")
        shown_ips += 1
        if shown_ips >= top_ips:
            break

    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description="Parse custom access logs and store per-date stats in a JSON database."
    )
    subparsers = parser.add_subparsers(dest="command")

    parse_cmd = subparsers.add_parser("parse", help="Parse logs and update JSON database.")
    parse_cmd.add_argument("--log", action="append", required=True, help="Log file path (repeatable).")
    parse_cmd.add_argument("--db", default="log_stats.json", help="Path to JSON database.")
    parse_cmd.add_argument("--show-errors", action="store_true", help="Print lines that do not match.")

    report_cmd = subparsers.add_parser("report", help="Show statistics from the JSON database.")
    report_cmd.add_argument("--db", default="log_stats.json", help="Path to JSON database.")
    report_cmd.add_argument("--date", help="Date to report (YYYY-MM-DD).")
    report_cmd.add_argument("--top-urls", type=int, default=20, help="Number of URLs to show.")
    report_cmd.add_argument("--top-ips", type=int, default=20, help="Number of IPs to show.")
    report_cmd.add_argument("--include-static", action="store_true", help="Include static assets in URL report.")
    report_cmd.add_argument("--per-ip-urls", type=int, default=5, help="Number of URLs to show under each IP.")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not getattr(args, "command", None):
        parser.print_help()
        return 2

    if args.command == "parse":
        db = load_db(args.db)
        parsed, matched = parse_logs(args.log, db, show_errors=args.show_errors)
        save_db(args.db, db)
        print("Parsed {} lines, matched {} lines.".format(parsed, matched))
        print("Database saved to {}".format(args.db))
        return 0

    if args.command == "report":
        db = load_db(args.db)
        return report(
            db,
            date_key=args.date,
            top_urls=args.top_urls,
            top_ips=args.top_ips,
            include_static=args.include_static,
            per_ip_urls=args.per_ip_urls,
        )

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
