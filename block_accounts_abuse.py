#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse
import json
import os
import subprocess


def load_db(path):
    if not os.path.exists(path):
        return {"dates": {}}
    with open(path, "rb") as f:
        try:
            return json.load(f)
        except ValueError:
            return {"dates": {}}


def load_blocked(path):
    if not os.path.exists(path):
        return set()
    with open(path, "r") as f:
        return set(line.strip() for line in f if line.strip())


def save_blocked(path, ips):
    with open(path, "a") as f:
        for ip in ips:
            f.write(ip + "\n")


def collect_accounts_hits(db, date_filter=None, prefix="/accounts/"):
    totals = {}
    dates = db.get("dates", {})
    for date_key, bucket in dates.items():
        if date_filter and date_key != date_filter:
            continue
        ip_urls = bucket.get("ip_urls", {})
        for ip, urls in ip_urls.items():
            for url, count in urls.items():
                if url.startswith(prefix):
                    totals[ip] = totals.get(ip, 0) + count
    return totals


def main():
    parser = argparse.ArgumentParser(
        description="Block IPs with many /accounts/ requests using UFW."
    )
    parser.add_argument("--db", default="log_stats.json", help="Path to JSON stats database.")
    parser.add_argument("--date", help="Date to analyze (YYYY-MM-DD). If omitted, all dates are used.")
    parser.add_argument("--min-requests", type=int, default=200, help="Minimum /accounts/ hits to block.")
    parser.add_argument("--blocked-file", default="blocked_accounts_ips.txt", help="File to store blocked IPs.")
    parser.add_argument("--dry-run", action="store_true", help="Only print IPs, do not block.")
    args = parser.parse_args()

    db = load_db(args.db)
    totals = collect_accounts_hits(db, date_filter=args.date)
    candidates = set(ip for ip, count in totals.items() if count >= args.min_requests)

    if not candidates:
        print("No IPs found with >= {} /accounts/ requests.".format(args.min_requests))
        return 0

    blocked = load_blocked(args.blocked_file)
    new_ips = sorted(candidates - blocked)

    print("Found {} IPs with >= {} /accounts/ requests.".format(len(candidates), args.min_requests))
    print("New IPs to block: {}".format(len(new_ips)))

    if args.dry_run:
        for ip in new_ips:
            print("Would block: {} ({} hits)".format(ip, totals.get(ip, 0)))
        return 0

    for ip in new_ips:
        try:
            command = "ufw insert 1 deny from {}".format(ip)
            subprocess.call(command, shell=True)
            print("Blocked IP: {} ({} hits)".format(ip, totals.get(ip, 0)))
        except Exception as e:
            print("Failed to block {}: {}".format(ip, e))

    save_blocked(args.blocked_file, new_ips)
    subprocess.call("ufw reload", shell=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
