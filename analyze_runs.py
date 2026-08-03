#!/usr/bin/env python
from __future__ import print_function

import argparse
import collections
import json
import os
import re
import sys


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r") as f:
        return json.load(f)


def load_summary(path):
    data = {}
    for line in read_lines(path):
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def parse_country_rows(report):
    countries = {}
    for country, counts in report.get("countries", {}).items():
        countries[country] = {
            "total": int(counts.get("total", 0)),
            "blocked": int(counts.get("blocked", 0)),
            "allowed": int(counts.get("allowed", 0)),
        }
    return countries


def extract_ips_from_file(path):
    if not os.path.exists(path):
        return set()
    with open(path, "r") as f:
        return set(IP_RE.findall(f.read()))


def analyze_run(path):
    summary = load_summary(os.path.join(path, "summary.txt"))
    country_report = load_json(os.path.join(path, "generiek_country_report.json"), {})
    output_ips = set(read_lines(os.path.join(path, "output_ips.txt")))
    blocked_candidate_ips = extract_ips_from_file(os.path.join(path, "generiek_blocked_candidate_ips.txt"))
    allowed_ips = extract_ips_from_file(os.path.join(path, "generiek_allowed_non_target_ips.txt"))
    candidates = load_json(os.path.join(path, "aggregated_generiek_subnets.json"), [])
    bad_rules = load_json(os.path.join(path, "bad_ufw_rules.json"), {"count": 0, "rules": []})

    return {
        "run": os.path.basename(path.rstrip(os.sep)),
        "path": path,
        "date": summary.get("date", ""),
        "apply": summary.get("apply", ""),
        "check_existing": summary.get("check_existing", ""),
        "target_prefix": summary.get("target_prefix", ""),
        "min_hits": summary.get("min_hits", ""),
        "input_ips": len(output_ips),
        "blocked_candidate_ips": len(blocked_candidate_ips),
        "allowed_ips": len(allowed_ips),
        "candidate_subnets": len(candidates) if isinstance(candidates, list) else len(candidates.keys()),
        "bad_ufw_rules": int(bad_rules.get("count", 0)),
        "countries": parse_country_rows(country_report),
        "ip_set": output_ips,
        "blocked_ip_set": blocked_candidate_ips,
        "allowed_ip_set": allowed_ips,
    }


def iter_runs(runs_dir):
    if not os.path.isdir(runs_dir):
        return []
    paths = []
    for name in os.listdir(runs_dir):
        path = os.path.join(runs_dir, name)
        if os.path.isdir(path):
            paths.append(path)
    return sorted(paths)


def country_counter(runs, field):
    counts = collections.Counter()
    for run in runs:
        for country, row in run["countries"].items():
            counts[country] += row.get(field, 0)
    return counts


def write_text(path, runs, max_countries):
    with open(path, "w") as f:
        f.write("Run analysis\n")
        f.write("============\n\n")
        f.write("Run | date | apply | check_existing | input IPs | blocked candidate IPs | allowed IPs | candidate subnets | bad UFW rules\n")
        previous = None
        for run in runs:
            new_ips = len(run["ip_set"] - previous["ip_set"]) if previous else 0
            repeated_ips = len(run["ip_set"] & previous["ip_set"]) if previous else 0
            f.write("%s | %s | %s | %s | %d | %d | %d | %d | %d\n" % (
                run["run"],
                run["date"],
                run["apply"],
                run["check_existing"],
                run["input_ips"],
                run["blocked_candidate_ips"],
                run["allowed_ips"],
                run["candidate_subnets"],
                run["bad_ufw_rules"],
            ))
            if previous:
                f.write("  delta vs previous: new_ips=%d repeated_ips=%d\n" % (new_ips, repeated_ips))
            previous = run

        f.write("\nTop countries by blocked candidate IPs\n")
        f.write("--------------------------------------\n")
        for country, count in country_counter(runs, "blocked").most_common(max_countries):
            f.write("%s %d\n" % (country, count))

        f.write("\nTop countries by allowed/non-target IPs\n")
        f.write("---------------------------------------\n")
        for country, count in country_counter(runs, "allowed").most_common(max_countries):
            f.write("%s %d\n" % (country, count))

        if len(runs) >= 2:
            first = runs[0]
            last = runs[-1]
            f.write("\nFirst vs last\n")
            f.write("-------------\n")
            f.write("first=%s last=%s\n" % (first["run"], last["run"]))
            f.write("last_new_vs_first=%d\n" % len(last["ip_set"] - first["ip_set"]))
            f.write("last_repeated_vs_first=%d\n" % len(last["ip_set"] & first["ip_set"]))
            f.write("last_still_allowed_vs_first=%d\n" % len(last["allowed_ip_set"] & first["allowed_ip_set"]))
            f.write("last_still_block_candidate_vs_first=%d\n" % len(last["blocked_ip_set"] & first["blocked_ip_set"]))


def json_safe_run(run):
    data = dict(run)
    data.pop("ip_set", None)
    data.pop("blocked_ip_set", None)
    data.pop("allowed_ip_set", None)
    return data


def write_json(path, runs):
    payload = {
        "runs": [json_safe_run(run) for run in runs],
        "totals": {
            "runs": len(runs),
            "unique_ips_seen": len(set().union(*[run["ip_set"] for run in runs])) if runs else 0,
            "blocked_candidate_ip_observations": sum(run["blocked_candidate_ips"] for run in runs),
            "allowed_ip_observations": sum(run["allowed_ips"] for run in runs),
        },
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2, sort_keys=True)


def build_parser():
    parser = argparse.ArgumentParser(description="Analyze run_prepare_generiek_blocks.sh snapshots.")
    parser.add_argument("--runs-dir", default="runs")
    parser.add_argument("--text-output", default="runs_analysis.txt")
    parser.add_argument("--json-output", default="runs_analysis.json")
    parser.add_argument("--max-countries", type=int, default=40)
    return parser


def main():
    args = build_parser().parse_args()
    paths = iter_runs(args.runs_dir)
    if not paths:
        print("ERROR: no run directories found in %s" % args.runs_dir, file=sys.stderr)
        return 1

    runs = [analyze_run(path) for path in paths]
    write_text(args.text_output, runs, args.max_countries)
    write_json(args.json_output, runs)

    print("Runs:", len(runs))
    print("Unique IPs seen:", len(set().union(*[run["ip_set"] for run in runs])) if runs else 0)
    print("Wrote:", args.text_output)
    print("Wrote:", args.json_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
