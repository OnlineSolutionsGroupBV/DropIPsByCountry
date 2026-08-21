#!/usr/bin/env python
from __future__ import print_function

import argparse
import csv
import os
import time

from local_ip_country import atomic_write_json, cidr_to_range, range_row_to_tsv, to_text
from local_ip_country import ipv4_to_int


def clean(value):
    if value is None:
        return ""
    return to_text(value).strip()


def build_ranges(input_path, output_path, meta_path=None, limit=0):
    rows = []
    loaded = 0
    skipped_ipv6 = 0
    skipped_invalid = 0

    with open(input_path, "r") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            loaded += 1
            network = clean(row.get("network"))
            start_ip = clean(row.get("start_ip"))
            end_ip = clean(row.get("end_ip"))
            if not network and not (start_ip and end_ip):
                skipped_invalid += 1
                continue
            if (network and ":" in network) or (start_ip and ":" in start_ip) or (end_ip and ":" in end_ip):
                skipped_ipv6 += 1
                continue
            try:
                if network:
                    start_int, end_int = cidr_to_range(network)
                    output_network = network
                else:
                    start_int = ipv4_to_int(start_ip)
                    end_int = ipv4_to_int(end_ip)
                    if end_int < start_int:
                        raise ValueError("end before start")
                    output_network = "%s-%s" % (start_ip, end_ip)
            except Exception:
                skipped_invalid += 1
                continue
            rows.append({
                "start_int": start_int,
                "end_int": end_int,
                "country": clean(row.get("country_code")).upper()[:2] or clean(row.get("country")).upper()[:2] or "Unknown",
                "asn": clean(row.get("asn"))[:40],
                "as_name": clean(row.get("as_name"))[:255],
                "network": output_network,
            })
            if limit and len(rows) >= limit:
                break

    rows.sort(key=lambda item: (item["start_int"], item["end_int"]))
    overlap_count = 0
    previous_end = -1
    for row in rows:
        if row["start_int"] <= previous_end:
            overlap_count += 1
        if row["end_int"] > previous_end:
            previous_end = row["end_int"]

    if not rows:
        raise RuntimeError("no IPv4 ranges built from %s" % input_path)

    tmp_path = "%s.tmp-%s" % (output_path, os.getpid())
    with open(tmp_path, "w") as out:
        out.write("# start_int\tend_int\tcountry\tasn\tas_name\tnetwork\n")
        for row in rows:
            out.write(range_row_to_tsv(row) + "\n")
    os.rename(tmp_path, output_path)

    meta = {
        "version": 1,
        "source": os.path.basename(input_path),
        "created_at": int(time.time()),
        "loaded_rows": loaded,
        "ipv4_ranges": len(rows),
        "skipped_ipv6": skipped_ipv6,
        "skipped_invalid": skipped_invalid,
        "overlap_count": overlap_count,
        "output": output_path,
    }
    if meta_path:
        atomic_write_json(meta_path, meta)
    return meta


def main():
    parser = argparse.ArgumentParser(description="Build compact local IPv4 country ranges from an IPinfo Lite style CSV.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default=os.path.join("data", "fast_geo_ranges.tsv"))
    parser.add_argument("--meta-output", default="")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    meta_output = args.meta_output or args.output + ".meta.json"
    meta = build_ranges(args.input, args.output, meta_output, args.limit)
    print("Built fast geo ranges:", args.output)
    print("IPv4 ranges:", meta["ipv4_ranges"])
    print("Skipped IPv6:", meta["skipped_ipv6"])
    print("Skipped invalid:", meta["skipped_invalid"])
    print("Overlaps:", meta["overlap_count"])
    print("Metadata:", meta_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
