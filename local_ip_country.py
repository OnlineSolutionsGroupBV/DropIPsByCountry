#!/usr/bin/env python
from __future__ import print_function

import bisect
import json
import os
import socket
import struct
import time

try:
    text_type = unicode
except NameError:
    text_type = str

try:
    binary_type = bytes
except NameError:
    binary_type = str


def to_text(value):
    if isinstance(value, text_type):
        return value
    if isinstance(value, binary_type):
        return value.decode("utf-8", "replace")
    return text_type(value)


def ipv4_to_int(value):
    value = to_text(value).strip()
    return struct.unpack("!I", socket.inet_aton(value))[0]


def cidr_to_range(network):
    network = to_text(network).strip()
    if "/" in network:
        ip_text, prefix_text = network.split("/", 1)
        prefix = int(prefix_text)
    else:
        ip_text = network
        prefix = 32
    if prefix < 0 or prefix > 32:
        raise ValueError("invalid IPv4 prefix length: %s" % network)
    start = ipv4_to_int(ip_text)
    mask = (0xffffffff << (32 - prefix)) & 0xffffffff if prefix else 0
    start = start & mask
    end = start | (0xffffffff ^ mask)
    return start, end


def atomic_write_json(path, data):
    tmp_path = "%s.tmp-%s" % (path, os.getpid())
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.rename(tmp_path, path)


def range_row_to_tsv(row):
    values = [
        row["start_int"],
        row["end_int"],
        row.get("country", "Unknown"),
        row.get("asn", ""),
        row.get("as_name", ""),
        row.get("network", ""),
    ]
    return "\t".join(to_text(value).replace("\t", " ").replace("\n", " ") for value in values)


def parse_tsv_range_line(line):
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 6:
        raise ValueError("expected 6 tab-separated fields")
    return {
        "start_int": int(parts[0]),
        "end_int": int(parts[1]),
        "country": parts[2] or "Unknown",
        "asn": parts[3],
        "as_name": parts[4],
        "network": parts[5],
    }


def load_ranges(path):
    starts = []
    ranges = []
    with open(path, "rb") as f:
        for raw in f:
            line = to_text(raw).strip()
            if not line or line.startswith("#"):
                continue
            row = parse_tsv_range_line(line)
            starts.append(row["start_int"])
            ranges.append(row)
    return starts, ranges


def lookup_ip(ip, starts, ranges):
    ip_int = ipv4_to_int(ip)
    index = bisect.bisect_right(starts, ip_int) - 1
    if index < 0:
        return None
    row = ranges[index]
    if ip_int <= row["end_int"]:
        return row
    return None


def row_to_geo_details(row):
    org = "Unknown"
    asn = to_text(row.get("asn", "")).strip()
    as_name = to_text(row.get("as_name", "")).strip()
    if asn and as_name:
        org = "%s %s" % (asn, as_name)
    elif as_name:
        org = as_name
    elif asn:
        org = asn
    return {
        "country": to_text(row.get("country", "Unknown")).upper() or "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "org": org,
        "loc": "Unknown",
        "source": "local_range",
        "network": to_text(row.get("network", "")),
        "lookup_updated_at": int(time.time()),
    }
