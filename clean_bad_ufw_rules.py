#!/usr/bin/env python
from __future__ import print_function
import argparse
import json
import subprocess


def run_ufw_delete(num, sudo):
    cmd = ["ufw", "--force", "delete", str(num)]
    if sudo:
        cmd = ["sudo"] + cmd
    proc = subprocess.Popen(cmd)
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError("ufw delete failed for rule %s" % num)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="bad_ufw_rules.json")
    parser.add_argument("--sudo", action="store_true", help="Use sudo for ufw delete")
    parser.add_argument("--dry-run", action="store_true", help="Only print planned deletions")
    args = parser.parse_args()

    with open(args.input, "r") as f:
        data = json.load(f)

    nums = sorted(set(int(r["num"]) for r in data.get("rules", [])), reverse=True)
    if not nums:
        print("No rules to delete.")
        return 0

    if args.dry_run:
        print("Would delete rules: %s" % ", ".join(str(n) for n in nums))
        return 0

    for n in nums:
        print("Deleting rule %s" % n)
        run_ufw_delete(n, args.sudo)

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
