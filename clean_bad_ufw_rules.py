#!/usr/bin/env python3
import argparse
import json
import subprocess
from typing import List


def run_ufw_delete(num: int, sudo: bool) -> None:
    cmd = ["ufw", "--force", "delete", str(num)]
    if sudo:
        cmd = ["sudo"] + cmd
    subprocess.run(cmd, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="bad_ufw_rules.json")
    parser.add_argument("--sudo", action="store_true", help="Use sudo for ufw delete")
    parser.add_argument("--dry-run", action="store_true", help="Only print planned deletions")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    nums: List[int] = sorted({int(r["num"]) for r in data.get("rules", [])}, reverse=True)
    if not nums:
        print("No rules to delete.")
        return 0

    if args.dry_run:
        print("Would delete rules:", ", ".join(str(n) for n in nums))
        return 0

    for n in nums:
        print(f"Deleting rule {n}")
        run_ufw_delete(n, args.sudo)

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
