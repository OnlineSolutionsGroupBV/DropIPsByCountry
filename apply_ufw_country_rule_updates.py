#!/usr/bin/env python
from __future__ import print_function

import argparse
import json
import subprocess
import sys


def load_plan(path):
    with open(path, "r") as f:
        return json.load(f)


def run_command(cmd):
    proc = subprocess.Popen(cmd)
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError("command failed: %s" % " ".join(cmd))


def build_delete_command(rule, sudo):
    cmd = ["ufw", "--force", "delete", str(rule["num"])]
    if sudo:
        cmd = ["sudo"] + cmd
    return cmd


def build_add_command(rule, sudo):
    cmd = ["ufw", "insert", "1", "deny", "from", rule["cidr"]]
    if sudo:
        cmd = ["sudo"] + cmd
    return cmd


def build_reload_command(sudo):
    cmd = ["ufw", "reload"]
    if sudo:
        cmd = ["sudo"] + cmd
    return cmd


def command_text(cmd):
    return " ".join(cmd)


def apply_plan(plan, sudo, apply, no_reload):
    delete_rules = sorted(plan.get("delete_rules", []), key=lambda row: int(row["num"]), reverse=True)
    add_rules = plan.get("add_rules", [])

    print("Rules to delete:", len(delete_rules))
    print("Rules to add:", len(add_rules))

    for rule in delete_rules:
        cmd = build_delete_command(rule, sudo)
        print(command_text(cmd))
        if apply:
            run_command(cmd)

    for rule in add_rules:
        cmd = build_add_command(rule, sudo)
        print(command_text(cmd))
        if apply:
            run_command(cmd)

    if add_rules and not no_reload:
        cmd = build_reload_command(sudo)
        print(command_text(cmd))
        if apply:
            run_command(cmd)

    if not apply:
        print("Dry-run only. No UFW rules changed. Use --apply to execute this plan.")
    else:
        print("Done. Applied UFW country rule update plan.")


def build_parser():
    parser = argparse.ArgumentParser(description="Apply a reviewed UFW country rule update plan.")
    parser.add_argument("--plan", default="ufw_country_update_plan.json")
    parser.add_argument("--sudo", action="store_true", help="Use sudo for ufw commands")
    parser.add_argument("--apply", action="store_true", help="Actually modify UFW. Default is dry-run.")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without modifying UFW")
    parser.add_argument("--no-reload", action="store_true", help="Do not run ufw reload after changes")
    return parser


def main():
    args = build_parser().parse_args()
    try:
        if args.apply and args.dry_run:
            raise RuntimeError("use either --apply or --dry-run, not both")
        plan = load_plan(args.plan)
        apply_plan(plan, args.sudo, args.apply, args.no_reload)
        return 0
    except (IOError, KeyError, RuntimeError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
