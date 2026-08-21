#!/usr/bin/env python
from __future__ import print_function

import argparse
import os
import shutil
import subprocess
import sys
import time

import block_generiek_subnet as blocker
from local_ip_country import to_text


def is_source_drop_line(line):
    return line.startswith("-A ufw-user-input ") and " -s " in line and line.rstrip().endswith(" -j DROP")


def generate_ufw_deny_block(cidr):
    cidr = to_text(cidr)
    return [
        "### tuple ### deny any any 0.0.0.0/0 any %s in" % cidr,
        "-A ufw-user-input -s %s -j DROP" % cidr,
        "",
    ]


def parse_user_rules_denies(text):
    denied = []
    for line in text.splitlines():
        if not is_source_drop_line(line.strip()):
            continue
        for net in blocker.networks_from_text(line):
            denied.append(net)
    return denied


def find_insert_anchor(lines):
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("-A ufw-user-input "):
            continue
        if is_source_drop_line(stripped):
            continue
        if index > 0 and lines[index - 1].strip().startswith("### tuple ###"):
            return index - 1
        return index
    return None


def validate_user_rules_text(text):
    required = ["*filter", ":ufw-user-input", "COMMIT"]
    for item in required:
        if item not in text:
            raise RuntimeError("user.rules missing required marker: %s" % item)


def build_new_user_rules_text(original_text, cidrs_to_add):
    validate_user_rules_text(original_text)
    lines = original_text.splitlines()
    anchor = find_insert_anchor(lines)
    if anchor is None:
        raise RuntimeError("could not find safe ufw-user-input insertion anchor")

    generated = []
    for cidr in cidrs_to_add:
        generated.extend(generate_ufw_deny_block(cidr))

    new_lines = lines[:anchor] + generated + lines[anchor:]
    new_text = "\n".join(new_lines) + "\n"
    validate_user_rules_text(new_text)
    return new_text, anchor


def write_preview(path, content):
    with open(path, "w") as f:
        f.write(content)


def atomic_replace_with_backup(path, content, make_backup=True):
    directory = os.path.dirname(os.path.abspath(path))
    basename = os.path.basename(path)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    backup_path = None
    if make_backup:
        backup_path = os.path.join(directory, "%s.backup-%s" % (basename, timestamp))
    tmp_path = os.path.join(directory, "%s.tmp-%s" % (basename, os.getpid()))

    with open(tmp_path, "w") as f:
        f.write(content)
    with open(tmp_path, "r") as f:
        validate_user_rules_text(f.read())
    if make_backup:
        shutil.copy2(path, backup_path)
    os.rename(tmp_path, path)
    return backup_path


def run_command(cmd):
    proc = subprocess.Popen(cmd)
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError("command failed: %s" % " ".join(cmd))


def reload_ufw(sudo=False):
    cmd = ["ufw", "reload"]
    if sudo:
        cmd = ["sudo"] + cmd
    run_command(cmd)


def status_ufw(sudo=False):
    cmd = ["ufw", "status", "numbered"]
    if sudo:
        cmd = ["sudo"] + cmd
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        raise RuntimeError("ufw status failed: %s" % err)
    if isinstance(out, bytes):
        out = out.decode("utf-8", "replace")
    return out


def build_args_for_country_check(args):
    class CheckArgs(object):
        pass
    check_args = CheckArgs()
    check_args.skip_country_check = args.skip_country_check
    check_args.country_codes = args.country_codes
    check_args.geo_data = args.geo_data
    check_args.max_country_examples = args.max_country_examples
    return check_args


def plan_fast_apply(args):
    candidates = blocker.load_candidate_networks(args.input)
    candidates, country_mismatch_skips = blocker.split_country_mismatch_candidates(
        candidates,
        build_args_for_country_check(args),
    )

    allowlisted_skips = []
    if args.skip_allowlist_overlaps or args.fail_on_allowlist_overlap:
        allowlist = blocker.load_allowlist_networks(args.allowlist)
        candidates, allowlisted_skips = blocker.split_allowlisted_candidates(candidates, allowlist)
        if allowlisted_skips and args.fail_on_allowlist_overlap:
            raise RuntimeError("candidate list contains allowlist overlaps")

    with open(args.user_rules, "r") as f:
        original_text = f.read()
    existing_rules = parse_user_rules_denies(original_text)
    to_add = blocker.plan_new_rules(candidates, existing_rules)
    cidrs_to_add = [to_text(net) for net in to_add]
    new_text, anchor = build_new_user_rules_text(original_text, cidrs_to_add)
    return {
        "candidates": candidates,
        "country_mismatch_skips": country_mismatch_skips,
        "allowlisted_skips": allowlisted_skips,
        "existing_rules": existing_rules,
        "cidrs_to_add": cidrs_to_add,
        "new_text": new_text,
        "anchor": anchor,
    }


def build_parser():
    parser = argparse.ArgumentParser(description="Batch-add UFW deny CIDRs by editing user.rules once.")
    parser.add_argument("--input", default="aggregated_generiek_subnets.json")
    parser.add_argument("--user-rules", required=True)
    parser.add_argument("--blocked-file", default="blocked_generiek_ips.txt")
    parser.add_argument("--allowlist", default=os.path.join("ip_cache", "allowlist_cidrs.json"))
    parser.add_argument("--geo-data", default="geo_data.json")
    parser.add_argument("--country-codes", default=",".join(blocker.DEFAULT_COUNTRY_CODES))
    parser.add_argument("--skip-country-check", action="store_true")
    parser.add_argument("--max-country-examples", type=int, default=10)
    parser.add_argument("--skip-allowlist-overlaps", action="store_true", default=True)
    parser.add_argument("--fail-on-allowlist-overlap", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--reload", action="store_true")
    parser.add_argument("--no-reload", action="store_true")
    parser.add_argument("--no-backup", action="store_true", help="Replace user.rules without writing a timestamped backup")
    parser.add_argument("--sudo", action="store_true", help="Use sudo for ufw reload/status only; file writes still require permissions")
    parser.add_argument("--output-preview", default="")
    return parser


def main():
    args = build_parser().parse_args()
    try:
        plan = plan_fast_apply(args)
        print("Candidate subnets:", len(plan["candidates"]))
        print("Existing user.rules deny rules parsed:", len(plan["existing_rules"]))
        print("Country-mismatch skips:", len(plan["country_mismatch_skips"]))
        print("Allowlist-overlap skips:", len(plan["allowlisted_skips"]))
        print("New user.rules deny blocks to add:", len(plan["cidrs_to_add"]))
        print("Insertion anchor line:", plan["anchor"] + 1)

        if args.output_preview:
            write_preview(args.output_preview, plan["new_text"])
            print("Wrote preview:", args.output_preview)

        if not args.apply or args.dry_run:
            print("Dry-run only. No UFW files changed.")
            return 0

        if not plan["cidrs_to_add"]:
            print("No new deny blocks to add. No UFW files changed.")
            return 0

        backup_path = atomic_replace_with_backup(args.user_rules, plan["new_text"], make_backup=not args.no_backup)
        print("Replaced:", args.user_rules)
        if backup_path:
            print("Backup:", backup_path)
        else:
            print("Backup skipped (--no-backup).")
        blocker.append_tracking_file(args.blocked_file, plan["cidrs_to_add"])

        should_reload = args.reload and not args.no_reload
        if should_reload:
            reload_ufw(args.sudo)
            status_text = status_ufw(args.sudo)
            print("ufw status numbered first lines:")
            print("\n".join(status_text.splitlines()[:20]))
        else:
            print("Reload skipped. Run ufw reload after reviewing the generated file.")

        print("Done. Added %d new user.rules deny block(s)." % len(plan["cidrs_to_add"]))
        return 0
    except (IOError, OSError, ValueError, RuntimeError, ImportError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
