#!/usr/bin/env python
from __future__ import print_function

import argparse
import os
import shutil
import subprocess
import sys
import time

import fast_apply_ufw_user_rules as fast_ufw


def run_command(cmd):
    proc = subprocess.Popen(cmd)
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError("command failed: %s" % " ".join(cmd))


def restore_backup(backup_path, user_rules_path, apply=False):
    if not os.path.exists(backup_path):
        raise RuntimeError("backup does not exist: %s" % backup_path)
    with open(backup_path, "r") as f:
        content = f.read()
    fast_ufw.validate_user_rules_text(content)

    if not apply:
        return None

    directory = os.path.dirname(os.path.abspath(user_rules_path))
    current_backup = os.path.join(
        directory,
        "%s.before-restore-%s" % (os.path.basename(user_rules_path), time.strftime("%Y%m%d-%H%M%S")),
    )
    shutil.copy2(user_rules_path, current_backup)
    shutil.copy2(backup_path, user_rules_path)
    return current_backup


def main():
    parser = argparse.ArgumentParser(description="Restore a UFW user.rules backup created by fast_apply_ufw_user_rules.py.")
    parser.add_argument("--backup", required=True)
    parser.add_argument("--user-rules", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--reload", action="store_true")
    parser.add_argument("--sudo", action="store_true")
    args = parser.parse_args()

    try:
        current_backup = restore_backup(args.backup, args.user_rules, apply=args.apply)
        if not args.apply:
            print("Dry-run only. Backup is valid and no files were changed.")
            return 0
        print("Restored:", args.user_rules)
        print("Previous current file backup:", current_backup)
        if args.reload:
            cmd = ["ufw", "reload"]
            if args.sudo:
                cmd = ["sudo"] + cmd
            run_command(cmd)
        else:
            print("Reload skipped. Run ufw reload after reviewing the restored file.")
        return 0
    except (IOError, OSError, RuntimeError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
