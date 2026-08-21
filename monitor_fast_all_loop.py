#!/usr/bin/env python
from __future__ import print_function

import argparse
import os
import subprocess
import sys
import time

import monitor_server_status_blocks as status_monitor


def current_timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S %Z")


def build_headers(args):
    headers = list(args.header)
    if args.host_header:
        headers.append("Host: %s" % args.host_header)
    return status_monitor.parse_headers(headers)


def build_prepare_env(args):
    env = os.environ.copy()
    env["POLICY_MODE"] = str(args.policy_mode)
    env["TARGET_PREFIX"] = str(args.target_prefix)
    env["MIN_HITS"] = str(args.min_hits)
    env["APPLY"] = "0" if args.dry_run else "1"
    env["PYTHON"] = args.python_bin
    env["UFW_USER_RULES"] = args.user_rules
    env["FAST_UFW_BACKUP"] = "0" if args.no_ufw_backup else "1"
    return env


def fetch_busy_requests(args):
    status = status_monitor.fetch_url(
        args.url,
        args.timeout,
        insecure=args.insecure,
        headers=build_headers(args),
    )
    busy = status_monitor.parse_busy_requests(status)
    if busy is None:
        raise RuntimeError("could not parse busy request count from server-status")
    return busy


def run_prepare_script(args):
    env = build_prepare_env(args)
    proc = subprocess.Popen([args.script], env=env)
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError("%s failed with exit code %d" % (args.script, proc.returncode))


def run_once(args, fetch_func=fetch_busy_requests, run_func=run_prepare_script):
    print("Started at:", current_timestamp())
    busy = fetch_func(args)
    print("Busy requests:", busy)
    print("Threshold:", args.threshold)

    if busy <= args.threshold:
        print("Below threshold. No block run.")
        return 0

    print("Threshold exceeded. Running:", args.script)
    run_func(args)
    print("Block run complete.")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description="Continuously run the fast Apache status UFW workflow while busy workers stay above a threshold.")
    parser.add_argument("--url", default="https://www.nieuwejobs.com/server-status")
    parser.add_argument("--threshold", type=int, default=100)
    parser.add_argument("--sleep-seconds", type=int, default=300)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification for trusted status endpoints")
    parser.add_argument("--header", action="append", default=[], help="HTTP header for server-status fetch, for example 'Host: www.example.com'")
    parser.add_argument("--host-header", help="Shortcut for --header 'Host: ...' when fetching a local vhost URL")
    parser.add_argument("--script", default="./run_prepare_generiek_blocks_fast_all.sh")
    parser.add_argument("--python-bin", default=os.environ.get("PYTHON", "python2"))
    parser.add_argument("--user-rules", default="/lib/ufw/user.rules")
    parser.add_argument("--policy-mode", type=int, default=0)
    parser.add_argument("--target-prefix", type=int, default=16)
    parser.add_argument("--min-hits", type=int, default=1)
    parser.add_argument("--dry-run", action="store_true", help="Run the fast-all command with APPLY=0")
    parser.add_argument("--once", action="store_true", help="Check once and exit instead of looping forever")
    parser.add_argument("--no-ufw-backup", action="store_true", default=True, help="Run fast UFW apply without timestamped user.rules backups")
    parser.add_argument("--with-ufw-backup", dest="no_ufw_backup", action="store_false", help="Keep timestamped user.rules backups")
    return parser


def main(argv):
    args = build_parser().parse_args(argv)
    while True:
        try:
            run_once(args)
        except (IOError, OSError, RuntimeError) as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            if args.once:
                return 1

        if args.once:
            return 0

        print("Sleeping %d seconds." % args.sleep_seconds)
        time.sleep(args.sleep_seconds)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
