#!/usr/bin/env python
from __future__ import print_function

import argparse
import os
import re
import shutil
import ssl
import subprocess
import sys
import time

try:
    from urllib2 import urlopen, Request
except ImportError:
    from urllib.request import urlopen, Request

try:
    text_type = unicode
except NameError:
    text_type = str


BUSY_RE = re.compile(r"\b(\d+)\s+requests currently being processed\b")


def to_text(value):
    if isinstance(value, text_type):
        return value
    return value.decode("utf-8", "replace")


def parse_busy_requests(status_text):
    match = BUSY_RE.search(status_text)
    if not match:
        return None
    return int(match.group(1))


def insecure_ssl_context():
    if hasattr(ssl, "_create_unverified_context"):
        return ssl._create_unverified_context()
    return None


def fetch_url(url, timeout, insecure=False):
    request = Request(url, headers={"User-Agent": "DropIPsByCountry-monitor/1.0"})
    context = insecure_ssl_context() if insecure else None
    if context is not None:
        response = urlopen(request, timeout=timeout, context=context)
    else:
        response = urlopen(request, timeout=timeout)
    data = response.read()
    return to_text(data)


def acquire_lock(lock_dir, stale_seconds):
    try:
        os.mkdir(lock_dir)
    except OSError:
        if stale_seconds > 0 and os.path.isdir(lock_dir):
            age = time.time() - os.path.getmtime(lock_dir)
            if age > stale_seconds:
                shutil.rmtree(lock_dir)
                os.mkdir(lock_dir)
            else:
                return False
        else:
            return False
    with open(os.path.join(lock_dir, "pid"), "w") as f:
        f.write(str(os.getpid()) + "\n")
    return True


def release_lock(lock_dir):
    if os.path.isdir(lock_dir):
        shutil.rmtree(lock_dir)


def write_text(path, content):
    with open(path, "wb") as f:
        f.write(content.encode("utf-8"))


def current_run_timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S %Z")


def run_prepare(script, python_bin, apply, extra_env):
    env = os.environ.copy()
    env["PYTHON"] = python_bin
    env["APPLY"] = "1" if apply else "0"
    for item in extra_env:
        if "=" not in item:
            raise RuntimeError("invalid --env value, expected KEY=VALUE: %s" % item)
        key, value = item.split("=", 1)
        env[key] = value
    proc = subprocess.Popen([script], env=env)
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError("%s failed with exit code %d" % (script, proc.returncode))


def build_parser():
    parser = argparse.ArgumentParser(description="Fetch Apache server-status and run subnet blocking when busy workers exceed a threshold.")
    parser.add_argument("--url", default="https://www.nieuwejobs.com/server-status")
    parser.add_argument("--threshold", type=int, default=200)
    parser.add_argument("--input-file", default="input.txt")
    parser.add_argument("--snapshot-file", default="last_server_status.txt")
    parser.add_argument("--lock-dir", default=".server_status_block.lock")
    parser.add_argument("--stale-lock-seconds", type=int, default=7200)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification for local/self-signed server-status checks")
    parser.add_argument("--script", default="./run_prepare_generiek_blocks.sh")
    parser.add_argument("--python-bin", default=os.environ.get("PYTHON", "python2"))
    parser.add_argument("--apply", action="store_true", help="Run blocker with APPLY=1. This is the default unless --dry-run is used.")
    parser.add_argument("--dry-run", action="store_true", help="Run blocker with APPLY=0")
    parser.add_argument("--env", action="append", default=[], help="Extra environment KEY=VALUE for run_prepare_generiek_blocks.sh")
    parser.add_argument("--status-file", help="Read status HTML/text from file instead of fetching URL")
    return parser


def main_with_args(argv):
    args = build_parser().parse_args(argv)
    print("Started at:", current_run_timestamp())
    locked = acquire_lock(args.lock_dir, args.stale_lock_seconds)
    if not locked:
        print("Another monitor run is active. Skipping.")
        return 0

    try:
        if args.status_file:
            with open(args.status_file, "rb") as f:
                status = to_text(f.read())
        else:
            status = fetch_url(args.url, args.timeout, insecure=args.insecure)
        busy = parse_busy_requests(status)
        if busy is None:
            raise RuntimeError("could not parse busy request count from server-status")

        print("Busy requests:", busy)
        print("Threshold:", args.threshold)
        if busy <= args.threshold:
            print("Below threshold. No block run.")
            return 0

        write_text(args.snapshot_file, status)
        write_text(args.input_file, status)
        print("Threshold exceeded. Wrote %s and %s." % (args.snapshot_file, args.input_file))
        run_prepare(args.script, args.python_bin, not args.dry_run, args.env)
        print("Block run complete.")
        return 0
    except (IOError, OSError, RuntimeError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1
    finally:
        release_lock(args.lock_dir)


if __name__ == "__main__":
    raise SystemExit(main_with_args(sys.argv[1:]))
