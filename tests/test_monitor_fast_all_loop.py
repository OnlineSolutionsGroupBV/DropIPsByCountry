import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import monitor_fast_all_loop as loop


class Args(object):
    pass


def make_args():
    args = Args()
    args.policy_mode = 0
    args.target_prefix = 16
    args.min_hits = 1
    args.dry_run = False
    args.python_bin = "python2"
    args.user_rules = "/lib/ufw/user.rules"
    args.no_ufw_backup = True
    args.threshold = 100
    args.script = "./run_prepare_generiek_blocks_fast_all.sh"
    return args


class MonitorFastAllLoopTests(unittest.TestCase):
    def test_build_prepare_env_sets_fast_incident_defaults(self):
        args = make_args()

        env = loop.build_prepare_env(args)

        self.assertEqual(env["POLICY_MODE"], "0")
        self.assertEqual(env["TARGET_PREFIX"], "16")
        self.assertEqual(env["MIN_HITS"], "1")
        self.assertEqual(env["APPLY"], "1")
        self.assertEqual(env["PYTHON"], "python2")
        self.assertEqual(env["UFW_USER_RULES"], "/lib/ufw/user.rules")
        self.assertEqual(env["FAST_UFW_BACKUP"], "0")

    def test_build_prepare_env_can_enable_backup(self):
        args = make_args()
        args.no_ufw_backup = False

        env = loop.build_prepare_env(args)

        self.assertEqual(env["FAST_UFW_BACKUP"], "1")

    def test_run_once_skips_below_threshold(self):
        args = make_args()
        calls = []

        result = loop.run_once(args, fetch_func=lambda _args: 100, run_func=lambda _args: calls.append("run"))

        self.assertEqual(result, 0)
        self.assertEqual(calls, [])

    def test_run_once_runs_above_threshold(self):
        args = make_args()
        calls = []

        result = loop.run_once(args, fetch_func=lambda _args: 101, run_func=lambda _args: calls.append("run"))

        self.assertEqual(result, 0)
        self.assertEqual(calls, ["run"])


if __name__ == "__main__":
    unittest.main()
