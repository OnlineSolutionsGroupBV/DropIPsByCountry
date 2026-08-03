import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import apply_ufw_country_rule_updates as applier


class ApplyUfwCountryRuleUpdatesTests(unittest.TestCase):
    def test_builds_delete_command_with_sudo(self):
        self.assertEqual(
            applier.build_delete_command({"num": 12}, True),
            ["sudo", "ufw", "--force", "delete", "12"],
        )

    def test_builds_add_command(self):
        self.assertEqual(
            applier.build_add_command({"cidr": "10.10.0.0/20"}, False),
            ["ufw", "insert", "1", "deny", "from", "10.10.0.0/20"],
        )

    def test_apply_plan_dry_run_does_not_execute_commands(self):
        calls = []
        original = applier.run_command
        applier.run_command = calls.append
        try:
            applier.apply_plan({
                "delete_rules": [{"num": 1, "old_cidr": "10.10.1.0/24"}],
                "add_rules": [{"cidr": "10.10.0.0/20"}],
            }, sudo=False, apply=False, no_reload=False)
        finally:
            applier.run_command = original

        self.assertEqual(calls, [])

    def test_apply_plan_deletes_highest_rule_numbers_first(self):
        calls = []
        original = applier.run_command
        applier.run_command = calls.append
        try:
            applier.apply_plan({
                "delete_rules": [{"num": 2}, {"num": 9}, {"num": 4}],
                "add_rules": [],
            }, sudo=False, apply=True, no_reload=True)
        finally:
            applier.run_command = original

        self.assertEqual(calls, [
            ["ufw", "--force", "delete", "9"],
            ["ufw", "--force", "delete", "4"],
            ["ufw", "--force", "delete", "2"],
        ])


if __name__ == "__main__":
    unittest.main()
