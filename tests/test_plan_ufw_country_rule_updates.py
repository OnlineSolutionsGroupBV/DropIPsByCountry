import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import plan_ufw_country_rule_updates as planner


class PlanUfwCountryRuleUpdatesTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def net(self, value):
        return planner.ip_network(value, strict=False)

    def test_replaces_existing_rule_with_recommended_country_subnet(self):
        status = """
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] Anywhere                   DENY IN     10.10.1.0/24
"""
        geo_data = {
            "10.10.1.1": {"country": "CN", "org": "AS123 Example ISP"},
            "10.10.2.1": {"country": "CN", "org": "AS123 Example ISP"},
            "10.10.3.1": {"country": "CN", "org": "AS123 Example ISP"},
        }
        recommendations = {"CN": {"target_prefix": 20, "min_hits": 3, "reason": "clustered"}}

        plan = planner.build_plan(status, geo_data, recommendations, [], 5)

        self.assertEqual(plan["summary"]["REPLACE"], 1)
        self.assertEqual(plan["delete_rules"][0]["num"], 1)
        self.assertEqual(plan["add_rules"][0]["cidr"], "10.10.0.0/20")
        self.assertEqual(plan["add_rules"][0]["hits"], 3)

    def test_skips_protected_country_evidence(self):
        status = "[ 4] Anywhere                   DENY IN     109.134.6.0/24"
        geo_data = {
            "109.134.6.10": {"country": "BE", "org": "AS54321 Home ISP"},
        }

        plan = planner.build_plan(status, geo_data, {"BE": {"target_prefix": 24, "min_hits": 1}}, [], 5)

        self.assertEqual(plan["summary"]["SKIP_PROTECTED_COUNTRY"], 1)
        self.assertEqual(plan["delete_rules"], [])
        self.assertEqual(plan["add_rules"], [])

    def test_skips_existing_rule_when_allowlist_overlaps(self):
        status = "[ 8] Anywhere                   DENY IN     66.249.75.0/24"
        geo_data = {
            "66.249.75.10": {"country": "US", "org": "AS15169 Google LLC"},
            "66.249.75.11": {"country": "US", "org": "AS15169 Google LLC"},
        }
        recommendations = {"US": {"target_prefix": 24, "min_hits": 2, "reason": "clustered"}}
        allowlist = [self.net("66.249.75.0/24")]

        plan = planner.build_plan(status, geo_data, recommendations, allowlist, 5)

        self.assertEqual(plan["summary"]["SKIP_EXISTING_ALLOWLIST_OVERLAP"], 1)
        self.assertEqual(plan["delete_rules"], [])
        self.assertEqual(plan["add_rules"], [])
        self.assertEqual(plan["rules"][0]["allowlist_overlaps"], ["66.249.75.0/24"])

    def test_write_text_outputs_readable_plan(self):
        plan = {
            "rules_parsed": 1,
            "summary": {"REPLACE": 1},
            "delete_rules": [{"num": 2, "old_cidr": "10.10.1.0/24", "country": "CN", "line": "x"}],
            "add_rules": [{"cidr": "10.10.0.0/20", "hits": 3, "blocks_ips": 4096}],
            "rules": [{
                "num": 2,
                "old_cidr": "10.10.1.0/24",
                "action": "REPLACE",
                "reason": "test",
                "source_count": 3,
                "country": "CN",
                "country_counts": [{"country": "CN", "ips": 3}],
                "provider_counts": [{"org": "AS123 Example ISP", "ips": 3}],
                "examples": [],
                "recommendation": {"target_prefix": 20, "min_hits": 3, "reason": "clustered"},
                "new_cidrs": [{"cidr": "10.10.0.0/20", "hits": 3, "blocks_ips": 4096, "example_ips": ["10.10.1.1"]}],
                "skipped_candidates": [],
            }],
        }
        path = os.path.join(self.tmpdir, "plan.txt")

        planner.write_text(path, plan, 10)

        with open(path) as f:
            output = f.read()
        self.assertIn("UFW country rule update plan", output)
        self.assertIn("delete #2 10.10.1.0/24 CN", output)
        self.assertIn("add 10.10.0.0/20 hits=3 blocks_ips=4096", output)


if __name__ == "__main__":
    unittest.main()
