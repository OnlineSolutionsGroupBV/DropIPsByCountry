import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import find_bad_ufw_rules as bad_rules


class FindBadUfwRulesTests(unittest.TestCase):
    def net(self, value):
        return bad_rules.ip_network(value, strict=False)

    def test_broad_deny_overlapping_allowlist_is_bad(self):
        candidate = self.net("66.249.0.0/16")
        allowlist = [self.net("66.249.64.0/19")]

        self.assertTrue(bad_rules.is_blocking_allowed(candidate, allowlist))

    def test_unrelated_deny_is_not_bad(self):
        candidate = self.net("117.40.0.0/16")
        allowlist = [self.net("66.249.64.0/19")]

        self.assertFalse(bad_rules.is_blocking_allowed(candidate, allowlist))

    def test_find_non_target_sources_flags_existing_ufw_rule_for_allowed_country(self):
        candidate = self.net("148.251.129.0/24")
        geo_data = {
            "148.251.129.80": {"country": "DE", "org": "AS24940 Hetzner Online GmbH"},
            "1.2.3.4": {"country": "CN", "org": "Example CN"},
        }

        found = bad_rules.find_non_target_sources(candidate, geo_data, set(["CN", "IN"]), 10)

        self.assertEqual(found, ["148.251.129.80 DE AS24940 Hetzner Online GmbH"])


if __name__ == "__main__":
    unittest.main()
