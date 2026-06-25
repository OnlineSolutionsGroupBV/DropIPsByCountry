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


if __name__ == "__main__":
    unittest.main()
