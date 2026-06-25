import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import block_generiek_subnet as blocker


class BlockGeneriekSubnetTests(unittest.TestCase):
    def net(self, value):
        return blocker.ip_network(value, strict=False)

    def test_parse_ufw_denies_reads_only_numbered_deny_in_rules(self):
        status = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] Anywhere                   DENY IN     47.84.0.0/16
[ 2] 443                        ALLOW IN    Anywhere
[ 3] Anywhere                   DENY OUT    1.2.3.4
[ 4] Anywhere                   DENY IN     52.167.144.208
"""

        parsed = [str(net) for net in blocker.parse_ufw_denies(status)]

        self.assertEqual(parsed, ["47.84.0.0/16", "52.167.144.208/32"])

    def test_existing_broader_rule_covers_candidate(self):
        existing = [self.net("47.84.0.0/15")]

        self.assertTrue(blocker.is_covered_by_existing_rule(self.net("47.84.0.0/16"), existing))
        self.assertFalse(blocker.is_covered_by_existing_rule(self.net("47.86.0.0/16"), existing))

    def test_plan_new_rules_skips_exact_and_covered_subnets(self):
        candidates = [
            self.net("47.84.0.0/16"),
            self.net("216.234.0.0/16"),
            self.net("177.62.0.0/16"),
        ]
        existing = [
            self.net("47.84.0.0/16"),
            self.net("216.234.0.0/15"),
        ]

        planned = [str(net) for net in blocker.plan_new_rules(candidates, existing)]

        self.assertEqual(planned, ["177.62.0.0/16"])

    def test_load_candidate_networks_accepts_json_list_and_deduplicates(self):
        handle, path = tempfile.mkstemp()
        os.close(handle)
        try:
            with open(path, "w") as f:
                f.write('["47.84.0.0/16", "47.84.0.1", "bad-value", "47.84.0.0/16"]')

            loaded = [str(net) for net in blocker.load_candidate_networks(path)]

            self.assertEqual(loaded, ["47.84.0.0/16", "47.84.0.1/32"])
        finally:
            os.unlink(path)

    def test_load_candidate_networks_accepts_reported_valid_16_cidrs(self):
        handle, path = tempfile.mkstemp()
        os.close(handle)
        try:
            with open(path, "w") as f:
                f.write('["88.245.0.0/16", "82.222.0.0/16", "105.190.0.0/16", "117.40.0.0/16"]')

            loaded = [str(net) for net in blocker.load_candidate_networks(path)]

            self.assertEqual(loaded, [
                "88.245.0.0/16",
                "82.222.0.0/16",
                "105.190.0.0/16",
                "117.40.0.0/16",
            ])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
