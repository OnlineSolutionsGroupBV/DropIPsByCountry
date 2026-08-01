import unittest

import aggregate_generiek_subnets as aggregate


class AggregateGeneriekSubnetsTests(unittest.TestCase):
    def test_parse_ips_from_text_deduplicates_and_skips_invalid_values(self):
        text = "1.2.3.4 1.2.3.4 999.1.1.1 5.6.7.8"

        self.assertEqual(aggregate.parse_ips_from_text(text), ["1.2.3.4", "5.6.7.8"])

    def test_build_subnets_from_ips_groups_by_target_prefix(self):
        selected, subnets = aggregate.build_subnets_from_ips(
            ["1.2.3.4", "1.2.3.99", "5.6.7.8"],
            24,
            1,
        )

        self.assertEqual(selected, 3)
        self.assertEqual(subnets, ["1.2.3.0/24", "5.6.7.0/24"])

    def test_build_subnets_from_ips_respects_min_hits(self):
        selected, subnets = aggregate.build_subnets_from_ips(
            ["1.2.3.4", "1.2.3.99", "5.6.7.8"],
            24,
            2,
        )

        self.assertEqual(selected, 3)
        self.assertEqual(subnets, ["1.2.3.0/24"])


if __name__ == "__main__":
    unittest.main()
