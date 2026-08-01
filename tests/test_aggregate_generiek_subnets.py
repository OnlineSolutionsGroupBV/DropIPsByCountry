import unittest
import os
import tempfile

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

    def test_build_subnets_from_geo_can_filter_to_source_ips(self):
        geo_data = {
            "1.2.3.4": {"country": "CN"},
            "5.6.7.8": {"country": "CN"},
            "109.134.6.23": {"country": "BE"},
        }

        selected, subnets = aggregate.build_subnets_from_geo(
            geo_data,
            ["CN"],
            24,
            1,
            source_ips=["1.2.3.4", "109.134.6.23"],
        )

        self.assertEqual(selected, 1)
        self.assertEqual(subnets, ["1.2.3.0/24"])

    def test_build_country_report_splits_blocked_and_allowed_ips(self):
        geo_data = {
            "1.2.3.4": {"country": "CN", "region": "Shanghai", "city": "Shanghai", "org": "Example CN"},
            "109.134.6.23": {"country": "BE", "region": "Flanders", "city": "Antwerp", "org": "AS5432 Proximus NV"},
        }

        report = aggregate.build_country_report(
            geo_data,
            ["CN", "IN"],
            source_ips=["1.2.3.4", "109.134.6.23", "9.9.9.9"],
        )

        self.assertEqual([row["ip"] for row in report["blocked_ips"]], ["1.2.3.4"])
        self.assertEqual([row["ip"] for row in report["allowed_ips"]], ["109.134.6.23"])
        self.assertEqual(report["missing_geo_ips"], ["9.9.9.9"])
        self.assertEqual(report["countries"]["CN"], {"total": 1, "blocked": 1, "allowed": 0})
        self.assertEqual(report["countries"]["BE"], {"total": 1, "blocked": 0, "allowed": 1})

    def test_write_ip_detail_file_writes_unicode_as_utf8(self):
        handle, path = tempfile.mkstemp()
        os.close(handle)
        try:
            aggregate.write_ip_detail_file(path, [{
                "ip": "84.126.19.181",
                "country": "ES",
                "region": "Andalusia",
                "city": u"M\xe1laga",
                "org": "AS6739 Vodafone ONO AS",
            }])

            with open(path, "rb") as f:
                self.assertIn(u"M\xe1laga".encode("utf-8"), f.read())
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
