import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import recommend_country_prefixes as recommend


class RecommendCountryPrefixesTests(unittest.TestCase):
    def test_distributed_country_recommends_32(self):
        geo_data = {
            "1.1.1.1": {"country": "CN"},
            "2.2.2.2": {"country": "CN"},
        }

        rows = recommend.build_recommendations(geo_data, ["CN"], [24, 20, 16])

        self.assertEqual(rows[0]["recommendation"]["target_prefix"], 32)
        self.assertEqual(rows[0]["recommendation"]["min_hits"], 1)

    def test_clustered_country_recommends_20(self):
        geo_data = {
            "10.10.1.1": {"country": "CN"},
            "10.10.2.1": {"country": "CN"},
            "10.10.3.1": {"country": "CN"},
        }
        for i in range(30):
            geo_data["192.0.%d.1" % i] = {"country": "CN"}

        rows = recommend.build_recommendations(geo_data, ["CN"], [24, 20, 16])

        self.assertEqual(rows[0]["recommendation"]["target_prefix"], 20)
        self.assertEqual(rows[0]["recommendation"]["min_hits"], 3)

    def test_heavy_country_recommends_16(self):
        geo_data = {}
        for i in range(120):
            geo_data["10.20.%d.1" % i] = {"country": "CN"}

        rows = recommend.build_recommendations(geo_data, ["CN"], [24, 20, 16])

        self.assertEqual(rows[0]["recommendation"]["target_prefix"], 16)
        self.assertEqual(rows[0]["recommendation"]["min_hits"], 10)


if __name__ == "__main__":
    unittest.main()
