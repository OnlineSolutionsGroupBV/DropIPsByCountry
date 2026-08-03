import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import recommend_provider_subnets as recommend


class RecommendProviderSubnetsTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_provider_cluster_recommends_candidate_subnet(self):
        geo_data = {
            "10.10.1.1": {"country": "CN", "org": "AS123 Example ISP"},
            "10.10.2.1": {"country": "CN", "org": "AS123 Example ISP"},
            "10.10.3.1": {"country": "CN", "org": "AS123 Example ISP"},
        }

        rows = recommend.build_recommendations(geo_data, ["CN"], [24, 20, 16], 3)

        self.assertEqual(rows[0]["country"], "CN")
        self.assertEqual(rows[0]["org"], "AS123 Example ISP")
        self.assertEqual(rows[0]["recommendation"]["target_prefix"], 20)
        self.assertEqual(rows[0]["candidate_cidrs"], ["10.10.0.0/20"])
        self.assertEqual(rows[0]["candidate_details"][0]["hits"], 3)
        self.assertEqual(rows[0]["candidate_details"][0]["blocks_ips"], 4096)

    def test_safe_provider_is_skipped(self):
        geo_data = {
            "66.249.75.1": {"country": "US", "org": "AS15169 Google LLC"},
            "66.249.75.2": {"country": "US", "org": "AS15169 Google LLC"},
            "66.249.75.3": {"country": "US", "org": "AS15169 Google LLC"},
        }

        rows = recommend.build_recommendations(geo_data, ["US"], [24, 20, 16], 3)

        self.assertEqual(rows[0]["recommendation"]["decision"], "SKIP_SAFE_PROVIDER")
        self.assertEqual(rows[0]["candidate_cidrs"], [])

    def test_write_candidates_outputs_json_list(self):
        rows = [{
            "candidate_cidrs": ["10.10.0.0/20", "10.10.0.0/20", "11.11.0.0/20"],
        }]
        path = os.path.join(self.tmpdir, "candidates.json")

        recommend.write_candidates(path, rows)

        with open(path) as f:
            self.assertEqual(json.load(f), ["10.10.0.0/20", "11.11.0.0/20"])

    def test_write_text_handles_unicode_provider_names(self):
        rows = recommend.build_recommendations({
            "10.10.1.1": {"country": "CN", "org": u"AS123 Málaga ISP"},
            "10.10.2.1": {"country": "CN", "org": u"AS123 Málaga ISP"},
            "10.10.3.1": {"country": "CN", "org": u"AS123 Málaga ISP"},
        }, ["CN"], [24, 20, 16], 3)
        path = os.path.join(self.tmpdir, "providers.txt")

        recommend.write_text(path, rows, 10)

        with open(path, "rb") as f:
            self.assertIn(u"Málaga", f.read().decode("utf-8"))

    def test_write_danger_text_contains_provider_stats_and_subnets(self):
        rows = recommend.build_recommendations({
            "10.10.1.1": {"country": "CN", "org": "AS123 Example ISP"},
            "10.10.2.1": {"country": "CN", "org": "AS123 Example ISP"},
            "10.10.3.1": {"country": "CN", "org": "AS123 Example ISP"},
            "66.249.75.1": {"country": "US", "org": "AS15169 Google LLC"},
            "66.249.75.2": {"country": "US", "org": "AS15169 Google LLC"},
            "66.249.75.3": {"country": "US", "org": "AS15169 Google LLC"},
        }, ["CN", "US"], [24, 20, 16], 3)
        path = os.path.join(self.tmpdir, "danger.txt")

        recommend.write_danger_text(path, rows, 10)

        with open(path, "rb") as f:
            output = f.read().decode("utf-8")
        self.assertIn("Dangerous provider subnet candidates", output)
        self.assertIn("CN | AS123 Example ISP", output)
        self.assertIn("10.10.0.0/20 hits=3 blocks_ips=4096", output)
        self.assertNotIn("Google LLC", output)


if __name__ == "__main__":
    unittest.main()
