import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import country_policy


class CountryPolicyTests(unittest.TestCase):
    def test_default_country_codes_exclude_protected_local_markets(self):
        defaults = set(country_policy.default_country_codes())

        self.assertNotIn("BE", defaults)
        self.assertNotIn("DE", defaults)
        self.assertNotIn("FR", defaults)
        self.assertNotIn("NL", defaults)

    def test_default_country_codes_include_recent_attack_sources(self):
        defaults = set(country_policy.default_country_codes())

        for code in [
            "GB", "US", "ES", "EG", "IT", "IN", "PL", "TH", "AU", "MX",
            "RO", "CL", "VN", "ID", "CA", "SE", "PT", "JP", "NG", "IL",
            "CG", "GR", "PE", "DO", "TW", "AO", "HU", "IE", "PA", "LY",
            "BG", "CZ", "KR", "NZ", "CI", "LK", "QA", "BO", "CR", "BF",
            "MN", "TZ", "GH", "MG", "KW", "CM", "TG", "MD", "DK", "KG",
            "UG", "NO", "XK",
        ]:
            self.assertIn(code, defaults)

    def test_effective_country_codes_removes_protected_overrides(self):
        self.assertEqual(
            country_policy.effective_country_codes(["CN", "DE", "NL", "IN", "BE", "FR"]),
            ["CN", "IN"],
        )

    def test_default_country_block_policy_uses_default_24_prefix(self):
        policy = country_policy.default_country_block_policy()

        self.assertEqual(policy["CN"]["target_prefix"], 24)
        self.assertEqual(policy["CN"]["min_hits"], 1)
        self.assertNotIn("BE", policy)

    def test_is_safe_provider_matches_known_crawlers(self):
        self.assertTrue(country_policy.is_safe_provider("AS15169 Google LLC"))
        self.assertTrue(country_policy.is_safe_provider("AS8075 Microsoft Corporation"))
        self.assertTrue(country_policy.is_safe_provider("OpenAI crawler"))
        self.assertFalse(country_policy.is_safe_provider("AS123 Example ISP"))


if __name__ == "__main__":
    unittest.main()
