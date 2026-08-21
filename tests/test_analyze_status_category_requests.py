import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import analyze_status_category_requests as analyze


class AnalyzeStatusCategoryRequestsTests(unittest.TestCase):
    def test_parse_rows_filters_by_category_count(self):
        text = "\n".join([
            "0-0 1 0/0/0 W 0 1 0 0.0 0 0 1.2.3.4 www.example.com:443 GET /job/?categories=a&categories=b HTTP/1.1",
            "0-1 1 0/0/0 W 0 1 0 0.0 0 0 5.6.7.8 www.example.com:443 GET /job/?categories=a&categories=b&categories=c HTTP/1.1",
        ])

        rows = analyze.parse_rows(text, 3)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "5.6.7.8")
        self.assertEqual(rows[0]["category_count"], 3)

    def test_summarize_counts_country_and_provider(self):
        rows = [{
            "ip": "5.6.7.8",
            "vhost": "www.example.com:443",
            "method": "GET",
            "url": "/job/?categories=a&categories=b&categories=c",
            "category_count": 3,
        }]
        geo_data = {
            "5.6.7.8": {"country": "US", "org": "AS123 Example Net"},
        }

        stats = analyze.summarize(rows, geo_data, None)

        self.assertEqual(stats["rows"], 1)
        self.assertEqual(stats["unique_ips"], 1)
        self.assertEqual(stats["by_country"]["US"], 1)
        self.assertEqual(stats["by_provider"]["AS123 Example Net"], 1)


if __name__ == "__main__":
    unittest.main()
