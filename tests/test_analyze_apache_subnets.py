import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import analyze_apache_subnets as analyze


class AnalyzeApacheSubnetsTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def write_log(self, name, lines):
        path = os.path.join(self.tmpdir, name)
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return path

    def test_parse_log_line_accepts_standard_access_log(self):
        parsed = analyze.parse_log_line(
            '1.2.3.4 - - [01/Aug/2026:12:00:00 +0200] "GET /jobs HTTP/1.1" 200 123 "-" "bot"',
            "site-access",
        )

        self.assertEqual(parsed["ip"], "1.2.3.4")
        self.assertEqual(parsed["site"], "site-access")
        self.assertEqual(parsed["url"], "/jobs")
        self.assertEqual(parsed["status"], "200")

    def test_parse_log_line_accepts_vhost_combined_log(self):
        parsed = analyze.parse_log_line(
            'www.example.com 1.2.3.4 - - [01/Aug/2026:12:00:00 +0200] "GET /jobs?q=x HTTP/1.1" 404 123 "-" "bot"',
            "fallback",
        )

        self.assertEqual(parsed["ip"], "1.2.3.4")
        self.assertEqual(parsed["site"], "www.example.com")
        self.assertEqual(parsed["url"], "/jobs")
        self.assertEqual(parsed["status"], "404")

    def test_analyze_logs_reports_candidate_subnet_and_non_target_review(self):
        path = self.write_log("jobs-access.log", [
            '1.2.3.4 - - [01/Aug/2026:12:00:00 +0200] "GET /a HTTP/1.1" 200 1 "-" "bot"',
            '1.2.3.5 - - [01/Aug/2026:12:00:01 +0200] "GET /b HTTP/1.1" 200 1 "-" "bot"',
            '1.2.3.6 - - [01/Aug/2026:12:00:02 +0200] "GET /c HTTP/1.1" 200 1 "-" "bot"',
            '109.134.6.23 - - [01/Aug/2026:12:00:03 +0200] "GET /real HTTP/1.1" 200 1 "-" "browser"',
        ])
        geo_data = {
            "1.2.3.4": {"country": "CN"},
            "1.2.3.5": {"country": "CN"},
            "1.2.3.6": {"country": "CN"},
            "109.134.6.23": {"country": "BE"},
        }

        totals, ips, subnets = analyze.analyze_logs([path], geo_data, set(["CN"]), [24])
        report = analyze.build_report(totals, ips, subnets, set(["CN"]), 3, 3)

        by_cidr = dict((row["cidr"], row) for row in report["subnets"])
        self.assertEqual(by_cidr["1.2.3.0/24"]["decision"], "CANDIDATE")
        self.assertEqual(by_cidr["1.2.3.0/24"]["would_block_ips"], 256)
        self.assertEqual(by_cidr["109.134.6.0/24"]["decision"], "REVIEW_NON_TARGET_PRESENT")

    def test_writes_json_text_and_candidate_files(self):
        path = self.write_log("jobs-access.log", [
            '1.2.3.4 - - [01/Aug/2026:12:00:00 +0200] "GET /a HTTP/1.1" 200 1 "-" "bot"',
            '1.2.3.5 - - [01/Aug/2026:12:00:01 +0200] "GET /b HTTP/1.1" 200 1 "-" "bot"',
            '1.2.3.6 - - [01/Aug/2026:12:00:02 +0200] "GET /c HTTP/1.1" 200 1 "-" "bot"',
            '9.9.9.9 - - [01/Aug/2026:12:00:03 +0200] "GET /d HTTP/1.1" 200 1 "-" "bot"',
        ])
        geo_data = {
            "1.2.3.4": {"country": "CN"},
            "1.2.3.5": {"country": "CN"},
            "1.2.3.6": {"country": "CN"},
        }
        totals, ips, subnets = analyze.analyze_logs([path], geo_data, set(["CN"]), [24])
        report = analyze.build_report(totals, ips, subnets, set(["CN"]), 3, 3)
        json_path = os.path.join(self.tmpdir, "report.json")
        text_path = os.path.join(self.tmpdir, "report.txt")
        candidates_path = os.path.join(self.tmpdir, "candidates.txt")
        ips_path = os.path.join(self.tmpdir, "ips.txt")
        missing_path = os.path.join(self.tmpdir, "missing.txt")

        analyze.write_json(json_path, report)
        analyze.write_text_report(text_path, report, 20)
        analyze.write_candidates(candidates_path, report)
        analyze.write_ip_lists(ips_path, missing_path, report)

        with open(json_path) as f:
            data = json.load(f)
            self.assertEqual(data["summary"]["unique_ips"], 4)
            self.assertEqual(data["summary"]["missing_geo_ips"], 1)
        with open(text_path) as f:
            self.assertIn("1.2.3.0/24 | CANDIDATE", f.read())
        with open(candidates_path) as f:
            self.assertEqual(f.read().strip(), "1.2.3.0/24")
        with open(ips_path) as f:
            self.assertIn("9.9.9.9", f.read())
        with open(missing_path) as f:
            self.assertEqual(f.read().strip(), "9.9.9.9")


if __name__ == "__main__":
    unittest.main()
