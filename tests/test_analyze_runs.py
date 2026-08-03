import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import analyze_runs


class AnalyzeRunsTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.runs_dir = os.path.join(self.tmpdir, "runs")
        os.mkdir(self.runs_dir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def write_run(self, name, ips, blocked_ips, allowed_ips, countries):
        path = os.path.join(self.runs_dir, name)
        os.mkdir(path)
        with open(os.path.join(path, "summary.txt"), "w") as f:
            f.write("date=2026-08-03T10:00:00Z\n")
            f.write("apply=1\n")
            f.write("check_existing=0\n")
            f.write("target_prefix=24\n")
            f.write("min_hits=1\n")
        with open(os.path.join(path, "output_ips.txt"), "w") as f:
            f.write("\n".join(ips) + "\n")
        with open(os.path.join(path, "generiek_blocked_candidate_ips.txt"), "w") as f:
            f.write("\n".join(blocked_ips) + "\n")
        with open(os.path.join(path, "generiek_allowed_non_target_ips.txt"), "w") as f:
            f.write("\n".join(allowed_ips) + "\n")
        with open(os.path.join(path, "aggregated_generiek_subnets.json"), "w") as f:
            json.dump(["1.2.3.0/24"], f)
        with open(os.path.join(path, "generiek_country_report.json"), "w") as f:
            json.dump({"countries": countries}, f)
        return path

    def test_analyze_run_counts_snapshot_files(self):
        path = self.write_run(
            "20260803-100000",
            ["1.2.3.4", "5.6.7.8"],
            ["1.2.3.4 CN Example"],
            ["5.6.7.8 BE Example"],
            {
                "CN": {"total": 1, "blocked": 1, "allowed": 0},
                "BE": {"total": 1, "blocked": 0, "allowed": 1},
            },
        )

        run = analyze_runs.analyze_run(path)

        self.assertEqual(run["input_ips"], 2)
        self.assertEqual(run["blocked_candidate_ips"], 1)
        self.assertEqual(run["allowed_ips"], 1)
        self.assertEqual(run["candidate_subnets"], 1)
        self.assertEqual(run["countries"]["CN"]["blocked"], 1)

    def test_writes_text_and_json_analysis_for_multiple_runs(self):
        self.write_run(
            "20260803-100000",
            ["1.2.3.4", "5.6.7.8"],
            ["1.2.3.4 CN Example"],
            ["5.6.7.8 BE Example"],
            {"CN": {"total": 1, "blocked": 1, "allowed": 0}},
        )
        self.write_run(
            "20260803-110000",
            ["1.2.3.4", "9.9.9.9"],
            ["9.9.9.9 CN Example"],
            ["1.2.3.4 BE Example"],
            {"CN": {"total": 1, "blocked": 1, "allowed": 0}},
        )
        runs = [analyze_runs.analyze_run(path) for path in analyze_runs.iter_runs(self.runs_dir)]
        text_path = os.path.join(self.tmpdir, "analysis.txt")
        json_path = os.path.join(self.tmpdir, "analysis.json")

        analyze_runs.write_text(text_path, runs, 10)
        analyze_runs.write_json(json_path, runs)

        with open(text_path) as f:
            text = f.read()
            self.assertIn("delta vs previous: new_ips=1 repeated_ips=1", text)
        with open(json_path) as f:
            data = json.load(f)
            self.assertEqual(data["totals"]["runs"], 2)
            self.assertEqual(data["totals"]["unique_ips_seen"], 3)


if __name__ == "__main__":
    unittest.main()
