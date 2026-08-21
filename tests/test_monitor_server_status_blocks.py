import os
import shutil
import sys
import tempfile
import unittest
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import monitor_server_status_blocks as monitor


class MonitorServerStatusBlocksTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_parse_busy_requests(self):
        self.assertEqual(
            monitor.parse_busy_requests("149 requests currently being processed, 56 idle workers"),
            149,
        )

    def test_parse_busy_requests_returns_none_when_missing(self):
        self.assertIsNone(monitor.parse_busy_requests("Server status unavailable"))

    def test_lock_prevents_second_run(self):
        lock_dir = os.path.join(self.tmpdir, "lock")

        self.assertTrue(monitor.acquire_lock(lock_dir, 7200))
        self.assertFalse(monitor.acquire_lock(lock_dir, 7200))

        monitor.release_lock(lock_dir)
        self.assertFalse(os.path.exists(lock_dir))

    def test_main_prints_start_timestamp(self):
        status = os.path.join(self.tmpdir, "status.txt")
        input_file = os.path.join(self.tmpdir, "input.txt")
        snapshot = os.path.join(self.tmpdir, "snapshot.txt")
        lock_dir = os.path.join(self.tmpdir, "lock")
        with open(status, "w") as f:
            f.write("149 requests currently being processed, 56 idle workers")

        original_timestamp = monitor.current_run_timestamp
        original_stdout = sys.stdout
        output = StringIO()
        monitor.current_run_timestamp = lambda: "2026-08-21 12:34:56 CEST"
        sys.stdout = output
        try:
            rc = monitor.main_with_args([
                "--status-file", status,
                "--threshold", "200",
                "--input-file", input_file,
                "--snapshot-file", snapshot,
                "--lock-dir", lock_dir,
            ])
        finally:
            monitor.current_run_timestamp = original_timestamp
            sys.stdout = original_stdout

        self.assertEqual(rc, 0)
        self.assertIn("Started at: 2026-08-21 12:34:56 CEST", output.getvalue())

    def test_main_below_threshold_does_not_run_prepare(self):
        status = os.path.join(self.tmpdir, "status.txt")
        input_file = os.path.join(self.tmpdir, "input.txt")
        snapshot = os.path.join(self.tmpdir, "snapshot.txt")
        lock_dir = os.path.join(self.tmpdir, "lock")
        with open(status, "w") as f:
            f.write("149 requests currently being processed, 56 idle workers")

        original = monitor.run_prepare
        calls = []
        monitor.run_prepare = calls.append
        try:
            rc = monitor.main_with_args([
                "--status-file", status,
                "--threshold", "200",
                "--input-file", input_file,
                "--snapshot-file", snapshot,
                "--lock-dir", lock_dir,
            ])
        finally:
            monitor.run_prepare = original

        self.assertEqual(rc, 0)
        self.assertEqual(calls, [])
        self.assertFalse(os.path.exists(input_file))

    def test_main_above_threshold_writes_input_and_runs_prepare(self):
        status = os.path.join(self.tmpdir, "status.txt")
        input_file = os.path.join(self.tmpdir, "input.txt")
        snapshot = os.path.join(self.tmpdir, "snapshot.txt")
        lock_dir = os.path.join(self.tmpdir, "lock")
        with open(status, "w") as f:
            f.write("201 requests currently being processed, 10 idle workers\n1.2.3.4")

        original = monitor.run_prepare
        calls = []

        def fake_run_prepare(script, python_bin, apply, extra_env):
            calls.append((script, python_bin, apply, extra_env))

        monitor.run_prepare = fake_run_prepare
        try:
            rc = monitor.main_with_args([
                "--status-file", status,
                "--threshold", "200",
                "--input-file", input_file,
                "--snapshot-file", snapshot,
                "--lock-dir", lock_dir,
                "--dry-run",
                "--python-bin", "python2",
                "--env", "POLICY_MODE=1",
            ])
        finally:
            monitor.run_prepare = original

        self.assertEqual(rc, 0)
        self.assertEqual(calls, [("./run_prepare_generiek_blocks.sh", "python2", False, ["POLICY_MODE=1"])])
        with open(input_file) as f:
            self.assertIn("1.2.3.4", f.read())
        with open(snapshot) as f:
            self.assertIn("201 requests", f.read())

    def test_main_passes_insecure_to_fetch_url(self):
        input_file = os.path.join(self.tmpdir, "input.txt")
        snapshot = os.path.join(self.tmpdir, "snapshot.txt")
        lock_dir = os.path.join(self.tmpdir, "lock")
        original_fetch = monitor.fetch_url
        original_run = monitor.run_prepare
        calls = []

        def fake_fetch(url, timeout, insecure=False):
            calls.append((url, timeout, insecure))
            return "149 requests currently being processed, 56 idle workers"

        monitor.fetch_url = fake_fetch
        monitor.run_prepare = lambda *args: None
        try:
            rc = monitor.main_with_args([
                "--url", "https://example.test/server-status",
                "--threshold", "200",
                "--input-file", input_file,
                "--snapshot-file", snapshot,
                "--lock-dir", lock_dir,
                "--insecure",
            ])
        finally:
            monitor.fetch_url = original_fetch
            monitor.run_prepare = original_run

        self.assertEqual(rc, 0)
        self.assertEqual(calls, [("https://example.test/server-status", 30, True)])


if __name__ == "__main__":
    unittest.main()
