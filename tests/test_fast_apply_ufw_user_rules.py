import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import fast_apply_ufw_user_rules as fast_ufw


class FastApplyUfwUserRulesTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def user_rules_text(self):
        return """*filter
:ufw-user-input - [0:0]
### tuple ### deny any any 0.0.0.0/0 any 111.42.0.0/16 in
-A ufw-user-input -s 111.42.0.0/16 -j DROP

### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp -m tcp --dport 80 -j ACCEPT
COMMIT
"""

    def test_generate_ufw_deny_block_matches_user_rules_shape(self):
        self.assertEqual(fast_ufw.generate_ufw_deny_block("123.201.0.0/16"), [
            "### tuple ### deny any any 0.0.0.0/0 any 123.201.0.0/16 in",
            "-A ufw-user-input -s 123.201.0.0/16 -j DROP",
            "",
        ])

    def test_build_new_user_rules_inserts_before_allow_tuple(self):
        new_text, anchor = fast_ufw.build_new_user_rules_text(
            self.user_rules_text(),
            ["123.201.0.0/16"],
        )

        new_drop = new_text.index("-A ufw-user-input -s 123.201.0.0/16 -j DROP")
        allow = new_text.index("-A ufw-user-input -p tcp -m tcp --dport 80 -j ACCEPT")
        self.assertLess(new_drop, allow)
        self.assertIn("### tuple ### deny any any 0.0.0.0/0 any 123.201.0.0/16 in", new_text)
        self.assertEqual(anchor, 5)

    def test_parse_user_rules_denies_reads_existing_source_drops(self):
        parsed = [str(net) for net in fast_ufw.parse_user_rules_denies(self.user_rules_text())]

        self.assertEqual(parsed, ["111.42.0.0/16"])

    def test_build_new_user_rules_fails_without_commit(self):
        with self.assertRaises(RuntimeError):
            fast_ufw.build_new_user_rules_text("*filter\n:ufw-user-input - [0:0]\n", ["1.2.3.0/24"])

    def test_build_new_user_rules_with_no_cidrs_preserves_text(self):
        original = self.user_rules_text()
        new_text, _ = fast_ufw.build_new_user_rules_text(original, [])

        self.assertEqual(new_text, original)


if __name__ == "__main__":
    unittest.main()
