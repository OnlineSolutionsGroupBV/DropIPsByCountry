import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import audit_generiek_subnets as audit


class AuditGeneriekSubnetsTests(unittest.TestCase):
    def test_ip_network_accepts_bytes_cidr(self):
        self.assertEqual(str(audit.ip_network(b"31.27.219.0/24", strict=False)), "31.27.219.0/24")

    def test_load_network_list_accepts_valid_24_cidrs(self):
        handle, path = tempfile.mkstemp()
        os.close(handle)
        try:
            with open(path, "w") as f:
                json.dump(["31.27.219.0/24", "36.95.114.0/24"], f)

            networks, invalid = audit.load_network_list(path)

            self.assertEqual([str(net) for net in networks], ["31.27.219.0/24", "36.95.114.0/24"])
            self.assertEqual(invalid, [])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
