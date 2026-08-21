import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import build_fast_geo_ranges as builder
import fast_geo_lookup as lookup
import local_ip_country as local_geo


class FastGeoLookupTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def path(self, name):
        return os.path.join(self.tmpdir, name)

    def write_csv(self):
        path = self.path("ipinfo_lite.csv")
        with open(path, "w") as f:
            f.write("network,country,country_code,continent,continent_code,asn,as_name,as_domain\n")
            f.write("123.201.0.0/16,India,IN,Asia,AS,AS12345,Example Network,example.test\n")
            f.write("2001:db8::/32,Example,EX,Nowhere,NA,AS0,IPv6 Network,example.test\n")
            f.write("bad-value,Bad,BD,Nowhere,NA,AS0,Bad Network,example.test\n")
        return path

    def test_build_ranges_and_lookup_ip(self):
        csv_path = self.write_csv()
        ranges_path = self.path("ranges.tsv")
        meta_path = self.path("ranges.meta.json")

        meta = builder.build_ranges(csv_path, ranges_path, meta_path)
        starts, ranges = local_geo.load_ranges(ranges_path)
        row = local_geo.lookup_ip("123.201.10.20", starts, ranges)

        self.assertEqual(meta["ipv4_ranges"], 1)
        self.assertEqual(meta["skipped_ipv6"], 1)
        self.assertEqual(meta["skipped_invalid"], 1)
        self.assertEqual(row["country"], "IN")
        self.assertEqual(row["asn"], "AS12345")
        self.assertEqual(row["network"], "123.201.0.0/16")

    def test_fast_geo_lookup_updates_geo_data_without_overwriting_cache(self):
        csv_path = self.write_csv()
        ranges_path = self.path("ranges.tsv")
        builder.build_ranges(csv_path, ranges_path, self.path("ranges.meta.json"))

        input_path = self.path("output.txt")
        geo_path = self.path("geo_data.json")
        with open(input_path, "w") as f:
            f.write("123.201.10.20\n")
            f.write("1.1.1.1\n")
        with open(geo_path, "w") as f:
            json.dump({"1.1.1.1": {"country": "AU", "org": "Existing"}}, f)

        stats = lookup.update_geo_data(input_path, geo_path, ranges_path)

        with open(geo_path) as f:
            data = json.load(f)
        self.assertEqual(stats["cache_hits"], 1)
        self.assertEqual(stats["local_hits"], 1)
        self.assertEqual(data["123.201.10.20"]["country"], "IN")
        self.assertEqual(data["1.1.1.1"]["country"], "AU")
        self.assertEqual(data["123.201.10.20"]["source"], "local_range")

    def test_build_ranges_accepts_start_end_ip_csv(self):
        csv_path = self.path("country_asn.csv")
        ranges_path = self.path("ranges.tsv")
        with open(csv_path, "w") as f:
            f.write("start_ip,end_ip,country,country_name,continent,continent_name,asn,as_name,as_domain\n")
            f.write('1.1.1.0,1.1.1.255,AU,Australia,OC,Oceania,AS13335,"Cloudflare, Inc.",cloudflare.com\n')

        meta = builder.build_ranges(csv_path, ranges_path, self.path("ranges.meta.json"))
        starts, ranges = local_geo.load_ranges(ranges_path)
        row = local_geo.lookup_ip("1.1.1.1", starts, ranges)

        self.assertEqual(meta["ipv4_ranges"], 1)
        self.assertEqual(row["country"], "AU")
        self.assertEqual(row["asn"], "AS13335")
        self.assertEqual(row["network"], "1.1.1.0-1.1.1.255")


if __name__ == "__main__":
    unittest.main()
