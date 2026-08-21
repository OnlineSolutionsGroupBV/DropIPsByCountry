import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import cache_crawler_ips as crawler


class FakeResponse(object):
    def __init__(self, body):
        self.body = body
        self.closed = False

    def read(self):
        return self.body

    def close(self):
        self.closed = True


class CacheCrawlerIpsTests(unittest.TestCase):
    def test_fetch_json_retries_certificate_verify_failure_unverified(self):
        original_urlopen = crawler.urlopen
        original_context = crawler.ssl._create_unverified_context
        calls = []
        context = object()

        def fake_context():
            return context

        def fake_urlopen(req, timeout=0, context=None):
            calls.append((timeout, context))
            if len(calls) == 1:
                raise crawler.URLError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
            return FakeResponse(b'{"prefixes": ["1.2.3.0/24"]}')

        crawler.urlopen = fake_urlopen
        crawler.ssl._create_unverified_context = fake_context
        try:
            data = crawler.fetch_json("https://example.test/crawlers.json")
        finally:
            crawler.urlopen = original_urlopen
            crawler.ssl._create_unverified_context = original_context

        self.assertEqual(data, {"prefixes": ["1.2.3.0/24"]})
        self.assertEqual(calls, [(30, None), (30, context)])

    def test_fetch_json_does_not_retry_non_certificate_error(self):
        original_urlopen = crawler.urlopen
        calls = []

        def fake_urlopen(req, timeout=0, context=None):
            calls.append((timeout, context))
            raise crawler.URLError("connection refused")

        crawler.urlopen = fake_urlopen
        try:
            with self.assertRaises(crawler.URLError):
                crawler.fetch_json("https://example.test/crawlers.json")
        finally:
            crawler.urlopen = original_urlopen

        self.assertEqual(calls, [(30, None)])

    def test_unverified_urlopen_uses_https_handler_when_context_arg_unsupported(self):
        original_urlopen = crawler.urlopen
        original_build_opener = crawler.build_opener
        original_https_handler = crawler.HTTPSHandler
        original_context = crawler.ssl._create_unverified_context
        context = object()
        calls = []

        class FakeHandler(object):
            def __init__(self, context=None):
                calls.append(("handler", context))

        class FakeOpener(object):
            def open(self, req, timeout=0):
                calls.append(("open", timeout))
                return FakeResponse(b"{}")

        def fake_urlopen(req, timeout=0, context=None):
            calls.append(("urlopen", timeout, context))
            raise TypeError("urlopen() got an unexpected keyword argument 'context'")

        crawler.urlopen = fake_urlopen
        crawler.build_opener = lambda handler: (calls.append(("build", handler)) or FakeOpener())
        crawler.HTTPSHandler = FakeHandler
        crawler.ssl._create_unverified_context = lambda: context
        try:
            response = crawler.urlopen_without_certificate_check(object(), timeout=30)
        finally:
            crawler.urlopen = original_urlopen
            crawler.build_opener = original_build_opener
            crawler.HTTPSHandler = original_https_handler
            crawler.ssl._create_unverified_context = original_context

        self.assertEqual(response.read(), b"{}")
        self.assertEqual(calls[0], ("urlopen", 30, context))
        self.assertEqual(calls[1], ("handler", context))
        self.assertEqual(calls[3], ("open", 30))


if __name__ == "__main__":
    unittest.main()
