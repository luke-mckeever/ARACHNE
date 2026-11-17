"""Exposure Results source (osint/modules/exposure.py). Offline: no network. Run: python -m unittest discover -s tests"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from osint import modules  # noqa: F401,E402  (registers modules)
from osint.modules import exposure as X  # noqa: E402
from osint.registry import MODULES, NotFound, Result  # noqa: E402

CVEDB = {
    "CVE-2021-41773": {"cvss_v3": 7.5, "epss": 0.94, "ranking_epss": 0.999, "kev": True, "ransomware_campaign": "Known",
                       "summary": "Path traversal", "published_time": "2021-10-05T09:15:07"},
    "CVE-2019-0211": {"cvss": 7.8, "cvss_v3": 7.8, "epss": 0.4, "kev": False, "summary": "Privilege escalation"},
    "CVE-2024-38476": {"cvss_v3": 9.8, "epss": 0.02, "kev": False, "ransomware_campaign": "Unknown", "summary": "Critical flaw"},
}


class FakeCtx:
    def __init__(self, internetdb, dns=None):
        self.internetdb, self.dns_answers, self.calls = internetdb, dns or {}, []

    def dns(self, host, rtype):
        return 0, self.dns_answers.get(rtype, [])

    def get_json(self, url, **kw):
        self.calls.append(url)
        if "internetdb.shodan.io" in url:
            ip = url.rsplit("/", 1)[1]
            if ip not in self.internetdb:
                raise NotFound("No information available")
            return self.internetdb[ip]
        cid = url.rsplit("/", 1)[1]
        if cid in CVEDB:
            return CVEDB[cid]
        raise NotFound("Not Found")


class Ent:
    def __init__(self, t, v):
        self.type, self.value = t, v


def run(ctx, t, v):
    X.CVE_CACHE.clear()
    r = Result()
    MODULES["exposure"].fn(Ent(t, v), ctx, r)
    return r


class ExposureTest(unittest.TestCase):
    def test_ip_ranked_kev_first(self):
        ctx = FakeCtx({"203.0.113.5": {"ports": [443, 80, 3389], "cpes": [], "tags": [],
                                       "vulns": ["CVE-2019-0211", "CVE-2024-38476", "CVE-2021-41773", "CVE-2099-0001"]}})
        r = run(ctx, "ipv4", "203.0.113.5")
        h = r.data["hosts"][0]
        self.assertEqual(h["ports"], [80, 443, 3389])
        self.assertEqual(h["vulns"], ["CVE-2021-41773", "CVE-2019-0211", "CVE-2024-38476", "CVE-2099-0001"])
        self.assertTrue(r.data["cves"]["CVE-2021-41773"]["ransomware"])
        self.assertEqual(r.data["unranked"], 1)
        self.assertIn("kev-vuln", r.tags)
        self.assertIsNone(r.verdict)

    def test_domain_uses_public_ips_only(self):
        ctx = FakeCtx({"93.184.215.9": {"ports": [22, 443], "vulns": []}},
                      {"A": [(5, "cdn.example."), (1, "10.0.0.8"), (1, "93.184.215.9")]})
        r = run(ctx, "domain", "example.org")
        self.assertEqual([h["ip"] for h in r.data["hosts"]], ["93.184.215.9"])
        self.assertFalse(any("10.0.0.8" in u for u in ctx.calls))

    def test_unknown_ip_is_not_an_error(self):
        r = run(FakeCtx({}), "ipv4", "192.0.2.44")
        self.assertFalse(r.data["hosts"][0]["known"])
        self.assertEqual(r.message, "Shodan has no record of open ports here")

    def test_at_most_40_ranked(self):
        vulns = [f"CVE-2020-{1000 + i}" for i in range(70)]
        ctx = FakeCtx({"203.0.113.77": {"ports": [80], "vulns": vulns}})
        r = run(ctx, "ipv4", "203.0.113.77")
        self.assertEqual(len([u for u in ctx.calls if "cvedb" in u]), 40)
        self.assertEqual(r.data["unranked"], 70)   # none known to the fake CVEDB

    def test_private_url_host_refused(self):
        with self.assertRaises(NotFound):
            run(FakeCtx({}), "url", "http://192.168.1.1/admin")


if __name__ == "__main__":
    unittest.main()
