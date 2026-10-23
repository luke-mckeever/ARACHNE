"""ASN, CVE and malware-family modules."""
import urllib.parse

from ..registry import NotFound, module
from .filehash import add_ioc


@module("ripestat_asn", "RIPEstat ASN", types=["asn"], provider="ripestat", rate=60, category="Network & Geo",
        sample="AS15169", desc="AS holder, announced prefixes and neighbours (free).")
def ripestat_asn(e, ctx, r):
    ov = ctx.get_json("https://stat.ripe.net/data/as-overview/data.json", params={"resource": e.value})["data"]
    if not ov.get("holder"):
        raise NotFound("Unknown ASN")
    r.kv("Holder", ov.get("holder"))
    r.kv("Announced", ov.get("announced"))
    r.add("org", ov["holder"].split(" - ")[-1] if " - " in ov["holder"] else ov["holder"], "operated_by")
    try:
        pf = ctx.get_json("https://stat.ripe.net/data/announced-prefixes/data.json", params={"resource": e.value})["data"]
        prefixes = [p.get("prefix") for p in pf.get("prefixes", [])]
        r.kv("Announced prefixes", len(prefixes))
        r.table("Prefixes", ["Prefix"], [[p] for p in prefixes], limit=100)
    except Exception:
        pass
    r.link("bgp.he.net", f"https://bgp.he.net/{e.value}")
    r.data = ov


def _kev(resp):
    j = resp.json()
    return {v["cveID"]: v for v in j.get("vulnerabilities", [])}


@module("cve", "CVE Details (NVD + CISA KEV)", types=["cve"], keys=["nvd"], provider="nvd", rate=10,
        category="Vulnerability", sample="CVE-2021-44228",
        desc="CVSS score, description, affected products and whether it is in CISA's Known Exploited list.")
def cve(e, ctx, r):
    k = ctx.key("nvd")
    d = ctx.get_json("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": e.value},
                     headers={"apiKey": k} if k else None)
    vulns = d.get("vulnerabilities") or []
    if not vulns:
        raise NotFound("Unknown CVE")
    c = vulns[0]["cve"]
    desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
    score, sev = None, None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = (c.get("metrics") or {}).get(key)
        if m:
            cd = m[0].get("cvssData", {})
            score, sev = cd.get("baseScore"), cd.get("baseSeverity") or m[0].get("baseSeverity")
            break
    r.kv("CVSS", f"{score} ({sev})" if score is not None else None)
    r.kv("Published", (c.get("published") or "")[:10])
    r.kv("Status", c.get("vulnStatus"))
    r.kv("Description", desc[:600])
    r.kv("CWE", [x["value"] for w in c.get("weaknesses", []) for x in w.get("description", [])][:4])
    try:
        kev = ctx.feed("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", _kev,
                   ttl=86400).get(e.value)
    except Exception:
        kev = None
    if kev:
        r.kv("CISA KEV", f"Yes - added {kev.get('dateAdded')}, ransomware use: {kev.get('knownRansomwareCampaignUse')}")
        r.tag("known-exploited")
        r.set_verdict("malicious", 90)
    elif score is not None and score >= 9:
        r.set_verdict("suspicious", int(score * 10))
    if sev:
        r.tag(sev.lower())
    r.table("References", ["URL", "Tags"], [[x.get("url"), ", ".join(x.get("tags", []))] for x in c.get("references", [])], limit=30)
    r.link("NVD", f"https://nvd.nist.gov/vuln/detail/{e.value}")
    r.data = {"id": c.get("id"), "published": c.get("published"), "metrics": c.get("metrics"), "kev": kev}


@module("bazaar_family", "MalwareBazaar Family Samples", types=["malware"], provider="abusech", keys=["abusech"],
        key_required=True, rate=60, pivot=False, category="Malware", sample="AgentTesla",
        desc="Recent samples tagged with this malware family/signature.")
def bazaar_family(e, ctx, r):
    d = ctx.post_json("https://mb-api.abuse.ch/api/v1/", data={"query": "get_siginfo", "signature": e.value, "limit": 50},
                      headers={"Auth-Key": ctx.need("abusech")})
    if d.get("query_status") != "ok":
        raise NotFound(f"No samples ({d.get('query_status')})")
    s = d.get("data") or []
    r.set_verdict("malicious")
    r.kv("Recent samples", len(s))
    for x in s[:min(ctx.max_children, 10)]:
        r.add("hash", x.get("sha256_hash"), "sample", pivot=False)
    r.table("Samples", ["First seen", "SHA256", "File name", "Type"], [
        [x.get("first_seen"), x.get("sha256_hash"), x.get("file_name"), x.get("file_type")] for x in s])
    r.link("MalwareBazaar", f"https://bazaar.abuse.ch/browse.php?search=signature%3A{urllib.parse.quote(e.value)}")


@module("threatfox_family", "ThreatFox Family IOCs", types=["malware"], provider="abusech", keys=["abusech"],
        key_required=True, rate=60, pivot=False, category="Malware", sample="Cobalt Strike",
        desc="Recent C2 / IOCs reported for this malware family.")
def threatfox_family(e, ctx, r):
    d = ctx.post_json("https://threatfox-api.abuse.ch/api/v1/",
                      json_body={"query": "malwareinfo", "malware": e.value, "limit": 50},
                      headers={"Auth-Key": ctx.need("abusech")})
    if d.get("query_status") != "ok" or not isinstance(d.get("data"), list):
        raise NotFound(f"No IOCs ({d.get('query_status')})")
    iocs = d["data"]
    r.set_verdict("malicious")
    r.kv("Recent IOCs", len(iocs))
    for i in iocs[:min(ctx.max_children, 10)]:
        add_ioc(r, i.get("ioc"), i.get("ioc_type"), "family_ioc")
    r.table("IOCs", ["IOC", "Type", "Threat", "Confidence", "First seen"], [
        [i.get("ioc"), i.get("ioc_type"), i.get("threat_type"), i.get("confidence_level"), i.get("first_seen")] for i in iocs])
