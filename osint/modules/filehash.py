"""File hash modules."""
from .. import entities as E
from ..registry import NotFound, module

H = ["hash"]


def add_ioc(r, ioc, ioc_type, rel, via=None):
    """Add a ThreatFox/abuse.ch style IOC string to the result."""
    if not ioc:
        return
    if ioc_type in ("ip:port",) or (":" in ioc and ioc.count(":") == 1 and ioc.split(":")[0].replace(".", "").isdigit()):
        r.add("ipv4", ioc.rsplit(":", 1)[0], rel, via=via)
    elif ioc_type == "domain":
        r.add("domain", ioc, rel, via=via)
    elif ioc_type == "url":
        r.add("url", ioc, rel, via=via)
    elif ioc_type in ("md5_hash", "sha1_hash", "sha256_hash"):
        r.add("hash", ioc, rel, via=via)
    else:
        t, v = E.detect(ioc)
        if t:
            r.add(t, v, rel, via=via)


@module("malwarebazaar", "MalwareBazaar", types=H, provider="abusech", keys=["abusech"], key_required=True,
        rate=60, category="Malware", sample="094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d",
        desc="abuse.ch MalwareBazaar sample info: family, tags, file names, delivery, vendor intel.")
def malwarebazaar(e, ctx, r):
    d = ctx.post_json("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": e.value},
                      headers={"Auth-Key": ctx.need("abusech")})
    if d.get("query_status") != "ok":
        raise NotFound(f"Not in MalwareBazaar ({d.get('query_status')})")
    s = d["data"][0]
    r.set_verdict("malicious", 95)
    r.kv("Signature", s.get("signature"))
    r.kv("File name", s.get("file_name"))
    r.kv("File type", f"{s.get('file_type')} ({s.get('file_type_mime')})")
    r.kv("Size", s.get("file_size"))
    r.kv("First seen", s.get("first_seen"))
    r.kv("Last seen", s.get("last_seen"))
    r.kv("Delivery", s.get("delivery_method"))
    r.kv("Origin country", s.get("origin_country"))
    r.kv("Reporter", s.get("reporter"))
    r.kv("Imphash", s.get("imphash"))
    r.kv("SSDeep", s.get("ssdeep"))
    r.tag(*(s.get("tags") or []))
    if s.get("signature"):
        r.add("malware", s["signature"], "family")
    for k in ("sha256_hash", "md5_hash", "sha1_hash"):
        if s.get(k) and s[k] != e.value:
            r.add("hash", s[k], "same_file", pivot=False)
    vi = s.get("vendor_intel") or {}
    rows = []
    for vendor, info in vi.items():
        items = info if isinstance(info, list) else [info]
        for it in items:
            if not isinstance(it, dict):
                continue
            fam = it.get("malware_family") or it.get("detection") or it.get("verdict") or it.get("result")
            link = it.get("analysis_url") or it.get("link") or it.get("report_link")
            rows.append([vendor, fam, it.get("score") or it.get("status"), link])
            if link:
                r.link(vendor, link)
            for c2 in it.get("c2", []) or []:
                t, v = E.detect(c2)
                if t:
                    r.add(t, v, "c2")
    r.table("Vendor intel", ["Vendor", "Family / verdict", "Score", "Report"], rows)
    yara = s.get("yara_rules") or []
    r.table("YARA matches", ["Rule", "Author", "Description"], [[y.get("rule_name"), y.get("author"), y.get("description")] for y in yara])
    r.link("MalwareBazaar", f"https://bazaar.abuse.ch/sample/{s.get('sha256_hash')}/")
    r.data = s


@module("threatfox_hash", "ThreatFox (hash)", types=H, provider="abusech", keys=["abusech"], key_required=True,
        rate=60, category="Malware", sample="2151c4b970eff0071948dbbc19066aa4",
        desc="IOCs (C2 servers, payload URLs) that ThreatFox links to this sample.")
def threatfox_hash(e, ctx, r):
    d = ctx.post_json("https://threatfox-api.abuse.ch/api/v1/", json_body={"query": "search_hash", "hash": e.value},
                      headers={"Auth-Key": ctx.need("abusech")})
    if d.get("query_status") != "ok" or not isinstance(d.get("data"), list):
        raise NotFound(f"No IOCs ({d.get('query_status')})")
    iocs = d["data"]
    r.set_verdict("malicious", 90)
    r.kv("Linked IOCs", len(iocs))
    for i in iocs[:ctx.max_children]:
        add_ioc(r, i.get("ioc"), i.get("ioc_type"), "c2" if "c2" in (i.get("threat_type") or "") else "ioc")
        if i.get("malware_printable"):
            r.add("malware", i["malware_printable"], "family")
        r.tag(*(i.get("tags") or [])[:3])
    r.table("IOCs", ["IOC", "Type", "Threat", "Malware", "Confidence", "First seen"], [
        [i.get("ioc"), i.get("ioc_type"), i.get("threat_type"), i.get("malware_printable"),
         i.get("confidence_level"), i.get("first_seen")] for i in iocs])
    r.data = iocs


@module("urlhaus_payload", "URLhaus Payload", types=H, provider="abusech", keys=["abusech"], key_required=True,
        rate=60, category="Malware", sample="12c8aec5766ac3e6f26f2505e2f4a8f2",
        desc="URLs that served this payload (MD5 / SHA256).")
def urlhaus_payload(e, ctx, r):
    kind = E.hash_kind(e.value)
    if kind not in ("md5", "sha256"):
        raise NotFound("URLhaus supports MD5/SHA256 only")
    d = ctx.post_json("https://urlhaus-api.abuse.ch/v1/payload/", data={f"{kind}_hash": e.value},
                      headers={"Auth-Key": ctx.need("abusech")})
    if d.get("query_status") != "ok":
        raise NotFound(f"Not in URLhaus ({d.get('query_status')})")
    r.set_verdict("malicious", 90)
    r.kv("File type", d.get("file_type"))
    r.kv("Signature", d.get("signature"))
    r.kv("First seen", d.get("firstseen"))
    r.kv("Times served", d.get("url_count"))
    if d.get("signature"):
        r.add("malware", d["signature"], "family")
    urls = d.get("urls") or []
    for u in urls[:ctx.max_children]:
        r.add("url", u.get("url"), "served_from")
    r.table("Served from", ["URL", "Status", "First seen"], [[u.get("url"), u.get("url_status"), u.get("firstseen")] for u in urls])
    d.pop("urls", None)
    r.data = d


@module("circl_hashlookup", "CIRCL hashlookup", types=H, provider="circl", rate=60, category="Malware",
        sample="8ED4B4ED952526D89899E723F3488DE4", desc="Known-good file lookup (NSRL & friends) - flags benign system files.")
def circl_hashlookup(e, ctx, r):
    kind = E.hash_kind(e.value)
    d = ctx.get_json(f"https://hashlookup.circl.lu/lookup/{kind}/{e.value}")
    r.data = d
    r.kv("File name", d.get("FileName"))
    r.kv("Product", d.get("ProductName") or (d.get("ProductCode") or {}).get("ProductName"))
    r.kv("Size", d.get("FileSize"))
    r.kv("Source", d.get("source") or d.get("db"))
    r.kv("Trust", d.get("hashlookup:trust"))
    r.tag("known-file")
    r.set_verdict("clean")


@module("hybrid", "Hybrid Analysis", types=H, keys=["hybrid"], key_required=True, rate=20, category="Malware",
        sample="094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d",
        desc="Falcon Sandbox verdict, threat score, family and network indicators.")
def hybrid(e, ctx, r):
    hdr = {"api-key": ctx.need("hybrid"), "User-Agent": "Falcon Sandbox", "Accept": "application/json"}
    rep = None
    if E.hash_kind(e.value) == "sha256":
        rep = ctx.get_json(f"https://www.hybrid-analysis.com/api/v2/overview/{e.value}", headers=hdr)
    else:
        res = ctx.get_json("https://www.hybrid-analysis.com/api/v2/search/hash", params={"hash": e.value}, headers=hdr)
        res = res.get("reports") if isinstance(res, dict) else res
        if not res:
            raise NotFound("No reports")
        rep = res[0]
    r.data = rep
    verdict = rep.get("verdict")
    r.kv("Verdict", verdict)
    r.kv("Threat score", rep.get("threat_score"))
    r.kv("Family", rep.get("vx_family"))
    r.kv("Type", rep.get("type_short") or rep.get("type"))
    r.kv("Submit name", rep.get("submit_name") or rep.get("last_file_name"))
    r.tag(*(rep.get("tags") or [])[:8])
    if verdict == "malicious":
        r.set_verdict("malicious", rep.get("threat_score"))
    elif verdict == "suspicious":
        r.set_verdict("suspicious", rep.get("threat_score"))
    elif verdict in ("no specific threat", "whitelisted"):
        r.set_verdict("clean")
    if rep.get("vx_family"):
        r.add("malware", rep["vx_family"], "family")
    for d in (rep.get("domains") or [])[:ctx.max_children]:
        r.add("domain", d, "contacted")
    for h in (rep.get("hosts") or rep.get("compromised_hosts") or [])[:ctx.max_children]:
        r.add("ipv4", h, "contacted")
    sha = rep.get("sha256") or e.value
    r.link("Hybrid Analysis", f"https://www.hybrid-analysis.com/sample/{sha}")
