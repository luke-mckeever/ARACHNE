"""Multi-type threat-intel platforms: VirusTotal, OTX, ThreatFox, Pulsedive, urlscan, Mnemonic PDNS."""
import base64
import urllib.parse

from .. import entities as E
from ..registry import NotFound, module, vt_url_id
from ..util import friendly_error, ts
from .filehash import add_ioc

ALL = ["ipv4", "ipv6", "domain", "url", "hash"]
VT = "https://www.virustotal.com/api/v3"


def _vt_stats(r, a):
    st = a.get("last_analysis_stats") or {}
    mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
    total = sum(v for v in st.values() if isinstance(v, int))
    r.kv("Detections", f"{mal} malicious / {sus} suspicious / {total} engines")
    r.kv("Reputation", a.get("reputation"))
    if mal >= 3:
        r.set_verdict("malicious", min(100, 40 + mal * 4))
    elif mal >= 1 or sus >= 2:
        r.set_verdict("suspicious", 30 + mal * 10)
    elif total:
        r.set_verdict("clean", 0)
    res = a.get("last_analysis_results") or {}
    rows = [[k, v.get("category"), v.get("result")] for k, v in res.items() if v.get("category") in ("malicious", "suspicious")]
    r.table("Flagging engines", ["Engine", "Category", "Result"], rows)
    r.tag(*(a.get("tags") or [])[:8])


def _vt_rel(ctx, path, rel, limit):
    try:
        d = ctx.get_json(f"{VT}/{path}/{rel}", params={"limit": limit},
                         headers={"x-apikey": ctx.key("virustotal")})
        return d.get("data") or []
    except Exception:
        return []


@module("virustotal", "VirusTotal", types=ALL, keys=["virustotal"], key_required=True, rate=4,
        category="Threat Intel", sample="8.8.8.8",
        desc="Multi-AV detections, reputation, passive DNS, subdomains and related files.",
        options=[{"id": "relationships", "label": "Fetch relationships (resolutions, subdomains, contacted hosts) - extra API calls",
                  "type": "bool", "default": True}])
def virustotal(e, ctx, r):
    hdr = {"x-apikey": ctx.need("virustotal")}
    rel_on = ctx.opt("relationships")
    lim = min(ctx.max_children, 20)
    if e.type in ("ipv4", "ipv6"):
        path = f"ip_addresses/{e.value}"
        gui = f"https://www.virustotal.com/gui/ip-address/{e.value}"
    elif e.type == "domain":
        path = f"domains/{e.value}"
        gui = f"https://www.virustotal.com/gui/domain/{e.value}"
    elif e.type == "url":
        path = f"urls/{vt_url_id(e.value)}"
        gui = f"https://www.virustotal.com/gui/search/{urllib.parse.quote(e.value, safe='')}"
    else:
        path = f"files/{e.value}"
        gui = f"https://www.virustotal.com/gui/file/{e.value}"
    a = ctx.get_json(f"{VT}/{path}", headers=hdr)["data"]["attributes"]
    _vt_stats(r, a)
    r.link("VirusTotal", gui)
    if e.type in ("ipv4", "ipv6"):
        r.kv("AS owner", a.get("as_owner"))
        r.kv("Network", a.get("network"))
        r.kv("Country", a.get("country"))
        if a.get("asn"):
            r.add("asn", a["asn"], "asn", label=f"AS{a['asn']} {a.get('as_owner') or ''}")
        if rel_on:
            res = _vt_rel(ctx, path, "resolutions", 40)
            hosts = [(x.get("attributes") or {}).get("host_name") for x in res]
            if not ctx.shared_hosting(r, hosts):
                for hn in hosts[:lim]:
                    r.add("domain", hn, "vt_resolution")
            for x in _vt_rel(ctx, path, "communicating_files", min(lim, 10)):
                r.add("hash", x.get("id"), "communicating_file", pivot=False)
    elif e.type == "domain":
        r.kv("Registrar", a.get("registrar"))
        r.kv("Created", ts(a.get("creation_date")))
        r.kv("Categories", sorted(set((a.get("categories") or {}).values())))
        ranks = a.get("popularity_ranks") or {}
        r.kv("Popularity", ", ".join(f"{k}: {v.get('rank')}" for k, v in list(ranks.items())[:4]))
        for rec in a.get("last_dns_records") or []:
            if rec.get("type") in ("A", "AAAA"):
                r.add("ipv4", rec.get("value"), "resolves_to")
        if rel_on:
            for x in _vt_rel(ctx, path, "resolutions", lim):
                r.add("ipv4", (x.get("attributes") or {}).get("ip_address"), "vt_resolution")
            for x in _vt_rel(ctx, path, "subdomains", lim):
                r.add("domain", x.get("id"), "subdomain")
            for x in _vt_rel(ctx, path, "communicating_files", min(lim, 10)):
                r.add("hash", x.get("id"), "communicating_file", pivot=False)
    elif e.type == "url":
        r.kv("Title", a.get("title"))
        r.kv("Final URL", a.get("last_final_url"))
        r.kv("HTTP code", a.get("last_http_response_code"))
        r.kv("Categories", sorted(set((a.get("categories") or {}).values())))
        r.kv("First submitted", ts(a.get("first_submission_date")))
        if a.get("last_final_url") and a["last_final_url"] != e.value:
            r.add("url", a["last_final_url"], "redirects_to")
        for u in (a.get("outgoing_links") or [])[:min(lim, 10)]:
            r.add("url", u, "links_to", pivot=False)
    else:
        r.kv("Name", a.get("meaningful_name"))
        r.kv("Type", a.get("type_description"))
        r.kv("Size", a.get("size"))
        r.kv("First seen", ts(a.get("first_submission_date")))
        r.kv("Names", (a.get("names") or [])[:6])
        ptc = a.get("popular_threat_classification") or {}
        r.kv("Threat label", ptc.get("suggested_threat_label"))
        for fam in (ptc.get("popular_threat_name") or [])[:3]:
            r.add("malware", fam.get("value"), "family")
        for k in ("sha256", "md5", "sha1"):
            if a.get(k) and a[k] != e.value:
                r.add("hash", a[k], "same_file", pivot=False)
        if rel_on:
            for x in _vt_rel(ctx, path, "contacted_domains", lim):
                r.add("domain", x.get("id"), "contacted")
            for x in _vt_rel(ctx, path, "contacted_ips", lim):
                r.add("ipv4", x.get("id"), "contacted")
            for x in _vt_rel(ctx, path, "itw_urls", min(lim, 10)):
                r.add("url", (x.get("attributes") or {}).get("url") or x.get("context_attributes", {}).get("url"), "in_the_wild_url")
    a.pop("last_analysis_results", None)
    r.data = a


OTX_PATH = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "url": "url", "hash": "file"}


@module("otx", "AlienVault OTX", types=ALL, keys=["otx"], rate=60, category="Threat Intel", sample="8.8.8.8",
        desc="Open Threat Exchange pulses, malware families, adversaries and passive DNS.",
        options=[{"id": "pdns", "label": "Fetch passive DNS - can be slow for busy IPs (capped at 20s)",
                  "type": "bool", "default": True}])
def otx(e, ctx, r):
    k = ctx.key("otx")
    hdr = {"X-OTX-API-KEY": k} if k else {}
    kind = OTX_PATH[e.type]
    if e.type == "domain" and E.registered_domain(e.value) != e.value:
        kind = "hostname"
    base = f"https://otx.alienvault.com/api/v1/indicators/{kind}/{urllib.parse.quote(e.value, safe='')}"
    g = ctx.get_json(f"{base}/general", headers=hdr, timeout=max(ctx.timeout, 45))
    pi = g.get("pulse_info") or {}
    pulses = pi.get("pulses") or []
    count = pi.get("count", 0)
    validation = [v.get("name") or v.get("source") for v in g.get("validation") or []]
    r.kv("Pulses", count)
    r.kv("Whitelisted by", validation)
    fams = sorted({f.get("display_name") for p in pulses for f in p.get("malware_families", []) or [] if f.get("display_name")})
    adv = sorted({p.get("adversary") for p in pulses if p.get("adversary")})
    r.kv("Malware families", fams[:10])
    r.kv("Adversaries", adv[:10])
    for f in fams[:5]:
        r.add("malware", f, "family")
    for a in adv[:5]:
        r.tag(a)
    tags = {}
    for p in pulses:
        for t in p.get("tags", []) or []:
            tags[t.lower()] = tags.get(t.lower(), 0) + 1
    for t, _ in sorted(tags.items(), key=lambda x: -x[1])[:6]:
        r.tag(t)
    if validation:
        r.set_verdict("clean")
    elif fams or count >= 5:
        r.set_verdict("malicious" if fams and count >= 3 else "suspicious", min(100, 30 + count * 5))
    elif count:
        r.set_verdict("suspicious", 30)
    r.table("Pulses", ["Name", "Author", "Created", "Tags"], [
        [p.get("name"), (p.get("author") or {}).get("username"), (p.get("created") or "")[:10], ", ".join((p.get("tags") or [])[:5])]
        for p in pulses])
    if e.type in ("ipv4", "ipv6", "domain") and ctx.opt("pdns"):
        try:
            pd = ctx.get_json(f"{base}/passive_dns", headers=hdr, timeout=20, retries=0)
            recs = sorted(pd.get("passive_dns") or [], key=lambda x: x.get("last", ""), reverse=True)
            shared = e.type != "domain" and ctx.shared_hosting(r, [x.get("hostname") for x in recs])
            for x in ([] if shared else recs[:ctx.max_children]):
                if e.type == "domain":
                    if x.get("record_type") in ("A", "AAAA"):
                        r.add("ipv4", x.get("address"), "pdns")
                else:
                    r.add("domain", x.get("hostname"), "pdns")
            r.table("Passive DNS", ["Hostname", "Address", "Type", "First", "Last"], [
                [x.get("hostname"), x.get("address"), x.get("record_type"), (x.get("first") or "")[:10], (x.get("last") or "")[:10]]
                for x in recs])
        except Exception as ex:
            r.kv("Passive DNS", "unavailable (" + friendly_error(ex).split(": ")[-1] + ")")
    page = {"ipv4": "ip", "ipv6": "ip", "domain": "domain", "url": "url", "hash": "file"}[e.type]
    r.link("OTX", f"https://otx.alienvault.com/indicator/{page}/{urllib.parse.quote(e.value, safe='')}")
    r.data = {k_: g.get(k_) for k_ in ("indicator", "type", "reputation", "sections", "asn", "country_name", "whois")}


@module("threatfox", "ThreatFox", types=["ipv4", "domain", "url"], provider="abusech", keys=["abusech"],
        key_required=True, rate=60, category="Threat Intel", sample="139.180.203.104",
        desc="abuse.ch ThreatFox IOC database - C2 servers, botnets, malware families.")
def threatfox(e, ctx, r):
    d = ctx.post_json("https://threatfox-api.abuse.ch/api/v1/",
                      json_body={"query": "search_ioc", "search_term": e.value, "exact_match": False},
                      headers={"Auth-Key": ctx.need("abusech")})
    if d.get("query_status") != "ok" or not isinstance(d.get("data"), list):
        raise NotFound(f"Not listed ({d.get('query_status')})")
    iocs = d["data"]
    r.set_verdict("malicious", max(int(i.get("confidence_level") or 50) for i in iocs))
    r.kv("Matches", len(iocs))
    fams = sorted({i.get("malware_printable") for i in iocs if i.get("malware_printable")})
    r.kv("Malware", fams)
    r.kv("Threat types", sorted({i.get("threat_type_desc") or i.get("threat_type") for i in iocs if i.get("threat_type")}))
    for f in fams[:5]:
        r.add("malware", f, "family")
    for i in iocs:
        r.tag(*(i.get("tags") or [])[:3])
        if i.get("ioc") and i["ioc"] != e.value and not i["ioc"].startswith(e.value + ":"):
            add_ioc(r, i["ioc"], i.get("ioc_type"), "related_ioc")
    r.table("IOCs", ["IOC", "Type", "Threat", "Malware", "Confidence", "First seen"], [
        [i.get("ioc"), i.get("ioc_type"), i.get("threat_type"), i.get("malware_printable"),
         i.get("confidence_level"), i.get("first_seen")] for i in iocs])
    r.link("ThreatFox", f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{urllib.parse.quote(e.value)}")
    r.data = iocs


@module("pulsedive", "Pulsedive", types=ALL, keys=["pulsedive"], rate=10, category="Threat Intel",
        sample="pulsedive.com", desc="Risk score, threats, feeds and attributes. Key optional, but keyless use is limited to ~10 lookups/day.")
def pulsedive(e, ctx, r):
    d = ctx.get_json("https://pulsedive.com/api/info.php",
                     params={"indicator": e.value, "pretty": 0, "key": ctx.key("pulsedive") or None})
    if d.get("error"):
        raise NotFound(d["error"])
    risk = d.get("risk")
    r.kv("Risk", risk)
    r.kv("Risk factors", [f.get("description") for f in d.get("riskfactors") or []][:8])
    r.kv("Threats", [t.get("name") for t in d.get("threats") or []])
    r.kv("Feeds", [f.get("name") for f in d.get("feeds") or []])
    r.kv("Last seen", d.get("stamp_seen"))
    for t in (d.get("threats") or [])[:5]:
        r.add("malware", t.get("name"), "threat")
    if risk in ("high", "critical"):
        r.set_verdict("malicious", 85 if risk == "high" else 95)
    elif risk == "medium":
        r.set_verdict("suspicious", 55)
    elif risk in ("low", "none"):
        r.set_verdict("clean" if risk == "none" else None)
    props = d.get("properties") or {}
    for k_, v in (props.get("dns") or {}).items():
        if k_ == "A":
            for ip in (v if isinstance(v, list) else [v])[:ctx.max_children]:
                r.add("ipv4", ip, "resolves_to")
    b64 = base64.b64encode(e.value.encode()).decode()
    r.link("Pulsedive", f"https://pulsedive.com/indicator/?ioc={b64}")
    r.data = {k_: d.get(k_) for k_ in ("indicator", "type", "risk", "risk_recommended", "stamp_added", "stamp_seen", "attributes", "properties")}


@module("urlscan", "urlscan.io Search", types=["ipv4", "domain", "url", "hash"], keys=["urlscan"], rate=30,
        category="Threat Intel", sample="example.com",
        desc="Historic urlscan.io scans: hosting IPs, ASNs, final URLs, malicious verdicts.")
def urlscan(e, ctx, r):
    if e.type == "ipv4":
        q = f'ip:"{e.value}"'
    elif e.type == "domain":
        q = f"domain:{e.value}"
    elif e.type == "hash":
        q = f"hash:{e.value}"
    else:
        q = f'page.url:"{e.value}"'
    k = ctx.key("urlscan")
    d = ctx.get_json("https://urlscan.io/api/v1/search/", params={"q": q, "size": 50},
                     headers={"API-Key": k} if k else None)
    res = d.get("results") or []
    if not res:
        raise NotFound("No scans")
    r.kv("Scans", d.get("total", len(res)))
    mal = [x for x in res if (x.get("verdicts") or {}).get("malicious")]
    if mal:
        r.set_verdict("malicious", 85)
        r.kv("Malicious verdicts", len(mal))
    ips, doms, asns = {}, {}, {}
    for x in res:
        p = x.get("page") or {}
        if p.get("ip"):
            ips[p["ip"]] = ips.get(p["ip"], 0) + 1
        if p.get("domain"):
            doms[p["domain"]] = doms.get(p["domain"], 0) + 1
        if p.get("asn"):
            asns[p["asn"]] = p.get("asnname")
    if e.type != "ipv4":
        for ip in list(ips)[:ctx.max_children]:
            r.add("ipv4", ip, "urlscan_ip")
    if e.type != "domain":
        for dm in list(doms)[:ctx.max_children]:
            r.add("domain", dm, "urlscan_domain")
    for a, name in list(asns.items())[:5]:
        r.add("asn", a, "asn", label=f"{a} {name or ''}".strip())
    r.table("Scans", ["Time", "URL", "IP", "Country", "Server", "Malicious"], [
        [(x.get("task") or {}).get("time", "")[:16], (x.get("page") or {}).get("url"), (x.get("page") or {}).get("ip"),
         (x.get("page") or {}).get("country"), (x.get("page") or {}).get("server"),
         (x.get("verdicts") or {}).get("malicious")] for x in res])
    for x in res[:3]:
        if x.get("result"):
            r.link(f"Scan {(x.get('task') or {}).get('time', '')[:10]}", x["result"].replace("/api/v1/result/", "/result/"))
    r.data = [{"task": x.get("task"), "page": x.get("page"), "verdicts": x.get("verdicts")} for x in res[:20]]


@module("mnemonic", "Mnemonic Passive DNS", types=["ipv4", "ipv6", "domain"], provider="mnemonic", rate=30,
        category="DNS", sample="example.com",
        desc="Historic DNS resolutions from Mnemonic's free passive DNS (no key).")
def mnemonic(e, ctx, r):
    d = ctx.get_json(f"https://api.mnemonic.no/pdns/v3/{urllib.parse.quote(e.value)}", params={"limit": 200})
    recs = d.get("data") or []
    if not recs:
        raise NotFound("No passive DNS")
    recs.sort(key=lambda x: x.get("lastSeenTimestamp") or 0, reverse=True)
    r.kv("Records", d.get("count", len(recs)))
    rows = []
    for x in recs:
        rows.append([x.get("query"), x.get("rrtype"), x.get("answer"), ts((x.get("firstSeenTimestamp") or 0) / 1000),
                     ts((x.get("lastSeenTimestamp") or 0) / 1000)])
    n = 0
    if e.type != "domain" and ctx.shared_hosting(r, [x.get("query") for x in recs]):
        recs = []
    for x in recs:
        if n >= ctx.max_children:
            break
        rt = (x.get("rrtype") or "").lower()
        if e.type == "domain":
            if rt in ("a", "aaaa") and x.get("query") == e.value:
                r.add("ipv4", x.get("answer"), "pdns")
                n += 1
            elif rt == "cname":
                r.add("domain", x.get("answer"), "cname")
                n += 1
        else:
            if x.get("query"):
                r.add("domain", x["query"], "pdns")
                n += 1
    r.table("Passive DNS", ["Query", "Type", "Answer", "First seen", "Last seen"], rows, limit=100)
