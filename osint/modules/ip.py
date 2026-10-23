"""IP address modules."""
import ipaddress

from ..registry import NotFound, module

IP = ["ipv4", "ipv6"]

ABUSE_CATS = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot",
    20: "Exploited Host", 21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


def rdap_emails(entities, roles=None, out=None, depth=0):
    """Walk RDAP entities collecting (role, name, email)."""
    out = [] if out is None else out
    for ent in entities or []:
        rls = ent.get("roles") or []
        name, email = None, None
        vc = ent.get("vcardArray")
        if isinstance(vc, list) and len(vc) > 1:
            for item in vc[1]:
                if item[0] == "fn":
                    name = item[3]
                elif item[0] == "email":
                    email = item[3]
        if roles is None or set(rls) & set(roles):
            out.append((",".join(rls), name, email))
        if depth < 3:
            rdap_emails(ent.get("entities"), roles, out, depth + 1)
    return out


@module("ipapi", "IP-API Geolocation", types=IP, provider="ip-api", rate=40,
        category="Network & Geo", sample="8.8.8.8",
        desc="Geolocation, ISP, organisation, ASN, hosting/proxy flags. Free, no key.")
def ipapi(e, ctx, r):
    d = ctx.get_json(f"http://ip-api.com/json/{e.value}", params={
        "fields": "status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"})
    if d.get("status") != "success":
        raise NotFound(d.get("message") or "No data")
    r.data = d
    r.kv("Location", ", ".join(x for x in (d.get("city"), d.get("regionName"), d.get("country")) if x))
    r.kv("ISP", d.get("isp"))
    r.kv("Organisation", d.get("org"))
    r.kv("AS", d.get("as"))
    r.kv("Reverse DNS", d.get("reverse"))
    r.kv("Hosting / DC", d.get("hosting"))
    r.kv("Proxy / VPN / Tor", d.get("proxy"))
    r.kv("Mobile", d.get("mobile"))
    r.kv("Coordinates", f"{d.get('lat')}, {d.get('lon')}")
    if d.get("proxy"):
        r.tag("proxy")
    if d.get("hosting"):
        r.tag("hosting")
    if d.get("countryCode"):
        r.tag(d["countryCode"])
    asn = (d.get("as") or "").split(" ")[0]
    if asn.startswith("AS"):
        r.add("asn", asn, "asn", label=f"{asn} {d.get('asname') or ''}".strip())
    if d.get("reverse"):
        r.add("domain", d["reverse"], "ptr")
    if d.get("org") or d.get("isp"):
        r.add("org", d.get("org") or d.get("isp"), "hosted_by")


@module("ipinfo", "ipinfo.io", types=IP, keys=["ipinfo"], rate=50, category="Network & Geo",
        sample="1.1.1.1", enabled=False,
        desc="Hostname, geolocation, ASN/org (token optional).")
def ipinfo(e, ctx, r):
    d = ctx.get_json(f"https://ipinfo.io/{e.value}/json", params={"token": ctx.key("ipinfo") or None})
    if d.get("bogon"):
        raise NotFound("Bogon address")
    r.data = d
    r.kv("Hostname", d.get("hostname"))
    r.kv("Location", ", ".join(x for x in (d.get("city"), d.get("region"), d.get("country")) if x))
    r.kv("Org", d.get("org"))
    r.kv("Timezone", d.get("timezone"))
    if d.get("hostname"):
        r.add("domain", d["hostname"], "ptr")
    org = d.get("org") or ""
    if org.startswith("AS"):
        asn, _, name = org.partition(" ")
        r.add("asn", asn, "asn", label=org)
        if name:
            r.add("org", name, "hosted_by")
    r.link("ipinfo", f"https://ipinfo.io/{e.value}")


@module("abuseipdb", "AbuseIPDB", types=IP, keys=["abuseipdb"], key_required=True, rate=30,
        category="Threat Intel", sample="185.220.101.1",
        desc="Community abuse reports, confidence score, ISP and usage type.")
def abuseipdb(e, ctx, r):
    d = ctx.get_json("https://api.abuseipdb.com/api/v2/check",
                     params={"ipAddress": e.value, "maxAgeInDays": 90, "verbose": ""},
                     headers={"Key": ctx.need("abuseipdb"), "Accept": "application/json"})["data"]
    score = d.get("abuseConfidenceScore", 0)
    r.kv("Abuse confidence", f"{score}%")
    r.kv("Total reports (90d)", d.get("totalReports"))
    r.kv("Distinct reporters", d.get("numDistinctUsers"))
    r.kv("Last reported", d.get("lastReportedAt"))
    r.kv("ISP", d.get("isp"))
    r.kv("Usage type", d.get("usageType"))
    r.kv("Domain", d.get("domain"))
    r.kv("Country", d.get("countryName") or d.get("countryCode"))
    r.kv("Tor exit", d.get("isTor"))
    r.kv("Whitelisted", d.get("isWhitelisted"))
    if d.get("isTor"):
        r.tag("tor")
    if d.get("isWhitelisted"):
        r.set_verdict("clean", 0)
    elif d.get("totalReports"):
        r.score_verdict(score, 50, 5)
    else:
        r.set_verdict("clean", 0)
    if d.get("domain"):
        r.add("domain", d["domain"], "isp_domain", pivot=False)
    for h in (d.get("hostnames") or [])[:ctx.max_children]:
        r.add("domain", h, "hostname")
    reports = d.get("reports") or []
    cats = {}
    for rep in reports:
        for c in rep.get("categories", []):
            cats[c] = cats.get(c, 0) + 1
    for c, _ in sorted(cats.items(), key=lambda x: -x[1])[:6]:
        r.tag(ABUSE_CATS.get(c, f"cat {c}").lower())
    r.table("Recent reports", ["Date", "Categories", "Comment"], [
        [rep.get("reportedAt", "")[:16], ", ".join(ABUSE_CATS.get(c, str(c)) for c in rep.get("categories", [])),
         (rep.get("comment") or "")[:160]] for rep in reports[:25]])
    d.pop("reports", None)
    r.data = d
    r.link("AbuseIPDB", f"https://www.abuseipdb.com/check/{e.value}")


@module("internetdb", "Shodan InternetDB", types=IP, provider="internetdb", rate=60,
        category="Network & Geo", sample="1.1.1.1",
        desc="Open ports, hostnames, CPEs, tags and known CVEs (free, no key).")
def internetdb(e, ctx, r):
    d = ctx.get_json(f"https://internetdb.shodan.io/{e.value}")
    r.data = d
    r.kv("Open ports", d.get("ports"))
    r.kv("Hostnames", d.get("hostnames"))
    r.kv("CPEs", d.get("cpes"))
    r.kv("Tags", d.get("tags"))
    r.kv("Vulns", len(d.get("vulns") or []))
    r.tag(*(d.get("tags") or []))
    if d.get("vulns"):
        r.tag("vulnerable")
    for h in (d.get("hostnames") or [])[:ctx.max_children]:
        r.add("domain", h, "hostname")
    for v in (d.get("vulns") or [])[:ctx.max_children]:
        r.add("cve", v, "vulnerable_to")
    if "malware" in (d.get("tags") or []) or "c2" in (d.get("tags") or []):
        r.set_verdict("malicious")
    r.link("Shodan", f"https://www.shodan.io/host/{e.value}")


@module("shodan", "Shodan Host", types=IP, keys=["shodan"], key_required=True, rate=50,
        category="Network & Geo", sample="1.1.1.1",
        desc="Full Shodan host record: services, banners, OS, vulns.")
def shodan(e, ctx, r):
    d = ctx.get_json(f"https://api.shodan.io/shodan/host/{e.value}", params={"key": ctx.need("shodan")})
    r.kv("Organisation", d.get("org"))
    r.kv("ISP", d.get("isp"))
    r.kv("OS", d.get("os"))
    r.kv("Ports", d.get("ports"))
    r.kv("Hostnames", d.get("hostnames"))
    r.kv("Last update", d.get("last_update"))
    r.kv("Vulns", len(d.get("vulns") or []))
    r.tag(*(d.get("tags") or []))
    for h in (d.get("hostnames") or [])[:ctx.max_children]:
        r.add("domain", h, "hostname")
    for dm in (d.get("domains") or [])[:ctx.max_children]:
        r.add("domain", dm, "shodan_domain")
    for v in list(d.get("vulns") or [])[:ctx.max_children]:
        r.add("cve", v, "vulnerable_to")
    if d.get("asn"):
        r.add("asn", d["asn"], "asn")
    rows = []
    for s in d.get("data", [])[:40]:
        http = s.get("http") or {}
        ssl = s.get("ssl") or {}
        cn = ((ssl.get("cert") or {}).get("subject") or {}).get("CN")
        rows.append([f"{s.get('port')}/{s.get('transport')}", s.get("product") or s.get("_shodan", {}).get("module"),
                     s.get("version"), http.get("title"), cn, (s.get("timestamp") or "")[:10]])
        if cn and "*" not in cn:
            r.add("domain", cn, "tls_cn")
    r.table("Services", ["Port", "Product", "Version", "HTTP title", "TLS CN", "Seen"], rows)
    d.pop("data", None)
    r.data = d
    r.link("Shodan", f"https://www.shodan.io/host/{e.value}")


@module("greynoise", "GreyNoise Community", types=["ipv4"], keys=["greynoise"], rate=10,
        category="Threat Intel", sample="185.220.101.1",
        desc="Is this IP mass-scanning the internet? Benign service (RIOT) or malicious noise.")
def greynoise(e, ctx, r):
    k = ctx.key("greynoise")
    d = ctx.get_json(f"https://api.greynoise.io/v3/community/{e.value}",
                     headers={"key": k} if k else None)
    r.data = d
    r.kv("Classification", d.get("classification"))
    r.kv("Name", d.get("name"))
    r.kv("Internet noise", d.get("noise"))
    r.kv("Benign service (RIOT)", d.get("riot"))
    r.kv("Last seen", d.get("last_seen"))
    cls = d.get("classification")
    if cls == "malicious":
        r.set_verdict("malicious")
        r.tag("scanner")
    elif cls == "benign" or d.get("riot"):
        r.set_verdict("clean")
    elif d.get("noise"):
        r.set_verdict("suspicious")
        r.tag("scanner")
    if d.get("link"):
        r.link("GreyNoise", d["link"])


@module("isc", "SANS ISC DShield", types=IP, provider="isc", rate=20, category="Threat Intel",
        sample="185.220.101.1", desc="SANS Internet Storm Center attack reports and threat feeds (free).")
def isc(e, ctx, r):
    d = ctx.get_json(f"https://isc.sans.edu/api/ip/{e.value}", params={"json": ""}, user_agent="ARACHNE-OSINT/1.0")
    ip = d.get("ip", d) if isinstance(d, dict) else {}
    r.data = ip
    feeds = ip.get("threatfeeds") or {}
    r.kv("Reports", ip.get("count"))
    r.kv("Targets attacked", ip.get("attacks"))
    r.kv("First seen", ip.get("mindate"))
    r.kv("Last seen", ip.get("maxdate"))
    r.kv("AS", f"AS{ip.get('as')} {ip.get('asname') or ''}" if ip.get("as") else None)
    r.kv("Threat feeds", list(feeds.keys()))
    for f in list(feeds)[:8]:
        r.tag(f)
    attacks = int(ip.get("attacks") or 0)
    if attacks > 50 or feeds:
        r.set_verdict("suspicious", min(100, attacks))
    if ip.get("asabusecontact"):
        r.add("email", ip["asabusecontact"], "abuse_contact", pivot=False)
    r.link("SANS ISC", f"https://isc.sans.edu/ipinfo/{e.value}")


@module("rdap_ip", "RDAP / WHOIS (IP)", types=IP, provider="rdap", rate=60, category="Network & Geo",
        sample="8.8.8.8", desc="Network allocation owner, range and abuse contacts via RDAP.")
def rdap_ip(e, ctx, r):
    d = ctx.get_json(f"https://rdap.org/ip/{e.value}", headers={"Accept": "application/rdap+json"})
    r.kv("Network name", d.get("name"))
    r.kv("Handle", d.get("handle"))
    r.kv("Range", f"{d.get('startAddress')} - {d.get('endAddress')}")
    r.kv("Country", d.get("country"))
    r.kv("Type", d.get("type"))
    contacts = rdap_emails(d.get("entities"))
    for role, name, email in contacts:
        if "registrant" in role and name:
            r.add("org", name, "allocated_to")
        if email:
            r.add("email", email, "abuse_contact" if "abuse" in role else "rdap_contact", pivot=False)
    r.table("Contacts", ["Role", "Name", "Email"], contacts)
    for ev in d.get("events", []) or []:
        r.kv(ev.get("eventAction", "event").title(), (ev.get("eventDate") or "")[:10])
    r.data = {k: d.get(k) for k in ("handle", "name", "type", "startAddress", "endAddress", "country", "cidr0_cidrs", "status")}


@module("ptr", "Reverse DNS (PTR)", types=IP, provider="doh", category="DNS", sample="8.8.8.8",
        desc="PTR record lookup over DNS-over-HTTPS.")
def ptr(e, ctx, r):
    name = ipaddress.ip_address(e.value).reverse_pointer
    status, ans = ctx.dns(name, "PTR")
    hosts = [a[1].rstrip(".") for a in ans if a[0] == 12]
    if not hosts:
        raise NotFound("No PTR record")
    r.kv("PTR", hosts)
    for h in hosts[:ctx.max_children]:
        r.add("domain", h, "ptr")


def _tor_exits(resp):
    return set(l.strip() for l in resp.text().splitlines() if l.strip() and not l.startswith("#"))


@module("tor", "Tor Exit List", types=IP, provider="torproject", category="Threat Intel",
        sample="185.220.101.1", desc="Checks the Tor Project bulk exit-node list (cached 6h).")
def tor(e, ctx, r):
    exits = ctx.feed("https://check.torproject.org/torbulkexitlist", _tor_exits)
    if e.value in exits:
        r.kv("Tor exit node", True)
        r.tag("tor")
        r.set_verdict("suspicious", 60)
    else:
        r.kv("Tor exit node", False)
    r.kv("Exit nodes in list", len(exits))


@module("ipqs", "IPQualityScore", types=IP, keys=["ipqs"], key_required=True, rate=30,
        category="Threat Intel", sample="185.220.101.1", enabled=True,
        desc="Fraud score, proxy/VPN/Tor detection, bot activity, recent abuse.")
def ipqs(e, ctx, r):
    d = ctx.get_json(f"https://ipqualityscore.com/api/json/ip/{ctx.need('ipqs')}/{e.value}",
                     params={"strictness": 1, "allow_public_access_points": "true"})
    if not d.get("success", True):
        raise NotFound(d.get("message"))
    r.data = d
    r.kv("Fraud score", d.get("fraud_score"))
    for k in ("proxy", "vpn", "tor", "active_vpn", "active_tor", "recent_abuse", "bot_status", "is_crawler"):
        r.kv(k.replace("_", " ").title(), d.get(k))
        if d.get(k) is True:
            r.tag(k.replace("_", "-"))
    r.kv("ISP", d.get("ISP"))
    r.kv("Host", d.get("host"))
    r.score_verdict(d.get("fraud_score"), 85, 75)
    if d.get("host") and d["host"] != e.value:
        r.add("domain", d["host"], "ptr")


@module("criminalip", "Criminal IP", types=IP, keys=["criminalip"], key_required=True, rate=30,
        category="Threat Intel", sample="185.220.101.1", enabled=True,
        desc="Inbound/outbound risk score, open ports, VPN/proxy/Tor and malicious-activity flags.")
def criminalip(e, ctx, r):
    d = ctx.get_json("https://api.criminalip.io/v1/asset/ip/report", params={"ip": e.value},
                     headers={"x-api-key": ctx.need("criminalip")})
    r.data = d
    score = (d.get("score") or {})
    r.kv("Inbound score", score.get("inbound"))
    r.kv("Outbound score", score.get("outbound"))
    issues = d.get("issues") or {}
    for k, v in issues.items():
        if v is True:
            r.tag(k.replace("is_", ""))
    r.kv("Flags", [k.replace("is_", "") for k, v in issues.items() if v is True])
    worst = " ".join(str(v).lower() for v in score.values())
    if "critical" in worst or "dangerous" in worst:
        r.set_verdict("malicious")
    elif "moderate" in worst:
        r.set_verdict("suspicious")
    elif score:
        r.set_verdict("clean")
    r.link("Criminal IP", f"https://www.criminalip.io/asset/report/{e.value}")
