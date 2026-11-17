"""Exposure: what an IP (or the IPs behind a domain or URL) has open to the internet, and how vulnerable it is.

Passive only: ARACHNE never connects to the target. Open ports and known CVEs come from Shodan's free
InternetDB (what Shodan's own scanners saw, usually within the last week); each CVE is then ranked with
Shodan's free CVEDB: severity (CVSS), the chance it gets exploited (EPSS) and whether attackers already use it
(CISA KEV). Neither needs a key. The report's "Exposure Results" button (static/js/exposure.js) shows the result.
"""
import re
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from .. import entities as E
from ..registry import NotFound, module

MAX_IPS = 3        # IPs checked for one domain or URL
MAX_CVES = 40      # CVEs ranked per lookup (the website's Worker can make ~50 requests per lookup)
CVE_RX = re.compile(r"^CVE-(\d{4})-(\d{4,7})$", re.I)
CVE_CACHE = {}     # CVE -> (time, info): bulk scans share the same CVEs; CVEDB data changes daily at most
CVE_TTL = 12 * 3600


def target_ips(e, ctx):
    """The public IPs to check: the IP itself, or what the domain / URL host resolves to."""
    if e.type in ("ipv4", "ipv6"):
        return [e.value], None
    host = e.value if e.type == "domain" else (urlsplit(e.value).hostname or "")
    host = host.strip().lower().rstrip(".")
    if not host:
        raise NotFound("No host in this URL")
    if E.is_ip(host):
        if E.is_private_ip(host):
            raise NotFound("Private address - not on the internet")
        return [host], None
    ips = []
    for rtype in ("A", "AAAA"):
        if len(ips) >= MAX_IPS:
            break
        try:
            _, answers = ctx.dns(host, rtype)
        except Exception:
            continue
        for t, d in answers:
            if t in (1, 28) and E.is_ip(d) and not E.is_private_ip(d) and d not in ips:
                ips.append(d)
    if not ips:
        raise NotFound(f"{host} doesn't resolve to a public IP")
    return ips[:MAX_IPS], host


def cve_order(cid):
    """Newest CVEs first when there are more than can be ranked."""
    m = CVE_RX.match(cid or "")
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def num(v):
    try:
        return round(float(v), 4) if v is not None else None
    except (TypeError, ValueError):
        return None


def slim_cve(d):
    """The few CVEDB fields the report shows."""
    v3 = num(d.get("cvss_v3"))
    cvss = v3 if v3 is not None else num(d.get("cvss"))
    rw = d.get("ransomware_campaign")
    return {
        "cvss": cvss,
        "cvss_version": "3" if v3 is not None else (str(d.get("cvss_version")) if d.get("cvss_version") else None),
        "epss": num(d.get("epss")),
        "epss_rank": num(d.get("ranking_epss")),
        "kev": bool(d.get("kev")),
        "ransomware": isinstance(rw, str) and rw.strip().lower() == "known",
        "summary": (d.get("summary") or "")[:400],
        "published": (d.get("published_time") or "")[:10] or None,
        "action": (d.get("propose_action") or "")[:300] or None,
    }


def severity(cvss):
    if cvss is None:
        return None
    return "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low" if cvss > 0 else None


def danger(cid, info):
    """Sort key: exploited in the wild first, then the chance of exploitation, then severity."""
    if not info:
        return (0, -1, -1, cve_order(cid))
    return (1 if info["kev"] else 0, info["epss"] or 0, info["cvss"] or 0, cve_order(cid))


@module("exposure", "Exposure (open ports & vulnerabilities)", types=["ipv4", "ipv6", "domain", "url"],
        provider="internetdb", rate=60, category="Network & Geo", sample="1.1.1.1", pivot=False,
        desc="Open ports, services and known vulnerabilities from Shodan's free InternetDB, ranked by real danger "
             "with Shodan CVEDB (severity, EPSS exploit chance, CISA KEV). For domains and URLs, the IPs they point to. "
             "Passive: the target is never scanned. Free, no key.")
def exposure(e, ctx, r):
    ips, host = target_ips(e, ctx)
    hosts = []
    for ip in ips:
        h = {"ip": ip, "ports": [], "hostnames": [], "cpes": [], "tags": [], "vulns": [], "known": True}
        try:
            d = ctx.get_json(f"https://internetdb.shodan.io/{ip}")
            h["ports"] = sorted({int(p) for p in d.get("ports") or [] if str(p).isdigit()})
            h["hostnames"] = list(d.get("hostnames") or [])[:20]
            h["cpes"] = list(d.get("cpes") or [])[:40]
            h["tags"] = list(d.get("tags") or [])[:20]
            h["vulns"] = sorted({str(v).upper() for v in d.get("vulns") or []}, key=cve_order, reverse=True)
        except NotFound:
            h["known"] = False
        hosts.append(h)

    all_cves = sorted({v for h in hosts for v in h["vulns"]}, key=cve_order, reverse=True)
    to_rank = all_cves[:MAX_CVES]
    ranked = {}

    def lookup(cid):
        hit = CVE_CACHE.get(cid)
        if hit and time.time() - hit[0] < CVE_TTL:
            return cid, hit[1]
        try:
            info = slim_cve(ctx.get_json(f"https://cvedb.shodan.io/cve/{cid}", throttle=False))
        except NotFound:
            info = None
        except Exception:      # the request failed: listed, just not ranked (and asked again next time)
            return cid, None
        if len(CVE_CACHE) > 5000:
            CVE_CACHE.clear()
        CVE_CACHE[cid] = (time.time(), info)
        return cid, info

    if to_rank:
        with ThreadPoolExecutor(max_workers=6) as pool:
            for cid, info in pool.map(lookup, to_rank):
                if info:
                    ranked[cid] = info
    for h in hosts:
        h["vulns"] = sorted(h["vulns"], key=lambda c: danger(c, ranked.get(c)), reverse=True)

    ports = sorted({p for h in hosts for p in h["ports"]})
    kev = [c for c in all_cves if ranked.get(c, {}).get("kev")]
    crit = [c for c in all_cves if severity(ranked.get(c, {}).get("cvss")) == "critical"]
    r.data = {"host": host, "hosts": hosts, "cves": ranked, "total_cves": len(all_cves),
              "unranked": len(all_cves) - len(ranked), "source": "Shodan InternetDB + CVEDB"}

    if host:
        r.kv("Host", host)
        r.kv("IPs checked", ", ".join(ips))
    r.kv("Open ports", ", ".join(str(p) for p in ports) if ports else "none known")
    r.kv("Known vulnerabilities", len(all_cves))
    if all_cves:
        r.kv("Exploited in the wild (CISA KEV)", len(kev))
        r.kv("Critical (CVSS 9+)", len(crit))
    if not any(h["known"] for h in hosts):
        r.message = "Shodan has no record of open ports here"
    if ports:
        r.tag("exposed")
    if all_cves:
        r.tag("vulnerable")
    if kev:
        r.tag("kev-vuln")

    rows = [[h["ip"], p] for h in hosts for p in h["ports"]]
    r.table("Open ports", ["IP", "Port"], rows, limit=100)
    vrows = []
    for h in hosts:
        for c in h["vulns"]:
            i = ranked.get(c)
            vrows.append([h["ip"], c, (i or {}).get("cvss"), f"{round(i['epss'] * 100, 1)}%" if i and i["epss"] is not None else "",
                          "yes" if i and i["kev"] else "", (i or {}).get("summary", "")[:160]])
    r.table("Vulnerabilities (most dangerous first)", ["IP", "CVE", "CVSS", "EPSS", "KEV", "Summary"], vrows, limit=100)
    for ip in ips:
        r.link(f"Shodan {ip}", f"https://www.shodan.io/host/{ip}")
