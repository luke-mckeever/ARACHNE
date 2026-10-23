"""URL modules."""
import html
import re
from urllib.parse import urljoin, urlsplit

from .. import entities as E
from ..registry import NotFound, module

SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
              "rebrand.ly", "rb.gy", "t.ly", "shorturl.at", "tiny.cc", "s.id", "bl.ink"}


@module("url_parse", "URL Breakdown", types=["url"], provider="local", category="URL", local_ok=True,
        sample="https://example.com/login.php?x=1", desc="Splits a URL into host, port, path and flags. Offline.")
def url_parse(e, ctx, r):
    p = urlsplit(e.value)
    host = p.hostname or ""
    r.kv("Scheme", p.scheme)
    r.kv("Host", host)
    r.kv("Port", p.port)
    r.kv("Path", p.path)
    r.kv("Query", p.query[:300])
    if E.is_ip(host):
        r.add("ipv4", host, "host")
        r.tag("ip-host")
    else:
        r.add("domain", host, "host")
    if host in SHORTENERS:
        r.tag("shortener")
    if p.username or "@" in p.netloc:
        r.tag("credentials-in-url")
        r.set_verdict("suspicious")
    if p.port and p.port not in (80, 443):
        r.tag("non-std-port")
    ext = re.search(r"\.([a-z0-9]{2,5})$", p.path.lower())
    if ext:
        r.kv("File extension", ext.group(1))
        if ext.group(1) in ("exe", "dll", "scr", "msi", "ps1", "bat", "vbs", "js", "jar", "apk", "hta", "lnk", "iso", "zip", "rar"):
            r.tag("payload-ext")
    if host.startswith("xn--") or ".xn--" in host:
        r.tag("punycode")


@module("urlhaus", "URLhaus", types=["url", "domain", "ipv4"], provider="abusech", keys=["abusech"],
        key_required=True, rate=60, category="Threat Intel", sample="http://example.com",
        desc="abuse.ch URLhaus malware distribution URLs - payloads, threat type, status.")
def urlhaus(e, ctx, r):
    hdr = {"Auth-Key": ctx.need("abusech")}
    if e.type == "url":
        d = ctx.post_json("https://urlhaus-api.abuse.ch/v1/url/", data={"url": e.value}, headers=hdr)
        if d.get("query_status") != "ok":
            raise NotFound(f"Not listed ({d.get('query_status')})")
        r.set_verdict("malicious", 90)
        r.kv("Threat", d.get("threat"))
        r.kv("Status", d.get("url_status"))
        r.kv("Date added", d.get("date_added"))
        r.kv("Reporter", d.get("reporter"))
        r.tag(*(d.get("tags") or []))
        r.tag(d.get("threat"))
        pays = d.get("payloads") or []
        for p in pays[:ctx.max_children]:
            r.add("hash", p.get("response_sha256"), "payload")
            if p.get("signature"):
                r.add("malware", p["signature"], "family", via=("hash", p.get("response_sha256")))
        r.table("Payloads", ["First seen", "File type", "SHA256", "Signature"], [
            [p.get("firstseen"), p.get("file_type"), p.get("response_sha256"), p.get("signature")] for p in pays])
        if d.get("urlhaus_reference"):
            r.link("URLhaus", d["urlhaus_reference"])
        d.pop("payloads", None)
        r.data = d
        return
    d = ctx.post_json("https://urlhaus-api.abuse.ch/v1/host/", data={"host": e.value}, headers=hdr)
    if d.get("query_status") != "ok":
        raise NotFound(f"Not listed ({d.get('query_status')})")
    urls = d.get("urls") or []
    online = [u for u in urls if u.get("url_status") == "online"]
    r.kv("Malicious URLs", d.get("url_count", len(urls)))
    r.kv("Online now", len(online))
    r.kv("First seen", d.get("firstseen"))
    r.set_verdict("malicious" if online else "suspicious", 90 if online else 55)
    for u in urls:
        r.tag(*(u.get("tags") or [])[:3])
    for u in urls[:ctx.max_children]:
        r.add("url", u.get("url"), "hosts_malware_url")
    r.table("URLs", ["Added", "Status", "Threat", "URL", "Tags"], [
        [u.get("date_added"), u.get("url_status"), u.get("threat"), u.get("url"), ", ".join(u.get("tags") or [])]
        for u in urls])
    if d.get("urlhaus_reference"):
        r.link("URLhaus", d["urlhaus_reference"])
    d.pop("urls", None)
    r.data = d


@module("gsb", "Google Safe Browsing", types=["url", "domain"], keys=["gsb"], key_required=True, rate=60,
        category="Threat Intel", sample="http://testsafebrowsing.appspot.com/s/malware.html",
        desc="Google's malware / social-engineering / unwanted-software list.")
def gsb(e, ctx, r):
    urls = [e.value] if e.type == "url" else [f"http://{e.value}/", f"https://{e.value}/"]
    body = {"client": {"clientId": "arachne-osint", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                           "POTENTIALLY_HARMFUL_APPLICATION"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": u} for u in urls]}}
    d = ctx.post_json("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                      params={"key": ctx.need("gsb")}, json_body=body)
    matches = d.get("matches") or []
    r.data = d
    if matches:
        r.set_verdict("malicious", 95)
        types = sorted({m.get("threatType") for m in matches})
        r.kv("Threats", types)
        r.tag(*[t.lower().replace("_", "-") for t in types])
    else:
        r.kv("Listed", False)
        r.set_verdict("clean")


def _openphish(resp):
    return [l.strip() for l in resp.text().splitlines() if l.strip().startswith("http")]


@module("openphish", "OpenPhish Feed", types=["url", "domain"], provider="openphish", category="Threat Intel",
        sample="http://example.com", desc="Checks the OpenPhish community phishing feed (cached 6h).")
def openphish(e, ctx, r):
    urls = ctx.feed("https://openphish.com/feed.txt", _openphish)
    if e.type == "url":
        hits = [u for u in urls if u.rstrip("/") == e.value.rstrip("/")]
    else:
        hits = [u for u in urls if (urlsplit(u).hostname or "").endswith(e.value)]
    r.kv("Feed size", len(urls))
    if not hits:
        r.kv("Listed", False)
        return
    r.set_verdict("malicious", 90)
    r.tag("phishing")
    r.kv("Matching phishing URLs", len(hits))
    for u in hits[:ctx.max_children]:
        if u != e.value:
            r.add("url", u, "phishing_url")
    r.table("Matches", ["URL"], [[u] for u in hits])


@module("http_probe", "HTTP Probe (active)", types=["url", "domain"], provider="probe", active=True,
        enabled=True, pivot=False, category="Active", sample="https://example.com",
        desc="ACTIVE: connects to the target, follows redirects manually, grabs title/server/headers. "
             "Requires 'Allow active modules' in Settings > Network.")
def http_probe(e, ctx, r):
    url = e.value if e.type == "url" else f"https://{e.value}/"
    chain = []
    resp = None
    for _ in range(8):
        resp = ctx.get(url, follow_redirects=False, timeout=min(ctx.timeout, 15), max_bytes=400_000)
        chain.append([resp.status, url, resp.headers.get("Server") if resp.headers else ""])
        loc = resp.headers.get("Location") if resp.headers else None
        if resp.status in (301, 302, 303, 307, 308) and loc:
            url = urljoin(url, loc)
            continue
        break
    final = chain[-1][1]
    r.kv("Final status", resp.status)
    r.kv("Final URL", final)
    r.kv("Redirects", len(chain) - 1)
    h = resp.headers or {}
    for k in ("Server", "X-Powered-By", "Content-Type", "Strict-Transport-Security", "Set-Cookie"):
        if h.get(k):
            r.kv(k, h.get(k)[:150])
    m = re.search(r"<title[^>]*>(.*?)</title>", resp.text(), re.I | re.S)
    if m:
        r.kv("Title", html.unescape(" ".join(m.group(1).split()))[:150])
    for _, u, _ in chain[1:]:
        if u != e.value:
            r.add("url", u, "redirects_to", pivot=False)
    if len(chain) > 1:
        host = urlsplit(final).hostname
        if host:
            r.add("domain", host, "final_host")
    r.table("Redirect chain", ["Status", "URL", "Server"], chain)
    for f in re.findall(r"""<form[^>]+action=["']([^"']+)""", resp.text(), re.I)[:5]:
        r.add("url", urljoin(final, f), "form_action", pivot=False)
    if re.search(r'type=["\']password', resp.text(), re.I):
        r.tag("password-form")
