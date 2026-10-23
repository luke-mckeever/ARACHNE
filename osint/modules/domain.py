"""Domain modules."""
import datetime as dt
import re
from concurrent.futures import ThreadPoolExecutor

from .. import entities as E
from ..registry import DNS_TYPES, ModuleError, NotFound, module
from .ip import rdap_emails

DOM = ["domain"]


@module("dns", "DNS Records", types=DOM, provider="doh", category="DNS", sample="example.com",
        desc="A/AAAA/MX/NS/CNAME/TXT/SOA/CAA + DMARC via DNS-over-HTTPS. Extracts SPF includes and report mailboxes.")
def dns(e, ctx, r):
    rows, nx = [], False
    records = {}
    for rt in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"):
        status, ans = ctx.dns(e.value, rt)
        if status == 3:
            nx = True
            break
        for t, data in ans:
            tname = DNS_TYPES.get(t, str(t))
            if tname != rt:
                continue
            records.setdefault(rt, []).append(data)
            rows.append([rt, data])
    if nx:
        raise NotFound("NXDOMAIN - domain does not resolve")
    try:
        _, dm = ctx.dns("_dmarc." + e.value, "TXT")
        for t, data in dm:
            if t == 16:
                records.setdefault("DMARC", []).append(data.strip('"'))
                rows.append(["DMARC", data])
    except Exception:
        pass
    if not rows:
        raise NotFound("No DNS records")
    r.data = records
    mc = ctx.max_children
    for ip in records.get("A", [])[:mc] + records.get("AAAA", [])[:mc]:
        r.add("ipv4", ip, "resolves_to")
    for c in records.get("CNAME", []):
        r.add("domain", c.rstrip("."), "cname")
    for mx in records.get("MX", [])[:mc]:
        host = mx.split()[-1].rstrip(".")
        if host:
            r.add("domain", host, "mx")
    for ns in records.get("NS", [])[:mc]:
        r.add("domain", ns.rstrip("."), "ns")
    spf = []
    for txt in records.get("TXT", []):
        t = txt.strip('"').replace('" "', "")
        if t.lower().startswith("v=spf1"):
            spf.append(t)
            for inc in re.findall(r"(?:include|redirect)[:=]([^\s]+)", t):
                r.add("domain", inc, "spf_include", pivot=False)
            for ip in re.findall(r"ip4:([0-9.]+)(?:\s|$)", t):
                r.add("ipv4", ip, "spf_ip", pivot=False)
        for m in re.findall(r"([a-z0-9-]+)-(?:site|domain)-verification", t.lower()):
            r.tag(f"{m}-verified")
    for dm in records.get("DMARC", []):
        for mail in re.findall(r"mailto:([^,;\s!]+)", dm):
            r.add("email", mail, "dmarc_report", pivot=False)
    for soa in records.get("SOA", []):
        parts = soa.split()
        if len(parts) > 1 and "." in parts[1]:
            rname = parts[1].rstrip(".")
            local, _, dom = rname.partition(".")
            r.add("email", f"{local}@{dom}", "soa_contact", pivot=False)
    r.kv("A", records.get("A"))
    r.kv("AAAA", records.get("AAAA"))
    r.kv("CNAME", records.get("CNAME"))
    r.kv("MX", records.get("MX"))
    r.kv("NS", records.get("NS"))
    r.kv("SPF", spf)
    r.kv("DMARC", records.get("DMARC") or "none")
    if not records.get("DMARC"):
        r.tag("no-dmarc")
    r.table("All records", ["Type", "Value"], rows, limit=120)


@module("parent", "Parent Domain", types=DOM, provider="local", category="DNS", sample="www.example.com",
        local_ok=True, desc="Links subdomains to their registered (apex) domain. Offline.")
def parent(e, ctx, r):
    reg = E.registered_domain(e.value)
    if reg == e.value:
        raise NotFound("Already a registered domain")
    r.kv("Registered domain", reg)
    r.add("domain", reg, "subdomain_of")


@module("rdap_domain", "RDAP / WHOIS (Domain)", types=DOM, provider="rdap", rate=60,
        category="Registration", sample="example.com",
        desc="Registrar, creation/expiry dates, nameservers and contacts. Flags newly registered domains.")
def rdap_domain(e, ctx, r):
    reg = E.registered_domain(e.value)
    d = ctx.get_json(f"https://rdap.org/domain/{reg}", headers={"Accept": "application/rdap+json"})
    events = {ev.get("eventAction"): (ev.get("eventDate") or "") for ev in d.get("events", []) or []}
    created = events.get("registration")
    r.kv("Domain", d.get("ldhName", reg).lower())
    r.kv("Registered", created[:10] if created else None)
    r.kv("Expires", (events.get("expiration") or "")[:10])
    r.kv("Updated", (events.get("last changed") or "")[:10])
    r.kv("Status", d.get("status"))
    ns = [n.get("ldhName", "").lower() for n in d.get("nameservers", []) or [] if n.get("ldhName")]
    r.kv("Nameservers", ns)
    contacts = rdap_emails(d.get("entities"))
    registrar = next((n for role, n, _ in contacts if "registrar" in role and n), None)
    r.kv("Registrar", registrar)
    if registrar:
        r.add("org", registrar, "registrar")
    for role, name, email in contacts:
        if email and "@" in email:
            abuse = "abuse" in role or "registrar" in role
            r.add("email", email, "abuse_contact" if abuse else "registrant_email", pivot=not abuse)
        if name and "registrant" in role and "redact" not in name.lower() and "privacy" not in name.lower():
            r.add("org", name, "registrant")
    r.table("Contacts", ["Role", "Name", "Email"], contacts)
    for n in ns[:ctx.max_children]:
        r.add("domain", n, "ns")
    if reg != e.value:
        r.add("domain", reg, "subdomain_of")
    if created:
        try:
            age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(created.replace("Z", "+00:00"))).days
            r.kv("Age (days)", age)
            if age < 30:
                r.tag("newly-registered")
                r.set_verdict("suspicious", 50)
            elif age < 180:
                r.tag("young-domain")
        except ValueError:
            pass
    r.data = {k: d.get(k) for k in ("ldhName", "handle", "status", "events", "secureDNS")}


@module("crtsh", "crt.sh Certificates", types=DOM, provider="crtsh", rate=20, pivot=False,
        category="Subdomains", sample="example.com",
        desc="Certificate Transparency logs - discovers subdomains. Root-only by default (heavy).")
def crtsh(e, ctx, r):
    resp = ctx.get("https://crt.sh/", params={"q": f"%.{e.value}", "output": "json"},
                   timeout=max(ctx.timeout, 45))
    if resp.status != 200:
        raise ModuleError(f"crt.sh returned HTTP {resp.status} (it is often overloaded - retry later)")
    try:
        certs = resp.json() or []
    except ValueError:
        raise ModuleError("crt.sh returned invalid JSON (overloaded)")
    if not certs:
        raise NotFound("No certificates")
    names = set()
    for c in certs:
        for n in (c.get("name_value") or "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(e.value) and n != e.value:
                names.add(n)
    r.kv("Certificates", len(certs))
    r.kv("Unique subdomains", len(names))
    for n in sorted(names, key=lambda x: (x.count("."), x))[:ctx.max_children]:
        r.add("domain", n, "subdomain")
    certs.sort(key=lambda c: c.get("not_before", ""), reverse=True)
    r.table("Subdomains", ["Name"], [[n] for n in sorted(names)], limit=200)
    r.table("Latest certificates", ["Not before", "Common name", "Issuer"], [
        [c.get("not_before", "")[:10], c.get("common_name"), (c.get("issuer_name") or "").split("O=")[-1][:50]]
        for c in certs[:30]])
    r.link("crt.sh", f"https://crt.sh/?q={e.value}")


@module("hackertarget", "HackerTarget Host Search", types=DOM, provider="hackertarget", rate=10,
        pivot=False, category="Subdomains", sample="example.com",
        desc="Subdomain + IP discovery (free tier 50 queries/day).")
def hackertarget(e, ctx, r):
    resp = ctx.get("https://api.hackertarget.com/hostsearch/", params={"q": e.value})
    txt = resp.text().strip()
    if resp.status != 200 or "API count exceeded" in txt or txt.startswith("error"):
        raise ModuleError(txt[:120] or f"HTTP {resp.status}")
    rows = [l.split(",", 1) for l in txt.splitlines() if "," in l]
    if not rows:
        raise NotFound("No hosts")
    r.kv("Hosts found", len(rows))
    for host, ip in rows[:ctx.max_children]:
        r.add("domain", host, "subdomain")
        r.add("ipv4", ip, "resolves_to", via=("domain", host), pivot=False)
    r.table("Hosts", ["Host", "IP"], rows, limit=200)


@module("securitytrails", "SecurityTrails", types=DOM, keys=["securitytrails"], key_required=True,
        rate=20, pivot=False, category="Subdomains", sample="example.com",
        desc="Subdomain enumeration and current DNS from SecurityTrails.")
def securitytrails(e, ctx, r):
    k = ctx.need("securitytrails")
    d = ctx.get_json(f"https://api.securitytrails.com/v1/domain/{e.value}/subdomains",
                     params={"children_only": "false"}, headers={"APIKEY": k})
    subs = d.get("subdomains") or []
    r.kv("Subdomains", d.get("subdomain_count", len(subs)))
    for s in subs[:ctx.max_children]:
        r.add("domain", f"{s}.{e.value}", "subdomain")
    r.table("Subdomains", ["Name"], [[f"{s}.{e.value}"] for s in subs], limit=200)
    r.link("SecurityTrails", f"https://securitytrails.com/domain/{e.value}/dns")


@module("hunter", "Hunter.io Domain Search", types=DOM, keys=["hunter"], key_required=True, rate=15,
        category="People", sample="stripe.com",
        desc="Email addresses, names and positions associated with a domain.")
def hunter_domain(e, ctx, r):
    d = ctx.get_json("https://api.hunter.io/v2/domain-search",
                     params={"domain": E.registered_domain(e.value), "api_key": ctx.need("hunter"), "limit": 25})["data"]
    emails = d.get("emails") or []
    r.kv("Organisation", d.get("organization"))
    r.kv("Email pattern", d.get("pattern"))
    r.kv("Emails found", len(emails))
    r.kv("Disposable / webmail", f"{d.get('disposable')} / {d.get('webmail')}")
    if d.get("organization"):
        r.add("org", d["organization"], "organisation")
    for m in emails[:ctx.max_children]:
        r.add("email", m.get("value"), "employee_email")
    r.table("Emails", ["Email", "Name", "Position", "Confidence"], [
        [m.get("value"), f"{m.get('first_name') or ''} {m.get('last_name') or ''}".strip(), m.get("position"),
         m.get("confidence")] for m in emails])
    r.data = {k: v for k, v in d.items() if k != "emails"}


@module("wayback", "Wayback Machine", types=DOM, provider="archive", rate=15, pivot=False,
        category="History", sample="example.com",
        desc="Archived URL history: first/last capture, interesting files and endpoints.")
def wayback(e, ctx, r):
    rows = ctx.get_json("https://web.archive.org/cdx/search/cdx", params={
        "url": e.value, "matchType": "domain", "output": "json", "fl": "timestamp,original,statuscode,mimetype",
        "collapse": "urlkey", "limit": 500}, timeout=max(ctx.timeout, 30), retries=0)
    if not rows or len(rows) < 2:
        raise NotFound("No archived URLs")
    rows = rows[1:]
    stamps = sorted(r_[0] for r_ in rows)
    fmt = lambda s: f"{s[:4]}-{s[4:6]}-{s[6:8]}"
    r.kv("Archived URLs", len(rows) if len(rows) < 500 else "500+")
    r.kv("First capture", fmt(stamps[0]))
    r.kv("Last capture", fmt(stamps[-1]))
    interesting = re.compile(r"\.(zip|rar|7z|exe|dll|msi|apk|ps1|bat|js|php|aspx|jsp|sql|bak|env|cfg|conf|xml|json|pdf|doc[xm]?|xls[xm]?)(\?|$)", re.I)
    hits = [x for x in rows if interesting.search(x[1])]
    for x in hits[:min(10, ctx.max_children)]:
        r.add("url", x[1], "archived_url", pivot=False)
    r.table("Interesting archived URLs", ["Captured", "URL", "Status", "MIME"],
            [[fmt(x[0]), x[1], x[2], x[3]] for x in hits], limit=100)
    r.link("Wayback", f"https://web.archive.org/web/*/{e.value}*")


TYPO_KEYS = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr", "f": "drtgvc", "g": "ftyhbv",
    "h": "gyujnb", "i": "ujko", "j": "huikmn", "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm",
    "o": "iklp", "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy", "u": "yhji",
    "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu", "z": "asx",
}
HOMO = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "m": "rn", "w": "vv"}


def permutations(domain):
    reg = E.registered_domain(domain)
    name, _, tld = reg.partition(".")
    out = set()
    for i in range(len(name)):
        out.add(name[:i] + name[i + 1:])                                    # omission
        out.add(name[:i] + name[i] + name[i:])                              # repetition
        if i < len(name) - 1:
            out.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])        # transposition
        for k in TYPO_KEYS.get(name[i], ""):
            out.add(name[:i] + k + name[i + 1:])                            # replacement
        if name[i] in HOMO:
            out.add(name[:i] + HOMO[name[i]] + name[i + 1:])                # homoglyph
        if 0 < i:
            out.add(name[:i] + "-" + name[i:])                              # hyphenation
    perms = {f"{p}.{tld}" for p in out if p and p != name and not p.startswith("-")}
    for t in ("com", "net", "org", "co", "io", "info", "xyz", "online", "site", "top", "app", "co.uk", "us"):
        if t != tld:
            perms.add(f"{name}.{t}")
    for w in ("login", "secure", "account", "support", "verify", "my"):
        perms.add(f"{name}-{w}.{tld}")
        perms.add(f"{w}-{name}.{tld}")
    return sorted(perms)


@module("typosquat", "Lookalike Domains", types=DOM, provider="doh", enabled=False, pivot=False,
        category="Brand Protection", sample="example.com",
        desc="dnstwist-style permutations (typos, homoglyphs, TLD swaps) and checks which resolve. Many DNS queries.")
def typosquat(e, ctx, r):
    perms = permutations(e.value)

    def check(d):
        try:
            st, ans = ctx.dns(d, "A")
            ips = [a[1] for a in ans if a[0] == 1]
            return (d, ips) if ips else None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=12) as ex:
        found = [x for x in ex.map(check, perms) if x]
    r.kv("Permutations tested", len(perms))
    r.kv("Registered lookalikes", len(found))
    if not found:
        raise NotFound(f"None of {len(perms)} permutations resolve")
    for d, ips in found[:max(ctx.max_children, 25)]:
        r.add("domain", d, "lookalike", pivot=False)
    r.table("Resolving lookalikes", ["Domain", "A records"], [[d, ", ".join(ips)] for d, ips in found], limit=200)
    if found:
        r.tag("lookalikes")
