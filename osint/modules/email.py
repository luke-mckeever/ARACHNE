"""Email modules."""
import urllib.parse

from .. import entities as E
from ..registry import NotFound, module
from ..util import HttpError

FREE_PROVIDERS = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
                  "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "gmx.de",
                  "mail.com", "yandex.com", "yandex.ru", "mail.ru", "zoho.com", "tutanota.com", "hey.com",
                  "fastmail.com", "qq.com", "163.com", "126.com", "web.de", "btinternet.com", "pm.me"}


def _disposable(resp):
    return set(l.strip().lower() for l in resp.text().splitlines() if l.strip() and not l.startswith("#"))


@module("email_parse", "Email Breakdown", types=["email"], provider="local", category="Email", local_ok=True,
        sample="someone@example.com", desc="Splits address into domain + username, flags free/disposable providers.")
def email_parse(e, ctx, r):
    local, _, dom = e.value.partition("@")
    base_local = local.split("+")[0]
    r.kv("Local part", local)
    r.kv("Domain", dom)
    if "+" in local:
        r.kv("Sub-address tag", local.split("+", 1)[1])
    free = dom in FREE_PROVIDERS
    r.kv("Free webmail", free)
    if free:
        r.tag("webmail")
    try:
        disp = dom in ctx.feed("https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/"
                           "master/disposable_email_blocklist.conf", _disposable, ttl=86400)
    except Exception:
        disp = None
    r.kv("Disposable", disp)
    if disp:
        r.tag("disposable")
        r.set_verdict("suspicious", 40)
    r.add("domain", dom, "email_domain", pivot=not free)
    if E.RE_USERNAME.match(base_local) and len(base_local) >= 3:
        r.add("username", base_local, "local_part")


@module("gravatar", "Gravatar Profile", types=["email", "username"], keys=["gravatar"], rate=60,
        category="People", sample="beau@dentedreality.com.au",
        desc="Public Gravatar profile: name, location, verified social accounts and links.")
def gravatar(e, ctx, r):
    ident = E.gravatar_hash(e.value) if e.type == "email" else e.value
    k = ctx.key("gravatar")
    d = ctx.get_json(f"https://api.gravatar.com/v3/profiles/{urllib.parse.quote(ident)}",
                     headers={"Authorization": f"Bearer {k}"} if k else None)
    r.data = d
    r.kv("Display name", d.get("display_name"))
    r.kv("Location", d.get("location"))
    r.kv("Job / Company", " @ ".join(x for x in (d.get("job_title"), d.get("company")) if x))
    r.kv("Pronouns", d.get("pronouns"))
    r.kv("About", (d.get("description") or "")[:300])
    r.kv("Profile", d.get("profile_url"))
    accts = d.get("verified_accounts") or []
    for a in accts[:ctx.max_children]:
        if a.get("url"):
            r.add("account", a["url"], "verified_account", label=f"{a.get('service_label')}: {a['url'].rstrip('/').split('/')[-1]}")
    for l in (d.get("links") or [])[:ctx.max_children]:
        if l.get("url"):
            r.add("url", l["url"], "profile_link", pivot=False)
    if d.get("profile_url"):
        r.add("account", d["profile_url"], "gravatar_profile", label=f"Gravatar: {d['profile_url'].rstrip('/').split('/')[-1]}")
        uname = d["profile_url"].rstrip("/").split("/")[-1]
        if e.type == "email":
            r.add("username", uname, "gravatar_user")
    if d.get("company"):
        r.add("org", d["company"], "works_at")
    E.extract_text_entities(d.get("description"), r)
    r.table("Verified accounts", ["Service", "URL"], [[a.get("service_label"), a.get("url")] for a in accts])
    if d.get("avatar_url"):
        r.link("Avatar", d["avatar_url"])


@module("hibp", "Have I Been Pwned", types=["email"], keys=["hibp"], key_required=True, rate=10,
        category="Breaches", sample="test@example.com",
        desc="Data breaches the address appears in (HIBP v3).")
def hibp(e, ctx, r):
    resp = ctx.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(e.value)}",
                   params={"truncateResponse": "false"},
                   headers={"hibp-api-key": ctx.need("hibp")}, user_agent="ARACHNE-OSINT")
    if resp.status == 404:
        r.kv("Breaches", 0)
        r.message = "Not found in any breach"
        return
    if resp.status != 200:
        raise HttpError(resp.status, resp.body, resp.url)
    breaches = resp.json()
    r.kv("Breaches", len(breaches))
    classes = sorted({c for b in breaches for c in b.get("DataClasses", [])})
    r.kv("Exposed data", classes[:20])
    r.tag("breached")
    if "Passwords" in classes:
        r.tag("password-exposed")
    r.table("Breaches", ["Name", "Date", "Domain", "Records", "Data"], [
        [b.get("Title"), b.get("BreachDate"), b.get("Domain"), b.get("PwnCount"), ", ".join(b.get("DataClasses", [])[:6])]
        for b in sorted(breaches, key=lambda b: b.get("BreachDate", ""), reverse=True)])
    for b in breaches[:ctx.max_children]:
        if b.get("Domain"):
            r.add("domain", b["Domain"], "breached_on", pivot=False)
    r.data = [{k: b.get(k) for k in ("Name", "BreachDate", "Domain", "PwnCount", "DataClasses", "IsVerified")} for b in breaches]


@module("emailrep", "EmailRep.io", types=["email"], keys=["emailrep"], key_required=True, rate=10,
        category="Email", sample="bill@microsoft.com",
        desc="Email reputation: blacklists, breaches, profiles, domain age, spoofability.")
def emailrep(e, ctx, r):
    d = ctx.get_json(f"https://emailrep.io/{urllib.parse.quote(e.value)}",
                     headers={"Key": ctx.need("emailrep"), "User-Agent": "ARACHNE-OSINT"})
    det = d.get("details") or {}
    r.data = d
    r.kv("Reputation", d.get("reputation"))
    r.kv("Suspicious", d.get("suspicious"))
    r.kv("References", d.get("references"))
    for k in ("blacklisted", "malicious_activity", "credentials_leaked", "data_breach", "spam", "free_provider",
              "disposable", "deliverable", "spoofable", "new_domain", "first_seen", "last_seen",
              "days_since_domain_creation"):
        r.kv(k.replace("_", " ").title(), det.get(k))
    r.kv("Profiles", det.get("profiles"))
    for p in det.get("profiles") or []:
        r.tag(p)
    if det.get("malicious_activity") or det.get("blacklisted"):
        r.set_verdict("malicious", 80)
    elif d.get("suspicious"):
        r.set_verdict("suspicious", 50)


@module("leakcheck", "LeakCheck (public)", types=["email", "username"], provider="leakcheck", rate=20,
        category="Breaches", sample="test@example.com",
        desc="Free public LeakCheck API - breach sources and exposed field types.")
def leakcheck(e, ctx, r):
    d = ctx.get_json("https://leakcheck.io/api/public", params={"check": e.value}, ok=(200, 400))
    if not d.get("success") or not d.get("found"):
        raise NotFound(d.get("error") or "Not found in leaks")
    r.data = d
    r.kv("Leaks found", d.get("found"))
    r.kv("Exposed fields", d.get("fields"))
    r.tag("leaked")
    if "password" in (d.get("fields") or []):
        r.tag("password-exposed")
    r.table("Sources", ["Name", "Date"], [[s.get("name"), s.get("date")] for s in d.get("sources") or []], limit=100)


@module("hunter_verify", "Hunter.io Email Verifier", types=["email"], keys=["hunter"], key_required=True,
        provider="hunter", rate=15, category="Email", sample="patrick@stripe.com",
        desc="Deliverability check plus the public web pages where the address was found.")
def hunter_verify(e, ctx, r):
    d = ctx.get_json("https://api.hunter.io/v2/email-verifier",
                     params={"email": e.value, "api_key": ctx.need("hunter")})["data"]
    r.data = d
    r.kv("Result", d.get("result") or d.get("status"))
    r.kv("Score", d.get("score"))
    for k in ("regexp", "gibberish", "disposable", "webmail", "mx_records", "smtp_server", "smtp_check", "accept_all", "block"):
        r.kv(k.replace("_", " ").title(), d.get(k))
    srcs = d.get("sources") or []
    for s in srcs[:ctx.max_children]:
        r.add("url", s.get("uri"), "seen_on", pivot=False)
    r.table("Seen on", ["Domain", "URL", "Last seen"], [[s.get("domain"), s.get("uri"), s.get("last_seen_on")] for s in srcs])


@module("github_email", "GitHub Email Search", types=["email"], keys=["github"], provider="github", rate=10,
        category="People", sample="torvalds@linux-foundation.org",
        desc="Finds GitHub users and commit authors using this address.")
def github_email(e, ctx, r):
    k = ctx.key("github")
    hdr = {"Accept": "application/vnd.github+json"}
    if k:
        hdr["Authorization"] = f"Bearer {k}"
    users = ctx.get_json("https://api.github.com/search/users", params={"q": f"{e.value} in:email"}, headers=hdr)
    logins = {u["login"]: u.get("html_url") for u in users.get("items", [])}
    try:
        commits = ctx.get_json("https://api.github.com/search/commits",
                               params={"q": f"author-email:{e.value}", "per_page": 30}, headers=hdr)
    except Exception:
        commits = {}
    repos = set()
    for c in commits.get("items", []):
        a = c.get("author") or {}
        if a.get("login"):
            logins.setdefault(a["login"], a.get("html_url"))
        if c.get("repository"):
            repos.add(c["repository"].get("full_name"))
    if not logins and not repos:
        raise NotFound("No GitHub users or commits")
    r.kv("Users", list(logins))
    r.kv("Commit repos", sorted(repos)[:15])
    r.kv("Commits found", commits.get("total_count"))
    for login, url in list(logins.items())[:ctx.max_children]:
        r.add("username", login, "github_user")
