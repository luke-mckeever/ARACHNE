"""Username / persona modules."""
import html
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from .. import entities as E
from ..registry import NotFound, module
from ..sites import SITES
from ..util import http_request, ts


def site_list(settings):
    cfg = settings.get("username_sites", {})
    disabled = set(cfg.get("disabled", []))
    sites = [s for s in SITES if s["name"] not in disabled]
    for c in cfg.get("custom", []) or []:
        if c.get("name") and c.get("url") and "{u}" in c["url"] and c["name"] not in disabled:
            sites.append({"cat": "Custom", "check": "status", **c})
    return sites


def check_site(site, user, ctx):
    q = urllib.parse.quote(user)
    url = site["url"].replace("{u}", q)
    try:
        resp = http_request(url, timeout=min(ctx.timeout, 12), proxy=ctx.proxy, verify=ctx.verify, max_bytes=600_000,
                            headers={"Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
                                     "Accept-Language": "en-US,en;q=0.9"})
    except Exception as ex:
        return site, "error", str(ex)[:80]
    body = resp.text() if site.get("check") in ("present", "absent") else ""
    chk = site.get("check", "status")
    if resp.status in (403, 429, 503) and chk == "status":
        return site, "blocked", f"HTTP {resp.status}"
    if chk == "status":
        found = resp.status == 200
    elif chk == "present":
        found = resp.status == 200 and site.get("match", "") in body
    else:  # absent
        found = resp.status == 200 and site.get("match", "\x00") not in body
    return site, "found" if found else "missing", resp.status


@module("username_sites", "Username Enumeration", types=["username"], provider="sites", category="People",
        sample="torvalds",
        desc="Sherlock-style check of the username across many sites (editable in Settings > Username sites).")
def username_sites(e, ctx, r):
    sites = site_list(ctx.settings)
    with ThreadPoolExecutor(max_workers=16) as ex:
        res = list(ex.map(lambda s: check_site(s, e.value, ctx), sites))
    found = [(s, st) for s, st, _ in res if st == "found"]
    r.kv("Sites checked", len(sites))
    r.kv("Profiles found", len(found))
    r.kv("Blocked / errors", sum(1 for _, st, _ in res if st in ("blocked", "error")))
    q = urllib.parse.quote(e.value)
    for s, _ in found:
        prof = (s.get("profile") or s["url"]).replace("{u}", q)
        r.add("account", prof, "has_account", label=f"{s['name']}: {e.value}")
    r.table("Results", ["Site", "Category", "Result", "Detail"], [
        [s["name"], s.get("cat"), st, d] for s, st, d in sorted(res, key=lambda x: (x[1] != "found", x[0]["name"]))],
        limit=200)
    if not found:
        raise NotFound(f"No profiles found on {len(sites)} sites")


@module("github_user", "GitHub Profile", types=["username"], keys=["github"], provider="github", rate=30,
        category="People", sample="torvalds",
        desc="GitHub profile, blog, company, and email addresses leaked in public commit metadata.")
def github_user(e, ctx, r):
    k = ctx.key("github")
    hdr = {"Accept": "application/vnd.github+json"}
    if k:
        hdr["Authorization"] = f"Bearer {k}"
    u = ctx.get_json(f"https://api.github.com/users/{urllib.parse.quote(e.value)}", headers=hdr)
    r.kv("Name", u.get("name"))
    r.kv("Company", u.get("company"))
    r.kv("Location", u.get("location"))
    r.kv("Blog", u.get("blog"))
    r.kv("Public email", u.get("email"))
    r.kv("Bio", u.get("bio"))
    r.kv("Twitter", u.get("twitter_username"))
    r.kv("Repos / Gists", f"{u.get('public_repos')} / {u.get('public_gists')}")
    r.kv("Followers", u.get("followers"))
    r.kv("Created", (u.get("created_at") or "")[:10])
    r.add("account", u.get("html_url"), "github_profile", label=f"GitHub: {u.get('login')}")
    if u.get("email"):
        r.add("email", u["email"], "profile_email")
    if u.get("blog"):
        blog = u["blog"] if "://" in u["blog"] else "https://" + u["blog"]
        r.add("url", blog, "website")
    if u.get("twitter_username"):
        r.add("account", f"https://x.com/{u['twitter_username']}", "twitter", label=f"X: {u['twitter_username']}")
    if u.get("company"):
        r.add("org", u["company"].lstrip("@"), "works_at")
    E.extract_text_entities(u.get("bio"), r)
    emails = {}
    try:
        events = ctx.get_json(f"https://api.github.com/users/{urllib.parse.quote(e.value)}/events/public",
                              params={"per_page": 100}, headers=hdr)
        for ev in events or []:
            if ev.get("type") != "PushEvent":
                continue
            for c in (ev.get("payload") or {}).get("commits", []):
                a = c.get("author") or {}
                m = (a.get("email") or "").lower()
                if m and "noreply" not in m and "@" in m:
                    emails.setdefault(m, set()).add(a.get("name") or "")
    except Exception:
        pass
    for m in list(emails)[:ctx.max_children]:
        r.add("email", m, "commit_email")
    r.table("Emails from commits", ["Email", "Author names"], [[m, ", ".join(sorted(n))] for m, n in emails.items()])
    try:
        repos = ctx.get_json(f"https://api.github.com/users/{urllib.parse.quote(e.value)}/repos",
                             params={"sort": "updated", "per_page": 15}, headers=hdr)
        r.table("Recent repositories", ["Repo", "Stars", "Language", "Updated", "Fork"], [
            [x.get("name"), x.get("stargazers_count"), x.get("language"), (x.get("pushed_at") or "")[:10], x.get("fork")]
            for x in repos])
    except Exception:
        pass
    r.data = u


@module("reddit", "Reddit Profile", types=["username"], provider="reddit", rate=20, category="People", enabled=False,
        sample="spez", desc="Reddit account age, karma and profile description. Off by default: Reddit blocks many unauthenticated clients.")
def reddit(e, ctx, r):
    d = ctx.get_json(f"https://www.reddit.com/user/{urllib.parse.quote(e.value)}/about.json",
                     user_agent="ARACHNE-OSINT/1.0 (by /u/arachne)")
    u = d.get("data") or {}
    if u.get("is_suspended"):
        r.tag("suspended")
    r.kv("Created", ts(u.get("created_utc")))
    r.kv("Link karma", u.get("link_karma"))
    r.kv("Comment karma", u.get("comment_karma"))
    r.kv("Verified email", u.get("has_verified_email"))
    r.kv("Employee", u.get("is_employee"))
    sub = u.get("subreddit") or {}
    r.kv("Description", sub.get("public_description"))
    E.extract_text_entities(sub.get("public_description"), r)
    r.add("account", f"https://www.reddit.com/user/{u.get('name', e.value)}", "reddit_profile", label=f"Reddit: {e.value}")
    r.data = {k: u.get(k) for k in ("name", "created_utc", "link_karma", "comment_karma", "is_employee", "is_mod", "verified")}


@module("keybase", "Keybase Proofs", types=["username"], provider="keybase", rate=30, category="People",
        sample="chris", desc="Keybase identity proofs linking accounts, domains and PGP keys.")
def keybase(e, ctx, r):
    d = ctx.get_json("https://keybase.io/_/api/1.0/user/lookup.json", params={"usernames": e.value})
    them = [t for t in (d.get("them") or []) if t]
    if not them:
        raise NotFound("No Keybase user")
    t = them[0]
    prof = t.get("profile") or {}
    r.kv("Full name", prof.get("full_name"))
    r.kv("Location", prof.get("location"))
    r.kv("Bio", prof.get("bio"))
    E.extract_text_entities(prof.get("bio"), r)
    r.add("account", f"https://keybase.io/{e.value}", "keybase_profile", label=f"Keybase: {e.value}")
    rows = []
    for p in (t.get("proofs_summary") or {}).get("all", []):
        rows.append([p.get("proof_type"), p.get("nametag"), p.get("service_url")])
        if p.get("proof_type") in ("dns", "generic_web_site"):
            host = (p.get("nametag") or "").replace("https://", "").replace("http://", "").split("/")[0]
            r.add("domain", host, "keybase_proof")
        elif p.get("service_url"):
            r.add("account", p["service_url"], "keybase_proof", label=f"{p.get('proof_type')}: {p.get('nametag')}")
            if p.get("nametag") and p.get("nametag").lower() != e.value.lower():
                r.add("username", p["nametag"], "alias")
    r.table("Proofs", ["Service", "Name", "URL"], rows)
    keys = ((t.get("public_keys") or {}).get("primary") or {})
    r.kv("PGP fingerprint", keys.get("key_fingerprint"))
    r.data = {"basics": t.get("basics"), "profile": prof}


@module("hackernews", "Hacker News", types=["username"], provider="hn", category="People", sample="pg",
        desc="Hacker News account karma, age and 'about' text (emails/URLs extracted).")
def hackernews(e, ctx, r):
    d = ctx.get_json(f"https://hacker-news.firebaseio.com/v0/user/{urllib.parse.quote(e.value)}.json")
    if not d:
        raise NotFound("No HN user")
    about = re.sub(r"<[^>]+>", " ", html.unescape(d.get("about") or ""))
    r.kv("Karma", d.get("karma"))
    r.kv("Created", ts(d.get("created")))
    r.kv("Submissions", len(d.get("submitted") or []))
    r.kv("About", about[:400])
    E.extract_text_entities(about, r)
    r.add("account", f"https://news.ycombinator.com/user?id={e.value}", "hn_profile", label=f"HN: {e.value}")
    d.pop("submitted", None)
    r.data = d
