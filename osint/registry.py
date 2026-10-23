"""Module registry, the Result object modules fill in, and the per-call context."""
import base64

from . import entities as E
from .util import HttpError, LIMITER, feed, http_request, trim

MODULES = {}

VERDICT_RANK = {None: 0, "info": 0, "clean": 1, "suspicious": 2, "malicious": 3}


class NotFound(Exception):
    pass


class MissingKey(Exception):
    pass


class ModuleError(Exception):
    pass


class ModuleDef:
    def __init__(self, name, label, fn, types, provider=None, category="Misc", desc="",
                 keys=(), key_required=False, enabled=True, pivot=True, rate=None,
                 active=False, sample=None, local_ok=False, options=None):
        self.name = name
        self.label = label
        self.fn = fn
        self.types = list(types)
        self.provider = provider or name
        self.category = category
        self.desc = desc
        self.keys = list(keys)
        self.key_required = key_required
        self.enabled = enabled            # default
        self.pivot = pivot                # default: run on auto-pivoted nodes
        self.rate = rate                  # default requests/minute (None = unlimited)
        self.active = active              # touches the target directly
        self.sample = sample
        self.local_ok = local_ok          # run on private IPs
        self.options = options or []      # [{id,label,type,default}]

    def meta(self):
        return {k: getattr(self, k) for k in (
            "name", "label", "types", "provider", "category", "desc", "keys", "key_required",
            "enabled", "pivot", "rate", "active", "sample", "options")}


def module(name, label, **kw):
    def deco(fn):
        MODULES[name] = ModuleDef(name, label, fn, **kw)
        return fn
    return deco


class Result:
    def __init__(self):
        self.status = "ok"
        self.message = None
        self.summary = []
        self.tables = []
        self.tags = []
        self.links = []
        self.entities = []
        self.verdict = None
        self.score = None
        self.data = None

    # --- presentation -------------------------------------------------
    def kv(self, key, value):
        if value is None or value == "" or value == [] or value == {}:
            return
        if isinstance(value, (list, tuple, set)):
            value = ", ".join(str(v) for v in value if v not in (None, ""))
            if not value:
                return
        elif not isinstance(value, (int, float, bool)):
            value = str(value)
        self.summary.append([key, value])

    def table(self, title, columns, rows, limit=50):
        rows = [[("" if c is None else str(c)) for c in row] for row in rows]
        if rows:
            self.tables.append({"title": title, "columns": columns, "rows": rows[:limit],
                                "total": len(rows)})

    def tag(self, *tags):
        for t in tags:
            if t and str(t) not in self.tags:
                self.tags.append(str(t)[:40])

    def link(self, label, url):
        self.links.append({"label": label, "url": url})

    def set_verdict(self, verdict, score=None):
        if VERDICT_RANK.get(verdict, 0) >= VERDICT_RANK.get(self.verdict, 0):
            self.verdict = verdict
        if score is not None:
            self.score = max(self.score or 0, score)

    def score_verdict(self, score, mal, sus, clean_below=None):
        if score is None:
            return
        if score >= mal:
            self.set_verdict("malicious", score)
        elif score >= sus:
            self.set_verdict("suspicious", score)
        elif clean_below is None or score < clean_below:
            self.set_verdict("clean", score)

    def not_found(self, msg="No data"):
        raise NotFound(msg)

    # --- graph --------------------------------------------------------
    def add(self, etype, value, rel, label=None, pivot=True, meta=None, via=None):
        """Attach a related indicator. `via=(type, value)` links it to another
        entity from this same result rather than to the queried node."""
        if value is None:
            return None
        v = E.normalize(etype, value)
        if v is None and etype in ("ipv4", "ipv6") and E.is_ip(str(value)):
            v = E.normalize(E.ip_type(str(value)), value)
        if v is None:
            return None
        if etype in ("ipv4", "ipv6"):
            etype = E.ip_type(v)
        ent = {"type": etype, "value": v, "rel": rel, "label": label, "pivot": pivot, "meta": meta}
        if via:
            vt, vv = via
            vv = E.normalize(vt, vv)
            if vv:
                ent["via"] = E.node_id(vt, vv)
        self.entities.append(ent)
        return v

    def to_dict(self, module_name):
        return {
            "module": module_name, "status": self.status, "message": self.message,
            "summary": self.summary, "tables": self.tables, "tags": self.tags,
            "links": self.links, "verdict": self.verdict, "score": self.score,
            "entities": [{k: e[k] for k in ("type", "value", "rel")} for e in self.entities],
            "data": trim(self.data) if self.data is not None else None,
        }


class Entity:
    def __init__(self, etype, value):
        self.type = etype
        self.value = value


class Ctx:
    def __init__(self, settings, mod: ModuleDef, stop_event=None):
        self.settings = settings
        self.mod = mod
        self.stop_event = stop_event
        net = settings.get("network", {})
        self.timeout = net.get("timeout", 20)
        self.proxy = net.get("proxy") or None
        self.ua = net.get("user_agent") or None
        self.verify = net.get("verify_tls", True)
        self.max_children = int(settings.get("pivot", {}).get("max_children", 15))
        self.shared_limit = int(settings.get("pivot", {}).get("shared_host_threshold", 30) or 0)
        mset = settings.get("modules", {}).get(mod.name, {})
        self.mset = mset
        self.rate = mset.get("rate", mod.rate)

    def key(self, name):
        return (self.settings.get("api_keys", {}).get(name) or "").strip()

    def shared_hosting(self, r, hostnames):
        """True (and tags the result) when an IP serves too many hostnames to be a useful pivot."""
        n = len(set(hostnames))
        if self.shared_limit and n > self.shared_limit:
            r.tag("shared-hosting")
            r.kv("Shared hosting", f"{n} hostnames - not added to graph (threshold {self.shared_limit})")
            return True
        return False

    def need(self, name):
        k = self.key(name)
        if not k:
            raise MissingKey(f"API key '{name}' not configured")
        return k

    def opt(self, option_id):
        if option_id in self.mset:
            return self.mset[option_id]
        for o in self.mod.options:
            if o["id"] == option_id:
                return o.get("default")
        return None

    def get(self, url, method="GET", throttle=True, **kw):
        if throttle:
            LIMITER.wait(self.mod.provider, self.rate, self.stop_event)
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("verify", self.verify)
        return http_request(url, method=method, proxy=self.proxy,
                            user_agent=kw.pop("user_agent", None) or self.ua, **kw)

    def get_json(self, url, method="GET", ok=(200,), notfound=(404,), **kw):
        r = self.get(url, method=method, **kw)
        if r.status in notfound:
            msg = None
            try:
                j = r.json()
                if isinstance(j, dict):
                    msg = j.get("message") or j.get("error") or j.get("detail")
            except Exception:
                pass
            raise NotFound(str(msg) if msg else "Not found")
        if r.status not in ok:
            raise HttpError(r.status, r.body, url)
        try:
            return r.json()
        except ValueError:
            raise ModuleError(f"Invalid JSON from {url.split('/')[2]}")

    def post_json(self, url, **kw):
        return self.get_json(url, method="POST", **kw)

    def feed(self, url, parse, **kw):
        return feed(url, parse, proxy=self.proxy, verify=self.verify, **kw)

    def dns(self, name, rtype="A"):
        """DNS-over-HTTPS query. Returns (status, answers[(type, data)])."""
        resolver = self.settings.get("network", {}).get("doh", "google")
        if resolver == "cloudflare":
            url, hdr = "https://cloudflare-dns.com/dns-query", {"Accept": "application/dns-json"}
        else:
            url, hdr = "https://dns.google/resolve", {}
        r = http_request(url, params={"name": name, "type": rtype}, headers=hdr,
                         timeout=self.timeout, proxy=self.proxy, verify=self.verify)
        if r.status != 200:
            raise HttpError(r.status, r.body, url)
        j = r.json()
        ans = [(a.get("type"), (a.get("data") or "").strip()) for a in j.get("Answer", []) or []]
        return j.get("Status", 0), ans


DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 257: "CAA"}


def vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
