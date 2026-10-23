"""Persistent settings (settings.json next to server.py)."""
import copy
import json
import os
import threading

API_KEYS = [
    {"id": "virustotal", "label": "VirusTotal", "url": "https://www.virustotal.com/gui/my-apikey",
     "help": "Free tier: 4 req/min, 500/day. Raise the module rate limit if you have premium."},
    {"id": "abuseipdb", "label": "AbuseIPDB", "url": "https://www.abuseipdb.com/account/api"},
    {"id": "abusech", "label": "abuse.ch Auth-Key", "url": "https://auth.abuse.ch/",
     "help": "One key covers MalwareBazaar, URLhaus and ThreatFox."},
    {"id": "otx", "label": "AlienVault OTX", "url": "https://otx.alienvault.com/api",
     "help": "Optional - works without a key at lower rate limits."},
    {"id": "shodan", "label": "Shodan", "url": "https://account.shodan.io/"},
    {"id": "greynoise", "label": "GreyNoise", "url": "https://viz.greynoise.io/account/api-key"},
    {"id": "urlscan", "label": "urlscan.io", "url": "https://urlscan.io/user/profile/",
     "help": "Optional - higher search quota with a key."},
    {"id": "ipinfo", "label": "ipinfo.io token", "url": "https://ipinfo.io/account/token",
     "help": "Optional."},
    {"id": "ipqs", "label": "IPQualityScore", "url": "https://www.ipqualityscore.com/user/settings"},
    {"id": "pulsedive", "label": "Pulsedive", "url": "https://pulsedive.com/account/",
     "help": "Optional."},
    {"id": "securitytrails", "label": "SecurityTrails", "url": "https://securitytrails.com/app/account/credentials"},
    {"id": "hunter", "label": "Hunter.io", "url": "https://hunter.io/api-keys"},
    {"id": "hibp", "label": "Have I Been Pwned", "url": "https://haveibeenpwned.com/API/Key"},
    {"id": "emailrep", "label": "EmailRep.io", "url": "https://emailrep.io/key"},
    {"id": "github", "label": "GitHub token", "url": "https://github.com/settings/tokens",
     "help": "Optional - a no-scope token raises rate limits from 60 to 5000/hr."},
    {"id": "gsb", "label": "Google Safe Browsing", "url": "https://developers.google.com/safe-browsing/v4/get-started"},
    {"id": "hybrid", "label": "Hybrid Analysis", "url": "https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab"},
    {"id": "criminalip", "label": "Criminal IP", "url": "https://www.criminalip.io/mypage/information"},
    {"id": "nvd", "label": "NVD API key", "url": "https://nvd.nist.gov/developers/request-an-api-key",
     "help": "Optional."},
    {"id": "gravatar", "label": "Gravatar API key", "url": "https://gravatar.com/developers/applications",
     "help": "Optional."},
]

DEFAULT_NOISE = [
    # big platforms / shared infra - shown in the graph but not expanded
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gmail.com",
    "googlemail.com", "youtube.com", "microsoft.com", "outlook.com", "hotmail.com",
    "live.com", "office.com", "office365.com", "azure.com", "azureedge.net", "windows.net",
    "msn.com", "yahoo.com", "aol.com", "icloud.com", "me.com", "apple.com", "proton.me",
    "protonmail.com", "facebook.com", "fbcdn.net", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "github.com", "githubusercontent.com", "github.io", "amazon.com",
    "amazonaws.com", "awsdns", "cloudfront.net", "cloudflare.com", "cloudflare.net",
    "akamai.net", "akamaiedge.net", "akamaitechnologies.com", "edgekey.net", "edgesuite.net",
    "fastly.net", "wikipedia.org", "w3.org", "domaincontrol.com", "registrar-servers.com",
    "godaddy.com", "namecheap.com", "markmonitor.com", "nsone.net", "ultradns", "dynect.net",
    "googledomains.com", "1e100.net", "digicert.com", "letsencrypt.org", "sectigo.com",
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
    # role mailbox local-parts never pivoted as usernames
    "user:info", "user:admin", "user:contact", "user:support", "user:sales", "user:abuse",
    "user:hostmaster", "user:postmaster", "user:webmaster", "user:noreply", "user:no-reply",
    "user:hello", "user:security", "user:privacy", "user:dns", "user:domains", "user:billing",
    "user:help", "user:office", "user:mail", "user:root", "user:test",
]

DEFAULTS = {
    "api_keys": {},
    "modules": {},   # name -> {"enabled": bool, "pivot": bool, "rate": int, <option>: value}
    "pivot": {
        "auto": True,
        "depth": 1,
        "max_nodes": 250,
        "max_children": 15,
        "types": ["ipv4", "ipv6", "domain", "url", "email", "username", "hash"],
        "skip_private": True,
        "skip_noise": True,
        "only_flagged": False,
        "shared_host_threshold": 30,   # IPs with more hostnames than this are treated as shared hosting   # only auto-pivot nodes with a suspicious/malicious verdict
    },
    "noise": DEFAULT_NOISE,
    "network": {
        "timeout": 20,
        "concurrency": 12,
        "provider_parallel": 4,
        "proxy": "",
        "user_agent": "",
        "doh": "google",
        "allow_active": False,
        "verify_tls": True,
    },
    "cache": {"enabled": True, "ttl_hours": 24},
    "username_sites": {"disabled": [], "custom": []},
    "ui": {},
}

_lock = threading.Lock()


def _merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and k not in ("api_keys", "modules", "ui"):
            out[k] = _merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


class Settings:
    def __init__(self, path):
        self.path = path
        self.data = copy.deepcopy(DEFAULTS)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    self.data = _merge(DEFAULTS, json.load(fh))
            except (OSError, ValueError):
                pass

    def get(self):
        with _lock:
            return copy.deepcopy(self.data)

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2)
        os.replace(tmp, self.path)

    def public(self):
        """Settings for the UI with API keys masked."""
        d = self.get()
        keys = {}
        raw = d.get("api_keys", {})
        for k, v in raw.items():
            if v:
                keys[k] = {"set": True, "preview": ("•" * 6) + v[-4:] if len(v) > 6 else "••••",
                           "same_as": [o for o, ov in raw.items() if o != k and ov == v]}
        d["api_keys"] = keys
        return d

    def update(self, patch):
        with _lock:
            patch = dict(patch or {})
            keys = patch.pop("api_keys", None)
            if keys:
                cur = self.data.setdefault("api_keys", {})
                for k, v in keys.items():
                    if v is None or v == "":
                        cur.pop(k, None)
                    else:
                        cur[k] = str(v).strip()
            mods = patch.pop("modules", None)
            if mods:
                cur = self.data.setdefault("modules", {})
                for name, cfg in mods.items():
                    if cfg is None:
                        cur.pop(name, None)
                    else:
                        cur.setdefault(name, {}).update(cfg)
            ui = patch.pop("ui", None)
            if ui is not None:
                self.data.setdefault("ui", {}).update(ui)
            self.data = _merge(self.data, patch)
            self.save()

    def reset(self, section):
        with _lock:
            if section == "all":
                keys = self.data.get("api_keys", {})
                self.data = copy.deepcopy(DEFAULTS)
                self.data["api_keys"] = keys
            elif section in DEFAULTS:
                self.data[section] = copy.deepcopy(DEFAULTS[section])
            self.save()

    def export(self, include_keys=False):
        d = self.get()
        if not include_keys:
            d.pop("api_keys", None)
        return d
