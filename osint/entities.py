"""Indicator types: detection, refanging, normalisation."""
import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

# type -> display metadata. "pivotable" types can be expanded with modules.
TYPES = {
    "ipv4":     {"label": "IPv4",      "pivotable": True},
    "ipv6":     {"label": "IPv6",      "pivotable": True},
    "domain":   {"label": "Domain",    "pivotable": True},
    "url":      {"label": "URL",       "pivotable": True},
    "email":    {"label": "Email",     "pivotable": True},
    "username": {"label": "Username",  "pivotable": True},
    "hash":     {"label": "File hash", "pivotable": True},
    "asn":      {"label": "ASN",       "pivotable": True},
    "cve":      {"label": "CVE",       "pivotable": True},
    "malware":  {"label": "Malware",   "pivotable": True},
    "account":  {"label": "Account",   "pivotable": False},
    "org":      {"label": "Org",       "pivotable": False},
}

RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
RE_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9_-]{1,63}(?<!-)\.)+[A-Za-z][A-Za-z0-9-]{1,62}$")
RE_HASH = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
RE_ASN = re.compile(r"^AS(\d{1,10})$", re.I)
RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
RE_USERNAME = re.compile(r"^@?[A-Za-z0-9_.\-]{2,40}$")

# Free text extraction (bios, comments, descriptions)
RX_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
RX_URL = re.compile(r"https?://[^\s\"'<>()\[\]]+")

# Second-level public suffixes commonly seen; good enough without a full PSL.
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
    "co.jp", "ne.jp", "or.jp", "co.kr", "or.kr", "com.br", "net.br", "org.br",
    "com.cn", "net.cn", "org.cn", "com.hk", "com.tw", "com.sg", "com.my", "co.in",
    "net.in", "org.in", "co.za", "com.mx", "com.ar", "com.tr", "com.ru", "co.il",
    "com.ua", "com.pl", "co.id", "or.id", "com.vn", "com.ph", "com.pk", "com.ng",
    "co.th", "in.th", "com.eg", "com.sa", "com.co", "com.pe", "eu.org",
}


def refang(s: str) -> str:
    s = s.strip().strip("\"'")
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    s = re.sub(r"^fxp", "ftp", s, flags=re.I)
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."),
                 ("[@]", "@"), ("(@)", "@"), ("[at]", "@"), ("[:]", ":"), ("[://]", "://")):
        s = s.replace(a, b)
    return s


def is_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def is_private_ip(v):
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return False
    return not ip.is_global


def registered_domain(d: str) -> str:
    parts = d.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in _MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def hash_kind(h: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h), "hash")


def detect(raw: str):
    """Return (type, normalised value) or (None, raw)."""
    v = refang(raw)
    if not v:
        return None, raw
    if re.match(r"^[a-z][a-z0-9+.\-]*://", v, re.I):
        return "url", normalize("url", v)
    if is_ip(v):
        return ("ipv6" if ":" in v else "ipv4"), normalize("ipv4", v)
    if RE_EMAIL.match(v):
        return "email", v.lower()
    if RE_CVE.match(v):
        return "cve", v.upper()
    if RE_ASN.match(v):
        return "asn", normalize("asn", v)
    if RE_HASH.match(v):
        return "hash", v.lower()
    if "/" in v and RE_DOMAIN.match(v.split("/", 1)[0]):
        return "url", normalize("url", "http://" + v)
    if RE_DOMAIN.match(v) and not v.replace(".", "").isdigit():
        return "domain", v.lower().rstrip(".")
    if RE_USERNAME.match(v):
        return "username", v.lstrip("@")
    return None, v


def normalize(etype: str, value):
    """Normalise a value for a given type; returns None when invalid."""
    if value is None:
        return None
    v = refang(str(value))
    if not v:
        return None
    if etype in ("ipv4", "ipv6"):
        try:
            return str(ipaddress.ip_address(v.strip("[]")))
        except ValueError:
            return None
    if etype == "domain":
        v = v.lower().rstrip(".")
        if v.startswith("*."):
            v = v[2:]
        return v if RE_DOMAIN.match(v) and not is_ip(v) else None
    if etype == "email":
        v = v.lower().removeprefix("mailto:")
        return v if RE_EMAIL.match(v) else None
    if etype == "url":
        try:
            p = urlsplit(v)
        except ValueError:
            return None
        if not p.scheme or not p.netloc:
            return None
        return p._replace(scheme=p.scheme.lower(), netloc=p.netloc.lower()).geturl()
    if etype == "hash":
        v = v.lower()
        return v if RE_HASH.match(v) else None
    if etype == "asn":
        m = re.match(r"^(?:AS)?\s*(\d{1,10})$", v, re.I)
        return f"AS{m.group(1)}" if m else None
    if etype == "cve":
        return v.upper() if RE_CVE.match(v) else None
    if etype == "username":
        v = v.lstrip("@")
        return v if RE_USERNAME.match(v) else None
    if etype in ("org", "malware"):
        v = " ".join(v.split()).strip(" .,;")
        return v[:120] if v else None
    if etype == "account":
        return v if v.startswith("http") else None
    return v


def node_id(etype, value):
    v = value.lower() if etype in ("org", "malware") else value
    return f"{etype}:{v}"


def ip_type(v):
    return "ipv6" if ":" in v else "ipv4"


def gravatar_hash(email, algo="sha256"):
    return hashlib.new(algo, email.strip().lower().encode()).hexdigest()


def extract_text_entities(text, result, rel="mentioned", limit=10):
    """Pull emails / urls out of free text into a Result."""
    if not text:
        return
    n = 0
    for m in RX_EMAIL.findall(text):
        if n >= limit:
            return
        result.add("email", m, rel)
        n += 1
    for m in RX_URL.findall(text):
        if n >= limit:
            return
        result.add("url", m.rstrip(".,;"), rel)
        n += 1
