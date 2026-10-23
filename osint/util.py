"""HTTP client, rate limiting, disk cache and feed cache (stdlib only)."""
import gzip
import hashlib
import http.client
import json
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/129.0 Safari/537.36")

_SSL = ssl.create_default_context()
# Windows only exposes root CAs it has already downloaded on demand (browsers trigger that,
# OpenSSL never does), so current CAs such as SwissSign 2022 (URLhaus) or GoDaddy G2
# (archive.org) can be missing. Add Mozilla's CA bundle: certifi's if installed (newer),
# otherwise the copy shipped next to this file.
try:
    import certifi
    TLS_EXTRA_ROOTS = certifi.where()
except ImportError:
    TLS_EXTRA_ROOTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cacert.pem")
try:
    _SSL.load_verify_locations(TLS_EXTRA_ROOTS)
except OSError as _ex:
    TLS_EXTRA_ROOTS = f"unavailable ({_ex})"
_SSL_NOVERIFY = ssl._create_unverified_context()

# ---- DNS: cache answers and cap concurrent lookups so bursts of parallel requests don't
# overwhelm the local resolver (seen as "getaddrinfo failed" on Windows).
_real_getaddrinfo = socket.getaddrinfo
_dns_cache = {}
_dns_lock = threading.Lock()
_dns_slots = threading.BoundedSemaphore(6)
DNS_TTL = 300


def _cached_getaddrinfo(host, port, *args, **kwargs):
    key = (host, port, args, tuple(sorted(kwargs.items())))
    hit = _dns_cache.get(key)
    if hit and time.monotonic() - hit[0] < DNS_TTL:
        return hit[1]
    err = None
    for attempt in range(3):
        try:
            with _dns_slots:
                res = _real_getaddrinfo(host, port, *args, **kwargs)
            with _dns_lock:
                _dns_cache[key] = (time.monotonic(), res)
            return res
        except socket.gaierror as ex:
            err = ex
            if ex.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -999)) and attempt:
                break  # genuinely does not exist
            time.sleep(0.6 * (attempt + 1))
    if hit:  # stale answer beats no answer
        return hit[1]
    raise err


socket.getaddrinfo = _cached_getaddrinfo

# Connection-level failures worth retrying. Read timeouts are deliberately excluded: a slow
# endpoint will be just as slow the second time.
TRANSIENT = (ConnectionResetError, ConnectionAbortedError, http.client.RemoteDisconnected)


def _is_transient(ex):
    if isinstance(ex, TRANSIENT):
        return True
    if isinstance(ex, urllib.error.URLError) and not isinstance(ex, urllib.error.HTTPError):
        r = ex.reason
        return isinstance(r, (socket.gaierror, socket.timeout, TimeoutError, ConnectionError)) or             "timed out" in str(r)
    return False


def friendly_error(ex):
    """Turn low-level network exceptions into a short, readable explanation."""
    r = getattr(ex, "reason", ex)
    txt = str(r)
    if isinstance(r, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in txt:
        return "TLS certificate could not be verified for this host"
    if isinstance(r, socket.gaierror) or "getaddrinfo" in txt:
        return "Network: hostname could not be resolved (DNS failure)"
    if isinstance(r, (socket.timeout, TimeoutError)) or "timed out" in txt:
        return "Network: request timed out"
    if isinstance(r, (ConnectionResetError, ConnectionAbortedError)) or "10054" in txt:
        return "Network: connection reset by remote host"
    if isinstance(ex, http.client.RemoteDisconnected):
        return "Network: server closed the connection"
    return f"{type(ex).__name__}: {ex}"


class HttpError(Exception):
    def __init__(self, status, body=b"", url=""):
        self.status = status
        self.body = body or b""
        self.url = url
        host = urllib.parse.urlsplit(url).netloc
        super().__init__(f"HTTP {status} from {host}: {self.snippet()}")

    def snippet(self, n=180):
        try:
            txt = self.body.decode("utf-8", "replace")
        except Exception:
            txt = ""
        try:
            j = json.loads(txt)
            for k in ("message", "error", "detail", "errors", "query_status"):
                if isinstance(j, dict) and j.get(k):
                    v = j[k]
                    if isinstance(v, list) and v and isinstance(v[0], dict):
                        v = v[0].get("details") or v[0].get("message") or v[0].get("detail") or v[0]
                    if isinstance(v, dict):
                        v = v.get("message") or v.get("details") or v
                    return str(v)[:n]
        except Exception:
            pass
        return " ".join(txt.split())[:n]


class Response:
    def __init__(self, status, headers, body, url):
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url

    def text(self):
        ctype = self.headers.get("Content-Type", "") if self.headers else ""
        enc = "utf-8"
        if "charset=" in ctype:
            enc = ctype.split("charset=")[-1].split(";")[0].strip() or "utf-8"
        try:
            return self.body.decode(enc, "replace")
        except LookupError:
            return self.body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.text() or "null")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http_request(url, method="GET", params=None, headers=None, data=None, json_body=None,
                 timeout=20, follow_redirects=True, proxy=None, user_agent=None,
                 max_bytes=12_000_000, verify=True, retries=2):
    if params:
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        url += ("&" if "?" in url else "?") + q
    hdrs = {"User-Agent": user_agent or DEFAULT_UA, "Accept": "*/*", "Accept-Encoding": "gzip, deflate"}
    hdrs.update({k: v for k, v in (headers or {}).items() if v is not None})
    body = None
    if json_body is not None:
        body = json.dumps(json_body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    elif data is not None:
        body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    handlers = [urllib.request.HTTPSHandler(context=_SSL if verify else _SSL_NOVERIFY)]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    if not follow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    try:
        for attempt in range(retries + 1):
            try:
                resp = opener.open(req, timeout=timeout)
                status, rh, raw, final = resp.status, resp.headers, resp.read(max_bytes), resp.geturl()
                break
            except urllib.error.HTTPError:
                raise
            except Exception as ex:
                if attempt >= retries or not _is_transient(ex):
                    raise
                time.sleep(1.0 * (attempt + 1))
    except urllib.error.HTTPError as e:
        status, rh, final = e.code, e.headers, url
        try:
            raw = e.read(max_bytes) if e.fp else b""
        except Exception:
            raw = b""
    enc = (rh.get("Content-Encoding") or "").lower() if rh else ""
    try:
        if enc == "gzip":
            raw = gzip.decompress(raw)
        elif enc == "deflate":
            raw = zlib.decompress(raw)
    except Exception:
        pass
    return Response(status, rh, raw, final)


class RateLimiter:
    """Global per-provider spacing of requests (requests per minute)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._next = {}

    def wait(self, provider, per_min, stop_event=None):
        if not per_min or per_min <= 0:
            return
        interval = 60.0 / per_min
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next.get(provider, 0))
            self._next[provider] = slot + interval
        delay = slot - now
        if delay > 0:
            if stop_event is not None:
                stop_event.wait(delay)
            else:
                time.sleep(delay)


LIMITER = RateLimiter()


class DiskCache:
    def __init__(self, path):
        self.path = path
        os.makedirs(path, exist_ok=True)

    def _file(self, key):
        return os.path.join(self.path, hashlib.sha1(key.encode()).hexdigest() + ".json")

    def get(self, key, ttl_seconds):
        f = self._file(key)
        try:
            if time.time() - os.path.getmtime(f) > ttl_seconds:
                return None
            with open(f, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def set(self, key, value):
        try:
            with open(self._file(key), "w", encoding="utf-8") as fh:
                json.dump(value, fh)
        except (OSError, TypeError):
            pass

    def clear(self):
        n = 0
        for name in os.listdir(self.path):
            if name.endswith(".json"):
                try:
                    os.remove(os.path.join(self.path, name))
                    n += 1
                except OSError:
                    pass
        return n

    def size(self):
        try:
            return len([n for n in os.listdir(self.path) if n.endswith(".json")])
        except OSError:
            return 0


_feeds = {}
_feed_lock = threading.Lock()


def feed(url, parse, ttl=6 * 3600, timeout=40, proxy=None, verify=True):
    """Download & parse a bulk feed, kept in memory for `ttl` seconds."""
    with _feed_lock:
        hit = _feeds.get(url)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
        r = http_request(url, timeout=timeout, proxy=proxy, verify=verify)
        if r.status >= 400:
            raise HttpError(r.status, r.body, url)
        val = parse(r)
        _feeds[url] = (time.time(), val)
        return val


def trim(obj, max_list=60, max_str=4000, depth=0):
    """Shrink big API responses before shipping them to the UI."""
    if depth > 8:
        return "…"
    if isinstance(obj, dict):
        return {k: trim(v, max_list, max_str, depth + 1) for k, v in list(obj.items())[:200]}
    if isinstance(obj, list):
        out = [trim(v, max_list, max_str, depth + 1) for v in obj[:max_list]]
        if len(obj) > max_list:
            out.append(f"… {len(obj) - max_list} more")
        return out
    if isinstance(obj, str) and len(obj) > max_str:
        return obj[:max_str] + "…"
    return obj


def ts(epoch):
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.gmtime(int(epoch)))
    except (TypeError, ValueError, OverflowError):
        return None
