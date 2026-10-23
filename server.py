"""ARACHNE OSINT - local web server.

    python server.py [--host 127.0.0.1] [--port 8777] [--no-browser]
"""
import argparse
import json
import mimetypes
import os
import re
import sys
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from osint import VERSION
from osint import entities as E
from osint import modules  # noqa: F401  (registers modules)
from osint.engine import ScanManager
from osint.registry import MODULES, Ctx, Entity, MissingKey, NotFound, Result
from osint.settings import API_KEYS, DEFAULT_NOISE, Settings
from osint.sites import SITES
from osint.util import TLS_EXTRA_ROOTS, DiskCache, HttpError, friendly_error

ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(ROOT, "static")
DATA = os.path.join(ROOT, "data")

os.makedirs(DATA, exist_ok=True)
settings = Settings(os.path.join(DATA, "settings.json"))
cache = DiskCache(os.path.join(DATA, "cache"))
manager = ScanManager(settings, cache, os.path.join(DATA, "scans"))

mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")


def parse_seeds(text, forced_type=None):
    seeds, bad = [], []
    for raw in re.split(r"[\n,;]+", text or ""):
        raw = raw.strip()
        if not raw:
            continue
        if forced_type and forced_type != "auto":
            v = E.normalize(forced_type, raw)
            (seeds.append((forced_type, v)) if v else bad.append(raw))
            continue
        t, v = E.detect(raw)
        (seeds.append((t, v)) if t else bad.append(raw))
    return seeds, bad


class Handler(BaseHTTPRequestHandler):
    server_version = f"ARACHNE/{VERSION}"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # request logging is noise; errors still go through log_error

    def log_error(self, fmt, *args):
        sys.stderr.write("  error: %s\n" % (fmt % args))

    def do_HEAD(self):
        self.send_response(200 if not self.path.startswith("/api/") else 405)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ------------------------------------------------------------- helpers
    def send_json(self, obj, status=200):
        body = json.dumps(obj, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode() or "{}")
        except ValueError:
            return {}

    def err(self, msg, status=400):
        self.send_json({"error": msg}, status)

    def _origin_ok(self):
        # block cross-site requests from other web pages to this local API
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = self.headers.get("Host", "")
        return urlsplit(origin).netloc == host

    # ------------------------------------------------------------- routing
    def do_GET(self):
        try:
            self.route("GET")
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception as ex:
            traceback.print_exc()
            self.err(str(ex), 500)

    def do_POST(self):
        if not self._origin_ok():
            return self.err("cross-origin request refused", 403)
        try:
            self.route("POST")
        except Exception as ex:
            traceback.print_exc()
            self.err(str(ex), 500)

    def do_DELETE(self):
        if not self._origin_ok():
            return self.err("cross-origin request refused", 403)
        self.route("DELETE")

    def route(self, method):
        u = urlsplit(self.path)
        path, qs = u.path, parse_qs(u.query)
        if method == "GET" and not path.startswith("/api/"):
            return self.static(path)
        m = re.match(r"^/api/scan/([a-f0-9]+)(?:/(\w+))?$", path)
        if m:
            sid, action = m.group(1), m.group(2)
            scan = manager.get(sid)
            if not scan:
                return self.err("scan not found", 404)
            return self.scan_action(method, scan, action, qs)
        m = re.match(r"^/api/modules/(\w+)/test$", path)
        if m and method == "POST":
            return self.test_module(m.group(1), self.body())
        key = (method, path)
        if key == ("GET", "/api/meta"):
            return self.send_json({
                "version": VERSION, "types": E.TYPES,
                "modules": [m.meta() for m in MODULES.values()],
                "api_keys": API_KEYS, "sites": SITES, "default_noise": DEFAULT_NOISE,
                "tls_extra_roots": TLS_EXTRA_ROOTS,
            })
        if key == ("GET", "/api/settings"):
            return self.send_json(settings.public())
        if key == ("POST", "/api/settings"):
            settings.update(self.body())
            return self.send_json(settings.public())
        if key == ("POST", "/api/settings/reset"):
            settings.reset(self.body().get("section", "all"))
            return self.send_json(settings.public())
        if key == ("GET", "/api/settings/export"):
            return self.send_json(settings.export(qs.get("keys", ["0"])[0] == "1"))
        if key == ("POST", "/api/detect"):
            seeds, bad = parse_seeds(self.body().get("value", ""))
            return self.send_json({"seeds": seeds, "invalid": bad})
        if key == ("POST", "/api/scan"):
            b = self.body()
            seeds, bad = parse_seeds(b.get("value", ""), b.get("type"))
            if not seeds:
                return self.err("No valid indicator found. Supported: IP, domain, URL, email, username, hash, ASN, CVE.")
            scan = manager.create(seeds, b.get("overrides") or {})
            return self.send_json({"id": scan.id, "seeds": seeds, "invalid": bad})
        if key == ("GET", "/api/scans"):
            return self.send_json(manager.list())
        m = re.match(r"^/api/scans/([a-f0-9]+)$", path)
        if m and method == "DELETE":
            manager.delete(m.group(1))
            return self.send_json({"ok": True})
        if key == ("POST", "/api/cache/clear"):
            return self.send_json({"cleared": cache.clear()})
        if key == ("GET", "/api/cache"):
            return self.send_json({"entries": cache.size()})
        return self.err("not found", 404)

    def static(self, path):
        if path in ("/", ""):
            path = "/index.html"
        full = os.path.normpath(os.path.join(STATIC, path.lstrip("/")))
        if not full.startswith(STATIC) or not os.path.isfile(full):
            return self.err("not found", 404)
        with open(full, "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", (mimetypes.guess_type(full)[0] or "application/octet-stream") + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    # ------------------------------------------------------------- scans
    def scan_action(self, method, scan, action, qs):
        if method == "GET" and action is None:
            return self.send_json(scan.snapshot())
        if method == "GET" and action == "events":
            return self.stream(scan, int(qs.get("from", ["0"])[0]))
        if method != "POST":
            return self.err("bad method", 405)
        b = self.body()
        if action == "stop":
            scan.stop()
            return self.send_json({"ok": True})
        if action == "expand":
            nid = b.get("node_id")
            if nid not in scan.nodes:
                return self.err("unknown node", 404)
            if b.get("deep"):
                scan.nodes[nid]["depth"] = 0
                scan.nodes[nid]["nopivot"] = False
            n = scan.expand(nid, "manual", b.get("modules"), force=bool(b.get("force")))
            return self.send_json({"scheduled": n})
        if action == "add":
            seeds, bad = parse_seeds(b.get("value", ""), b.get("type"))
            added = []
            for t, v in seeds:
                node = scan.add_seed(t, v, b.get("parent"))
                if b.get("expand", True):
                    scan.expand(node["id"], "manual")
                added.append(node["id"])
            return self.send_json({"added": added, "invalid": bad})
        if action == "remove":
            for nid in b.get("node_ids", []):
                scan.remove_node(nid)
            return self.send_json({"ok": True})
        if action == "save":
            manager.save(scan)
            return self.send_json({"ok": True})
        return self.err("unknown action", 404)

    def stream(self, scan, idx):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.close_connection = True
        last_ping = time.time()
        while True:
            with scan.cond:
                if len(scan.events) <= idx:
                    scan.cond.wait(timeout=10)
                batch = scan.events[idx:]
            try:
                if batch:
                    out = []
                    for evt in batch:
                        idx += 1
                        out.append(f"id: {idx}\ndata: {json.dumps(evt, default=str)}\n\n")
                    self.wfile.write("".join(out).encode())
                    self.wfile.flush()
                elif time.time() - last_ping > 10:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    last_ping = time.time()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                return

    def test_module(self, name, b):
        mod = MODULES.get(name)
        if not mod:
            return self.err("unknown module", 404)
        value = b.get("value") or mod.sample
        etype, v = E.detect(value)
        if etype not in mod.types:
            etype = mod.types[0]
            v = E.normalize(etype, value) or value
        r = Result()
        t0 = time.time()
        try:
            mod.fn(Entity(etype, v), Ctx(settings.get(), mod), r)
        except NotFound as ex:
            r.status, r.message = "notfound", str(ex) or "No data"
        except MissingKey as ex:
            r.status, r.message = "skipped", str(ex)
        except HttpError as ex:
            r.status, r.message = "error", str(ex)
        except Exception as ex:
            r.status, r.message = "error", friendly_error(ex)
        out = r.to_dict(name)
        out.update({"elapsed": round(time.time() - t0, 2), "value": v, "type": etype})
        return self.send_json(out)


def main():
    ap = argparse.ArgumentParser(description="ARACHNE OSINT pivoting scanner")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8777)
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    srv.daemon_threads = True
    url = f"http://{'127.0.0.1' if a.host in ('0.0.0.0', '') else a.host}:{a.port}/"
    print(f"\n  ARACHNE OSINT v{VERSION}  -  {len(MODULES)} modules loaded")
    print(f"  TLS extra roots: {TLS_EXTRA_ROOTS}")
    print(f"  UI: {url}\n  Ctrl+C to stop\n")
    if not a.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  bye")


if __name__ == "__main__":
    main()
