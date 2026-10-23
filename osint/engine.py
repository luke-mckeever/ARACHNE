"""Scan engine: runs modules against indicators and auto-pivots across the graph."""
import ipaddress
import json
import os
import threading
import time
import traceback
import uuid
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

from . import entities as E
from .registry import (MODULES, VERDICT_RANK, Ctx, Entity, MissingKey, ModuleError,
                       NotFound, Result)
from .settings import API_KEYS
from .util import HttpError, friendly_error

_pool = None
_pool_size = 0
_pool_lock = threading.Lock()


def get_pool(size):
    global _pool, _pool_size
    with _pool_lock:
        if _pool is None or size != _pool_size:
            old = _pool
            _pool = ThreadPoolExecutor(max_workers=max(1, size), thread_name_prefix="osint")
            _pool_size = size
            if old:
                old.shutdown(wait=False)
        return _pool


def module_enabled(settings, mod):
    return settings.get("modules", {}).get(mod.name, {}).get("enabled", mod.enabled)


def module_pivot(settings, mod):
    return settings.get("modules", {}).get(mod.name, {}).get("pivot", mod.pivot)


class NoiseFilter:
    def __init__(self, items):
        self.suffixes, self.words, self.exact, self.nets, self.users = [], [], set(), [], set()
        for raw in items or []:
            it = str(raw).strip().lower()
            if not it or it.startswith("#"):
                continue
            if it.startswith("user:"):
                self.users.add(it[5:])
                continue
            try:
                self.nets.append(ipaddress.ip_network(it, strict=False))
                continue
            except ValueError:
                pass
            if "." in it:
                self.suffixes.append(it)
            else:
                self.words.append(it)
            self.exact.add(it)

    def _host_noise(self, host):
        host = host.lower().strip(".")
        for s in self.suffixes:
            if host == s or host.endswith("." + s):
                return True
        return any(w in host for w in self.words)

    def match(self, etype, value):
        v = value.lower()
        if etype == "username":
            return v in self.users
        if v in self.exact:
            return True
        if etype in ("ipv4", "ipv6"):
            try:
                ip = ipaddress.ip_address(v)
                return any(ip in n for n in self.nets)
            except ValueError:
                return False
        if etype == "domain":
            return self._host_noise(v)
        if etype == "email":
            # personal mailboxes on big providers are interesting; only exact entries are noise
            return False
        if etype == "url":
            try:
                host = v.split("://", 1)[1].split("/", 1)[0].split(":")[0]
            except IndexError:
                return False
            return self._host_noise(host)
        return False


class Scan:
    def __init__(self, manager, seeds, overrides=None, scan_id=None):
        self.manager = manager
        self.id = scan_id or uuid.uuid4().hex[:12]
        self.created = time.time()
        self.settings = manager.settings.get()
        self.overrides = overrides or {}
        self.settings["pivot"].update({k: v for k, v in self.overrides.items()
                                       if k in self.settings["pivot"]})
        self.noise = NoiseFilter(self.settings.get("noise"))
        self.seeds = seeds
        self.title = ", ".join(v for _, v in seeds)[:120]
        self.nodes = {}
        self.edges = {}
        self.results = defaultdict(dict)
        self.events = []
        self.cond = threading.Condition()
        self.lock = threading.RLock()
        self.status = "idle"
        self.stop_event = threading.Event()
        self.pending = 0
        self.running = 0
        self.completed = 0
        self.errors = 0
        self.task_seen = set()
        self.prov_active = Counter()
        self.prov_queue = defaultdict(deque)
        self.max_logged = False
        self.finished_at = None
        self.last_save = time.time()

    # ------------------------------------------------------------------ events
    def emit(self, evt):
        with self.cond:
            self.events.append(evt)
            self.cond.notify_all()

    def log(self, msg, level="info"):
        self.emit({"t": "log", "level": level, "msg": msg, "ts": time.time()})

    def stats(self):
        return {"t": "stats", "pending": self.pending, "running": self.running,
                "completed": self.completed, "errors": self.errors,
                "nodes": len(self.nodes), "edges": len(self.edges)}

    # ------------------------------------------------------------------ graph
    def add_node(self, etype, value, depth, label=None, source=None, root=False, force=False):
        nid = E.node_id(etype, value)
        with self.lock:
            node = self.nodes.get(nid)
            if node:
                if depth < node["depth"]:
                    node["depth"] = depth
                if root and not node.get("root"):
                    node["root"] = True
                    self.emit({"t": "node_update", "id": nid, "root": True, "depth": depth})
                return node, False
            if not (root or force) and len(self.nodes) >= int(self.settings["pivot"]["max_nodes"]):
                if not self.max_logged:
                    self.max_logged = True
                    self.log(f"Node limit ({self.settings['pivot']['max_nodes']}) reached - "
                             "new indicators are no longer added. Raise it in Settings > Pivoting.", "warn")
                return None, False
            node = {
                "id": nid, "type": etype, "value": value, "label": (label or value)[:80],
                "depth": depth, "root": root, "verdict": None, "score": None, "tags": [],
                "noise": self.noise.match(etype, value),
                "private": etype in ("ipv4", "ipv6") and E.is_private_ip(value),
                "source": source, "expanded": False, "nopivot": False, "ts": time.time(),
            }
            self.nodes[nid] = node
        self.emit({"t": "node", "node": node})
        return node, True

    def add_edge(self, src, dst, rel, module):
        if src == dst:
            return
        eid = f"{src}|{dst}|{rel}"
        with self.lock:
            e = self.edges.get(eid)
            if e:
                if module not in e["modules"]:
                    e["modules"].append(module)
                return
            e = {"id": eid, "source": src, "target": dst, "rel": rel, "modules": [module]}
            self.edges[eid] = e
        self.emit({"t": "edge", "edge": e})

    def remove_node(self, nid):
        with self.lock:
            self.nodes.pop(nid, None)
            self.results.pop(nid, None)
            for eid in [k for k, e in self.edges.items() if e["source"] == nid or e["target"] == nid]:
                self.edges.pop(eid, None)
        self.emit({"t": "node_removed", "id": nid})

    # ------------------------------------------------------------------ scheduling
    def applicable(self, node, reason, only=None):
        mods = []
        allow_active = self.settings["network"].get("allow_active", False)
        for m in MODULES.values():
            if node["type"] not in m.types:
                continue
            if only is not None:
                if m.name in only:
                    mods.append(m)
                continue
            if not module_enabled(self.settings, m):
                continue
            if reason == "auto" and not module_pivot(self.settings, m):
                continue
            if m.active and not allow_active:
                continue
            if node["private"] and not m.local_ok:
                continue
            mods.append(m)
        return mods

    def should_pivot(self, node, parent):
        p = self.settings["pivot"]
        if not p.get("auto", True) or node["nopivot"]:
            return False
        if node["type"] not in p.get("types", []) or not E.TYPES[node["type"]]["pivotable"]:
            return False
        if node["depth"] > int(p.get("depth", 1)):
            return False
        if node["noise"] and p.get("skip_noise", True):
            return False
        if node["private"] and p.get("skip_private", True):
            return False
        if p.get("only_flagged") and VERDICT_RANK.get(parent.get("verdict"), 0) < 2:
            return False
        return True

    def expand(self, nid, reason="auto", only=None, force=False):
        node = self.nodes.get(nid)
        if not node:
            return 0
        n = 0
        for m in self.applicable(node, reason, only):
            key = (nid, m.name)
            with self.lock:
                if key in self.task_seen and not force:
                    continue
                self.task_seen.add(key)
            self._schedule(nid, m.name, force)
            n += 1
        if not node["expanded"]:
            node["expanded"] = True
            self.emit({"t": "node_update", "id": nid, "expanded": True})
        return n

    def _cap(self, mod):
        rate = self.settings.get("modules", {}).get(mod.name, {}).get("rate", mod.rate)
        if rate and rate < 30:
            return 1
        return int(self.settings["network"].get("provider_parallel", 4))

    def _schedule(self, nid, mname, force):
        mod = MODULES[mname]
        with self.lock:
            if self.status != "running":
                self.status = "running"
                self.stop_event.clear()
                self.emit({"t": "status", "status": "running"})
            self.pending += 1
            prov = mod.provider
            if self.prov_active[prov] < self._cap(mod):
                self.prov_active[prov] += 1
                self._submit(nid, mname, force)
            else:
                self.prov_queue[prov].append((nid, mname, force))
        self.emit({"t": "task", "id": nid, "module": mname, "state": "queued"})

    def _submit(self, nid, mname, force):
        pool = get_pool(int(self.settings["network"].get("concurrency", 12)))
        pool.submit(self._run, nid, mname, force)

    def _run(self, nid, mname, force):
        mod = MODULES[mname]
        node = self.nodes.get(nid)
        res = None
        started = False
        try:
            if self.stop_event.is_set() or node is None:
                return
            with self.lock:
                self.running += 1
            started = True
            self.emit({"t": "task", "id": nid, "module": mname, "state": "start"})
            res, ents = self._execute(mod, node, force)
            self._apply(node, mname, res, ents)
        except Exception as ex:  # engine bug safety net
            self.log(f"{mod.label}: internal error {ex}", "error")
            traceback.print_exc()
        finally:
            with self.lock:
                if started:
                    self.running -= 1
                self.pending -= 1
                self.completed += 1
                prov = mod.provider
                self.prov_active[prov] -= 1
                if self.prov_queue[prov] and not self.stop_event.is_set():
                    self.prov_active[prov] += 1
                    self._submit(*self.prov_queue[prov].popleft())
            self.emit({"t": "task", "id": nid, "module": mname, "state": "end",
                       "status": res["status"] if res else "cancelled"})
            self.emit(self.stats())
            if time.time() - self.last_save > 20:
                self.last_save = time.time()
                self.manager.save(self)
            self._check_done()

    def _execute(self, mod, node, force):
        cache_cfg = self.settings.get("cache", {})
        ckey = f"{mod.name}|{node['type']}|{node['value']}"
        if cache_cfg.get("enabled", True) and not force and not mod.active:
            hit = self.manager.cache.get(ckey, float(cache_cfg.get("ttl_hours", 24)) * 3600)
            if hit:
                hit["result"]["cached"] = True
                return hit["result"], hit["entities"]
        r = Result()
        ctx = Ctx(self.settings, mod, self.stop_event)
        t0 = time.time()
        try:
            mod.fn(Entity(node["type"], node["value"]), ctx, r)
        except NotFound as ex:
            r.status, r.message = "notfound", str(ex) or "No data"
        except MissingKey as ex:
            r.status, r.message = "skipped", str(ex)
        except HttpError as ex:
            r.status = "ratelimited" if ex.status == 429 else "error"
            r.message = str(ex)
            if ex.status in (401, 403):
                names = [k["label"] for k in API_KEYS if k["id"] in mod.keys]
                r.message += f" - check the {' / '.join(names) or 'API'} key in Settings > API Keys"
        except ModuleError as ex:
            r.status, r.message = "error", str(ex)
        except Exception as ex:
            r.status, r.message = "error", friendly_error(ex)
        out = r.to_dict(mod.name)
        out["elapsed"] = round(time.time() - t0, 2)
        out["ts"] = time.time()
        ents = r.entities[:150]
        if r.status in ("ok", "notfound") and cache_cfg.get("enabled", True) and not mod.active:
            self.manager.cache.set(ckey, {"result": out, "entities": ents})
        if r.status == "error":
            self.log(f"{mod.label} on {node['value']}: {r.message}", "error")
        elif r.status == "ratelimited":
            self.log(f"{mod.label}: rate limited ({r.message})", "warn")
        return out, ents

    def _apply(self, node, mname, res, ents):
        nid = node["id"]
        to_expand = []
        with self.lock:
            if nid not in self.nodes:
                return
            self.results[nid][mname] = res
            if res["status"] == "error":
                self.errors += 1
            changed = False
            if res.get("verdict") and VERDICT_RANK[res["verdict"]] > VERDICT_RANK.get(node["verdict"], 0):
                node["verdict"] = res["verdict"]
                changed = True
            if res.get("score") is not None and res["verdict"] in ("malicious", "suspicious"):
                node["score"] = max(node["score"] or 0, res["score"])
                changed = True
            for t in res.get("tags") or []:
                if t not in node["tags"]:
                    node["tags"].append(t)
                    changed = True
        self.emit({"t": "result", "id": nid, "module": mname, "result": res})
        if changed:
            self.emit({"t": "node_update", "id": nid, "verdict": node["verdict"],
                       "score": node["score"], "tags": node["tags"]})
        for ent in ents:
            child, created = self.add_node(ent["type"], ent["value"], node["depth"] + 1,
                                           ent.get("label"), mname)
            if child is None:
                continue
            src = ent.get("via") if ent.get("via") in self.nodes else nid
            self.add_edge(src, child["id"], ent["rel"], mname)
            if created:
                if ent.get("pivot") is False:
                    child["nopivot"] = True
                if self.should_pivot(child, node):
                    to_expand.append(child["id"])
        for cid in to_expand:
            if not self.stop_event.is_set():
                self.expand(cid, "auto")

    def _check_done(self):
        with self.lock:
            if self.pending > 0 or self.status not in ("running", "stopping"):
                return
            self.status = "stopped" if self.stop_event.is_set() else "done"
            self.finished_at = time.time()
        self.emit({"t": "status", "status": self.status})
        self.log(f"Scan {self.status}: {len(self.nodes)} indicators, {len(self.edges)} links, "
                 f"{self.completed} lookups ({self.errors} errors).")
        self.manager.save(self)

    # ------------------------------------------------------------------ control
    def start(self):
        self.status = "running"
        self.emit({"t": "status", "status": "running"})
        for etype, value in self.seeds:
            node, _ = self.add_node(etype, value, 0, root=True)
            self.log(f"Seed {E.TYPES[etype]['label']}: {value}")
            self.expand(node["id"], "root")
        self._check_done()

    def stop(self):
        with self.lock:
            if self.status not in ("running",):
                return
            self.stop_event.set()
            self.status = "stopping"
            dropped = 0
            for q in self.prov_queue.values():
                while q:
                    q.popleft()
                    self.pending -= 1
                    dropped += 1
        self.emit({"t": "status", "status": "stopping"})
        self.log(f"Stopping scan - {dropped} queued lookups dropped.", "warn")
        self._check_done()

    def add_seed(self, etype, value, parent=None):
        depth = 0
        if parent and parent in self.nodes:
            depth = self.nodes[parent]["depth"] + 1
        node, created = self.add_node(etype, value, depth, root=parent is None, force=True)
        if parent and parent in self.nodes:
            self.add_edge(parent, node["id"], "manual", "user")
        return node

    def snapshot(self):
        with self.lock:
            return {
                "id": self.id, "title": self.title, "created": self.created,
                "finished": self.finished_at, "status": self.status,
                "seeds": self.seeds, "overrides": self.overrides,
                "nodes": list(self.nodes.values()), "edges": list(self.edges.values()),
                "results": dict(self.results), "event_index": len(self.events),
                "stats": self.stats(),
            }

    @classmethod
    def restore(cls, manager, snap):
        s = cls(manager, [tuple(x) for x in snap.get("seeds", [])], snap.get("overrides"), snap["id"])
        s.created = snap.get("created", time.time())
        s.finished_at = snap.get("finished")
        s.title = snap.get("title", s.title)
        s.status = "done" if snap.get("status") == "done" else "stopped"
        for n in snap.get("nodes", []):
            s.nodes[n["id"]] = n
        for e in snap.get("edges", []):
            s.edges[e["id"]] = e
        for nid, mods in snap.get("results", {}).items():
            s.results[nid] = mods
            for m in mods:
                s.task_seen.add((nid, m))
        return s


class ScanManager:
    def __init__(self, settings, cache, scans_dir):
        self.settings = settings
        self.cache = cache
        self.dir = scans_dir
        os.makedirs(scans_dir, exist_ok=True)
        self.scans = {}
        self.lock = threading.Lock()

    def create(self, seeds, overrides=None):
        s = Scan(self, seeds, overrides)
        with self.lock:
            self.scans[s.id] = s
        threading.Thread(target=s.start, daemon=True).start()
        return s

    def get(self, sid):
        with self.lock:
            s = self.scans.get(sid)
        if s:
            return s
        path = os.path.join(self.dir, f"{sid}.json")
        if not sid.isalnum() or not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as fh:
            s = Scan.restore(self, json.load(fh))
        with self.lock:
            self.scans[sid] = s
        return s

    def save(self, scan):
        try:
            snap = scan.snapshot()
            with open(os.path.join(self.dir, f"{scan.id}.json"), "w", encoding="utf-8") as fh:
                json.dump(snap, fh)
        except (OSError, TypeError) as ex:
            print("save failed:", ex)

    def list(self):
        out = {}
        for name in os.listdir(self.dir):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.dir, name), "r", encoding="utf-8") as fh:
                    snap = json.load(fh)
                out[snap["id"]] = self._summary(snap)
            except (OSError, ValueError, KeyError):
                continue
        with self.lock:
            for s in self.scans.values():
                out[s.id] = self._summary(s.snapshot())
        return sorted(out.values(), key=lambda x: x["created"], reverse=True)

    @staticmethod
    def _summary(snap):
        nodes = snap.get("nodes", [])
        return {"id": snap["id"], "title": snap.get("title"), "created": snap.get("created"),
                "status": snap.get("status"), "nodes": len(nodes),
                "edges": len(snap.get("edges", [])),
                "malicious": sum(1 for n in nodes if n.get("verdict") == "malicious"),
                "suspicious": sum(1 for n in nodes if n.get("verdict") == "suspicious")}

    def delete(self, sid):
        with self.lock:
            s = self.scans.pop(sid, None)
        if s:
            s.stop()
        path = os.path.join(self.dir, f"{sid}.json")
        if sid.isalnum() and os.path.exists(path):
            os.remove(path)
