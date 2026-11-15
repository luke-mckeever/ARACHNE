"""MITRE ATT&CK and threat actor profiles from the knowledge base ARACHNE ships with (static/intel/threat-kb.json,
built by tools/build_threat_kb.py from MITRE ATT&CK and the MISP Galaxy). Works offline, needs no key."""
import json
import os
import re
import threading

from ..registry import NotFound, module

KB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "static", "intel", "threat-kb.json")
_kb = None
_lock = threading.Lock()


def norm(s):
    return re.sub(r"[^a-z0-9]", "", str(s or "").lower())


def kb():
    """The knowledge base plus name -> ID indexes (loaded once)."""
    global _kb
    with _lock:
        if _kb is None:
            with open(KB_PATH, encoding="utf-8") as fh:
                d = json.load(fh)
            idx = {"software": {}, "groups": {}, "campaigns": {}, "families": {}}
            for kind in ("software", "groups", "campaigns"):
                for k, o in d[kind].items():
                    idx[kind].setdefault(k.lower(), k)
                    for n in [o["n"]] + o.get("a", []):
                        if len(norm(n)) >= 3:
                            idx[kind].setdefault(norm(n), k)
                        short = re.sub(r"\s+(group|team|gang)$", "", n, flags=re.I)   # "Lazarus Group" -> "Lazarus"
                        if short != n and len(norm(short)) >= 4:
                            idx[kind].setdefault(norm(short), k)
            for i, (name, aliases, mp) in enumerate(d["families"]):
                for n in [name] + aliases + ([mp.split(".", 1)[-1]] if mp else []):
                    if len(norm(n)) >= 3:
                        idx["families"].setdefault(norm(n), i)
            used = {}
            for kind in ("groups", "software", "campaigns"):
                for k, o in d[kind].items():
                    for t in o.get("t", []):
                        used.setdefault(t, {"groups": [], "software": [], "campaigns": []})[kind].append(k)
            d["idx"], d["used"] = idx, used
            d["tactic_name"] = {s: n for s, _, n in d["tactics"]}
            d["tactic_order"] = {s: i for i, (s, _, _) in enumerate(d["tactics"])}
            _kb = d
        return _kb


def find(kind, value):
    d = kb()
    v = str(value or "").strip()
    k = d["idx"][kind].get(v.lower()) or d["idx"][kind].get(norm(v))
    if k is None and kind == "software":
        # "win.cobalt_strike", "Win32/Emotet", "Trojan.AgentTesla": try the last part of the name
        tail = re.split(r"[./:]", v)[-1]
        k = d["idx"][kind].get(norm(tail)) if len(norm(tail)) >= 4 else None
    return k


def find_family(value):
    d = kb()
    i = d["idx"]["families"].get(norm(value))
    if i is None:
        tail = re.split(r"[./:]", str(value))[-1]
        i = d["idx"]["families"].get(norm(tail)) if len(norm(tail)) >= 4 else None
    return d["families"][i] if i is not None else None


def technique_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def tech_rows(ids):
    d = kb()
    rows = []
    for t in ids:
        x = d["techniques"].get(t)
        if not x:
            continue
        rows.append((min((d["tactic_order"].get(a, 99) for a in x["ta"]), default=99), t,
                     [t, x["n"], ", ".join(d["tactic_name"].get(a, a) for a in x["ta"])]))
    return [r for _, _, r in sorted(rows, key=lambda r: (r[0], r[1]))]


def attack_link(r, kind, k):
    if not re.match(r"^[GSCT]\d{4}", k):
        return
    path = {"groups": "groups", "software": "software", "campaigns": "campaigns"}.get(kind)
    r.link("MITRE ATT&CK", technique_url(k) if kind == "techniques" else f"https://attack.mitre.org/{path}/{k}/")


def profile_software(e, ctx, r, sid):
    d = kb()
    s = d["software"][sid]
    r.kv("ATT&CK", f"{sid} · {s['n']}")
    r.kv("Type", "Tool" if s["k"] == "tool" else "Malware")
    r.kv("Also known as", s.get("a", [])[:12])
    r.kv("Platforms", s.get("pl"))
    r.kv("Used by", ", ".join(d["groups"][g]["n"] for g in s["g"][:12]) + (f" and {len(s['g']) - 12} more" if len(s["g"]) > 12 else "") if s["g"] else None)
    r.kv("Campaigns", [d["campaigns"][c]["n"] for c in s["c"]][:8])
    r.kv("ATT&CK techniques", len(s["t"]))
    r.kv("Description", s.get("d"))
    r.tag("att&ck", s["k"])
    r.table("ATT&CK techniques", ["ID", "Technique", "Tactic"], tech_rows(s["t"]), limit=200)
    groups = sorted(s["g"], key=lambda g: d["groups"][g]["n"].lower())
    r.table("Threat actors", ["Actor", "ID", "Country", "Also known as"],
            [[d["groups"][g]["n"], g, d["groups"][g].get("country", ""), ", ".join(d["groups"][g]["a"][:4])] for g in groups], limit=200)
    r.table("Campaigns", ["Campaign", "ID", "First seen", "Last seen"],
            [[d["campaigns"][c]["n"], c, d["campaigns"][c].get("first") or "", d["campaigns"][c].get("last") or ""] for c in s["c"]])
    for g in groups[:ctx.max_children]:
        r.add("actor", d["groups"][g]["n"], "used_by", pivot=False)
    for c in s["c"][:5]:
        r.add("campaign", d["campaigns"][c]["n"], "seen_in", pivot=False)
    attack_link(r, "software", sid)
    if s.get("mp"):
        r.link("Malpedia", f"https://malpedia.caad.fkie.fraunhofer.de/details/{s['mp']}")
    r.data = {"kb": "software", "id": sid}


@module("mitre_attack", "MITRE ATT&CK & Threat Actors", types=["malware", "actor", "technique", "campaign"],
        provider="local", category="Threat Intel", local_ok=True, sample="Cobalt Strike",
        desc="Links malware families to the threat actors, campaigns and ATT&CK techniques known to use them, and "
             "gives actor profiles (aliases, country, targets). Built in, works offline: MITRE ATT&CK + MISP Galaxy.")
def mitre_attack(e, ctx, r):
    d = kb()
    if e.type == "malware":
        sid = find("software", e.value)
        if sid:
            return profile_software(e, ctx, r, sid)
        fam = find_family(e.value)
        if not fam:
            raise NotFound("Not a known malware family or tool")
        name, aliases, mp = fam
        r.kv("Malware family", name)
        r.kv("Also known as", aliases[:12])
        r.kv("ATT&CK", "Not described in MITRE ATT&CK yet")
        if mp:
            r.kv("Platform", {"win": "Windows", "elf": "Linux", "osx": "macOS", "apk": "Android", "ios": "iOS", "js": "JavaScript",
                              "jar": "Java", "ps1": "PowerShell", "py": "Python", "php": "PHP", "vbs": "VBScript"}.get(mp.split(".")[0]))
            r.link("Malpedia", f"https://malpedia.caad.fkie.fraunhofer.de/details/{mp}")
        r.data = {"kb": "family", "name": name, "mp": mp}
        return
    if e.type == "actor":
        gid = find("groups", e.value)
        if not gid:
            raise NotFound("Not a known threat actor")
        g = d["groups"][gid]
        r.kv("Threat actor", g["n"])
        r.kv("ATT&CK", gid if g["src"] == "attack" else "Not in MITRE ATT&CK (profile from MISP Galaxy)")
        r.kv("Also known as", g.get("a", [])[:15])
        r.kv("Country", g.get("country"))
        r.kv("Suspected sponsor", g.get("sponsor"))
        r.kv("Motive", g.get("motive"))
        r.kv("Targets", g.get("sectors"))
        r.kv("Victims", g.get("victims", [])[:15])
        r.kv("Active since", g.get("since"))
        r.kv("Software", len(g["s"]) or None)
        r.kv("ATT&CK techniques", len(g["t"]) or None)
        r.kv("Description", g.get("d"))
        r.tag("threat-actor", g.get("country"), (g.get("motive") or "").lower() or None)
        r.table("ATT&CK techniques", ["ID", "Technique", "Tactic"], tech_rows(g["t"]), limit=300)
        sw = sorted(g["s"], key=lambda s: d["software"][s]["n"].lower())
        r.table("Software", ["Name", "ID", "Type"], [[d["software"][s]["n"], s, d["software"][s]["k"]] for s in sw], limit=200)
        r.table("Campaigns", ["Campaign", "ID", "First seen", "Last seen"],
                [[d["campaigns"][c]["n"], c, d["campaigns"][c].get("first") or "", d["campaigns"][c].get("last") or ""] for c in g["c"]])
        r.table("References", ["URL"], [[u] for u in g.get("refs", [])])
        for s in [s for s in sw if d["software"][s]["k"] == "malware"][:ctx.max_children]:
            r.add("malware", d["software"][s]["n"], "uses", pivot=False)
        for c in g["c"][:5]:
            r.add("campaign", d["campaigns"][c]["n"], "conducted", pivot=False)
        attack_link(r, "groups", gid)
        r.data = {"kb": "group", "id": gid}
        return
    if e.type == "campaign":
        cid = find("campaigns", e.value)
        if not cid:
            raise NotFound("Not a campaign in MITRE ATT&CK")
        c = d["campaigns"][cid]
        r.kv("Campaign", f"{cid} · {c['n']}")
        r.kv("Also known as", c.get("a"))
        r.kv("First seen", c.get("first"))
        r.kv("Last seen", c.get("last"))
        r.kv("Attributed to", [d["groups"][g]["n"] for g in c["g"]])
        r.kv("Description", c.get("d"))
        r.table("ATT&CK techniques", ["ID", "Technique", "Tactic"], tech_rows(c["t"]), limit=300)
        r.table("Software", ["Name", "ID", "Type"], [[d["software"][s]["n"], s, d["software"][s]["k"]] for s in c["s"]])
        for g in c["g"]:
            r.add("actor", d["groups"][g]["n"], "attributed_to", pivot=False)
        for s in [s for s in c["s"] if d["software"][s]["k"] == "malware"][:ctx.max_children]:
            r.add("malware", d["software"][s]["n"], "uses", pivot=False)
        attack_link(r, "campaigns", cid)
        r.data = {"kb": "campaign", "id": cid}
        return
    # technique
    tid = e.value.upper()
    t = d["techniques"].get(tid)
    if not t:
        raise NotFound("Not an ATT&CK technique")
    u = d["used"].get(tid, {"groups": [], "software": [], "campaigns": []})
    r.kv("Technique", f"{tid} · {t['n']}")
    if "." in tid and tid.split(".")[0] in d["techniques"]:
        r.kv("Sub-technique of", f"{tid.split('.')[0]} · {d['techniques'][tid.split('.')[0]]['n']}")
    r.kv("Tactic", [d["tactic_name"].get(a, a) for a in t["ta"]])
    r.kv("Platforms", t.get("pl"))
    r.kv("Used by", f"{len(u['groups'])} threat actors, {len(u['software'])} malware/tools, {len(u['campaigns'])} campaigns")
    r.kv("Description", t.get("d"))
    r.tag(*[d["tactic_name"].get(a, a).lower() for a in t["ta"]])
    r.table("Threat actors", ["Actor", "ID"], sorted([[d["groups"][g]["n"], g] for g in u["groups"]]), limit=300)
    r.table("Software", ["Name", "ID", "Type"], sorted([[d["software"][s]["n"], s, d["software"][s]["k"]] for s in u["software"]]), limit=400)
    r.table("Campaigns", ["Campaign", "ID"], sorted([[d["campaigns"][c]["n"], c] for c in u["campaigns"]]))
    r.link("MITRE ATT&CK", technique_url(tid))
    r.data = {"kb": "technique", "id": tid}
