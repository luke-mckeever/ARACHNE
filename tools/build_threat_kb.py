#!/usr/bin/env python3
"""Build static/intel/threat-kb.json: the threat actor / malware / ATT&CK knowledge base ARACHNE ships with.

    python tools/build_threat_kb.py            download the sources and rebuild
    python tools/build_threat_kb.py DIR        use files already downloaded to DIR

Run it now and then (MITRE releases ATT&CK twice a year) and commit the new JSON. ARACHNE itself never
downloads these sources; it only reads the file this writes.

Sources (all allow commercial use; see "about" in the output and the README):
  - MITRE ATT&CK Enterprise (STIX 2.1): techniques, tactics, groups, software, campaigns and how they link,
    plus the mitigations, detection strategies and log sources (data components) for each technique.
    (c) The MITRE Corporation, royalty-free licence for research, development and commercial use.
  - MISP Galaxy threat-actor cluster: extra actors, country, suspected sponsor, victims, sectors, references.
    CC0 1.0 (or BSD 2-Clause).
  - MISP Galaxy malpedia cluster: malware family names and aliases only (to recognise the names that
    ThreatFox, MalwareBazaar and VirusTotal use). Its descriptions are not copied: Malpedia's own content is
    CC BY-NC-SA, so ARACHNE only links to Malpedia.
"""
import datetime as dt
import json
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "static", "intel", "threat-kb.json")
SOURCES = {
    "enterprise-attack.json": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "threat-actor.json": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
    "malpedia.json": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json",
}
ATTACK_NOTICE = ("© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE "
                 "Corporation. MITRE ATT&CK® is used under MITRE's royalty-free licence for research, development and "
                 "commercial purposes: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/")


def load(src_dir, name):
    path = os.path.join(src_dir, name)
    if not os.path.exists(path):
        print(f"downloading {SOURCES[name]}")
        os.makedirs(src_dir, exist_ok=True)
        urllib.request.urlretrieve(SOURCES[name], path)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def norm(s):
    return re.sub(r"[^a-z0-9]", "", str(s or "").lower())


def clean(text, limit):
    """ATT&CK descriptions: markdown links -> text, drop (Citation: ...) markers and HTML tags, cut at a sentence."""
    t = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text or "")
    t = re.sub(r"\(Citation:[^)]*\)", "", t)
    t = re.sub(r"<[^>]+>", "", t)
    t = re.sub(r"[ \t]+", " ", t).replace(" .", ".").replace(" ,", ",")
    t = re.sub(r"\n\s*\n+", "\n\n", t).strip()
    if len(t) > limit:
        cut = t[:limit]
        end = max(cut.rfind(". "), cut.rfind(".\n"))
        t = (cut[:end + 1] if end > limit * 0.5 else cut.rstrip() + "…")
    return t


def ext_id(o):
    for r in o.get("external_references") or []:
        if r.get("source_name") == "mitre-attack" and r.get("external_id"):
            return r["external_id"]
    return None


def live(o):
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def day(s):
    return (s or "")[:10] or None


def build(src_dir):
    stix = load(src_dir, "enterprise-attack.json")["objects"]
    misp_actors = load(src_dir, "threat-actor.json")["values"]
    malpedia = load(src_dir, "malpedia.json")["values"]
    by_id = {o["id"]: o for o in stix}
    coll = next((o for o in stix if o["type"] == "x-mitre-collection"), {})
    matrix = next(o for o in stix if o["type"] == "x-mitre-matrix")

    tactics = []
    for ref in matrix["tactic_refs"]:
        t = by_id[ref]
        tactics.append([t["x_mitre_shortname"], ext_id(t), t["name"]])

    techniques, groups, software, campaigns = {}, {}, {}, {}
    mitigations, detections, datacomps = {}, {}, {}
    sid = {}  # stix id -> ATT&CK id
    for o in stix:
        if not live(o):
            continue
        eid = ext_id(o)
        if not eid:
            continue
        if o["type"] == "attack-pattern":
            techniques[eid] = {"n": o["name"], "ta": [p["phase_name"] for p in o.get("kill_chain_phases") or []
                                                      if p.get("kill_chain_name") == "mitre-attack"],
                               "pl": o.get("x_mitre_platforms") or [], "d": clean(o.get("description"), 420)}
        elif o["type"] == "intrusion-set":
            groups[eid] = {"n": o["name"], "a": [a for a in o.get("aliases") or [] if a != o["name"]],
                           "d": clean(o.get("description"), 1400), "t": [], "s": [], "c": [],
                           "first": day(o.get("first_seen")), "last": day(o.get("last_seen")),
                           "created": day(o.get("created")), "modified": day(o.get("modified")), "src": "attack"}
        elif o["type"] in ("malware", "tool"):
            software[eid] = {"n": o["name"], "k": o["type"], "a": [a for a in o.get("x_mitre_aliases") or [] if a != o["name"]],
                             "d": clean(o.get("description"), 900), "pl": o.get("x_mitre_platforms") or [],
                             "t": [], "g": [], "c": [], "created": day(o.get("created")), "modified": day(o.get("modified"))}
        elif o["type"] == "course-of-action":
            mitigations[eid] = {"n": o["name"], "d": clean(o.get("description"), 360), "t": []}
        elif o["type"] == "x-mitre-detection-strategy":
            detections[eid] = {"n": o["name"], "an": o.get("x_mitre_analytic_refs") or []}
        elif o["type"] == "x-mitre-data-component":
            datacomps[eid] = {"n": o["name"]}
        elif o["type"] == "campaign":
            campaigns[eid] = {"n": o["name"], "a": [a for a in o.get("aliases") or [] if a != o["name"]],
                              "d": clean(o.get("description"), 1200), "first": day(o.get("first_seen")),
                              "last": day(o.get("last_seen")), "g": [], "s": [], "t": []}
        else:
            continue
        sid[o["id"]] = eid

    def add(lst, v):
        if v not in lst:
            lst.append(v)

    for o in stix:
        if o["type"] != "relationship" or not live(o):
            continue
        s, t, rel = sid.get(o["source_ref"]), sid.get(o["target_ref"]), o["relationship_type"]
        if not s or not t:
            continue
        if rel == "uses":
            if t in techniques:
                tgt = groups.get(s) or software.get(s) or campaigns.get(s)
                if tgt is not None:
                    add(tgt["t"], t)
            elif t in software:
                if s in groups:
                    add(groups[s]["s"], t)
                    add(software[t]["g"], s)
                elif s in campaigns:
                    add(campaigns[s]["s"], t)
                    add(software[t]["c"], s)
        elif rel == "mitigates" and s in mitigations and t in techniques:
            add(mitigations[s]["t"], t)
            add(techniques[t].setdefault("m", []), s)
        elif rel == "detects" and s in detections and t in techniques:
            add(techniques[t].setdefault("det", []), s)
        elif rel == "attributed-to" and s in campaigns and t in groups:
            add(campaigns[s]["g"], t)
            add(groups[t]["c"], s)
    # detection strategy -> analytics -> the log sources (data components) they read; per technique, the log
    # sources that can show it. Analytics have no ATT&CK ID of their own, so they are looked up by STIX id.
    analytics = {o["id"]: o for o in stix if o["type"] == "x-mitre-analytic" and live(o)}
    for det in detections.values():
        dcs = []
        for a in det.pop("an"):
            for ls in (analytics.get(a) or {}).get("x_mitre_log_source_references") or []:
                dc = sid.get(ls.get("x_mitre_data_component_ref"))
                if dc and dc not in dcs:
                    dcs.append(dc)
        det["dc"] = dcs
    for t in techniques.values():
        dcs = []
        for d in t.get("det") or []:
            for dc in detections[d]["dc"]:
                if dc not in dcs:
                    dcs.append(dc)
        if dcs:
            t["dc"] = dcs
    for d in detections.values():
        d.pop("dc")
    mitigations = {k: v for k, v in mitigations.items() if v["t"]}
    detections = {k: v for k, v in detections.items() if any(k in (t.get("det") or []) for t in techniques.values())}
    used_dc = {dc for t in techniques.values() for dc in t.get("dc") or []}
    datacomps = {k: v for k, v in datacomps.items() if k in used_dc}

    # software a group used in its campaigns counts as used by that group too
    for cid, c in campaigns.items():
        for g in c["g"]:
            for s in c["s"]:
                add(groups[g]["s"], s)
                add(software[s]["g"], g)

    # --- MISP Galaxy threat actors: enrich the ATT&CK groups, add the rest as their own profiles
    stix_uuid = {k.split("--", 1)[1]: v for k, v in sid.items() if v in groups}
    gname = {}
    for gid, g in groups.items():
        for n in [g["n"]] + g["a"]:
            gname.setdefault(norm(n), gid)
    misp_count = 0
    for a in misp_actors:
        meta = a.get("meta") or {}
        syn = [s for s in meta.get("synonyms") or [] if s and s != a["value"] and not re.match(r"^G\d{4}$", s)]
        gid = None
        for r in a.get("related") or []:
            if r.get("dest-uuid") in stix_uuid and r.get("type") in ("similar", "overlaps"):
                gid = stix_uuid[r["dest-uuid"]]
                break
        if not gid:
            for na in meta.get("name-attribution") or []:
                m = re.match(r"^(G\d{4}):", str(na))
                if m and m.group(1) in groups:
                    gid = m.group(1)
                    break
        if not gid:
            gid = next((gname[norm(n)] for n in [a["value"]] + syn if norm(n) in gname), None)
        victims = meta.get("cfr-suspected-victims") or meta.get("suspected-victims") or []
        sectors = meta.get("cfr-target-category") or meta.get("targeted-sector") or []
        extra = {
            "country": meta.get("country"), "sponsor": meta.get("cfr-suspected-state-sponsor"),
            "motive": meta.get("cfr-type-of-incident") or meta.get("motive"),
            "victims": victims[:30] if isinstance(victims, list) else [victims],
            "sectors": sectors[:20] if isinstance(sectors, list) else [sectors],
            "refs": [u for u in meta.get("refs") or [] if str(u).startswith(("http://", "https://"))][:12],
            "since": meta.get("since"),
        }
        for k in ("country", "sponsor", "motive", "since"):
            if isinstance(extra[k], list):
                extra[k] = ", ".join(str(x) for x in extra[k] if x) or None
        extra = {k: v for k, v in extra.items() if v}
        if gid:
            g = groups[gid]
            g["misp"] = True
            for n in [a["value"]] + syn:
                if n != g["n"] and norm(n) not in {norm(x) for x in g["a"]}:
                    g["a"].append(n)
            for k, v in extra.items():
                g.setdefault(k, v)
            if not g["d"] and a.get("description"):
                g["d"] = clean(a["description"], 1400)
        else:
            key = "M-" + a["uuid"][:8]
            groups[key] = {"n": a["value"], "a": syn, "d": clean(a.get("description"), 1400), "t": [], "s": [], "c": [],
                           "src": "misp", "misp": True, **extra}
            misp_count += 1

    # --- malware family names and aliases (MISP Galaxy malpedia cluster): names only, linked to ATT&CK software
    swname = {}
    for k, s in software.items():
        for n in [s["n"]] + s["a"]:
            swname.setdefault(norm(n), k)
    families = []
    for f in malpedia:
        meta = f.get("meta") or {}
        mp = next((u.rsplit("/", 1)[1] for u in meta.get("refs") or [] if "malpedia.caad.fkie.fraunhofer.de/details/" in u), None)
        names = [f["value"]] + [s for s in meta.get("synonyms") or [] if s]
        if mp:
            names.append(mp.split(".", 1)[-1])
        match = next((swname[norm(n)] for n in names if len(norm(n)) >= 3 and norm(n) in swname), None)
        if match:
            s = software[match]
            s.setdefault("mp", mp)
            for n in names[1:-1] if mp else names[1:]:
                if re.match(r"^[a-z0-9]+\.[a-z0-9_]+$", n):   # a Malpedia ID such as win.xloader, not a name
                    continue
                if norm(n) not in {norm(x) for x in [s["n"]] + s["a"]}:
                    s["a"].append(n)
        else:
            seen, alias = {norm(f["value"])}, []
            for n in names[1:]:
                if norm(n) not in seen:
                    seen.add(norm(n))
                    alias.append(n)
            families.append([f["value"], alias[:12], mp])

    about = {
        "built": dt.date.today().isoformat(),
        "attack_version": coll.get("x_mitre_version"),
        "counts": {"techniques": len(techniques), "attack_groups": sum(1 for g in groups.values() if g["src"] == "attack"),
                   "misp_actors": sum(1 for g in groups.values() if g["src"] == "misp"), "software": len(software),
                   "campaigns": len(campaigns), "families": len(families), "mitigations": len(mitigations),
                   "detections": len(detections), "data_components": len(datacomps)},
        "sources": [
            {"name": "MITRE ATT&CK Enterprise", "url": "https://attack.mitre.org/", "licence": "MITRE ATT&CK Terms of Use (royalty-free, commercial use allowed)", "notice": ATTACK_NOTICE},
            {"name": "MISP Galaxy (threat-actor cluster)", "url": "https://github.com/MISP/misp-galaxy", "licence": "CC0 1.0 / BSD 2-Clause"},
            {"name": "MISP Galaxy (malpedia cluster), names and aliases only", "url": "https://github.com/MISP/misp-galaxy", "licence": "CC0 1.0 / BSD 2-Clause"},
        ],
    }
    return {"about": about, "tactics": tactics, "techniques": techniques, "groups": groups, "software": software,
            "campaigns": campaigns, "families": families, "mitigations": mitigations, "detections": detections,
            "datacomps": datacomps}


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, ".kb-sources")
    kb = build(src)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(kb, fh, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    print(f"wrote {os.path.relpath(OUT)} ({os.path.getsize(OUT) // 1024} KB): {kb['about']['counts']}")


if __name__ == "__main__":
    main()
