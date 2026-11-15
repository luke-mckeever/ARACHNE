/* Threat intel: MITRE ATT&CK, threat actor and malware profiles, the scan's ATT&CK view and timeline.
   Uses the knowledge base ARACHNE ships with (/intel/threat-kb.json, built by tools/build_threat_kb.py from
   MITRE ATT&CK and the MISP Galaxy). Loaded only when needed, and everything here runs in the browser.
   Shares app.js's globals ($, esc, S, tc, typeLabel, select, ...). */
(() => {
  const KB_URL = "/intel/threat-kb.json";
  const KB_TYPES = ["malware", "actor", "technique", "campaign"];
  const KIND = { groups: "Threat actor", software: "Malware / tool", campaigns: "Campaign", techniques: "ATT&CK technique", family: "Malware family" };
  const KIND_TYPE = { groups: "actor", software: "malware", campaigns: "campaign", techniques: "technique", family: "malware" };
  let KB = null, loading = null, failed = null;
  const t_ = (s, v) => (typeof window.t === "function" ? window.t(s, v) : s);
  const view = { tab: "scan", stack: [], q: "", lib: "groups", showLeads: false };
  const SHIELD_SVG = '<svg viewBox="0 0 24 24"><path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z"/><path d="m9 12 2 2 4-4"/></svg>';

  const norm = (s) => String(s ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const attackUrl = (kind, id) => kind === "techniques" ? `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`
    : /^[GSC]\d{4}$/.test(id) ? `https://attack.mitre.org/${kind}/${id}/` : null;
  const malpediaUrl = (mp) => `https://malpedia.caad.fkie.fraunhofer.de/details/${encodeURIComponent(mp)}`;

  function index(d) {
    const idx = { software: new Map(), groups: new Map(), campaigns: new Map(), families: new Map() };
    const put = (m, k, v) => { if (k.length >= 3 && !m.has(k)) m.set(k, v); };
    for (const kind of ["software", "groups", "campaigns"]) {
      for (const [k, o] of Object.entries(d[kind])) {
        idx[kind].set(k.toLowerCase(), k);
        for (const n of [o.n, ...(o.a || [])]) {
          put(idx[kind], norm(n), k);
          const short = n.replace(/\s+(group|team|gang)$/i, "");
          if (short !== n && norm(short).length >= 4) put(idx[kind], norm(short), k);
        }
      }
    }
    d.families.forEach(([name, aliases, mp], i) => { for (const n of [name, ...aliases, ...(mp ? [mp.split(".").slice(1).join(".")] : [])]) put(idx.families, norm(n), i); });
    const used = {};
    for (const kind of ["groups", "software", "campaigns"]) for (const [k, o] of Object.entries(d[kind])) for (const t of o.t || []) {
      (used[t] ||= { groups: [], software: [], campaigns: [] })[kind].push(k);
    }
    d.idx = idx; d.used = used;
    d.tacticName = Object.fromEntries(d.tactics.map(([s, , n]) => [s, n]));
    return d;
  }
  function load() {
    if (KB) return Promise.resolve(KB);
    if (!loading) {
      loading = fetch(KB_URL).then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
        .then((d) => { KB = index(d); failed = null; refresh(); return KB; })
        .catch((e) => { failed = e.message || String(e); loading = null; refresh(); throw e; });
    }
    return loading;
  }
  function refresh() {
    try { renderDetails(); } catch { /* app not ready */ }
    if (S.view === "shield") render();
  }

  // ------------------------------------------------------------ matching (same rules as osint/modules/attack.py)
  function find(kind, value) {
    const v = String(value ?? "").trim();
    let k = KB.idx[kind].get(v.toLowerCase()) || KB.idx[kind].get(norm(v));
    if (!k && kind === "software") { const tail = v.split(/[./:]/).pop(); if (norm(tail).length >= 4) k = KB.idx.software.get(norm(tail)); }
    return k || null;
  }
  function resolve(type, value) {
    if (!KB) return null;
    if (type === "technique") { const t = String(value).toUpperCase(); return KB.techniques[t] ? { kind: "techniques", id: t } : null; }
    if (type === "actor") { const k = find("groups", value); return k ? { kind: "groups", id: k } : null; }
    if (type === "campaign") { const k = find("campaigns", value); return k ? { kind: "campaigns", id: k } : null; }
    if (type === "malware") {
      const k = find("software", value);
      if (k) return { kind: "software", id: k };
      let i = KB.idx.families.get(norm(value));
      if (i === undefined) { const tail = String(value).split(/[./:]/).pop(); if (norm(tail).length >= 4) i = KB.idx.families.get(norm(tail)); }
      return i !== undefined ? { kind: "family", id: String(i) } : null;
    }
    return null;
  }
  const obj = (ref) => ref.kind === "family" ? famObj(+ref.id) : KB[ref.kind][ref.id];
  function famObj(i) { const [n, a, mp] = KB.families[i]; return { n, a, mp, t: [], g: [], c: [], s: [] }; }
  const nameOf = (ref) => obj(ref)?.n || ref.id;

  // ------------------------------------------------------------ what this scan links to
  function kbNodes() { return [...S.nodes.values()].filter((n) => KB_TYPES.includes(n.type)); }
  function context(nodes = null) {
    const c = { software: new Map(), groups: new Map(), campaigns: new Map(), families: new Map(), tech: new Map(), observed: new Set(), nodes: new Map() };
    const tech = (t, why) => { if (!KB.techniques[t]) return; if (!c.tech.has(t)) c.tech.set(t, new Set()); c.tech.get(t).add(why); };
    for (const n of nodes || kbNodes()) {
      // actors / campaigns / malware the ATT&CK lookup itself added are reference data about a node already
      // counted here, not something a source linked to the IOCs: leave them out (APT29's 150 techniques etc.)
      if (n.source === "mitre_attack" && !n.root) continue;
      const ref = resolve(n.type, n.value);
      if (!ref) continue;
      c.nodes.set(n.id, ref);
      const o = obj(ref);
      if (ref.kind === "software") {
        c.software.set(ref.id, n);
        for (const t of o.t) tech(t, o.n);
        for (const g of o.g) if (!c.groups.has(g)) c.groups.set(g, null);
        for (const x of o.c) if (!c.campaigns.has(x)) c.campaigns.set(x, null);
      } else if (ref.kind === "family") c.families.set(ref.id, n);
      else if (ref.kind === "groups") { c.groups.set(ref.id, n); for (const t of o.t) tech(t, o.n); }
      else if (ref.kind === "campaigns") { c.campaigns.set(ref.id, n); for (const t of o.t) tech(t, o.n); }
      else if (ref.kind === "techniques") { tech(ref.id, "seen with this IOC (" + (n.source ? modLabel(n.source) : "scan") + ")"); c.observed.add(ref.id); }
    }
    return c;
  }
  // malware / actor / technique / campaign nodes linked to one indicator
  function linkedKbNodes(n) {
    const out = new Map();
    if (KB_TYPES.includes(n.type)) out.set(n.id, n);
    for (const e of S.edges.values()) {
      const oid = e.source === n.id ? e.target : e.target === n.id ? e.source : null;
      const o = oid && S.nodes.get(oid);
      if (o && KB_TYPES.includes(o.type)) out.set(o.id, o);
    }
    return [...out.values()];
  }

  // ------------------------------------------------------------ small pieces
  const chip = (ref, extra = "") => `<button translate="no" class="ix-chip ${ref.kind}" data-intel-profile="${esc(ref.kind)}:${esc(ref.id)}" title="${esc(KIND[ref.kind])}${/^[GSCT]\d/.test(ref.id) ? " · " + esc(ref.id) : ""}">${esc(nameOf(ref))}${extra}</button>`;
  const ref = (kind, id) => ({ kind, id });
  const listChips = (kind, ids, max = 40) => ids.length ? ids.slice(0, max).map((id) => chip(ref(kind, id))).join("") + (ids.length > max ? `<span class="msg"> +${ids.length - max} more</span>` : "") : '<span class="msg">None recorded</span>';
  const sortBy = (kind, ids) => [...ids].sort((a, b) => (KB[kind][a]?.n || a).localeCompare(KB[kind][b]?.n || b));

  function matrixHTML(counts, { scale = null, title = "", observed = null } = {}) {
    // counts: Map technique id -> number (or Set of reasons)
    const byTac = new Map(KB.tactics.map(([s]) => [s, []]));
    for (const [t, v] of counts) for (const ta of KB.techniques[t]?.ta || []) byTac.get(ta)?.push([t, typeof v === "number" ? v : v.size, v]);
    const max = scale || Math.max(1, ...[...counts.values()].map((v) => typeof v === "number" ? v : v.size));
    return `<div class="ix-matrix" translate="no" ${title ? `aria-label="${esc(title)}"` : ""}>${KB.tactics.map(([s, , name]) => {
      const cells = byTac.get(s).sort((a, b) => (observed ? observed.has(b[0]) - observed.has(a[0]) : 0) || b[1] - a[1] || a[0].localeCompare(b[0]));
      return `<div class="mcol ${cells.length ? "on" : ""}"><div class="mhead"><b>${esc(name)}</b><span>${cells.length || ""}</span></div>${cells.map(([t, n, v]) => {
        const lvl = n >= 3 && n / max > 0.66 ? 3 : n >= 2 ? 2 : 1;
        const seen = observed && observed.has(t);
        const why = typeof v === "number" ? "" : [...v].slice(0, 12).join("\n");
        return `<button class="mcell h${lvl}${seen ? " seen" : ""}" data-intel-profile="techniques:${esc(t)}" title="${esc(t)} ${esc(KB.techniques[t].n)}${why ? "\n\n" + esc(why) : ""}"><b>${esc(t)}${n > 1 && max > 1 ? `<em>${n}</em>` : ""}</b><span>${esc(KB.techniques[t].n)}</span>${seen ? "<i>reported for these IOCs</i>" : ""}</button>`;
      }).join("")}</div>`;
    }).join("")}</div>`;
  }

  // ------------------------------------------------------------ report hooks (called from app.js)
  function profileButton(n) {
    if (!KB_TYPES.includes(n.type)) return "";
    return `<button class="btn sm ghost" data-intel-node="${esc(n.id)}" title="Open the profile: aliases, actors, campaigns, ATT&CK techniques, timeline">${ICON.select}Profile</button>`;
  }
  function reportSection(n) {
    const linked = linkedKbNodes(n);
    if (!linked.length) return "";
    if (!KB) {
      load().catch(() => {});
      return `<div class="rep-sec ix-sec"><h3>Threat context</h3><div class="msg">${failed ? `Threat intel data could not be loaded (${esc(failed)}).` : '<span class="spinner"></span> Loading MITRE ATT&amp;CK and threat actor data…'}</div></div>`;
    }
    const c = context(linked);
    if (!c.nodes.size) return `<div class="rep-sec ix-sec"><h3>Threat context</h3><div class="msg">No ATT&amp;CK or threat actor profile matches ${linked.map((x) => esc(x.value)).join(", ")}.</div></div>`;
    const direct = [...c.nodes.values()];
    let actorRows = "", note = "";
    if (KB_TYPES.includes(n.type)) {
      // the indicator is itself malware / an actor: its known users only when the malware is distinctive
      const r = c.nodes.get(n.id);
      const o = r && r.kind === "software" ? KB.software[r.id] : null;
      if (o && o.g.length && !sharedMal(o)) actorRows = `<div class="ix-row"><span class="ix-lbl">Used by</span><div class="ix-chips">${sortBy("groups", o.g).map((g) => chip(ref("groups", g))).join("")}</div></div>`;
      else if (o && o.g.length) note = `<p class="msg ix-note">${esc(o.n)}: used by ${o.g.length} actors in MITRE ATT&amp;CK, too widely shared to point to one.</p>`;
    } else {
      const a = attributeIoc(n);
      if (a.actors.length) actorRows = `<div class="ix-row"><span class="ix-lbl">Attributed to</span><div class="ix-chips">${a.actors.slice(0, 8).map((x) => chip(ref("groups", x.g), ` <small class="sh-c-${x.conf}">${esc(t_(CONF[x.conf][0]).toLowerCase())}</small>`)).join("")}${a.actors.length > 8 ? `<span class="msg">+${a.actors.length - 8}</span>` : ""}</div></div>`;
      if (a.shared.length) note = `<p class="msg ix-note"><span translate="no">${esc(a.shared.map((s) => KB.software[s].n).join(", "))}</span>: <span>shared by many actors, so not used for attribution.</span></p>`;
    }
    const camps = [...c.campaigns].filter(([, node]) => node).map(([x]) => x);
    return `<div class="rep-sec ix-sec"><h3>Threat context <em>${direct.length}</em><button class="btn xs ghost" data-intel-open="scan" title="Open Shield: attribution, ATT&CK matrix and timeline for the whole scan">Shield</button></h3>
      <div class="ix-ctx">
        <div class="ix-row"><span class="ix-lbl">Linked</span><div class="ix-chips">${direct.map((r) => chip(r)).join("")}</div></div>
        ${actorRows}
        ${camps.length ? `<div class="ix-row"><span class="ix-lbl">Campaigns</span><div class="ix-chips">${camps.slice(0, 8).map((x) => chip(ref("campaigns", x))).join("")}</div></div>` : ""}
        ${c.tech.size ? `<div class="ix-row"><span class="ix-lbl">Techniques</span><div class="ix-chips"><button class="ix-chip techniques" data-intel-open="attack">${c.tech.size} ATT&amp;CK technique${c.tech.size === 1 ? "" : "s"} across ${new Set([...c.tech.keys()].flatMap((t) => KB.techniques[t].ta)).size} tactics</button></div></div>` : ""}
      </div>${note}</div>`;
  }

  // ------------------------------------------------------------ timeline
  const DATE_KEY = /first seen|last seen|first submitted|first submission|registered|registration|date added|added|created|published|last analysis|last seen|updated|changed|expires|seen/i;
  function dateOf(v) {
    const m = String(v ?? "").match(/\b((?:19|20)\d{2})-(\d{2})-(\d{2})\b/);
    return m ? `${m[1]}-${m[2]}-${m[3]}` : null;
  }
  function timeline() {
    const ev = [];
    for (const [nid, res] of S.results) {
      const n = S.nodes.get(nid);
      if (!n) continue;
      for (const [m, r] of Object.entries(res)) {
        if (r.status !== "ok") continue;
        for (const [k, v] of r.summary || []) {
          const d = DATE_KEY.test(k) && dateOf(v);
          if (d) ev.push({ d, what: k, n, m });
        }
        for (const t of r.tables || []) {
          const col = t.columns.findIndex((c) => DATE_KEY.test(c) || /^(date|first|last)$/i.test(c));
          if (col < 0) continue;
          const lab = col === 0 ? 1 : 0;
          let shown = 0;
          for (const row of t.rows) {
            const d = dateOf(row[col]);
            if (!d) continue;
            ev.push({ d, what: `${t.title}: ${row[lab] || ""}`.slice(0, 140), sub: t.columns[col], n, m });
            if (++shown >= 12) break;
          }
        }
      }
    }
    if (KB) {
      const c = context();
      for (const [cid, node] of c.campaigns) {
        const x = KB.campaigns[cid];
        if (!x.first && !x.last) continue;
        const by = x.g.map((g) => KB.groups[g].n).join(", ");
        ev.push({ d: x.first || x.last, end: x.first && x.last && x.last !== x.first ? x.last : null, what: `Campaign: ${x.n}${by ? " (" + by + ")" : ""}`, campaign: cid, n: node, m: "mitre_attack" });
      }
    }
    // the same fact from several rows collapses to one entry
    const seen = new Set();
    return ev.filter((e) => { const k = `${e.d}|${e.what}|${e.n?.id}`; if (seen.has(k)) return false; seen.add(k); return true; })
      .sort((a, b) => b.d.localeCompare(a.d));
  }
  function timelineHTML(ev, { empty = "No dated events yet." } = {}) {
    if (!ev.length) return `<div class="empty-note">${empty}</div>`;
    const years = {}; for (const e of ev) years[e.d.slice(0, 4)] = (years[e.d.slice(0, 4)] || 0) + 1;
    const ys = Object.keys(years).sort(), max = Math.max(...Object.values(years));
    const bar = ys.length > 1 ? `<div class="ix-years" translate="no">${ys.map((y) => `<div title="${y}: ${years[y]} event${years[y] === 1 ? "" : "s"}"><i style="height:${Math.max(8, (years[y] / max) * 100)}%"></i><span>${y.slice(2)}</span></div>`).join("")}</div>` : "";
    let lastY = null;
    return bar + `<div class="ix-tl">${ev.map((e) => {
      const y = e.d.slice(0, 4), head = y !== lastY ? `<div class="ix-tl-y">${y}</div>` : "";
      lastY = y;
      const node = e.n ? `<button class="ix-tl-node" data-intel-goto="${esc(e.n.id)}" title="Show ${esc(e.n.value)} in the report"><span style="color:${tc(e.n.type)}">${esc(glyph(e.n.type))}</span>${esc(e.n.value)}</button>` : "";
      return head + `<div class="ix-tl-e ${e.campaign ? "camp" : ""}" translate="no"><time>${esc(e.d)}${e.end ? ` → ${esc(e.end)}` : ""}</time><div><b>${e.campaign ? `<button class="ix-link" data-intel-profile="campaigns:${esc(e.campaign)}">${esc(e.what)}</button>` : esc(e.what)}</b>
        <div class="ix-tl-meta">${node}${e.m ? `<span>${esc(modLabel(e.m))}</span>` : ""}${e.sub ? `<span>${esc(e.sub)}</span>` : ""}</div></div></div>`;
    }).join("")}</div>`;
  }

  // ------------------------------------------------------------ the Shield page: attribution / ATT&CK / timeline / library / profiles
  // Shield is a view of its own next to Report and Graph (app.js setView("shield")); everything is drawn into #intelBody.
  const TABS = ["scan", "attack", "timeline", "library"];
  const scroller = () => $("#shieldWrap");
  // A site built on ARACHNE can limit Shield to some accounts: window.ArachneShieldGate() returns false (and
  // explains why) when this user may not open it. The app itself has no accounts, so Shield is always open there.
  function allowed() {
    try { return typeof window.ArachneShieldGate !== "function" || window.ArachneShieldGate() !== false; } catch { return true; }
  }
  function open(tab = null, prof = null) {
    if (S.view !== "shield" && !allowed()) return;
    if (tab === "matrix") tab = "attack";
    if (tab && TABS.includes(tab)) view.tab = tab;
    view.stack = prof ? [prof] : [];
    if (S.view !== "shield") setView("shield"); else render();
    const sc = scroller(); if (sc) sc.scrollTop = 0;
    load().catch(() => {});
  }
  function openProfile(r) {
    if (S.view !== "shield" && !allowed()) return;
    if (S.view !== "shield") { view.stack = [r]; setView("shield"); }
    else { view.stack.push(r); render(); }
    const sc = scroller(); if (sc) sc.scrollTop = 0;
  }
  function back() {
    view.stack.pop(); render();
    const sc = scroller(); if (sc) sc.scrollTop = 0;
  }
  // scan events arrive in bursts: redraw the page at most a few times a second, and never under the user's typing
  let soon = null;
  function renderSoon() {
    if (soon) return;
    soon = setTimeout(() => { soon = null; if (S.view === "shield") render(); }, 400);
  }
  function render() {
    const body = $("#intelBody");
    if (!body) return;
    const prof = view.stack[view.stack.length - 1];
    $$("#intelTabs [data-intel-tab]").forEach((b) => b.classList.toggle("on", !prof && b.dataset.intelTab === view.tab));
    $("#intelBack").hidden = !prof;
    if (!KB) {
      load().catch(() => {});
      body.innerHTML = failed ? `<div class="empty-note">Threat intel data could not be loaded ({err}). <button class="btn xs" data-intel-retry>Try again</button></div>`.replace("{err}", esc(failed))
        : '<div class="src-running"><span class="spinner"></span>Loading MITRE ATT&amp;CK and threat actor data…</div>';
      return;
    }
    // library search: a scan event must not wipe what is being typed
    const q = $("[data-intel-q]", body);
    if (!prof && view.tab === "library" && q && document.activeElement === q && !view.focusQ) return;
    const sc = scroller(), st = sc ? sc.scrollTop : 0;
    body.innerHTML = prof ? profileHTML(prof) : view.tab === "timeline" ? scanTimelineHTML() : view.tab === "library" ? libraryHTML() : view.tab === "attack" ? attackHTML() : scanHTML();
    if (sc) sc.scrollTop = st;
    if (view.tab === "library" && !prof) { const i = $("[data-intel-q]", body); if (i && document.activeElement !== i && view.focusQ) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); view.focusQ = false; } }
  }

  // ------------------------------------------------------------ attribution: which threat actors an IOC points to, and how sure that is
  // Only evidence about the IOC itself counts:
  //   high    a source named the actor and a second source agrees (or the IOC's malware / campaign is that actor's)
  //   medium  one source named the actor, or named a campaign that MITRE ATT&CK attributes to it
  //   low     the IOC's malware is distinctive: MITRE ATT&CK knows of at most RARE actors using it
  // Malware many actors share (Cobalt Strike, Mimikatz, tools in general) attributes nothing: it is listed as shared.
  const RARE = 3;
  const CONF = {
    high: ["High", "A source named this actor and another piece of evidence agrees: a second source, or malware or a campaign that belongs to the actor"],
    medium: ["Medium", "One source named this actor, or named a campaign MITRE ATT&CK attributes to it"],
    low: ["Low", "The IOC's malware is used by only a few actors according to MITRE ATT&CK. A lead, not proof"],
    none: ["Not attributed", "Sources linked this IOC to malware or techniques that many actors share, so it doesn't point to anyone"],
  };
  const RANK = { high: 3, medium: 2, low: 1, none: 0 };
  const sharedMal = (o) => o.k === "tool" || o.g.length > RARE;
  function attributeIoc(n) {
    const named = new Map(), namedCamps = new Map(), mal = new Map(), fam = new Map(), tech = new Set(), srcs = new Set();
    for (const e of S.edges.values()) {
      const oid = e.source === n.id ? e.target : e.target === n.id ? e.source : null;
      const o = oid && S.nodes.get(oid);
      if (!o || !KB_TYPES.includes(o.type)) continue;
      const r = resolve(o.type, o.value);
      if (!r) continue;
      const mods = new Set([...(e.modules || []), o.source].filter((m) => m && m !== "mitre_attack" && m !== "user"));
      mods.forEach((m) => srcs.add(m));
      const add = (map, k) => { if (!map.has(k)) map.set(k, new Set()); mods.forEach((m) => map.get(k).add(m)); };
      if (r.kind === "groups") add(named, r.id);
      else if (r.kind === "campaigns") add(namedCamps, r.id);
      else if (r.kind === "software") add(mal, r.id);
      else if (r.kind === "family") add(fam, r.id);
      else if (r.kind === "techniques") tech.add(r.id);
    }
    const actors = new Map();
    const put = (g, conf, why) => {
      if (!KB.groups[g]) return;
      const a = actors.get(g) || { g, conf: "none", why: [] };
      if (RANK[conf] > RANK[a.conf]) a.conf = conf;
      if (!a.why.includes(why)) a.why.push(why);
      actors.set(g, a);
    };
    for (const [g, mods] of named) put(g, mods.size >= 2 ? "high" : "medium", `named by ${[...mods].map(modLabel).join(", ") || "a source"}`);
    for (const [cid, mods] of namedCamps) for (const g of KB.campaigns[cid].g) put(g, named.has(g) ? "high" : "medium", `campaign ${KB.campaigns[cid].n}`);
    const shared = [];
    for (const sid of mal.keys()) {
      const o = KB.software[sid];
      if (sharedMal(o)) { shared.push(sid); for (const g of o.g) if (actors.has(g)) put(g, "high", `uses ${o.n}`); continue; }
      for (const g of o.g) put(g, named.has(g) ? "high" : "low", `uses ${o.n}`);
    }
    const list = [...actors.values()].sort((a, b) => RANK[b.conf] - RANK[a.conf] || KB.groups[a.g].n.localeCompare(KB.groups[b.g].n));
    const conf = list.length ? list[0].conf : "none";
    return { n, actors: list, conf, named, namedCamps, mal: [...mal.keys()], fam: [...fam.keys()], shared, tech, srcs };
  }
  // every IOC in the scan with a malware / actor / campaign / technique link
  function attributionRows() {
    const rows = [];
    for (const n of S.nodes.values()) {
      if (KB_TYPES.includes(n.type)) continue;
      const a = attributeIoc(n);
      if (!a.actors.length && !a.mal.length && !a.fam.length && !a.tech.size && !a.namedCamps.size) continue;
      a.c = context(linkedKbNodes(n).filter((x) => x.id !== n.id));
      a.rk = typeof riskOf === "function" ? riskOf(n.id) : { score: null };
      rows.push(a);
    }
    return rows.sort((a, b) => RANK[b.conf] - RANK[a.conf] || ((b.rk.score ?? -1) - (a.rk.score ?? -1)) || a.n.value.localeCompare(b.n.value));
  }
  // actor -> the IOCs pointing at it, with the best confidence
  function actorBoard(rows) {
    const a = new Map();
    for (const r of rows) for (const x of r.actors) {
      const b = a.get(x.g) || { g: x.g, conf: "none", iocs: new Set(), why: new Set() };
      if (RANK[x.conf] > RANK[b.conf]) b.conf = x.conf;
      b.iocs.add(r.n.id); x.why.forEach((w) => b.why.add(w));
      a.set(x.g, b);
    }
    return [...a.values()].sort((x, y) => RANK[y.conf] - RANK[x.conf] || y.iocs.size - x.iocs.size || KB.groups[x.g].n.localeCompare(KB.groups[y.g].n));
  }
  const confPill = (c) => `<span class="sh-pill ${c}" title="${esc(CONF[c][1])}">${CONF[c][0]}</span>`;
  const iocBtn = (x) => `<button class="ix-chip ioc" data-intel-goto="${esc(x.id)}" title="Show ${esc(x.value)} in the report"><span style="color:${tc(x.type)}">${esc(glyph(x.type))}</span> <span translate="no">${esc(x.value)}</span></button>`;

  function scanHTML() {
    if (!S.scanId) return `<div class="sh-empty"><div class="sh-empty-ic">${SHIELD_SVG}</div><h2>Nothing to attribute yet</h2>
      <p>Scan an IOC and Shield shows which threat actors the sources tie it to and how sure that is, the malware and campaigns involved, the ATT&amp;CK techniques and a timeline of everything the sources dated.</p>
      <p>You can also scan an actor, a malware family or an ATT&amp;CK ID directly (for example <span class="mono">APT29</span>, <span class="mono">Emotet</span> or <span class="mono">T1059.001</span>), or browse the library.</p>
      <p><button class="btn sm" data-intel-tab="library">Browse the library</button></p></div>`;
    const c = context();
    const kb = kbNodes();
    if (!c.nodes.size) {
      return `<div class="empty-note">${kb.length ? `None of the ${kb.length} malware / actor indicators in this scan match a profile.` : "No source has linked this scan to a malware family, threat actor or ATT&CK technique yet."} Sources that do: ThreatFox, MalwareBazaar, URLhaus, VirusTotal, AlienVault OTX, Hybrid Analysis. You can also scan a family name, an actor or a technique ID (for example <span class="mono">T1059.001</span>) directly.</div>`
        + `<p style="text-align:center"><button class="btn sm ghost" data-intel-tab="library">Browse the library</button></p>`;
    }
    const rows = attributionRows();
    const iocs = [...S.nodes.values()].filter((n) => !KB_TYPES.includes(n.type) && (n.root || S.results.has(n.id)));
    const tile = (v, label, tab = "") => `<${tab ? `button data-intel-tab="${tab}"` : "div"} class="rep-tile ${v ? "" : "zero"}"><b>${v}</b><span>${label}</span></${tab ? "button" : "div"}>`;
    const sw = [...c.software.keys()];
    const board = actorBoard(rows);
    // actors scanned directly (APT29 typed in the search box) are shown too
    for (const [g, node] of c.groups) if (node && node.root && !board.some((x) => x.g === g)) board.unshift({ g, conf: "scanned", iocs: new Set(), why: new Set() });
    const attributed = rows.filter((r) => r.actors.length);
    const sharedAll = new Map();
    for (const r of rows) for (const s of r.shared) { if (!sharedAll.has(s)) sharedAll.set(s, new Set()); sharedAll.get(s).add(r.n.id); }
    const actorRow = (x) => {
      const o = KB.groups[x.g];
      return `<div class="sh-actor"><button translate="no" class="sh-actor-n" data-intel-profile="groups:${esc(x.g)}"><b>${esc(o.n)}</b>${o.country ? `<span class="ix-cc">${esc(o.country)}</span>` : ""}<span class="ix-id">${esc(x.g.startsWith("G") ? x.g : "MISP")}</span></button>
        <div class="sh-actor-m">${x.conf === "scanned" ? '<span class="sh-pill high">Scanned</span>' : confPill(x.conf)} ${x.iocs.size ? `<span class="msg">${x.iocs.size === 1 ? "1 IOC" : `${x.iocs.size} IOCs`}</span>` : ""}</div>
        ${x.why.size ? `<div class="ix-card-a" translate="no">${esc([...x.why].slice(0, 4).join(" · "))}</div>` : ""}</div>`;
    };
    const row = (r) => {
      const camps = [...r.c.campaigns].filter(([, node]) => node).map(([x]) => x);
      const malRefs = [...r.mal.map((s) => ref("software", s)), ...r.fam.map((i) => ref("family", i))];
      return `<div class="sh-row">
        <div class="sh-ioc">${typeof riskBadge === "function" && r.rk.grade ? riskBadge(r.rk) : ""}${iocBtn(r.n)}</div>
        <div class="sh-cell"><span class="ix-lbl">Confidence</span>${confPill(r.conf)}${r.srcs.size ? `<span class="msg sh-src" translate="no">${[...r.srcs].map((m) => esc(modLabel(m))).join(", ")}</span>` : ""}</div>
        <div class="sh-cell"><span class="ix-lbl">Threat actors</span><div class="ix-chips">${r.actors.length ? r.actors.slice(0, 4).map((x) => chip(ref("groups", x.g), ` <small class="sh-c-${x.conf}">${esc(t_(CONF[x.conf][0]).toLowerCase())}</small>`)).join("") + (r.actors.length > 4 ? `<span class="msg">+${r.actors.length - 4}</span>` : "") : '<span class="msg">–</span>'}</div></div>
        <div class="sh-cell"><span class="ix-lbl">Malware</span><div class="ix-chips">${malRefs.length ? malRefs.slice(0, 4).map((m) => chip(m, m.kind === "software" && r.shared.includes(m.id) ? ` <small title="Used by ${KB.software[m.id].g.length} actors in MITRE ATT&CK">shared</small>` : "")).join("") : '<span class="msg">–</span>'}</div></div>
        <div class="sh-cell"><span class="ix-lbl">Campaigns</span><div class="ix-chips">${camps.length ? camps.slice(0, 3).map((x) => chip(ref("campaigns", x))).join("") : '<span class="msg">–</span>'}</div></div>
        <div class="sh-cell"><span class="ix-lbl">ATT&amp;CK</span>${r.c.tech.size ? `<button class="ix-chip techniques" data-intel-tab="attack">${r.c.tech.size === 1 ? "1 technique" : `${r.c.tech.size} techniques`}</button>` : '<span class="msg">–</span>'}</div></div>`;
    };
    const leads = view.showLeads ? [...sharedAll.keys()].flatMap((s) => KB.software[s].g).filter((g, i, a) => a.indexOf(g) === i && !board.some((x) => x.g === g)) : [];
    return `<div class="rep-tiles ix-tiles sh-tiles">${tile(`${attributed.length}<small>/${iocs.length}</small>`, "IOCs attributed")}${tile(board.length, "Threat actors")}${tile(sw.length + c.families.size, "Malware & tools")}${tile([...c.campaigns.values()].filter(Boolean).length, "Campaigns")}${tile(c.tech.size, "ATT&CK techniques", "attack")}</div>
      ${rows.length ? `<div class="rep-sec"><h3>Attribution by IOC <em>${rows.length}</em></h3>
        <p class="msg ix-note"><span>How each IOC in this scan ties to a threat actor, based only on what the sources said about that IOC.</span> <span>Malware that many actors share (Cobalt Strike, Mimikatz, remote access tools) doesn't attribute anything on its own.</span> <span>What each confidence level means is under How Shield works, at the bottom of the page.</span></p>
        <div class="sh-rows">${rows.slice(0, 200).map(row).join("")}</div>${rows.length > 200 ? `<p class="msg">Showing the first 200 of ${rows.length}.</p>` : ""}</div>` : ""}
      ${board.length ? `<div class="rep-sec"><h3>Threat actors <em>${board.length}</em></h3><div class="sh-actors">${board.map(actorRow).join("")}</div></div>`
        : rows.length ? `<div class="rep-sec"><h3>Threat actors <em>0</em></h3><div class="empty-note">No source named a threat actor for these IOCs, and their malware is too widely shared to point to one.</div></div>` : ""}
      ${sharedAll.size ? `<div class="rep-sec"><h3>Shared malware <em>${sharedAll.size}</em></h3><p class="msg ix-note">Used by many actors according to MITRE ATT&amp;CK, so these don't count towards attribution.</p>
        <div class="ix-chips">${[...sharedAll.keys()].map((s) => chip(ref("software", s), ` <small>${KB.software[s].k === "tool" ? "tool" : `${KB.software[s].g.length} actors`}</small>`)).join("")}</div>
        ${view.showLeads ? `<p class="msg ix-note">Every actor MITRE ATT&amp;CK records as using them. A lead only, not attribution.</p><div class="ix-chips">${sortBy("groups", leads).map((g) => chip(ref("groups", g), KB.groups[g].country ? ` <small>${esc(KB.groups[g].country)}</small>` : "")).join("")}</div>`
          : `<p><button class="btn xs ghost" data-intel-leads>List the actors that use them</button></p>`}</div>` : ""}
      ${sw.length + c.families.size ? `<div class="rep-sec"><h3>Malware &amp; tools <em>${sw.length + c.families.size}</em></h3><div class="ix-cards">${sw.map((s) => profileCard(ref("software", s), c.software.get(s))).join("")}${[...c.families].map(([i, n]) => profileCard(ref("family", i), n)).join("")}</div></div>` : ""}
      ${c.tech.size ? `<div class="rep-sec"><h3>ATT&amp;CK tactics <em>${new Set([...c.tech.keys()].flatMap((t) => KB.techniques[t].ta)).size}</em><button class="btn xs ghost" data-intel-tab="attack">Open the matrix</button></h3>${tacticBars(c)}</div>` : ""}
      ${attribution()}`;
  }
  // one bar per ATT&CK tactic: how many of the scan's techniques fall under it
  function tacticBars(c) {
    const per = KB.tactics.map(([s, , name]) => [name, [...c.tech.keys()].filter((t) => KB.techniques[t].ta.includes(s)).length]);
    const max = Math.max(1, ...per.map((x) => x[1]));
    return `<div class="sh-tactics">${per.map(([name, n]) => `<button translate="no" class="sh-tac ${n ? "" : "zero"}" data-intel-tab="attack" title="${esc(name)}: ${n}"><span translate="no">${esc(name)}</span><i><b style="width:${(n / max) * 100}%"></b></i><em>${n}</em></button>`).join("")}</div>`;
  }

  function attackHTML() {
    if (!S.scanId) return `<div class="empty-note">Scan an IOC first: the ATT&amp;CK techniques of the malware, actors and campaigns the sources link it to are mapped here. Or browse the <button class="btn xs" data-intel-tab="library">Library</button>.</div>`;
    const c = context();
    if (!c.tech.size) return `<div class="empty-note">No ATT&amp;CK techniques are linked to this scan yet. They come from the malware, threat actors and campaigns the sources tie the IOCs to, and from techniques sources report directly.</div>`;
    const rows = [...c.tech].map(([t, why]) => [t, why]).sort((a, b) => c.observed.has(b[0]) - c.observed.has(a[0]) || b[1].size - a[1].size || a[0].localeCompare(b[0]));
    const tacs = new Set(rows.flatMap(([t]) => KB.techniques[t].ta)).size;
    return `<div class="rep-sec"><h3>MITRE ATT&amp;CK matrix <em>${c.tech.size}</em>
        <span class="sh-acts"><button class="btn xs ghost" data-intel-copytech title="Copy every technique ID, one per line">${ICON.copy}Copy IDs</button><button class="btn xs ghost" data-intel-navigator title="A layer file for the MITRE ATT&CK Navigator (mitre-attack.github.io/attack-navigator): Open Existing Layer, Upload from local">Navigator layer</button></span></h3>
      <p class="msg ix-note"><span>${c.tech.size} techniques across ${tacs} tactics.</span> <span>Techniques the malware, actors and campaigns linked to this scan are known to use.</span>${c.observed.size ? ` <span>${c.observed.size} of them were reported by sources for these IOCs (marked).</span>` : ""} <span>Darker cells are shared by more of them. Click one for its profile.</span></p>
      ${matrixHTML(c.tech, { observed: c.observed })}</div>
      <div class="rep-sec"><h3>Techniques <em>${rows.length}</em></h3><div class="ix-list sh-tech" translate="no">${rows.slice(0, 400).map(([t, why]) => `<button class="ix-li" data-intel-profile="techniques:${esc(t)}"><span class="ix-id">${esc(t)}</span><b>${esc(KB.techniques[t].n)}</b>
        <span class="ix-li-a">${esc(KB.techniques[t].ta.map((x) => KB.tacticName[x] || x).join(", "))} · <span translate="no">${esc([...why].slice(0, 4).join(", "))}${why.size > 4 ? "…" : ""}</span></span>${c.observed.has(t) ? '<span class="sh-pill direct">Reported</span>' : `<span class="ix-cc">${why.size}</span>`}</button>`).join("")}</div></div>
      ${attribution()}`;
  }
  // ATT&CK Navigator layer (format 4.5) for the scan's techniques
  function navigatorLayer() {
    const c = context();
    const max = Math.max(1, ...[...c.tech.values()].map((v) => v.size));
    const seeds = (typeof seedNodes === "function" ? seedNodes() : []).map((n) => n.value);
    const av = String(KB.about?.attack_version || "").split(".")[0];
    return {
      name: `ARACHNE Shield: ${seeds.slice(0, 3).join(", ")}${seeds.length > 3 ? ` +${seeds.length - 3}` : ""}`.slice(0, 120),
      versions: { ...(av ? { attack: av } : {}), navigator: "5.1.0", layer: "4.5" },
      domain: "enterprise-attack",
      description: `ATT&CK techniques linked to an ARACHNE scan (${new Date().toISOString().slice(0, 10)}). Score = how many of the linked malware, actors and campaigns use the technique.`,
      techniques: [...c.tech].map(([t, why]) => ({ techniqueID: t, score: why.size, comment: [...why].slice(0, 20).join(", "), enabled: true, showSubtechniques: false,
        ...(c.observed.has(t) ? { color: "#f59e0b" } : {}) })),
      gradient: { colors: ["#ffffff", "#ff6666"], minValue: 0, maxValue: max },
      legendItems: c.observed.size ? [{ label: "Reported by a source for these IOCs", color: "#f59e0b" }] : [],
      sorting: 3, hideDisabled: false, showTacticRowBackground: false, selectSubtechniquesWithParent: false,
    };
  }
  function profileCard(r, node) {
    const o = obj(r);
    const meta = r.kind === "groups" ? [o.country, o.motive, r.id.startsWith("G") ? r.id : "MISP Galaxy"] : r.kind === "software" ? [o.k === "tool" ? "Tool" : "Malware", r.id, o.t.length === 1 ? "1 technique" : `${o.t.length} techniques`, o.g.length === 1 ? "1 actor" : `${o.g.length} actors`] : ["Not in ATT&CK", o.mp];
    return `<button class="ix-card" translate="no" data-intel-profile="${esc(r.kind)}:${esc(r.id)}"><div class="ix-card-h"><b>${esc(o.n)}</b>${node ? `<span class="msg">${esc(node.value !== o.n ? node.value : "")}</span>` : ""}</div>
      <div class="ix-card-m">${meta.filter(Boolean).map((x) => `<span>${esc(x)}</span>`).join("")}</div>
      ${o.a?.length ? `<div class="ix-card-a">aka ${esc(o.a.slice(0, 5).join(", "))}${o.a.length > 5 ? "…" : ""}</div>` : ""}</button>`;
  }
  function scanTimelineHTML() {
    if (!S.scanId) return '<div class="empty-note">Scan an IOC first. Dates the sources report (first seen, registered, added to a blocklist, campaign activity) are put in order here.</div>';
    return `<p class="msg ix-note">Every date the sources reported for this scan, newest first: when IOCs were first and last seen, registered, submitted or added to a list, and when the linked ATT&amp;CK campaigns were active.</p>${timelineHTML(timeline(), { empty: "No source has reported a date for this scan yet." })}`;
  }
  function libraryHTML() {
    const q = view.q.trim(), nq = norm(q);
    const kinds = [["groups", "Threat actors"], ["software", "Malware & tools"], ["campaigns", "Campaigns"], ["techniques", "Techniques"]];
    const kind = view.lib;
    let items = Object.entries(KB[kind]);
    if (q) {
      const ql = q.toLowerCase();
      items = items.map(([id, o]) => {
        const names = [o.n, ...(o.a || [])];
        const score = id.toLowerCase() === ql ? 0 : norm(o.n) === nq ? 1 : names.some((n) => norm(n) === nq) ? 2 : norm(o.n).startsWith(nq) ? 3 : names.some((n) => norm(n).includes(nq)) ? 4 : id.toLowerCase().startsWith(ql) ? 5 : (o.country || "").toLowerCase() === ql ? 6 : 99;
        return [id, o, score];
      }).filter((x) => x[2] < 99).sort((a, b) => a[2] - b[2] || a[1].n.localeCompare(b[1].n));
    } else {
      items = items.filter(([id, o]) => kind !== "groups" || o.src === "attack").sort((a, b) => kind === "techniques" ? a[0].localeCompare(b[0]) : a[1].n.localeCompare(b[1].n));
    }
    const total = items.length, shown = items.slice(0, 120);
    const counts = Object.fromEntries(kinds.map(([k]) => [k, Object.keys(KB[k]).length]));
    return `<div class="ix-lib-h"><input class="inp" data-intel-q placeholder="Search by name, alias or ATT&CK ID (APT29, Cozy Bear, Emotet, T1566, RU)…" value="${esc(view.q)}" spellcheck="false">
      <div class="seg">${kinds.map(([k, l]) => `<button data-intel-lib="${k}" class="${k === kind ? "on" : ""}">${esc(l)} <em>${counts[k]}</em></button>`).join("")}</div></div>
      <p class="msg ix-note"><span>${q ? (total === 1 ? "1 match." : `${total} matches.`) : kind === "groups" ? `The ${total} MITRE ATT&amp;CK groups.` : `${total} entries.`}</span>${!q && kind === "groups" ? ` <span>Search to include the ${counts.groups - total} more actors from the MISP Galaxy.</span>` : ""}${total > shown.length ? ` <span>Showing the first ${shown.length}.</span>` : ""}</p>
      <div class="ix-list" translate="no">${shown.map(([id, o]) => `<button class="ix-li" data-intel-profile="${kind}:${esc(id)}"><span class="ix-id">${esc(/^[GSCT]\d/.test(id) ? id : "MISP")}</span><b>${esc(o.n)}</b>
        <span class="ix-li-a">${esc(kind === "techniques" ? o.ta.map((t) => KB.tacticName[t] || t).join(", ") : (o.a || []).slice(0, 6).join(", "))}</span>${o.country ? `<span class="ix-cc">${esc(o.country)}</span>` : ""}</button>`).join("") || '<div class="empty-note">Nothing matches.</div>'}</div>
      ${attribution()}`;
  }
  function attribution() {
    const a = KB.about || {};
    return `<p class="ix-attr" translate="no">Data: <a href="https://attack.mitre.org/" target="_blank" rel="noopener noreferrer">MITRE ATT&amp;CK®</a>${a.attack_version ? ` v${esc(a.attack_version)}` : ""} © The MITRE Corporation, reproduced and distributed with the permission of The MITRE Corporation; <a href="https://github.com/MISP/misp-galaxy" target="_blank" rel="noopener noreferrer">MISP Galaxy</a> (CC0). Built ${esc(a.built || "")}.</p>`;
  }

  function profileHTML(r) {
    const o = obj(r);
    if (!o) return '<div class="empty-note">Profile not found.</div>';
    const inScan = kbNodes().filter((n) => { const x = resolve(n.type, n.value); return x && x.kind === r.kind && x.id === r.id; });
    const kv = [];
    const add = (k, v) => { if (v != null && v !== "" && !(Array.isArray(v) && !v.length)) kv.push(`<dt>${esc(k)}</dt><dd>${esc(Array.isArray(v) ? v.join(", ") : v)}</dd>`); };
    const links = [];
    const au = attackUrl(r.kind, r.id); if (au) links.push(["MITRE ATT&CK", au]);
    if (o.mp) links.push(["Malpedia", malpediaUrl(o.mp)]);
    let sections = "";
    const tl = [];
    if (r.kind === "groups") {
      add("ATT&CK ID", r.id.startsWith("G") ? r.id : "Not in MITRE ATT&CK (MISP Galaxy profile)");
      add("Country", o.country); add("Suspected sponsor", o.sponsor); add("Motive", o.motive); add("Active since", o.since);
      add("Targets", o.sectors); add("Victims", o.victims);
      sections += sec("Malware & tools", o.s.length, `<div class="ix-chips">${listChips("software", sortBy("software", o.s), 80)}</div>`);
      sections += o.c.length ? sec("Campaigns", o.c.length, `<div class="ix-chips">${listChips("campaigns", o.c)}</div>`) : "";
      for (const x of o.c) { const cp = KB.campaigns[x]; if (cp.first || cp.last) tl.push({ d: cp.first || cp.last, end: cp.last !== cp.first ? cp.last : null, what: `Campaign: ${cp.n}`, campaign: x }); }
      if (o.since && dateOf(`${o.since}-01-01`)) tl.push({ d: `${String(o.since).slice(0, 4)}-01-01`, what: "Active since (MISP Galaxy)" });
    } else if (r.kind === "software") {
      add("ATT&CK ID", r.id); add("Type", o.k === "tool" ? "Tool (legitimate or dual-use software)" : "Malware"); add("Platforms", o.pl);
      sections += sec("Threat actors known to use it", o.g.length, `<div class="ix-chips">${listChips("groups", sortBy("groups", o.g), 80)}</div>`);
      sections += o.c.length ? sec("Campaigns", o.c.length, `<div class="ix-chips">${listChips("campaigns", o.c)}</div>`) : "";
      for (const x of o.c) { const cp = KB.campaigns[x]; if (cp.first || cp.last) tl.push({ d: cp.first || cp.last, end: cp.last !== cp.first ? cp.last : null, what: `Campaign: ${cp.n}`, campaign: x }); }
    } else if (r.kind === "campaigns") {
      add("ATT&CK ID", r.id); add("First seen", o.first); add("Last seen", o.last);
      sections += sec("Attributed to", o.g.length, `<div class="ix-chips">${listChips("groups", o.g)}</div>`);
      sections += sec("Malware & tools", o.s.length, `<div class="ix-chips">${listChips("software", sortBy("software", o.s))}</div>`);
      if (o.first) tl.push({ d: o.first, what: "First seen" });
      if (o.last && o.last !== o.first) tl.push({ d: o.last, what: "Last seen" });
    } else if (r.kind === "techniques") {
      const u = KB.used[r.id] || { groups: [], software: [], campaigns: [] };
      const parent = r.id.includes(".") ? r.id.split(".")[0] : null;
      add("Tactic", o.ta.map((t) => KB.tacticName[t] || t)); add("Platforms", o.pl);
      const subs = Object.keys(KB.techniques).filter((t) => t.startsWith(r.id + "."));
      if (parent && KB.techniques[parent]) sections += sec("Sub-technique of", 1, `<div class="ix-chips">${chip(ref("techniques", parent))}</div>`);
      if (subs.length) sections += sec("Sub-techniques", subs.length, `<div class="ix-chips">${subs.map((t) => chip(ref("techniques", t), ` <small>${esc(t)}</small>`)).join("")}</div>`);
      sections += sec("Threat actors using it", u.groups.length, `<div class="ix-chips">${listChips("groups", sortBy("groups", u.groups), 120)}</div>`);
      sections += sec("Malware & tools using it", u.software.length, `<div class="ix-chips">${listChips("software", sortBy("software", u.software), 120)}</div>`);
      if (u.campaigns.length) sections += sec("Campaigns", u.campaigns.length, `<div class="ix-chips">${listChips("campaigns", u.campaigns)}</div>`);
    } else {
      add("ATT&CK", "Not described in MITRE ATT&CK yet");
      add("Platform", o.mp ? ({ win: "Windows", elf: "Linux", osx: "macOS", apk: "Android", ios: "iOS", js: "JavaScript", jar: "Java", ps1: "PowerShell", py: "Python", php: "PHP", vbs: "VBScript" })[o.mp.split(".")[0]] : null);
    }
    if (o.created) tl.push({ d: o.created, what: "Added to MITRE ATT&CK" });
    if (o.modified && o.modified !== o.created) tl.push({ d: o.modified, what: "ATT&CK entry last updated" });
    for (const n of inScan) for (const [m, res] of Object.entries(S.results.get(n.id) || {})) for (const [k, v] of res.summary || []) { const d = DATE_KEY.test(k) && dateOf(v); if (d) tl.push({ d, what: k, m }); }
    // IOCs in this scan the sources linked to this malware / actor
    const iocs = new Map();
    for (const n of inScan) for (const e of S.edges.values()) {
      const oid = e.source === n.id ? e.target : e.target === n.id ? e.source : null;
      const x = oid && S.nodes.get(oid);
      if (x && !KB_TYPES.includes(x.type)) iocs.set(x.id, x);
    }
    const tech = new Map((o.t || []).map((t) => [t, 1]));
    const typ = KIND_TYPE[r.kind];
    return `<div class="ix-prof">
      <div class="ix-prof-h"><div class="d-top">${tchip(typ)}${inScan.length ? '<span class="vbadge">in this scan</span>' : ""}${r.kind === "groups" && o.src === "misp" ? '<span class="vbadge">MISP Galaxy</span>' : '<span class="vbadge">ATT&amp;CK</span>'}</div>
        <h2>${esc(o.n)}${/^[GSCT]\d/.test(r.id) ? ` <span class="ix-id">${esc(r.id)}</span>` : ""}</h2>
        ${o.a?.length ? `<div class="ix-aka"><span>Also known as</span> ${o.a.map((a) => `<i translate="no">${esc(a)}</i>`).join("")}</div>` : ""}
        <div class="d-actions">${links.map(([l, u]) => `<a class="btn sm ghost" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(l)} ↗</a>`).join("")}
          <button class="btn sm ghost" data-intel-scan="${esc(typ)}" data-value="${esc(r.kind === "techniques" ? r.id : o.n)}" title="Put it in the search box to look it up with the scanner">${ICON.pivot}Look up in scanner</button></div></div>
      ${kv.length ? `<dl class="kv ix-kv">${kv.join("")}</dl>` : ""}
      ${o.d ? `<div class="ix-desc" translate="no">${o.d.split(/\n\n+/).map((p) => `<p>${esc(p)}</p>`).join("")}</div>` : ""}
      ${iocs.size ? sec("IOCs in this scan linked to it", iocs.size, `<div class="ix-chips">${[...iocs.values()].slice(0, 40).map((x) => `<button class="ix-chip ioc" data-intel-goto="${esc(x.id)}"><span style="color:${tc(x.type)}">${esc(glyph(x.type))}</span> ${esc(x.value)}</button>`).join("")}</div>`) : ""}
      ${sections}
      ${tech.size ? sec("MITRE ATT&CK techniques", tech.size, matrixHTML(tech, { scale: 1 })) : ""}
      ${tl.length ? sec("Timeline", tl.length, timelineHTML(tl.sort((a, b) => b.d.localeCompare(a.d)))) : ""}
      ${o.refs?.length ? sec("References", o.refs.length, `<ul class="ix-refs" translate="no">${o.refs.map((u) => `<li><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a></li>`).join("")}</ul>`) : ""}
      ${attribution()}</div>`;
  }
  const sec = (title, n, html) => `<div class="rep-sec"><h3>${esc(title)}${n != null ? ` <em>${n}</em>` : ""}</h3>${html}</div>`;

  // ------------------------------------------------------------ events
  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-intel-profile],[data-intel-node],[data-intel-open],[data-intel-tab],[data-intel-lib],[data-intel-goto],[data-intel-scan],[data-intel-retry],[data-intel-leads],[data-intel-copytech],[data-intel-navigator],#intelBack");
    if (!t) return;
    e.preventDefault();
    if (t.id === "intelBack") return back();
    if (t.dataset.intelRetry !== undefined) { failed = null; render(); return load().catch(() => {}); }
    if (t.dataset.intelOpen) return open(t.dataset.intelOpen);
    if (t.dataset.intelTab) { view.stack = []; return open(t.dataset.intelTab); }
    if (t.dataset.intelLib) { view.lib = t.dataset.intelLib; return render(); }
    if (t.dataset.intelLeads !== undefined) { view.showLeads = true; return render(); }
    if (t.dataset.intelCopytech !== undefined) return KB && copy([...context().tech.keys()].sort().join("\n"));
    if (t.dataset.intelNavigator !== undefined) {
      if (!KB) return;
      download(`arachne-attack-layer-${(S.scanId || "scan").slice(0, 8)}.json`, JSON.stringify(navigatorLayer(), null, 2), "application/json");
      return toast(t_("Layer saved: open it in the ATT&CK Navigator"));
    }
    if (t.dataset.intelProfile) {
      const [kind, ...id] = t.dataset.intelProfile.split(":");
      return load().then(() => openProfile(ref(kind, id.join(":")))).catch(() => {});
    }
    if (t.dataset.intelNode) {
      const n = S.nodes.get(t.dataset.intelNode);
      return n && load().then(() => {
        const r = resolve(n.type, n.value);
        if (r) openProfile(r); else toast(`No ATT&CK or threat actor profile for ${n.value}`, "warn");
      }).catch(() => toast("Threat intel data could not be loaded", "error"));
    }
    if (t.dataset.intelGoto) {
      setView("report");
      select(t.dataset.intelGoto);
      return;
    }
    if (t.dataset.intelScan) {
      $("#typeSel").value = t.dataset.intelScan;
      $("#seedInput").value = t.dataset.value;
      $("#seedInput").focus();
      toast("Press Scan to look it up");
    }
  });
  document.addEventListener("input", (e) => {
    if (e.target.dataset?.intelQ === undefined) return;
    view.q = e.target.value; view.focusQ = true;
    clearTimeout(view.qt); view.qt = setTimeout(render, 120);
  });
  document.addEventListener("keydown", (e) => {
    const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || "");
    if (typing || $(".modal.open") || e.ctrlKey || e.metaKey || e.altKey) return;
    // I: Shield on and off (back to the report), unless the site turned Shield off
    if (e.key === "i" && (shown('#viewSeg [data-view="shield"]') || shown('#mnav [data-pane="shield"]') || S.view === "shield")) { e.preventDefault(); if (S.view === "shield") setView("report"); else open(S.scanId ? "scan" : "library"); }
    if (e.key === "Backspace" && S.view === "shield" && view.stack.length) { e.preventDefault(); back(); }
  });
  // a new scan starts on the attribution tab again
  let lastScan = null;
  function onView() {
    if (S.scanId !== lastScan) { lastScan = S.scanId; view.showLeads = false; if (S.scanId && view.tab === "library" && !view.stack.length) view.tab = "scan"; }
    render();
  }

  // #intel=scan | timeline | library | G0016 | S0154 | T1059.001 | C0022 (deep links, called from app.js init)
  function deepLink(hp) {
    const v = hp.get("intel");
    if (!v) return;
    if (["scan", "attack", "matrix", "timeline", "library"].includes(v)) return open(v);
    const kind = /^G/i.test(v) ? "groups" : /^S\d/i.test(v) ? "software" : /^C\d/i.test(v) ? "campaigns" : /^T\d/i.test(v) ? "techniques" : null;
    if (kind) { open("library"); load().then(() => { if (KB[kind][v.toUpperCase()] || KB[kind][v]) { view.stack = [ref(kind, KB[kind][v.toUpperCase()] ? v.toUpperCase() : v)]; render(); } }).catch(() => {}); }
  }

  window.Intel = { allowed, load, resolve, context, timeline, reportSection, profileButton, open, openProfile, deepLink, render: onView, renderSoon, navigatorLayer, get kb() { return KB; } };
})();
