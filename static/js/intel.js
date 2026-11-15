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
  const view = { tab: "scan", stack: [], showLeads: false, lens: "all" };
  // the threat library is a window of its own (top bar, key T): reference data, not tied to the scan
  const lib = { stack: [], q: "", kind: "groups" };
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
    if ($("#libModal")?.classList.contains("open")) renderLib();
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

  function matrixHTML(counts, { scale = null, title = "", observed = null, mark = "reported for these IOCs", cls = null } = {}) {
    // counts: Map technique id -> number (or Set of reasons)
    const byTac = new Map(KB.tactics.map(([s]) => [s, []]));
    for (const [t, v] of counts) for (const ta of KB.techniques[t]?.ta || []) byTac.get(ta)?.push([t, typeof v === "number" ? v : v.size, v]);
    const max = scale || Math.max(1, ...[...counts.values()].map((v) => typeof v === "number" ? v : v.size));
    return `<div class="ix-mxwrap" tabindex="0"><div class="ix-matrix" translate="no" ${title ? `aria-label="${esc(title)}"` : ""}>${KB.tactics.map(([s, , name]) => {
      const cells = byTac.get(s).sort((a, b) => (observed ? observed.has(b[0]) - observed.has(a[0]) : 0) || b[1] - a[1] || a[0].localeCompare(b[0]));
      return `<div class="mcol ${cells.length ? "on" : ""}"><div class="mhead"><b>${esc(name)}</b><span>${cells.length || ""}</span></div>${cells.map(([t, n, v]) => {
        const lvl = n >= 3 && n / max > 0.66 ? 3 : n >= 2 ? 2 : 1;
        const seen = observed && observed.has(t);
        const why = typeof v === "number" ? "" : [...v].slice(0, 12).join("\n");
        return `<button class="mcell h${lvl}${seen ? " seen" : ""}${cls ? " " + cls(t) : ""}" data-intel-profile="techniques:${esc(t)}" title="${esc(t)} ${esc(KB.techniques[t].n)}${why ? "\n\n" + esc(why) : ""}"><b>${esc(t)}${n > 1 && max > 1 ? `<em>${n}</em>` : ""}</b><span>${esc(KB.techniques[t].n)}</span>${seen ? `<i>${esc(t_(mark))}</i>` : ""}</button>`;
      }).join("")}</div>`;
    }).join("")}</div></div>`;
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
  const TABS = ["scan", "attack", "defend", "timeline"];
  const scroller = () => $("#shieldWrap");
  // A site built on ARACHNE can limit Shield to some accounts: window.ArachneShieldGate() returns false (and
  // explains why) when this user may not open it. The app itself has no accounts, so Shield is always open there.
  function allowed() {
    try { return typeof window.ArachneShieldGate !== "function" || window.ArachneShieldGate() !== false; } catch { return true; }
  }
  function open(tab = null, prof = null) {
    if (S.view !== "shield" && !allowed()) return;
    if (tab === "matrix") tab = "attack";
    if (tab === "library") { openLibrary(); return; }
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
    // the explanation belongs to the attribution tab only
    const how = $("#shieldWrap .sh-how"); if (how) how.hidden = !!prof || view.tab !== "scan";
    const rb = $("[data-intel-report]"); if (rb) rb.disabled = !S.scanId || !KB;
    if (!KB) {
      load().catch(() => {});
      body.innerHTML = failed ? `<div class="empty-note">Threat intel data could not be loaded ({err}). <button class="btn xs" data-intel-retry>Try again</button></div>`.replace("{err}", esc(failed))
        : '<div class="src-running"><span class="spinner"></span>Loading MITRE ATT&amp;CK and threat actor data…</div>';
      return;
    }
    const sc = scroller(), st = sc ? sc.scrollTop : 0;
    const mx = $(".ix-mxwrap", body), mxl = mx ? mx.scrollLeft : 0;
    body.innerHTML = prof ? profileHTML(prof) : view.tab === "timeline" ? scanTimelineHTML() : view.tab === "attack" ? attackHTML() : view.tab === "defend" ? defendHTML() : scanHTML();
    if (sc) sc.scrollTop = st;
    const mx2 = $(".ix-mxwrap", body); if (mx2 && mxl) mx2.scrollLeft = mxl;
  }

  // ------------------------------------------------------------ the threat library window (top bar, key T)
  function openLibrary() {
    if (!allowed()) return;
    lib.stack = [];
    $("#libModal").classList.add("open");
    renderLib();
    load().catch(() => {});
    setTimeout(() => $("#libModal [data-intel-q]")?.focus(), 30);
  }
  function renderLib() {
    const body = $("#libBody");
    if (!body) return;
    const prof = lib.stack[lib.stack.length - 1];
    $("#libBack").hidden = !prof;
    if (!KB) {
      body.innerHTML = failed ? `<div class="empty-note">Threat intel data could not be loaded ({err}). <button class="btn xs" data-intel-retry>Try again</button></div>`.replace("{err}", esc(failed))
        : '<div class="src-running"><span class="spinner"></span>Loading MITRE ATT&amp;CK and threat actor data…</div>';
      return;
    }
    // a search being typed is never wiped: only the list under it is redrawn
    if (!prof && $("[data-intel-q]", body) && document.activeElement === $("[data-intel-q]", body)) { const l = $("#ixLibList"); if (l) { l.innerHTML = libList(); return; } }
    body.innerHTML = prof ? profileHTML(prof, { lib: true }) : libraryHTML();
    body.scrollTop = 0;
  }
  const inLib = (el) => !!el.closest("#libModal");

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
      <p>You can also scan an actor, a malware family or an ATT&amp;CK ID directly (for example <span class="mono">APT29</span>, <span class="mono">Emotet</span> or <span class="mono">T1059.001</span>), or browse the threat library.</p>
      <p><button class="btn sm" data-intel-library>Browse the threat library</button></p></div>`;
    const c = context();
    const kb = kbNodes();
    if (!c.nodes.size) {
      return `<div class="empty-note">${kb.length ? `None of the ${kb.length} malware / actor indicators in this scan match a profile.` : "No source has linked this scan to a malware family, threat actor or ATT&CK technique yet."} Sources that do: ThreatFox, MalwareBazaar, URLhaus, VirusTotal, AlienVault OTX, Hybrid Analysis. You can also scan a family name, an actor or a technique ID (for example <span class="mono">T1059.001</span>) directly.</div>`
        + `<p style="text-align:center"><button class="btn sm ghost" data-intel-library>Browse the threat library</button></p>`;
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
      ${board.length ? `<div class="rep-sec"><h3>Threat actors <em>${board.length}</em>${board.length > 1 && board[1].g.startsWith("G") && board[0].g.startsWith("G") ? `<button class="btn xs ghost" data-intel-compare="${esc(board[0].g)}|${esc(board[1].g)}" title="Their ATT&CK techniques and malware side by side">Compare the top two</button>` : ""}</h3><div class="sh-actors">${board.map(actorRow).join("")}</div></div>`
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
  function tacticBars(c, link = true) {
    const per = KB.tactics.map(([s, , name]) => [name, [...c.tech.keys()].filter((t) => KB.techniques[t].ta.includes(s)).length]);
    const max = Math.max(1, ...per.map((x) => x[1]));
    const tag = link ? "button" : "div";
    return `<div class="sh-tactics">${per.map(([name, n]) => `<${tag} translate="no" class="sh-tac ${n ? "" : "zero"}"${link ? ' data-intel-tab="attack"' : ""} title="${esc(name)}: ${n}"><span translate="no">${esc(name)}</span><i><b style="width:${(n / max) * 100}%"></b></i><em>${n}</em></${tag}>`).join("")}</div>`;
  }

  // ATT&CK tab: the whole scan, or one lens on it (techniques a source reported, one actor, one malware, one campaign)
  function lenses(c) {
    const L = [];
    if (c.observed.size) L.push(["reported", null, "Reported for these IOCs"]);
    const seen = new Set();
    for (const x of actorBoard(attributionRows())) if (KB.groups[x.g].t.length) { seen.add(x.g); L.push(["g:" + x.g, "groups", KB.groups[x.g].n]); }
    for (const [g, node] of c.groups) if (node && !seen.has(g) && KB.groups[g].t.length) L.push(["g:" + g, "groups", KB.groups[g].n]);
    for (const sid of c.software.keys()) if (KB.software[sid].t.length) L.push(["s:" + sid, "software", KB.software[sid].n]);
    for (const [cid, node] of c.campaigns) if (node && KB.campaigns[cid].t.length) L.push(["c:" + cid, "campaigns", KB.campaigns[cid].n]);
    return L;
  }
  function attackHTML() {
    if (!S.scanId) return `<div class="empty-note">Scan an IOC first: the ATT&amp;CK techniques of the malware, actors and campaigns the sources link it to are mapped here.</div>`;
    const c = context();
    if (!c.tech.size) return `<div class="empty-note">No ATT&amp;CK techniques are linked to this scan yet. They come from the malware, threat actors and campaigns the sources tie the IOCs to, and from techniques sources report directly.</div>`;
    const L = lenses(c);
    if (!L.some((x) => x[0] === view.lens)) view.lens = "all";
    const lens = view.lens, kind = lens.slice(0, 2);
    let counts = c.tech, observed = c.observed, mark = "reported for these IOCs", note;
    const tacsOf = (m) => new Set([...m.keys()].flatMap((t) => KB.techniques[t].ta)).size;
    if (lens === "reported") {
      counts = new Map([...c.tech].filter(([t]) => c.observed.has(t)));
      observed = null;
      note = `<span>${counts.size === 1 ? "1 technique a source reported for these IOCs." : `${counts.size} techniques sources reported for these IOCs.`}</span> <span>The strongest evidence of what happened.</span>`;
    } else if (kind === "g:") {
      // an actor: everything it is known to use, with the techniques this scan also links to marked
      const g = lens.slice(2), o = KB.groups[g];
      counts = new Map(o.t.map((t) => [t, new Set([o.n])]));
      // marked: what other evidence in the scan (its malware, other actors, reported techniques) also points to
      observed = new Set(o.t.filter((t) => c.observed.has(t) || [...(c.tech.get(t) || [])].some((w) => w !== o.n)));
      mark = "also from other evidence";
      note = `<span translate="no">${esc(o.n)}</span>: <span>${o.t.length} techniques across ${tacsOf(counts)} tactics.</span> <span>${observed.size} of them also come from other evidence in this scan, such as its malware (marked).</span>`;
    } else if (kind === "s:" || kind === "c:") {
      const x = kind === "s:" ? KB.software[lens.slice(2)] : KB.campaigns[lens.slice(2)];
      counts = new Map([...c.tech].filter(([t]) => x.t.includes(t)));
      note = `<span translate="no">${esc(x.n)}</span>: <span>${counts.size} techniques across ${tacsOf(counts)} tactics.</span>`;
    } else {
      note = `<span>${c.tech.size} techniques across ${tacsOf(c.tech)} tactics.</span> <span>Techniques the malware, actors and campaigns linked to this scan are known to use.</span>${c.observed.size ? ` <span>${c.observed.size} of them were reported by sources for these IOCs (marked).</span>` : ""} <span>Darker cells are shared by more of them. Click one for its profile.</span>`;
    }
    const rows = [...counts].sort((a, b) => (observed ? observed.has(b[0]) - observed.has(a[0]) : 0) || b[1].size - a[1].size || a[0].localeCompare(b[0]));
    const lensBtn = (k, label, cls = "", raw = false) => `<button class="sh-lens ${cls} ${k === lens ? "on" : ""}" data-intel-lens="${esc(k)}"${raw ? ' translate="no"' : ""}>${esc(label)}</button>`;
    const group = (kd, title) => { const xs = L.filter((x) => x[1] === kd); return xs.length ? `<span class="sh-lens-g">${title}</span>${xs.slice(0, 12).map(([k, , n]) => lensBtn(k, n, kd, true)).join("")}` : ""; };
    return `<div class="rep-sec"><h3>MITRE ATT&amp;CK matrix <em>${counts.size}</em>
        <span class="sh-acts"><button class="btn xs ghost" data-intel-copytech title="Copy every technique ID, one per line">${ICON.copy}Copy IDs</button><button class="btn xs ghost" data-intel-navigator title="A layer file for the MITRE ATT&CK Navigator (mitre-attack.github.io/attack-navigator): Open Existing Layer, Upload from local">Navigator layer</button></span></h3>
      ${L.length ? `<div class="sh-lenses"><span class="sh-lens-g">Show</span>${lensBtn("all", "Everything linked")}${L.some((x) => x[0] === "reported") ? lensBtn("reported", "Reported for these IOCs", "lrep") : ""}${group("groups", "Actor")}${group("software", "Malware")}${group("campaigns", "Campaign")}</div>` : ""}
      <p class="msg ix-note">${note}</p>
      ${counts.size ? matrixHTML(counts, { observed, mark }) : '<div class="empty-note">Nothing to show for this choice.</div>'}</div>
      <div class="rep-sec"><h3>Techniques <em>${rows.length}</em></h3><div class="ix-list sh-tech" translate="no">${rows.slice(0, 400).map(([t, why]) => `<button class="ix-li" data-intel-profile="techniques:${esc(t)}"><span class="ix-id">${esc(t)}</span><b>${esc(KB.techniques[t].n)}</b>
        <span class="ix-li-a">${esc(KB.techniques[t].ta.map((x) => KB.tacticName[x] || x).join(", "))} · <span translate="no">${esc([...why].slice(0, 4).join(", "))}${why.size > 4 ? "…" : ""}</span></span>${c.observed.has(t) ? '<span class="sh-pill direct">Reported</span>' : `<span class="ix-cc">${why.size}</span>`}</button>`).join("")}</div></div>
      ${attribution()}`;
  }

  // ------------------------------------------------------------ Defend: what to do about the techniques (MITRE mitigations, detections, log sources)
  const mitUrl = (id) => `https://attack.mitre.org/mitigations/${id}/`;
  const detUrl = (id) => `https://attack.mitre.org/detectionstrategies/${id}/`;
  const dcUrl = (id) => `https://attack.mitre.org/datacomponents/${id}/`;
  // techW: technique -> weight. Each mitigation / detection / log source collects the techniques it covers.
  function defence(techW) {
    const mit = new Map(), dc = new Map(), det = new Map();
    const bump = (m, k, t, w) => { const x = m.get(k) || { id: k, t: [], w: 0 }; x.t.push(t); x.w += w; m.set(k, x); };
    for (const [t, w] of techW) {
      const o = KB.techniques[t];
      if (!o) continue;
      for (const k of o.m || []) if (KB.mitigations?.[k]) bump(mit, k, t, w);
      for (const k of o.dc || []) if (KB.datacomps?.[k]) bump(dc, k, t, w);
      for (const k of o.det || []) if (KB.detections?.[k]) bump(det, k, t, w);
    }
    const sort = (m) => [...m.values()].sort((a, b) => b.w - a.w || b.t.length - a.t.length || a.id.localeCompare(b.id));
    return { mit: sort(mit), dc: sort(dc), det: sort(det) };
  }
  // a technique a source reported for the IOCs counts most, then how many of the linked malware / actors use it
  const scanWeights = (c) => new Map([...c.tech].map(([t, why]) => [t, (c.observed.has(t) ? 5 : 0) + why.size]));
  const techChips = (ts, max = 12) => ts.slice(0, max).map((t) => chip(ref("techniques", t), ` <small>${esc(t)}</small>`)).join("") + (ts.length > max ? `<span class="msg">+${ts.length - max}</span>` : "");
  function defendHTML() {
    if (!S.scanId) return `<div class="empty-note">Scan an IOC first: Shield then ranks the MITRE ATT&amp;CK mitigations, log sources and detections that matter most against what is linked to it.</div>`;
    const c = context();
    if (!c.tech.size) return `<div class="empty-note">No ATT&amp;CK techniques are linked to this scan yet, so there is nothing to defend against.</div>`;
    if (!KB.mitigations) return `<div class="empty-note">This copy of the threat intel data has no mitigations. Rebuild it with tools/build_threat_kb.py.</div>`;
    return defendBody(scanWeights(c), c.observed) + attribution();
  }
  function defendBody(w, observed = new Set(), { compact = false } = {}) {
    const d = defence(w), total = w.size;
    const pct = (n) => `${Math.round((n / Math.max(1, total)) * 100)}%`;
    const top5 = new Set(d.mit.slice(0, 5).flatMap((x) => x.t));
    const top5dc = new Set(d.dc.slice(0, 5).flatMap((x) => x.t));
    const rep = (ts) => ts.filter((t) => observed.has(t)).length;
    const mitRow = (x, i) => {
      const o = KB.mitigations[x.id], r = rep(x.t);
      return `<div class="sh-mit"><div class="sh-mit-h"><span class="sh-rank">${i + 1}</span><b translate="no">${esc(o.n)}</b><a class="ix-id" href="${esc(mitUrl(x.id))}" target="_blank" rel="noopener noreferrer" translate="no">${esc(x.id)} ↗</a>
        <span class="sh-mit-n"><span>${x.t.length === 1 ? "Covers 1 technique" : `Covers ${x.t.length} techniques`}</span>${r ? ` · <span class="sh-c-low">${r === 1 ? "1 reported" : `${r} reported`}</span>` : ""}</span></div>
        ${compact ? "" : `<p class="sh-mit-d" translate="no">${esc(o.d)}</p><details class="sh-more"><summary>Techniques it covers</summary><div class="ix-chips">${techChips(x.t, 40)}</div></details>`}</div>`;
    };
    const max = Math.max(1, ...d.dc.map((x) => x.t.length));
    const dcRow = (x) => `<a class="sh-tac" href="${esc(dcUrl(x.id))}" target="_blank" rel="noopener noreferrer" title="${esc(x.id)}"><span translate="no">${esc(KB.datacomps[x.id].n)}</span><i><b style="width:${(x.t.length / max) * 100}%"></b></i><em>${x.t.length}</em></a>`;
    if (compact) return `<div class="sh-mits">${d.mit.slice(0, 5).map(mitRow).join("")}</div>`;
    const detRow = (x) => `<div class="sh-det"><a class="ix-id" href="${esc(detUrl(x.id))}" target="_blank" rel="noopener noreferrer" translate="no">${esc(x.id)} ↗</a><b translate="no">${esc(KB.detections[x.id].n)}</b><div class="ix-chips">${techChips(x.t, 3)}${x.t.some((t) => observed.has(t)) ? '<span class="sh-pill direct">Reported</span>' : ""}</div></div>`;
    return `<div class="rep-tiles ix-tiles sh-tiles">
        <div class="rep-tile"><b>${total}</b><span>Techniques to defend against</span></div>
        <div class="rep-tile"><b>${pct(top5.size)}</b><span>Covered by the top 5 mitigations</span></div>
        <div class="rep-tile"><b>${pct(top5dc.size)}</b><span>Visible in the top 5 log sources</span></div>
        <div class="rep-tile"><b>${d.det.length}</b><span>MITRE detection strategies</span></div>
        <div class="rep-tile"><b>${observed.size}</b><span>Reported for these IOCs</span></div></div>
      <div class="rep-sec"><h3>Mitigations, by impact <em>${d.mit.length}</em><span class="sh-acts"><button class="btn xs ghost" data-intel-copydefend title="Copy the mitigations and log sources as a checklist (Markdown)">${ICON.copy}Copy checklist</button></span></h3>
        <p class="msg ix-note"><span>MITRE ATT&amp;CK mitigations ranked by how much of this scan's activity they block.</span> <span>Techniques a source reported for these IOCs weigh most.</span> <span>Start at the top.</span></p>
        <div class="sh-mits">${d.mit.slice(0, 12).map(mitRow).join("")}</div>${d.mit.length > 12 ? `<details class="sh-more"><summary>${d.mit.length - 12} more mitigations</summary><div class="sh-mits">${d.mit.slice(12).map((x, i) => mitRow(x, i + 12)).join("")}</div></details>` : ""}</div>
      ${d.dc.length ? `<div class="rep-sec"><h3>Log sources to collect <em>${d.dc.length}</em></h3>
        <p class="msg ix-note"><span>The telemetry (ATT&amp;CK data components) that can show these techniques, and how many each one covers.</span> <span>If you can't see it, you can't detect it.</span></p>
        <div class="sh-tactics">${d.dc.slice(0, 16).map(dcRow).join("")}</div></div>` : ""}
      ${d.det.length ? `<div class="rep-sec"><h3>Detection strategies <em>${d.det.length}</em></h3>
        <p class="msg ix-note"><span>MITRE's detection guidance for these techniques, most relevant first.</span> <span>Each one opens the analytics on attack.mitre.org.</span> <span>For ready-made rules for the IOCs themselves, use Export, Detection rules.</span></p>
        <div class="sh-dets">${d.det.slice(0, 30).map(detRow).join("")}</div>${d.det.length > 30 ? `<details class="sh-more"><summary>${d.det.length - 30} more detection strategies</summary><div class="sh-dets">${d.det.slice(30, 200).map(detRow).join("")}</div></details>` : ""}</div>` : ""}`;
  }
  function defendChecklist() {
    const c = context(), d = defence(scanWeights(c));
    const lines = [`# Defensive checklist: ${seedLabel()}`, "", `${c.tech.size} MITRE ATT&CK techniques linked to this scan.`, "", "## Mitigations, by impact", ""];
    for (const x of d.mit) lines.push(`- [ ] ${KB.mitigations[x.id].n} (${x.id}): covers ${x.t.length} technique${x.t.length === 1 ? "" : "s"} ${mitUrl(x.id)}`);
    lines.push("", "## Log sources to collect", "");
    for (const x of d.dc.slice(0, 25)) lines.push(`- [ ] ${KB.datacomps[x.id].n} (${x.id}): ${x.t.length} technique${x.t.length === 1 ? "" : "s"}`);
    return lines.join("\n") + "\n";
  }
  const seedLabel = () => { const v = (typeof seedNodes === "function" ? seedNodes() : []).map((n) => n.value); return v.length ? v.slice(0, 3).join(", ") + (v.length > 3 ? ` +${v.length - 3}` : "") : "scan"; };

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
  const LIB_KINDS = [["groups", "Threat actors"], ["software", "Malware & tools"], ["campaigns", "Campaigns"], ["techniques", "Techniques"], ["mitigations", "Mitigations"]];
  function libItems() {
    const q = lib.q.trim(), nq = norm(q), kind = lib.kind;
    let items = Object.entries(KB[kind] || {});
    if (q) {
      const ql = q.toLowerCase();
      items = items.map(([id, o]) => {
        const names = [o.n, ...(o.a || [])];
        const score = id.toLowerCase() === ql ? 0 : norm(o.n) === nq ? 1 : names.some((n) => norm(n) === nq) ? 2 : norm(o.n).startsWith(nq) ? 3 : names.some((n) => norm(n).includes(nq)) ? 4 : id.toLowerCase().startsWith(ql) ? 5 : (o.country || "").toLowerCase() === ql ? 6 : 99;
        return [id, o, score];
      }).filter((x) => x[2] < 99).sort((a, b) => a[2] - b[2] || a[1].n.localeCompare(b[1].n));
    } else {
      items = items.filter(([, o]) => kind !== "groups" || o.src === "attack").sort((a, b) => kind === "techniques" || kind === "mitigations" ? a[0].localeCompare(b[0]) : a[1].n.localeCompare(b[1].n));
    }
    return items;
  }
  function libList() {
    const kind = lib.kind, items = libItems(), total = items.length, shown = items.slice(0, 120), q = lib.q.trim();
    const all = Object.keys(KB.groups).length;
    const sub = (id, o) => kind === "techniques" ? o.ta.map((t) => KB.tacticName[t] || t).join(", ") : kind === "mitigations" ? (o.t.length === 1 ? "1 technique" : `${o.t.length} techniques`) : (o.a || []).slice(0, 6).join(", ");
    return `<p class="msg ix-note"><span>${q ? (total === 1 ? "1 match." : `${total} matches.`) : kind === "groups" ? `The ${total} MITRE ATT&amp;CK groups.` : `${total} entries.`}</span>${!q && kind === "groups" ? ` <span>Search to include the ${all - total} more actors from the MISP Galaxy.</span>` : ""}${total > shown.length ? ` <span>Showing the first ${shown.length}.</span>` : ""}</p>
      <div class="ix-list" translate="no">${shown.map(([id, o]) => `<button class="ix-li" data-intel-profile="${kind}:${esc(id)}"><span class="ix-id">${esc(/^[GSCTM]\d/.test(id) ? id : "MISP")}</span><b>${esc(o.n)}</b>
        <span class="ix-li-a">${esc(sub(id, o))}</span>${o.country ? `<span class="ix-cc">${esc(o.country)}</span>` : ""}</button>`).join("") || '<div class="empty-note">Nothing matches.</div>'}</div>`;
  }
  function libraryHTML() {
    const counts = Object.fromEntries(LIB_KINDS.map(([k]) => [k, Object.keys(KB[k] || {}).length]));
    return `<div class="ix-lib-h"><input class="inp" data-intel-q placeholder="Search by name, alias or ATT&CK ID (APT29, Cozy Bear, Emotet, T1566, RU)…" value="${esc(lib.q)}" spellcheck="false">
      <div class="seg">${LIB_KINDS.filter(([k]) => counts[k]).map(([k, l]) => `<button data-intel-lib="${k}" class="${k === lib.kind ? "on" : ""}">${esc(l)} <em>${counts[k]}</em></button>`).join("")}</div></div>
      <div id="ixLibList">${libList()}</div>
      ${attribution()}`;
  }
  function attribution() {
    const a = KB.about || {};
    return `<p class="ix-attr" translate="no">Data: <a href="https://attack.mitre.org/" target="_blank" rel="noopener noreferrer">MITRE ATT&amp;CK®</a>${a.attack_version ? ` v${esc(a.attack_version)}` : ""} © The MITRE Corporation, reproduced and distributed with the permission of The MITRE Corporation; <a href="https://github.com/MISP/misp-galaxy" target="_blank" rel="noopener noreferrer">MISP Galaxy</a> (CC0). Built ${esc(a.built || "")}.</p>`;
  }

  function profileHTML(r, { lib: inLibrary = false } = {}) {
    if (r.kind === "compare") return compareHTML(...r.id.split("|"), inLibrary);
    if (r.kind === "mitigations") return mitigationHTML(r.id);
    const o = obj(r);
    if (!o) return '<div class="empty-note">Profile not found.</div>';
    // the library is reference data: nothing about the current scan there
    const inScan = inLibrary ? [] : kbNodes().filter((n) => { const x = resolve(n.type, n.value); return x && x.kind === r.kind && x.id === r.id; });
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
      if (!inLibrary && S.scanId) sections += inScanActor(r.id);
      sections += capabilitiesHTML(r.id);
      sections += sec("Malware & tools", o.s.length, `<div class="ix-chips">${listChips("software", sortBy("software", o.s), 80)}</div>`);
      sections += o.c.length ? sec("Campaigns", o.c.length, `<div class="ix-chips">${listChips("campaigns", o.c)}</div>`) : "";
      sections += similarHTML(r.id);
      if (o.t.length && KB.mitigations) sections += sec("Top mitigations against it", null, `<p class="msg ix-note"><span>The MITRE ATT&amp;CK mitigations that cover most of this actor's techniques.</span></p>${defendBody(new Map(o.t.map((t) => [t, 1])), new Set(), { compact: true })}`);
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
      if (o.m?.length) sections += sec("Mitigations", o.m.length, `<div class="ix-chips">${o.m.filter((m) => KB.mitigations[m]).map((m) => `<button translate="no" class="ix-chip mitigations" data-intel-profile="mitigations:${esc(m)}">${esc(KB.mitigations[m].n)} <small>${esc(m)}</small></button>`).join("")}</div>`);
      if (o.dc?.length) sections += sec("Log sources that can show it", o.dc.length, `<div class="ix-chips" translate="no">${o.dc.filter((d) => KB.datacomps[d]).map((d) => `<a class="ix-chip" href="${esc(dcUrl(d))}" target="_blank" rel="noopener noreferrer">${esc(KB.datacomps[d].n)}</a>`).join("")}</div>`);
      if (o.det?.length) sections += sec("Detection strategies", o.det.length, `<div class="sh-dets">${o.det.filter((d) => KB.detections[d]).map((d) => `<div class="sh-det"><a class="ix-id" href="${esc(detUrl(d))}" target="_blank" rel="noopener noreferrer" translate="no">${esc(d)} ↗</a><b translate="no">${esc(KB.detections[d].n)}</b></div>`).join("")}</div>`);
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
        <h2 translate="no">${esc(o.n)}${/^[GSCT]\d/.test(r.id) ? ` <span class="ix-id">${esc(r.id)}</span>` : ""}</h2>
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

  // ------------------------------------------------------------ actor capabilities, similar actors, comparison
  // what the actor can do: its techniques per tactic, and the platforms those techniques and its malware run on
  function capabilitiesHTML(g) {
    const o = KB.groups[g];
    if (!o.t.length && !o.s.length) return "";
    const tech = new Map(o.t.map((t) => [t, 1]));
    const pl = new Map();
    for (const t of o.t) for (const p of KB.techniques[t]?.pl || []) pl.set(p, (pl.get(p) || 0) + 1);
    for (const sid of o.s) for (const p of KB.software[sid]?.pl || []) pl.set(p, (pl.get(p) || 0) + 1);
    const plats = [...pl].sort((a, b) => b[1] - a[1]).slice(0, 10);
    const mal = o.s.filter((sid) => KB.software[sid].k === "malware").length, tools = o.s.length - mal;
    const own = o.s.filter((sid) => !sharedMal(KB.software[sid])).length;
    const tacs = new Set(o.t.flatMap((t) => KB.techniques[t]?.ta || [])).size;
    return `<div class="rep-sec"><h3>Capabilities</h3>
      <div class="rep-tiles ix-tiles sh-tiles">
        <div class="rep-tile"><b>${o.t.length}</b><span>ATT&amp;CK techniques</span></div>
        <div class="rep-tile"><b>${tacs}<small>/${KB.tactics.length}</small></b><span>Tactics covered</span></div>
        <div class="rep-tile"><b>${mal}</b><span>Malware</span></div>
        <div class="rep-tile"><b>${tools}</b><span>Tools</span></div>
        <div class="rep-tile"><b>${own}</b><span>Distinctive malware and tools</span></div></div>
      ${o.t.length ? `<p class="msg ix-note"><span>Techniques per tactic, from MITRE ATT&amp;CK.</span> <span>Long bars are where this actor is strongest.</span></p>${tacticBars({ tech }, false)}` : ""}
      ${plats.length ? `<div class="ix-row sh-plats"><span class="ix-lbl">Platforms</span><div class="ix-chips" translate="no">${plats.map(([p, n]) => `<span class="ix-chip">${esc(p)} <small>${n}</small></span>`).join("")}</div></div>` : ""}
      ${o.t.length ? `<details class="sh-more"><summary>Show the full ATT&amp;CK matrix</summary>${matrixHTML(tech, { scale: 1 })}</details>` : ""}</div>`;
  }
  // in the current scan: how strongly the scan's IOCs point to this actor, and why
  function inScanActor(g) {
    const rows = attributionRows();
    const b = actorBoard(rows).find((x) => x.g === g);
    if (!b) return "";
    const iocs = rows.filter((r) => r.actors.some((x) => x.g === g)).map((r) => r.n);
    const c = context(), mine = new Set(KB.groups[g].t);
    const overlap = [...c.observed].filter((t) => mine.has(t));
    return `<div class="rep-sec sh-inscan"><h3>In this scan</h3>
      <div class="ix-ctx"><div class="ix-row"><span class="ix-lbl">Confidence</span><div>${confPill(b.conf)} <span class="msg" translate="no">${esc([...b.why].slice(0, 5).join(" · "))}</span></div></div>
      <div class="ix-row"><span class="ix-lbl">IOCs</span><div class="ix-chips">${iocs.slice(0, 20).map(iocBtn).join("")}${iocs.length > 20 ? `<span class="msg">+${iocs.length - 20}</span>` : ""}</div></div>
      ${c.observed.size ? `<div class="ix-row"><span class="ix-lbl">TTP fit</span><div><span>${overlap.length} of the ${c.observed.size} techniques sources reported for these IOCs are known for this actor.</span></div></div>` : ""}</div></div>`;
  }
  // actors whose techniques and distinctive malware overlap most with this one (Jaccard on techniques)
  function similar(g, max = 6) {
    const a = KB.groups[g], A = new Set(a.t), SA = new Set(a.s);
    if (A.size < 5) return [];
    const out = [];
    for (const [k, b] of Object.entries(KB.groups)) {
      if (k === g || !b.t.length) continue;
      let both = 0;
      for (const t of b.t) if (A.has(t)) both++;
      const sim = both / (A.size + b.t.length - both);
      const sw = b.s.filter((x) => SA.has(x) && !sharedMal(KB.software[x]));
      if (both) out.push({ g: k, sim, both, sw, score: sim + 0.08 * Math.min(sw.length, 5) });
    }
    return out.sort((x, y) => y.score - x.score).slice(0, max);
  }
  function similarHTML(g) {
    const xs = similar(g);
    if (!xs.length) return "";
    return `<div class="rep-sec"><h3>Similar actors <em>${xs.length}</em></h3>
      <p class="msg ix-note"><span>Actors with the most ATT&amp;CK techniques and distinctive malware in common.</span> <span>Worth ruling out before settling on an attribution.</span></p>
      <div class="sh-sims">${xs.map((x) => `<div class="sh-sim"><button translate="no" class="sh-actor-n" data-intel-profile="groups:${esc(x.g)}"><b>${esc(KB.groups[x.g].n)}</b>${KB.groups[x.g].country ? `<span class="ix-cc">${esc(KB.groups[x.g].country)}</span>` : ""}</button>
        <i class="sh-bar"><b style="width:${Math.round(x.sim * 100)}%"></b></i><span class="sh-sim-n"><span>${Math.round(x.sim * 100)}% overlap</span> · <span>${x.both} shared techniques</span>${x.sw.length ? ` · <span translate="no">${esc(x.sw.slice(0, 3).map((s) => KB.software[s].n).join(", "))}</span>` : ""}</span>
        <button class="btn xs ghost" data-intel-compare="${esc(g)}|${esc(x.g)}">Compare</button></div>`).join("")}</div></div>`;
  }
  function compareHTML(ga, gb, inLibrary = false) {
    const A = KB.groups[ga], B = KB.groups[gb];
    if (!A || !B) return '<div class="empty-note">Profile not found.</div>';
    const ta = new Set(A.t), tb = new Set(B.t);
    const both = A.t.filter((t) => tb.has(t)), onlyA = A.t.filter((t) => !tb.has(t)), onlyB = B.t.filter((t) => !ta.has(t));
    const sim = Math.round((both.length / Math.max(1, ta.size + tb.size - both.length)) * 100);
    const counts = new Map([...new Set([...A.t, ...B.t])].map((t) => [t, new Set([ta.has(t) && tb.has(t) ? `${A.n} + ${B.n}` : ta.has(t) ? A.n : B.n])]));
    const sa = new Set(A.s), sb = new Set(B.s);
    const swBoth = A.s.filter((x) => sb.has(x)), swA = A.s.filter((x) => !sb.has(x)), swB = B.s.filter((x) => !sa.has(x));
    const swChips = (ids) => ids.length ? sortBy("software", ids).map((x) => chip(ref("software", x), sharedMal(KB.software[x]) ? " <small>shared</small>" : "")).join("") : '<span class="msg">None</span>';
    const rowKV = (k, f) => `<tr><th>${esc(k)}</th><td translate="no">${esc(f(A) ?? "–")}</td><td translate="no">${esc(f(B) ?? "–")}</td></tr>`;
    return `<div class="ix-prof">
      <div class="ix-prof-h"><div class="d-top"><span class="vbadge">Compare</span></div>
        <h2 class="sh-vs"><button translate="no" class="ix-link sh-ca" data-intel-profile="groups:${esc(ga)}">${esc(A.n)}</button> <span>vs</span> <button translate="no" class="ix-link sh-cb" data-intel-profile="groups:${esc(gb)}">${esc(B.n)}</button></h2></div>
      <div class="rep-tiles ix-tiles sh-tiles">
        <div class="rep-tile"><b>${sim}%</b><span>Technique overlap</span></div>
        <div class="rep-tile"><b>${both.length}</b><span>Shared techniques</span></div>
        <div class="rep-tile"><b>${swBoth.length}</b><span>Shared malware and tools</span></div>
        <div class="rep-tile"><b>${onlyA.length}</b><span>${esc(`Only ${A.n}`)}</span></div>
        <div class="rep-tile"><b>${onlyB.length}</b><span>${esc(`Only ${B.n}`)}</span></div></div>
      <div class="rep-sec"><table class="sh-cmp"><thead><tr><th></th><th translate="no" class="sh-ca">${esc(A.n)}</th><th translate="no" class="sh-cb">${esc(B.n)}</th></tr></thead><tbody>
        ${rowKV("Country", (o) => o.country)}${rowKV("Motive", (o) => o.motive)}${rowKV("Active since", (o) => o.since)}
        ${rowKV("ATT&CK techniques", (o) => String(o.t.length))}${rowKV("Malware & tools", (o) => String(o.s.length))}${rowKV("Campaigns", (o) => String(o.c.length))}</tbody></table></div>
      ${counts.size ? `<div class="rep-sec"><h3>ATT&amp;CK side by side <em>${counts.size}</em></h3>
        <p class="msg ix-note sh-legend"><span class="sh-key both"></span><span>Both</span> <span class="sh-key ca"></span><span translate="no">${esc(A.n)}</span> <span class="sh-key cb"></span><span translate="no">${esc(B.n)}</span></p>
        ${matrixHTML(counts, { scale: 1, cls: (t) => ta.has(t) && tb.has(t) ? "cmp-both" : ta.has(t) ? "cmp-a" : "cmp-b" })}</div>` : ""}
      ${sec("Shared malware & tools", swBoth.length, `<div class="ix-chips">${swChips(swBoth)}</div>`)}
      <div class="sh-cmp2">${sec(`Only ${A.n}`, swA.length, `<div class="ix-chips">${swChips(swA)}</div>`)}${sec(`Only ${B.n}`, swB.length, `<div class="ix-chips">${swChips(swB)}</div>`)}</div>
      ${attribution()}</div>`;
  }
  function mitigationHTML(id) {
    const o = KB.mitigations?.[id];
    if (!o) return '<div class="empty-note">Profile not found.</div>';
    const users = new Map();
    for (const t of o.t) for (const g of KB.used[t]?.groups || []) users.set(g, (users.get(g) || 0) + 1);
    const top = [...users].sort((a, b) => b[1] - a[1]).slice(0, 30);
    return `<div class="ix-prof">
      <div class="ix-prof-h"><div class="d-top"><span class="vbadge">Mitigation</span><span class="vbadge">ATT&amp;CK</span></div>
        <h2 translate="no">${esc(o.n)} <span class="ix-id">${esc(id)}</span></h2>
        <div class="d-actions"><a class="btn sm ghost" href="${esc(mitUrl(id))}" target="_blank" rel="noopener noreferrer">MITRE ATT&amp;CK ↗</a></div></div>
      <div class="ix-desc" translate="no"><p>${esc(o.d)}</p></div>
      ${sec("Techniques it covers", o.t.length, matrixHTML(new Map(o.t.map((t) => [t, 1])), { scale: 1 }))}
      ${top.length ? sec("Threat actors it works against most", top.length, `<div class="ix-chips">${top.map(([g, n]) => chip(ref("groups", g), ` <small>${n}</small>`)).join("")}</div>`) : ""}
      ${attribution()}</div>`;
  }

  // ------------------------------------------------------------ Shield report (Markdown): attribution, actors, ATT&CK, defences, timeline
  function reportMarkdown() {
    const c = context(), rows = attributionRows(), board = actorBoard(rows), d = defence(scanWeights(c));
    const cell = (v) => String(v ?? "").replace(/\|/g, "\\|").replace(/\s+/g, " ");
    const L = [`# Arachne Shield report: ${seedLabel()}`, "", `Generated ${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC by ARACHNE. Attribution is a lead for an analyst to confirm, not proof.`, ""];
    L.push("## Summary", "", `- IOCs attributed: ${rows.filter((r) => r.actors.length).length}`, `- Threat actors: ${board.length}`,
      `- Malware & tools: ${c.software.size + c.families.size}`, `- ATT&CK techniques: ${c.tech.size} (${c.observed.size} reported for these IOCs)`, "");
    if (board.length) {
      L.push("## Threat actors", "", "| Actor | ATT&CK ID | Country | Confidence | IOCs | Evidence |", "|---|---|---|---|---|---|");
      for (const x of board) { const o = KB.groups[x.g]; L.push(`| ${cell(o.n)} | ${x.g.startsWith("G") ? x.g : "MISP"} | ${cell(o.country || "")} | ${CONF[x.conf][0]} | ${x.iocs.size} | ${cell([...x.why].slice(0, 4).join("; "))} |`); }
      L.push("");
    }
    if (rows.length) {
      L.push("## Attribution by IOC", "", "| IOC | Type | Confidence | Threat actors | Malware | Sources |", "|---|---|---|---|---|---|");
      for (const r of rows) L.push(`| ${cell(defang(r.n.value, r.n.type))} | ${cell(r.n.type)} | ${CONF[r.conf][0]} | ${cell(r.actors.map((x) => `${KB.groups[x.g].n} (${CONF[x.conf][0].toLowerCase()})`).join(", ") || "-")} | ${cell([...r.mal.map((sid) => KB.software[sid].n + (r.shared.includes(sid) ? " (shared)" : "")), ...r.fam.map((i) => KB.families[i][0])].join(", ") || "-")} | ${cell([...r.srcs].map(modLabel).join(", "))} |`);
      L.push("");
    }
    if (c.tech.size) {
      L.push("## MITRE ATT&CK techniques", "");
      for (const [sn, , name] of KB.tactics) {
        const ts = [...c.tech.keys()].filter((t) => KB.techniques[t].ta.includes(sn)).sort();
        if (ts.length) L.push(`**${name}**: ${ts.map((t) => `${t} ${KB.techniques[t].n}${c.observed.has(t) ? " (reported)" : ""}`).join("; ")}`, "");
      }
    }
    if (d.mit.length) {
      L.push("## Recommended mitigations", "");
      d.mit.slice(0, 15).forEach((x, i) => L.push(`${i + 1}. **${KB.mitigations[x.id].n}** (${x.id}): covers ${x.t.length} technique${x.t.length === 1 ? "" : "s"}. ${mitUrl(x.id)}`));
      L.push("");
    }
    if (d.dc.length) { L.push("## Log sources to collect", ""); for (const x of d.dc.slice(0, 12)) L.push(`- ${KB.datacomps[x.id].n} (${x.id}): ${x.t.length} techniques`); L.push(""); }
    const tl = timeline().slice(0, 40);
    if (tl.length) { L.push("## Timeline (newest first)", ""); for (const e of tl) L.push(`- ${e.d}${e.end ? ` to ${e.end}` : ""}: ${e.what}${e.n ? ` (${defang(e.n.value, e.n.type)})` : ""}`); L.push(""); }
    L.push("---", "", `Threat data: MITRE ATT&CK${KB.about?.attack_version ? ` v${KB.about.attack_version}` : ""} © The MITRE Corporation, reproduced and distributed with the permission of The MITRE Corporation; MISP Galaxy (CC0). IOC values are defanged.`);
    return L.join("\n") + "\n";
  }

  // ------------------------------------------------------------ events
  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-intel-profile],[data-intel-node],[data-intel-open],[data-intel-tab],[data-intel-lib],[data-intel-goto],[data-intel-scan],[data-intel-retry],[data-intel-leads],[data-intel-copytech],[data-intel-navigator],[data-intel-library],[data-intel-lens],[data-intel-compare],[data-intel-copydefend],[data-intel-report],#intelBack,#libBack,#libraryBtn");
    if (!t) return;
    e.preventDefault();
    if (t.id === "intelBack") return back();
    if (t.id === "libBack") { lib.stack.pop(); return renderLib(); }
    if (t.id === "libraryBtn" || t.dataset.intelLibrary !== undefined) return openLibrary();
    if (t.dataset.intelRetry !== undefined) { failed = null; render(); renderLib(); return load().catch(() => {}); }
    if (t.dataset.intelOpen) return open(t.dataset.intelOpen);
    if (t.dataset.intelTab) { view.stack = []; return open(t.dataset.intelTab); }
    if (t.dataset.intelLib) { lib.kind = t.dataset.intelLib; lib.stack = []; return renderLib(); }
    if (t.dataset.intelLens) { view.lens = t.dataset.intelLens; return render(); }
    if (t.dataset.intelCompare) {
      const r = ref("compare", t.dataset.intelCompare);
      if (inLib(t)) { lib.stack.push(r); renderLib(); $("#libBody").scrollTop = 0; return; }
      return openProfile(r);
    }
    if (t.dataset.intelCopydefend !== undefined) return KB && copy(defendChecklist());
    if (t.dataset.intelReport !== undefined) {
      if (!KB || !S.scanId) return;
      download(`arachne-shield-${(S.scanId || "scan").slice(0, 8)}.md`, reportMarkdown(), "text/markdown");
      return toast(t_("Shield report saved"));
    }
    if (t.dataset.intelLeads !== undefined) { view.showLeads = true; return render(); }
    if (t.dataset.intelCopytech !== undefined) return KB && copy([...context().tech.keys()].sort().join("\n"));
    if (t.dataset.intelNavigator !== undefined) {
      if (!KB) return;
      download(`arachne-attack-layer-${(S.scanId || "scan").slice(0, 8)}.json`, JSON.stringify(navigatorLayer(), null, 2), "application/json");
      return toast(t_("Layer saved: open it in the ATT&CK Navigator"));
    }
    if (t.dataset.intelProfile) {
      const [kind, ...id] = t.dataset.intelProfile.split(":");
      const r = ref(kind, id.join(":"));
      // inside the library window, profiles open in the window
      if (inLib(t)) { lib.stack.push(r); renderLib(); $("#libBody").scrollTop = 0; return; }
      return load().then(() => openProfile(r)).catch(() => {});
    }
    if (t.dataset.intelNode) {
      const n = S.nodes.get(t.dataset.intelNode);
      return n && load().then(() => {
        const r = resolve(n.type, n.value);
        if (r) openProfile(r); else toast(`No ATT&CK or threat actor profile for ${n.value}`, "warn");
      }).catch(() => toast("Threat intel data could not be loaded", "error"));
    }
    if (t.dataset.intelGoto) {
      $("#libModal")?.classList.remove("open");
      setView("report");
      select(t.dataset.intelGoto);
      return;
    }
    if (t.dataset.intelScan) {
      $("#libModal")?.classList.remove("open");
      $("#typeSel").value = t.dataset.intelScan;
      $("#seedInput").value = t.dataset.value;
      $("#seedInput").focus();
      toast("Press Scan to look it up");
    }
  });
  document.addEventListener("input", (e) => {
    if (e.target.dataset?.intelQ === undefined) return;
    lib.q = e.target.value;
    clearTimeout(lib.qt); lib.qt = setTimeout(() => { const l = $("#ixLibList"); if (l && KB) l.innerHTML = libList(); }, 120);
  });
  document.addEventListener("keydown", (e) => {
    const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || "");
    if (e.key === "Backspace" && !typing && $("#libModal")?.classList.contains("open") && lib.stack.length) { e.preventDefault(); lib.stack.pop(); return renderLib(); }
    if (typing || $(".modal.open") || e.ctrlKey || e.metaKey || e.altKey) return;
    // I: Shield on and off (back to the report), unless the site turned Shield off
    if (e.key === "i" && (shown('#viewSeg [data-view="shield"]') || shown('#mnav [data-pane="shield"]') || S.view === "shield")) { e.preventDefault(); if (S.view === "shield") setView("report"); else open("scan"); }
    // T: the threat library
    if (e.key === "t" && shown("#libraryBtn")) { e.preventDefault(); openLibrary(); }
    if (e.key === "Backspace" && S.view === "shield" && view.stack.length) { e.preventDefault(); back(); }
  });
  // a new scan starts on the attribution tab again
  let lastScan = null;
  function onView() {
    if (S.scanId !== lastScan) { lastScan = S.scanId; view.showLeads = false; view.lens = "all"; }
    render();
  }

  // #intel=scan | timeline | library | G0016 | S0154 | T1059.001 | C0022 (deep links, called from app.js init)
  function deepLink(hp) {
    const v = hp.get("intel");
    if (!v) return;
    if (["scan", "attack", "matrix", "defend", "timeline", "library"].includes(v)) return open(v);
    const kind = /^G/i.test(v) ? "groups" : /^S\d/i.test(v) ? "software" : /^C\d/i.test(v) ? "campaigns" : /^T\d/i.test(v) ? "techniques" : /^M\d/i.test(v) ? "mitigations" : null;
    if (kind) { openLibrary(); load().then(() => { const id = KB[kind]?.[v.toUpperCase()] ? v.toUpperCase() : v; if (KB[kind]?.[id]) { lib.stack = [ref(kind, id)]; renderLib(); } }).catch(() => {}); }
  }

  window.Intel = { allowed, load, resolve, context, timeline, reportSection, profileButton, open, openProfile, openLibrary, deepLink, render: onView, renderSoon, navigatorLayer, reportMarkdown, get kb() { return KB; } };
})();
