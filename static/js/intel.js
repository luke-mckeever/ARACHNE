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
  const view = { tab: "scan", stack: [], q: "", lib: "groups" };

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
    if ($("#intelModal")?.classList.contains("open")) render();
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
  const chip = (ref, extra = "") => `<button class="ix-chip ${ref.kind}" data-intel-profile="${esc(ref.kind)}:${esc(ref.id)}" title="${esc(KIND[ref.kind])}${/^[GSCT]\d/.test(ref.id) ? " · " + esc(ref.id) : ""}">${esc(nameOf(ref))}${extra}</button>`;
  const ref = (kind, id) => ({ kind, id });
  const listChips = (kind, ids, max = 40) => ids.length ? ids.slice(0, max).map((id) => chip(ref(kind, id))).join("") + (ids.length > max ? `<span class="msg"> +${ids.length - max} more</span>` : "") : '<span class="msg">None recorded</span>';
  const sortBy = (kind, ids) => [...ids].sort((a, b) => (KB[kind][a]?.n || a).localeCompare(KB[kind][b]?.n || b));

  function matrixHTML(counts, { scale = null, title = "", observed = null } = {}) {
    // counts: Map technique id -> number (or Set of reasons)
    const byTac = new Map(KB.tactics.map(([s]) => [s, []]));
    for (const [t, v] of counts) for (const ta of KB.techniques[t]?.ta || []) byTac.get(ta)?.push([t, typeof v === "number" ? v : v.size, v]);
    const max = scale || Math.max(1, ...[...counts.values()].map((v) => typeof v === "number" ? v : v.size));
    return `<div class="ix-matrix" ${title ? `aria-label="${esc(title)}"` : ""}>${KB.tactics.map(([s, , name]) => {
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
    const actors = [...c.groups.keys()];
    const directActors = actors.filter((g) => c.groups.get(g));
    const knownActors = actors.filter((g) => !c.groups.get(g));
    return `<div class="rep-sec ix-sec"><h3>Threat context <em>${direct.length}</em><button class="btn xs ghost" data-intel-open="scan" title="ATT&CK matrix, actors and timeline for the whole scan">ATT&amp;CK view</button></h3>
      <div class="ix-ctx">
        <div class="ix-row"><span class="ix-lbl">Linked</span><div class="ix-chips">${direct.map((r) => chip(r)).join("")}</div></div>
        ${directActors.length ? `<div class="ix-row"><span class="ix-lbl">Attributed to</span><div class="ix-chips">${directActors.map((g) => chip(ref("groups", g))).join("")}</div></div>` : ""}
        ${knownActors.length ? `<div class="ix-row"><span class="ix-lbl">Known users</span><div class="ix-chips">${sortBy("groups", knownActors).slice(0, 10).map((g) => chip(ref("groups", g))).join("")}${knownActors.length > 10 ? `<span class="msg">+${knownActors.length - 10} more</span>` : ""}</div></div>` : ""}
        ${c.campaigns.size ? `<div class="ix-row"><span class="ix-lbl">Campaigns</span><div class="ix-chips">${[...c.campaigns.keys()].slice(0, 8).map((x) => chip(ref("campaigns", x))).join("")}</div></div>` : ""}
        ${c.tech.size ? `<div class="ix-row"><span class="ix-lbl">Techniques</span><div class="ix-chips"><button class="ix-chip techniques" data-intel-open="scan">${c.tech.size} ATT&amp;CK technique${c.tech.size === 1 ? "" : "s"} across ${new Set([...c.tech.keys()].flatMap((t) => KB.techniques[t].ta)).size} tactics</button></div></div>` : ""}
      </div>
      ${knownActors.length ? `<p class="msg ix-note">"Known users" are actors that MITRE ATT&amp;CK records as using this malware. It is context, not proof that this IOC belongs to them.</p>` : ""}</div>`;
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
    const bar = ys.length > 1 ? `<div class="ix-years">${ys.map((y) => `<div title="${y}: ${years[y]} event${years[y] === 1 ? "" : "s"}"><i style="height:${Math.max(8, (years[y] / max) * 100)}%"></i><span>${y.slice(2)}</span></div>`).join("")}</div>` : "";
    let lastY = null;
    return bar + `<div class="ix-tl">${ev.map((e) => {
      const y = e.d.slice(0, 4), head = y !== lastY ? `<div class="ix-tl-y">${y}</div>` : "";
      lastY = y;
      const node = e.n ? `<button class="ix-tl-node" data-intel-goto="${esc(e.n.id)}" title="Show ${esc(e.n.value)} in the report"><span style="color:${tc(e.n.type)}">${esc(glyph(e.n.type))}</span>${esc(e.n.value)}</button>` : "";
      return head + `<div class="ix-tl-e ${e.campaign ? "camp" : ""}"><time>${esc(e.d)}${e.end ? ` → ${esc(e.end)}` : ""}</time><div><b>${e.campaign ? `<button class="ix-link" data-intel-profile="campaigns:${esc(e.campaign)}">${esc(e.what)}</button>` : esc(e.what)}</b>
        <div class="ix-tl-meta">${node}${e.m ? `<span>${esc(modLabel(e.m))}</span>` : ""}${e.sub ? `<span>${esc(e.sub)}</span>` : ""}</div></div></div>`;
    }).join("")}</div>`;
  }

  // ------------------------------------------------------------ the modal: this scan / timeline / library / profiles
  function open(tab = null, prof = null) {
    if (tab) view.tab = tab;
    view.stack = prof ? [prof] : [];
    $("#intelModal").classList.add("open");
    render();
    load().catch(() => {});
  }
  function openProfile(r) {
    if (!$("#intelModal").classList.contains("open")) { view.stack = []; $("#intelModal").classList.add("open"); }
    view.stack.push(r);
    render();
    $("#intelBody").scrollTop = 0;
  }
  function render() {
    const body = $("#intelBody");
    const prof = view.stack[view.stack.length - 1];
    $$("#intelTabs [data-intel-tab]").forEach((b) => b.classList.toggle("on", !prof && b.dataset.intelTab === view.tab));
    $("#intelBack").hidden = !prof;
    if (!KB) {
      body.innerHTML = failed ? `<div class="empty-note">Threat intel data could not be loaded (${esc(failed)}). <button class="btn xs" data-intel-retry>Try again</button></div>`
        : '<div class="src-running"><span class="spinner"></span>Loading MITRE ATT&amp;CK and threat actor data…</div>';
      return;
    }
    const st = body.scrollTop;
    body.innerHTML = prof ? profileHTML(prof) : view.tab === "timeline" ? scanTimelineHTML() : view.tab === "library" ? libraryHTML() : scanHTML();
    if (!prof) body.scrollTop = st;
    if (view.tab === "library" && !prof) { const i = $("[data-intel-q]", body); if (i && document.activeElement !== i && view.focusQ) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); view.focusQ = false; } }
  }
  function scanHTML() {
    if (!S.scanId) return `<div class="empty-note">Scan an IOC first: malware families, threat actors and ATT&amp;CK techniques the sources link it to show up here. Or browse the <button class="btn xs" data-intel-tab="library">Library</button>.</div>`;
    const c = context();
    const kb = kbNodes();
    if (!c.nodes.size) {
      return `<div class="empty-note">${kb.length ? `None of the ${kb.length} malware / actor indicators in this scan match a profile.` : "No source has linked this scan to a malware family, threat actor or ATT&CK technique yet."} Sources that do: ThreatFox, MalwareBazaar, URLhaus, VirusTotal, AlienVault OTX, Hybrid Analysis. You can also scan a family name, an actor or a technique ID (for example <span class="mono">T1059.001</span>) directly.</div>`
        + `<p style="text-align:center"><button class="btn sm ghost" data-intel-tab="library">Browse the library</button></p>`;
    }
    const tile = (v, label) => `<div class="rep-tile ${v ? "" : "zero"}"><b>${v}</b><span>${label}</span></div>`;
    const directG = [...c.groups].filter(([, n]) => n).map(([g]) => g), knownG = [...c.groups].filter(([, n]) => !n).map(([g]) => g);
    const sw = [...c.software.keys()];
    return `<div class="rep-tiles ix-tiles">${tile(sw.length + c.families.size, "Malware & tools")}${tile(c.groups.size, "Threat actors")}${tile(c.campaigns.size, "Campaigns")}${tile(c.tech.size, "ATT&CK techniques")}</div>
      <div class="rep-sec"><h3>Malware &amp; tools <em>${sw.length + c.families.size}</em></h3><div class="ix-cards">${sw.map((s) => profileCard(ref("software", s), c.software.get(s))).join("")}${[...c.families].map(([i, n]) => profileCard(ref("family", i), n)).join("")}</div></div>
      ${directG.length ? `<div class="rep-sec"><h3>Threat actors linked by sources <em>${directG.length}</em></h3><div class="ix-cards">${directG.map((g) => profileCard(ref("groups", g), c.groups.get(g))).join("")}</div></div>` : ""}
      ${knownG.length ? `<div class="rep-sec"><h3>Known users of this malware <em>${knownG.length}</em></h3><p class="msg ix-note">Actors MITRE ATT&amp;CK records as using the malware above. Many share commodity tools, so treat this as a lead, not attribution.</p><div class="ix-chips">${sortBy("groups", knownG).map((g) => chip(ref("groups", g), KB.groups[g].country ? ` <small>${esc(KB.groups[g].country)}</small>` : "")).join("")}</div></div>` : ""}
      ${c.campaigns.size ? `<div class="rep-sec"><h3>Campaigns <em>${c.campaigns.size}</em></h3><div class="ix-chips">${[...c.campaigns.keys()].map((x) => chip(ref("campaigns", x), KB.campaigns[x].first ? ` <small>${esc(KB.campaigns[x].first.slice(0, 4))}</small>` : "")).join("")}</div></div>` : ""}
      ${c.tech.size ? `<div class="rep-sec"><h3>MITRE ATT&amp;CK matrix <em>${c.tech.size}</em></h3><p class="msg ix-note">Techniques the malware, actors and campaigns above are known to use${c.observed.size ? `, plus ${c.observed.size} that sources reported for these IOCs` : ""}. Darker cells are shared by more of them. Click one for its profile.</p>${matrixHTML(c.tech, { observed: c.observed })}</div>` : ""}
      ${attribution()}`;
  }
  function profileCard(r, node) {
    const o = obj(r);
    const meta = r.kind === "groups" ? [o.country, o.motive, r.id.startsWith("G") ? r.id : "MISP Galaxy"] : r.kind === "software" ? [o.k === "tool" ? "Tool" : "Malware", r.id, `${o.t.length} techniques`, `${o.g.length} actors`] : ["Not in ATT&CK", o.mp];
    return `<button class="ix-card" data-intel-profile="${esc(r.kind)}:${esc(r.id)}"><div class="ix-card-h"><b>${esc(o.n)}</b>${node ? `<span class="msg">${esc(node.value !== o.n ? node.value : "")}</span>` : ""}</div>
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
      <p class="msg ix-note">${q ? `${total} match${total === 1 ? "" : "es"}` : kind === "groups" ? `The ${total} MITRE ATT&amp;CK groups. Search to include the ${counts.groups - total} more actors from the MISP Galaxy.` : `${total} entries`}${total > shown.length ? `, showing the first ${shown.length}` : ""}.</p>
      <div class="ix-list">${shown.map(([id, o]) => `<button class="ix-li" data-intel-profile="${kind}:${esc(id)}"><span class="ix-id">${esc(/^[GSCT]\d/.test(id) ? id : "MISP")}</span><b>${esc(o.n)}</b>
        <span class="ix-li-a">${esc(kind === "techniques" ? o.ta.map((t) => KB.tacticName[t] || t).join(", ") : (o.a || []).slice(0, 6).join(", "))}</span>${o.country ? `<span class="ix-cc">${esc(o.country)}</span>` : ""}</button>`).join("") || '<div class="empty-note">Nothing matches.</div>'}</div>
      ${attribution()}`;
  }
  function attribution() {
    const a = KB.about || {};
    return `<p class="ix-attr">Data: <a href="https://attack.mitre.org/" target="_blank" rel="noopener noreferrer">MITRE ATT&amp;CK®</a>${a.attack_version ? ` v${esc(a.attack_version)}` : ""} © The MITRE Corporation, reproduced and distributed with the permission of The MITRE Corporation; <a href="https://github.com/MISP/misp-galaxy" target="_blank" rel="noopener noreferrer">MISP Galaxy</a> (CC0). Built ${esc(a.built || "")}.</p>`;
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
        ${o.a?.length ? `<div class="ix-aka"><span>Also known as</span> ${o.a.map((a) => `<i>${esc(a)}</i>`).join("")}</div>` : ""}
        <div class="d-actions">${links.map(([l, u]) => `<a class="btn sm ghost" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(l)} ↗</a>`).join("")}
          <button class="btn sm ghost" data-intel-scan="${esc(typ)}" data-value="${esc(r.kind === "techniques" ? r.id : o.n)}" title="Put it in the search box to look it up with the scanner">${ICON.pivot}Look up in scanner</button></div></div>
      ${kv.length ? `<dl class="kv ix-kv">${kv.join("")}</dl>` : ""}
      ${o.d ? `<div class="ix-desc">${o.d.split(/\n\n+/).map((p) => `<p>${esc(p)}</p>`).join("")}</div>` : ""}
      ${iocs.size ? sec("IOCs in this scan linked to it", iocs.size, `<div class="ix-chips">${[...iocs.values()].slice(0, 40).map((x) => `<button class="ix-chip ioc" data-intel-goto="${esc(x.id)}"><span style="color:${tc(x.type)}">${esc(glyph(x.type))}</span> ${esc(x.value)}</button>`).join("")}</div>`) : ""}
      ${sections}
      ${tech.size ? sec("MITRE ATT&CK techniques", tech.size, matrixHTML(tech, { scale: 1 })) : ""}
      ${tl.length ? sec("Timeline", tl.length, timelineHTML(tl.sort((a, b) => b.d.localeCompare(a.d)))) : ""}
      ${o.refs?.length ? sec("References", o.refs.length, `<ul class="ix-refs">${o.refs.map((u) => `<li><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a></li>`).join("")}</ul>`) : ""}
      ${attribution()}</div>`;
  }
  const sec = (title, n, html) => `<div class="rep-sec"><h3>${esc(title)}${n != null ? ` <em>${n}</em>` : ""}</h3>${html}</div>`;

  // ------------------------------------------------------------ events
  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-intel-profile],[data-intel-node],[data-intel-open],[data-intel-tab],[data-intel-lib],[data-intel-goto],[data-intel-scan],[data-intel-retry],#intelBack,#intelBtn");
    if (!t) return;
    e.preventDefault();
    if (t.id === "intelBtn") return open(S.scanId ? "scan" : "library");
    if (t.id === "intelBack") { view.stack.pop(); return render(); }
    if (t.dataset.intelRetry !== undefined) { failed = null; render(); return load().catch(() => {}); }
    if (t.dataset.intelOpen) return open(t.dataset.intelOpen);
    if (t.dataset.intelTab) { view.tab = t.dataset.intelTab; view.stack = []; return render(); }
    if (t.dataset.intelLib) { view.lib = t.dataset.intelLib; return render(); }
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
      $("#intelModal").classList.remove("open");
      select(t.dataset.intelGoto);
      if (S.view !== "report") setView("report");
      return;
    }
    if (t.dataset.intelScan) {
      $("#intelModal").classList.remove("open");
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
    if (e.key === "i" && !typing && !$(".modal.open") && !e.ctrlKey && !e.metaKey && !e.altKey) { e.preventDefault(); open(S.scanId ? "scan" : "library"); }
    if (e.key === "Backspace" && !typing && $("#intelModal")?.classList.contains("open") && view.stack.length) { e.preventDefault(); view.stack.pop(); render(); }
  });

  // #intel=scan | timeline | library | G0016 | S0154 | T1059.001 | C0022 (deep links, called from app.js init)
  function deepLink(hp) {
    const v = hp.get("intel");
    if (!v) return;
    if (["scan", "timeline", "library"].includes(v)) return open(v);
    const kind = /^G/i.test(v) ? "groups" : /^S\d/i.test(v) ? "software" : /^C\d/i.test(v) ? "campaigns" : /^T\d/i.test(v) ? "techniques" : null;
    if (kind) { open("library"); load().then(() => { if (KB[kind][v.toUpperCase()] || KB[kind][v]) { view.stack = [ref(kind, KB[kind][v.toUpperCase()] ? v.toUpperCase() : v)]; render(); } }).catch(() => {}); }
  }

  window.Intel = { load, resolve, context, timeline, reportSection, profileButton, open, openProfile, deepLink, get kb() { return KB; } };
})();
