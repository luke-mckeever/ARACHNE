"use strict";
/* ARACHNE front-end: scan report, pivot graph, live event stream, panels, exports. */

// ------------------------------------------------------------------ helpers
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function h(html) { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstElementChild; }
async function api(path, opts = {}) {
  const o = { method: opts.method || (opts.body !== undefined ? "POST" : "GET"), headers: {} };
  if (opts.body !== undefined) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(opts.body); }
  const r = await fetch(path, o);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
function toast(msg, kind = "info", ms = 3200) {
  const t = h(`<div class="toast ${kind}">${esc(msg)}</div>`);
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), ms);
}
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
function throttleRAF(fn) { let q = false; return () => { if (q) return; q = true; setTimeout(() => { q = false; fn(); }, 120); }; }
function copy(text) { navigator.clipboard.writeText(text).then(() => toast("Copied to clipboard"), () => toast("Copy failed", "error")); }
function download(name, data, mime = "application/octet-stream") {
  const blob = data instanceof Blob ? data : new Blob([data], { type: mime });
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
function fmtTime(ts) { return ts ? new Date(ts * 1000).toLocaleString() : ""; }
function hhmmss(ts) { return new Date(ts * 1000).toLocaleTimeString([], { hour12: false }); }
function b64(s) { try { return btoa(unescape(encodeURIComponent(s))); } catch { return ""; } }
function hexA(hex, a) {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex || ""); if (!m) return `rgba(160,160,170,${a})`;
  const n = parseInt(m[1], 16); return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`;
}
function inkFor(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex || ""); if (!m) return "#050506";
  const n = parseInt(m[1], 16); const l = (0.299 * (n >> 16) + 0.587 * ((n >> 8) & 255) + 0.114 * (n & 255)) / 255;
  return l > 0.55 ? "#050506" : "#fafafa";
}
const VRANK = { malicious: 3, suspicious: 2, clean: 1 };
const ICON = {
  pivot: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4M5 5l3 3M16 16l3 3M19 5l-3 3M8 16l-3 3"/></svg>',
  deep: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="2"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="10"/></svg>',
  run: '<svg viewBox="0 0 24 24"><path d="m7 4 13 8-13 8z"/></svg>',
  copy: '<svg viewBox="0 0 24 24"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>',
  focus: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M3 8V3h5M21 8V3h-5M3 16v5h5M21 16v5h-5"/></svg>',
  hide: '<svg viewBox="0 0 24 24"><path d="M3 3l18 18M10.6 10.6a2 2 0 0 0 2.8 2.8M9.9 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.1M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.4-1.6"/></svg>',
  trash: '<svg viewBox="0 0 24 24"><path d="M4 7h16M10 11v6M14 11v6M5 7l1 13h12l1-13M9 7V4h6v3"/></svg>',
  link: '<svg viewBox="0 0 24 24"><path d="M14 3h7v7M10 14 21 3M19 14v6a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h6"/></svg>',
  plus: '<svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>',
  redo: '<svg viewBox="0 0 24 24"><path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/></svg>',
  chev: '<svg viewBox="0 0 24 24" class="chev"><path d="m6 9 6 6 6-6"/></svg>',
  select: '<svg viewBox="0 0 24 24"><circle cx="6" cy="12" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="18" cy="18" r="2"/><path d="M8 11l8-4M8 13l8 4"/></svg>',
};

// ------------------------------------------------------------------ state
const S = {
  meta: null, settings: null, modules: {}, ui: {},
  scanId: null, status: "idle", title: "",
  nodes: new Map(), edges: new Map(), results: new Map(), busy: new Map(),
  selected: null, tab: "intel", collapsed: new Set(), collapsedGroups: new Set(), listCollapsed: new Set(),
  hiddenTypes: new Set(), hiddenVerdicts: new Set(), hiddenNodes: new Set(), search: "",
  es: null, evIdx: 0, logs: [], stats: {}, pendingNodes: [], pendingEdges: [], flushT: null,
  cy: null, hasFcose: false, layoutRun: null, firstLayout: true,
  view: "report", needLayout: false,
};
const tc = (t) => (S.ui.monochrome ? "#a1a1aa" : (S.ui.typeColors || {})[t] || CFG.typeColors[t] || "#a1a1aa");
const glyph = (t) => CFG.glyph[t] || t.slice(0, 3).toUpperCase();
const typeLabel = (t) => (S.meta?.types?.[t]?.label) || t;
const modLabel = (m) => S.modules[m]?.label || m;
const lookupLinks = () => (Array.isArray(S.ui.links) && S.ui.links.length ? S.ui.links : CFG.links);

function shortLabel(n) {
  let v = n.label || n.value;
  if (n.type === "url" && v === n.value) {
    try { const u = new URL(v); v = u.host + (u.pathname.length > 1 ? u.pathname : ""); } catch { /* keep */ }
  }
  return v.length > 30 ? v.slice(0, 28) + "…" : v;
}

// ------------------------------------------------------------------ UI config
function applyUI() {
  S.ui = Object.assign({}, CFG.ui, S.settings.ui || {});
  // ?shot - static rendering for headless screenshot capture (no animation, no timers)
  if (new URLSearchParams(location.search).has("shot")) Object.assign(S.ui, { animate: false, autoLayout: false, showLabels: true, showNoise: true });
  const root = document.documentElement.style;
  root.setProperty("--accent", S.ui.accent);
  root.setProperty("--accent-ink", inkFor(S.ui.accent));
  $("#graphWrap").classList.toggle("nogrid", !S.ui.grid);
  $("#layoutSel").value = S.ui.layout;
  $('[data-tool="labels"]').classList.toggle("on", !!S.ui.showLabels);
  $('[data-tool="edgelabels"]').classList.toggle("on", !!S.ui.showEdgeLabels);
  $('[data-tool="noise"]').classList.toggle("on", !!S.ui.showNoise);
  $('[data-tool="group"]').classList.toggle("on", !!S.ui.groupByType);
  $$("[data-listgroup]").forEach((b) => b.classList.toggle("on", b.dataset.listgroup === (S.ui.listGroup || "type")));
  glyphCache.clear();
  if (S.cy) { S.cy.style(buildStyle()); applyFilters(); }
  renderLegend();
  renderList();
}
async function saveUI(patch) {
  Object.assign(S.ui, patch);
  S.settings.ui = Object.assign({}, S.settings.ui || {}, patch);
  applyUI();
  try { await api("/api/settings", { body: { ui: patch } }); } catch (e) { toast("Could not save: " + e.message, "error"); }
}

// ------------------------------------------------------------------ graph
const glyphCache = new Map();
function glyphImg(t) {
  if (!t) return "none";
  const key = t + tc(t);
  if (!glyphCache.has(key)) {
    const g = glyph(t), fs = g.length > 2 ? 30 : g.length > 1 ? 36 : 46;
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><text x="50" y="53" font-family="JetBrains Mono,Consolas,monospace" font-weight="700" font-size="${fs}" fill="${tc(t)}" text-anchor="middle" dominant-baseline="middle">${esc(g)}</text></svg>`;
    glyphCache.set(key, "data:image/svg+xml;utf8," + encodeURIComponent(svg));
  }
  return glyphCache.get(key);
}
function buildStyle() {
  const sz = +S.ui.nodeSize || 34, fs = +S.ui.labelSize || 10, V = CFG.verdictColors, acc = S.ui.accent;
  return [
    { selector: "node", style: {
      width: sz, height: sz, "background-color": (n) => tc(n.data("type")), "background-opacity": 0.13,
      "background-image": (n) => glyphImg(n.data("type")), "background-fit": "none", "background-width": "78%", "background-height": "78%",
      "border-width": 1.5, "border-color": (n) => tc(n.data("type")), "border-opacity": 0.85,
      label: S.ui.showLabels ? "data(short)" : "", color: "#9a9aa3", "font-family": "JetBrains Mono, Consolas, monospace",
      "font-size": fs, "text-valign": "bottom", "text-margin-y": 5, "text-outline-color": "#050506", "text-outline-width": 2.5,
      "min-zoomed-font-size": 6, "overlay-opacity": 0,
    } },
    { selector: "node[?root]", style: { width: sz * 1.55, height: sz * 1.55, "border-width": 2.5, "font-size": fs + 2, color: "#f4f4f5", "font-weight": 700,
      "underlay-color": "#ffffff", "underlay-opacity": 0.07, "underlay-padding": 12, "underlay-shape": "ellipse" } },
    { selector: 'node[verdict="suspicious"]', style: { "border-color": V.suspicious, "border-width": 2.4, "border-opacity": 1,
      "underlay-color": V.suspicious, "underlay-opacity": 0.16, "underlay-padding": 6, "underlay-shape": "ellipse", color: "#fcd34d" } },
    { selector: 'node[verdict="malicious"]', style: { "border-color": V.malicious, "border-width": 2.8, "border-opacity": 1,
      "underlay-color": V.malicious, "underlay-opacity": 0.26, "underlay-padding": 8, "underlay-shape": "ellipse", color: "#fca5a5" } },
    { selector: "node[?noise]", style: { opacity: 0.4 } },
    { selector: "node.busy", style: { "border-style": "dashed", "underlay-color": acc, "underlay-opacity": 0.1, "underlay-padding": 7, "underlay-shape": "ellipse" } },
    { selector: "node.busy.pulse", style: { "underlay-opacity": 0.3 } },
    { selector: "node:selected", style: { "border-color": "#ffffff", "border-width": 3, "underlay-color": "#ffffff", "underlay-opacity": 0.2, "underlay-padding": 9, color: "#ffffff", "z-index": 20 } },
    { selector: "edge", style: {
      width: 1.1, "line-color": "#2c2c34", "curve-style": "bezier", "target-arrow-shape": "triangle", "target-arrow-color": "#2c2c34", "arrow-scale": 0.65,
      label: S.ui.showEdgeLabels ? "data(rel)" : "", "font-size": 8, "font-family": "JetBrains Mono, Consolas, monospace", color: "#5c5c66",
      "text-rotation": "autorotate", "text-background-color": "#050506", "text-background-opacity": 1, "text-background-padding": 1,
      "overlay-opacity": 0, "min-zoomed-font-size": 6,
    } },
    { selector: "edge[?mal]", style: { "line-color": hexA(V.malicious, 0.45), "target-arrow-color": hexA(V.malicious, 0.45) } },
    { selector: "node[?group]", style: {
      shape: "round-rectangle", "background-color": "data(color)", "background-opacity": 0.04, "background-image": "none",
      "border-width": 1, "border-style": "dashed", "border-color": "data(color)", "border-opacity": 0.45,
      label: "data(label)", "text-valign": "top", "text-halign": "center", "text-margin-y": -5, "font-size": fs + 1, "font-weight": 700,
      "text-outline-color": "#050506", "text-outline-width": 2.5,
      color: "data(color)", padding: 14, "underlay-opacity": 0, "corner-radius": 10,
    } },
    { selector: "node[?group].collapsed", style: { width: sz * 2.8, height: sz * 1.05, "background-opacity": 0.14,
      "border-style": "solid", "border-width": 1.5, "text-valign": "center", "text-margin-y": 0, padding: 0 } },
    { selector: "edge.proxy", style: { "line-style": "dashed", "line-dash-pattern": [4, 4], label: "" } },
    { selector: ".faded", style: { opacity: 0.08 } },
    { selector: "edge.hl", style: { "line-color": "#a1a1aa", "target-arrow-color": "#a1a1aa", width: 1.8, label: "data(rel)", color: "#b4b4bb", "z-index": 15 } },
    { selector: "node.match", style: { "underlay-color": acc, "underlay-opacity": 0.35, "underlay-padding": 9, "underlay-shape": "ellipse" } },
  ];
}
function initGraph() {
  try { if (window.cytoscapeFcose) { cytoscape.use(window.cytoscapeFcose); } } catch { /* already registered */ }
  try { S.hasFcose = !!cytoscape("layout", "fcose"); } catch { S.hasFcose = false; }
  S.cy = cytoscape({ container: $("#cy"), style: buildStyle(), wheelSensitivity: 0.3, minZoom: 0.04, maxZoom: 4, boxSelectionEnabled: true, selectionType: "single" });
  const cy = S.cy;
  cy.on("tap", "node", (e) => (e.target.data("group") ? toggleGroup(e.target.id()) : select(e.target.id())));
  cy.on("tap", (e) => { if (e.target === cy) select(null); });
  cy.on("dbltap", "node", (e) => { if (!e.target.data("group")) pivot(e.target.id()); });
  cy.on("cxttap", "node", (e) => {
    if (e.target.data("group")) return groupMenu(e.target.id(), e.originalEvent);
    select(e.target.id(), false); nodeMenu(e.target.id(), e.originalEvent);
  });
  cy.on("cxttap", (e) => { if (e.target === cy) bgMenu(e.originalEvent); });
  cy.on("mouseover", "node", (e) => {
    if (e.target.data("group")) return;
    let nb = e.target.closedNeighborhood();
    nb = nb.union(nb.nodes().parents());
    cy.batch(() => { cy.elements().not(nb).addClass("faded"); nb.edges().addClass("hl"); });
  });
  cy.on("mouseout", "node", () => cy.batch(() => { cy.elements().removeClass("faded hl"); applySearchHL(); }));
  setInterval(() => { const b = cy.nodes(".busy"); if (b.nonempty()) b.toggleClass("pulse"); }, 650);
}
function nodeData(n) {
  return { id: n.id, type: n.type, short: shortLabel(n), verdict: n.verdict || "", root: !!n.root, noise: !!n.noise, depth: n.depth };
}
function placeNear(n, edgesBatch) {
  const e = edgesBatch.find((x) => x.target === n.id) || [...S.edges.values()].find((x) => x.target === n.id);
  const p = e && S.cy.getElementById(e.source);
  const a = Math.random() * Math.PI * 2, r = 70 + Math.random() * 60;
  if (p && p.nonempty()) { const pp = p.position(); return { x: pp.x + Math.cos(a) * r, y: pp.y + Math.sin(a) * r }; }
  const ext = S.cy.extent();
  return { x: (ext.x1 + ext.x2) / 2 + Math.cos(a) * r * 1.5, y: (ext.y1 + ext.y2) / 2 + Math.sin(a) * r * 1.5 };
}
function scheduleFlush() { if (!S.flushT) S.flushT = setTimeout(flush, 180); }
function flush() {
  S.flushT = null;
  const nodes = S.pendingNodes.splice(0), edges = S.pendingEdges.splice(0);
  if (!nodes.length && !edges.length) return;
  const cy = S.cy; let added = 0;
  cy.batch(() => {
    for (const n of nodes) {
      if (!S.nodes.has(n.id) || cy.getElementById(n.id).nonempty()) continue;
      cy.add({ group: "nodes", data: nodeData(n), position: placeNear(n, edges) }); added++;
    }
    for (const e of edges) {
      if (!S.edges.has(e.id) || cy.getElementById(e.id).nonempty()) continue;
      if (cy.getElementById(e.source).empty() || cy.getElementById(e.target).empty()) continue;
      const t = S.nodes.get(e.target);
      cy.add({ group: "edges", data: { id: e.id, source: e.source, target: e.target, rel: e.rel, mal: t?.verdict === "malicious" } });
    }
  });
  $("#empty").hidden = S.nodes.size > 0;
  applyFilters();
  if (added && S.ui.autoLayout) relayoutSoon();
  renderListSoon(); renderCounts();
  if (S.view === "report") renderDetailsSoon();
}
function runLayout(opts = {}) {
  if (!S.cy || S.cy.nodes().empty()) return;
  // the graph container has no size while the report view is showing; lay out when it is opened
  if (S.view !== "graph" && !opts.offscreen) { S.needLayout = true; return; }
  if (S.layoutRun) { try { S.layoutRun.stop(); } catch { /* */ } }
  let name = S.ui.layout || "fcose";
  if (name === "fcose" && !S.hasFcose) name = "cose";
  const eles = S.cy.elements().filter((el) => el.style("display") !== "none");
  const big = eles.nodes().length > 350;
  const o = { name, animate: !!S.ui.animate && !big && !opts.offscreen, animationDuration: 450, fit: opts.fit ?? false, padding: 50 };
  if (name === "fcose") Object.assign(o, { quality: big ? "draft" : "default", randomize: !!opts.randomize, nodeRepulsion: 7000,
    idealEdgeLength: 85, edgeElasticity: 0.45, gravity: 0.3, gravityRange: 3.0, numIter: 2500, nodeSeparation: 70, packComponents: true });
  if (name === "cose") Object.assign(o, { randomize: !!opts.randomize, nodeRepulsion: () => 9000, idealEdgeLength: () => 80, numIter: 1200, componentSpacing: 80 });
  if (name === "concentric") Object.assign(o, { concentric: (n) => 100 - (n.data("depth") || 0) * 10 - (n.data("noise") ? 5 : 0), levelWidth: () => 5, minNodeSpacing: 22 });
  if (name === "breadthfirst") Object.assign(o, { roots: S.cy.nodes("[?root]"), directed: false, spacingFactor: 1.05 });
  if (name === "circle" || name === "grid") Object.assign(o, { avoidOverlap: true });
  S.layoutRun = eles.layout(o);
  S.layoutRun.run();
}
const relayoutSoon = debounce(() => {
  const fit = S.firstLayout || S.cy.nodes().length < 30;
  S.firstLayout = false;
  runLayout({ fit });
}, 650);

function isVisible(n) {
  if (S.hiddenNodes.has(n.id) || S.hiddenTypes.has(n.type)) return false;
  if (S.hiddenVerdicts.has(n.verdict || "unknown")) return false;
  if (n.noise && !S.ui.showNoise && !n.root) return false;
  return true;
}
/* Group leaf neighbours: indicators of one type whose only link is the same node are
   wrapped in a compound "group" node (e.g. "16 Domains" around an IP). Click to collapse. */
function regroup() {
  const cy = S.cy, want = new Map();
  if (S.ui.groupByType) {
    const min = Math.max(2, +S.ui.groupMin || 4);
    for (const n of S.nodes.values()) {
      if (n.root || !isVisible(n)) continue;
      const el = cy.getElementById(n.id); if (el.empty()) continue;
      const nb = el.neighborhood("node").filter((x) => !x.data("group") && S.nodes.has(x.id()) && isVisible(S.nodes.get(x.id())));
      if (nb.length !== 1) continue;
      const gid = `grp|${nb[0].id()}|${n.type}`;
      if (!want.has(gid)) want.set(gid, { owner: nb[0].id(), type: n.type, members: [] });
      want.get(gid).members.push(n.id);
    }
    for (const [gid, g] of want) if (g.members.length < min) want.delete(gid);
  }
  // collapsed groups keep no children (layouts can't handle hidden compound members);
  // their members are detached and hidden via S.memberOf instead
  const target = new Map();
  S.memberOf = new Map();
  for (const [gid, g] of want) for (const m of g.members) { S.memberOf.set(m, gid); if (!S.collapsedGroups.has(gid)) target.set(m, gid); }
  cy.batch(() => {
    cy.nodes().forEach((el) => {
      if (el.data("group")) return;
      const cur = el.data("parent") || null, dest = target.get(el.id()) || null;
      if (cur === dest) return;
      if (dest && cy.getElementById(dest).empty()) {
        const g = want.get(dest);
        cy.add({ group: "nodes", data: { id: dest, group: true, gtype: g.type, owner: g.owner, label: "" }, position: el.position() });
      }
      el.move({ parent: dest });
    });
    for (const [gid, g] of want) {
      if (cy.getElementById(gid).empty()) {
        const first = cy.getElementById(g.members[0]);
        cy.add({ group: "nodes", data: { id: gid, group: true, gtype: g.type, owner: g.owner, label: "" }, position: first.nonempty() ? { ...first.position() } : undefined });
      }
    }
    cy.nodes("[?group]").forEach((g) => {
      const info = want.get(g.id());
      if (!info) { cy.remove(cy.getElementById("proxy|" + g.id())); cy.remove(g); return; }
      const name = CFG.plural[info.type] || typeLabel(info.type);
      g.data("label", `${info.members.length} ${name}`);
      g.data("color", tc(info.type));
      const collapsed = S.collapsedGroups.has(g.id());
      g.toggleClass("collapsed", collapsed);
      const pid = "proxy|" + g.id(), proxy = cy.getElementById(pid);
      if (collapsed && proxy.empty()) cy.add({ group: "edges", data: { id: pid, source: info.owner, target: g.id(), rel: `${info.members.length} ${name.toLowerCase()}` }, classes: "proxy" });
      if (!collapsed && proxy.nonempty()) cy.remove(proxy);
    });
  });
}
function toggleGroup(gid, force) {
  const on = force ?? !S.collapsedGroups.has(gid);
  on ? S.collapsedGroups.add(gid) : S.collapsedGroups.delete(gid);
  applyFilters();
  if (S.ui.autoLayout) relayoutSoon();
}
function applyFilters() {
  if (!S.cy) return;
  regroup();
  S.cy.batch(() => S.cy.nodes().forEach((el) => {
    if (el.data("group")) return;
    const n = S.nodes.get(el.id());
    const gid = S.memberOf?.get(el.id());
    el.style("display", n && isVisible(n) && !(gid && S.collapsedGroups.has(gid)) ? "element" : "none");
  }));
  applySearchHL();
  $("#unhideBtn").hidden = S.hiddenNodes.size === 0;
  $("#hiddenCount").textContent = S.hiddenNodes.size || "";
}
function matchesSearch(n) {
  const q = S.search.toLowerCase();
  return !q || n.value.toLowerCase().includes(q) || (n.label || "").toLowerCase().includes(q) || n.tags.some((t) => t.toLowerCase().includes(q));
}
function applySearchHL() {
  const cy = S.cy; if (!cy) return;
  cy.batch(() => {
    cy.elements().removeClass("match faded");
    if (!S.search) return;
    cy.nodes().forEach((el) => { if (el.data("group")) return; const n = S.nodes.get(el.id()); if (n && matchesSearch(n)) el.addClass("match"); else el.addClass("faded"); });
    cy.edges().addClass("faded");
  });
}

// ------------------------------------------------------------------ event stream
function resetScan() {
  if (S.es) { S.es.close(); S.es = null; }
  Object.assign(S, { scanId: null, status: "idle", title: "", selected: null, evIdx: 0, logs: [], stats: {}, firstLayout: true });
  for (const k of ["nodes", "edges", "results", "busy"]) S[k].clear();
  S.hiddenNodes.clear(); S.collapsedGroups.clear(); S.pendingNodes = []; S.pendingEdges = [];
  S.cy.elements().remove();
  $("#logList").innerHTML = ""; $("#logCount").textContent = "0"; $("#logLast").textContent = "";
  $("#empty").hidden = false;
  setStatus("idle"); renderStats(); renderCounts(); renderList(); renderDetails();
}
function connect(id, from) {
  if (S.es) S.es.close();
  S.evIdx = from;
  const es = new EventSource(`/api/scan/${id}/events?from=${from}`);
  S.es = es;
  es.onmessage = (m) => { S.evIdx++; try { handle(JSON.parse(m.data)); } catch (err) { console.error(err, m.data); } };
  es.onerror = () => {
    es.close();
    if (S.es === es && S.scanId === id) setTimeout(() => { if (S.scanId === id && S.es === es) connect(id, S.evIdx); }, 2000);
  };
}
const renderListSoon = throttleRAF(() => renderList());
const renderDetailsSoon = throttleRAF(() => renderDetails());
function handle(ev) {
  switch (ev.t) {
    case "node": {
      const n = ev.node;
      if (!S.nodes.has(n.id)) { S.nodes.set(n.id, n); S.pendingNodes.push(n); scheduleFlush(); }
      break;
    }
    case "node_update": {
      const n = S.nodes.get(ev.id); if (!n) break;
      Object.assign(n, ev); delete n.t;
      const el = S.cy.getElementById(ev.id);
      if (el.nonempty()) {
        el.data(nodeData(n));
        if (n.verdict === "malicious") el.incomers("edge").data("mal", true);
      }
      renderListSoon(); renderCounts();
      if (S.selected === ev.id || !S.selected) renderDetailsSoon();
      break;
    }
    case "node_removed": {
      S.nodes.delete(ev.id); S.results.delete(ev.id); S.busy.delete(ev.id);
      for (const [k, e] of S.edges) if (e.source === ev.id || e.target === ev.id) S.edges.delete(k);
      S.cy.getElementById(ev.id).remove();
      if (S.selected === ev.id) select(null);
      renderListSoon(); renderCounts();
      break;
    }
    case "edge":
      if (!S.edges.has(ev.edge.id)) { S.edges.set(ev.edge.id, ev.edge); S.pendingEdges.push(ev.edge); scheduleFlush(); }
      break;
    case "task": {
      let m = S.busy.get(ev.id);
      if (ev.state === "end") { if (m) m.delete(ev.module); }
      else { if (!m) S.busy.set(ev.id, (m = new Map())); m.set(ev.module, ev.state); }
      const el = S.cy.getElementById(ev.id);
      if (el.nonempty()) el.toggleClass("busy", !!(m && m.size));
      if (S.selected === ev.id) renderDetailsSoon();
      break;
    }
    case "result": {
      if (!S.results.has(ev.id)) S.results.set(ev.id, {});
      S.results.get(ev.id)[ev.module] = ev.result;
      if (S.selected === ev.id || !S.selected) renderDetailsSoon();
      break;
    }
    case "log": addLog(ev); break;
    case "stats": S.stats = ev; renderStats(); break;
    case "status":
      setStatus(ev.status);
      if (ev.status === "done") { toast(`Scan complete — ${S.nodes.size} indicators`); renderDetailsSoon(); if (S.ui.autoLayout) relayoutSoon(); }
      break;
  }
}
function addLog(ev) {
  S.logs.push(ev);
  const line = h(`<div class="log-line ${ev.level}"><time>${hhmmss(ev.ts)}</time><span>${esc(ev.msg)}</span></div>`);
  const list = $("#logList");
  const atBottom = list.scrollTop + list.clientHeight >= list.scrollHeight - 20;
  list.appendChild(line);
  while (list.children.length > 600) list.firstChild.remove();
  if (atBottom) list.scrollTop = list.scrollHeight;
  $("#logCount").textContent = S.logs.length;
  $("#logLast").textContent = ev.msg;
}
function setStatus(st) {
  S.status = st;
  const pill = $("#stStatus");
  pill.className = "status-pill " + st; pill.textContent = st.toUpperCase();
  const running = st === "running" || st === "stopping";
  $("#stopBtn").hidden = !running;
  $("#progress").classList.toggle("running", running);
  $("#addBtn").disabled = !S.scanId;
  if (!running) { $("#progress div").style.width = S.scanId ? "100%" : "0"; setTimeout(() => { if (S.status !== "running") $("#progress div").style.width = "0"; }, 1200); }
}
function renderStats() {
  const s = S.stats, queued = Math.max(0, (s.pending || 0) - (s.running || 0));
  $("#stRun").textContent = s.pending ? `${s.running || 0} running · ${queued} queued · ${s.completed || 0} done` : `${s.completed || 0} lookups${s.errors ? ` · ${s.errors} errors` : ""}`;
  const total = (s.completed || 0) + (s.pending || 0);
  if (S.status === "running" && total) $("#progress div").style.width = Math.round(((s.completed || 0) / total) * 100) + "%";
}
function renderCounts() {
  let mal = 0, sus = 0;
  for (const n of S.nodes.values()) { if (n.verdict === "malicious") mal++; else if (n.verdict === "suspicious") sus++; }
  $("#stNodes").textContent = S.nodes.size; $("#stEdges").textContent = S.edges.size;
  $("#stMal").textContent = mal; $("#stSus").textContent = sus;
}

// ------------------------------------------------------------------ left list & filters
function renderLegend() {
  const present = new Set([...S.nodes.values()].map((n) => n.type));
  const types = Object.keys(CFG.glyph).filter((t) => !present.size || present.has(t));
  $("#legend").innerHTML = types.map((t) => `<span><i style="border-color:${tc(t)};background:${hexA(tc(t), 0.2)}"></i>${esc(typeLabel(t))}</span>`).join("") +
    `<span><i style="border-color:${CFG.verdictColors.malicious};background:${hexA(CFG.verdictColors.malicious, 0.4)}"></i>malicious</span>` +
    `<span><i style="border-color:${CFG.verdictColors.suspicious};background:${hexA(CFG.verdictColors.suspicious, 0.4)}"></i>suspicious</span>`;
}
function renderList() {
  if (!S.meta) return;
  const counts = {}, vcounts = { malicious: 0, suspicious: 0, clean: 0, unknown: 0 };
  for (const n of S.nodes.values()) { counts[n.type] = (counts[n.type] || 0) + 1; vcounts[n.verdict || "unknown"]++; }
  $("#typeFilters").innerHTML = Object.keys(counts).sort((a, b) => counts[b] - counts[a]).map((t) =>
    `<span class="chip ${S.hiddenTypes.has(t) ? "off" : ""}" data-type="${t}" title="Click to toggle · Shift+click to solo"><i class="dot" style="background:${tc(t)}"></i>${esc(typeLabel(t))}<em>${counts[t]}</em></span>`).join("") || '<span class="msg">—</span>';
  const vc = { malicious: CFG.verdictColors.malicious, suspicious: CFG.verdictColors.suspicious, clean: CFG.verdictColors.clean, unknown: "#55555e" };
  $("#verdictFilters").innerHTML = Object.keys(vcounts).map((v) =>
    `<span class="chip ${S.hiddenVerdicts.has(v) ? "off" : ""}" data-verdict="${v}"><i class="dot" style="background:${vc[v]}"></i>${v}<em>${vcounts[v]}</em></span>`).join("");
  const items = [...S.nodes.values()].filter((n) => isVisible(n) && matchesSearch(n)).sort((a, b) =>
    (b.root - a.root) || ((VRANK[b.verdict] || 0) - (VRANK[a.verdict] || 0)) || (a.noise - b.noise) || (a.depth - b.depth) || a.type.localeCompare(b.type) || a.value.localeCompare(b.value));
  const row = (n) => {
    const busy = S.busy.get(n.id)?.size;
    const vcol = n.verdict ? CFG.verdictColors[n.verdict] : "";
    return `<div class="ent ${S.selected === n.id ? "sel" : ""} ${busy ? "busy" : ""} ${n.noise ? "noise" : ""} ${n.root ? "root" : ""}" data-id="${esc(n.id)}" title="${esc(n.value)}">
      <i class="vd" ${vcol ? `style="background:${vcol}"` : ""}></i><span class="ty" style="color:${tc(n.type)};background:${hexA(tc(n.type), 0.12)}">${esc(glyph(n.type))}</span>
      <span class="val">${esc(n.label && n.type === "account" ? n.label : n.value)}</span><span class="meta">${n.root ? "seed" : "d" + n.depth}</span></div>`;
  };
  const mode = S.ui.listGroup || "type";
  let html = "";
  if (mode === "none") html = items.slice(0, 800).map(row).join("");
  else {
    // bucket by type, or by the indicator each one was discovered from
    const parentOf = new Map();
    if (mode === "source") for (const e of S.edges.values()) if (!parentOf.has(e.target)) parentOf.set(e.target, e.source);
    const buckets = new Map();
    for (const n of items) {
      let key, label, color;
      if (mode === "type") { key = n.type; label = typeLabel(n.type); color = tc(n.type); }
      else if (n.root) { key = "_seeds"; label = "Seeds"; color = S.ui.accent; }
      else {
        const p = S.nodes.get(parentOf.get(n.id));
        key = p ? p.id : "_other"; label = p ? (p.label && p.type === "account" ? p.label : p.value) : "Other"; color = p ? tc(p.type) : "#55555e";
      }
      if (!buckets.has(key)) buckets.set(key, { label, color, list: [], bad: 0 });
      const b = buckets.get(key); b.list.push(n); if (VRANK[n.verdict] >= 2) b.bad++;
    }
    const order = Object.keys(CFG.glyph);
    const sorted = [...buckets.entries()].sort((a, b) => mode === "type" ? order.indexOf(a[0]) - order.indexOf(b[0])
      : (a[0] === "_seeds" ? -1 : b[0] === "_seeds" ? 1 : b[1].list.length - a[1].list.length));
    let budget = 800;
    for (const [key, b] of sorted) {
      const closed = S.listCollapsed.has(mode + key);
      html += `<div class="ent-h ${closed ? "closed" : ""}" data-lg="${esc(mode + key)}"><i style="background:${b.color}"></i><span>${esc(b.label)}</span>${b.bad ? `<b title="flagged">${b.bad}</b>` : ""}<em>${b.list.length}</em>${ICON.chev}</div>`;
      if (!closed) { html += `<div class="ent-g">${b.list.slice(0, budget).map(row).join("")}</div>`; budget = Math.max(0, budget - b.list.length); }
    }
  }
  $("#entityList").innerHTML = html || `<div class="msg" style="padding:10px 8px">${S.nodes.size ? "No indicators match the filters." : "No indicators yet."}</div>`;
  renderLegend();
}

// ------------------------------------------------------------------ selection & details
function select(id, center = true) {
  S.selected = id && S.nodes.has(id) ? id : null;
  S.cy.$(":selected").unselect();
  if (S.selected) {
    const el = S.cy.getElementById(S.selected);
    el.select();
    if (center && S.view === "graph" && el.visible()) S.cy.animate({ center: { eles: el }, duration: 300 });
  }
  $$(".ent.sel").forEach((e) => e.classList.remove("sel"));
  if (S.selected) $(`.ent[data-id="${CSS.escape(S.selected)}"]`)?.classList.add("sel");
  renderDetails();
}
function tchip(t) { return `<span class="tchip" style="color:${tc(t)};border-color:${hexA(tc(t), 0.45)};background:${hexA(tc(t), 0.1)}">${esc(typeLabel(t))}</span>`; }
function vbadge(v, score) { return v ? `<span class="vbadge ${v}">${v}${score && v !== "clean" ? " · " + score : ""}</span>` : `<span class="vbadge">no verdict</span>`; }
function fillTpl(url, v) { return url.replaceAll("{value}", v).replaceAll("{enc}", encodeURIComponent(v)).replaceAll("{b64}", encodeURIComponent(b64(v))); }

function renderDetails() {
  if (S.view === "report") renderReport(); else renderPanel();
}
function renderPanel() {
  const box = $("#details");
  const n = S.selected && S.nodes.get(S.selected);
  if (!n) { box.innerHTML = overviewHTML(); return; }
  const res = S.results.get(n.id) || {};
  const busy = S.busy.get(n.id) || new Map();
  const edges = [...S.edges.values()].filter((e) => e.source === n.id || e.target === n.id);
  const nOk = Object.values(res).filter((r) => r.status === "ok").length;
  const links = lookupLinks().filter((l) => l.types.includes(n.type));
  const hot = /malware|phish|c2|botnet|tor|scanner|breach|leak|exploit|ransom|malicious/i;
  const scrollTop = box.scrollTop;
  box.innerHTML = `
    <div class="d-head">
      <div class="d-top">${tchip(n.type)}${vbadge(n.verdict, n.score)}${n.root ? '<span class="vbadge">seed</span>' : ""}${n.noise ? '<span class="vbadge" title="Matches the noise filter - not auto-pivoted">noise</span>' : ""}${n.private ? '<span class="vbadge">private</span>' : ""}</div>
      <div class="d-val"><span>${esc(n.value)}</span><button class="icon-btn" data-act="copy" title="Copy">${ICON.copy}</button></div>
      ${n.label && n.label !== n.value ? `<div class="d-sub">${esc(n.label)}</div>` : ""}
      <div class="d-sub"><span>depth ${n.depth}</span><span>${edges.length} links</span><span>${nOk}/${Object.keys(res).length} sources hit</span>${n.source ? `<span>via ${esc(modLabel(n.source))}</span>` : ""}${busy.size ? `<span>${busy.size} running…</span>` : ""}</div>
      ${n.tags.length ? `<div class="tags">${[...n.tags].sort((a, b) => hot.test(b) - hot.test(a)).map((t, i) => `<span class="tag ${hot.test(t) ? "hot" : ""}" ${i >= 10 && !S.allTags ? "hidden" : ""}>${esc(t)}</span>`).join("")}${n.tags.length > 10 ? `<span class="tag more" data-act="tags">${S.allTags ? "show less" : `+${n.tags.length - 10} more`}</span>` : ""}</div>` : ""}
      <div class="d-actions">
        ${S.meta.types[n.type]?.pivotable ? `<button class="btn sm" data-act="pivot" title="Run all enabled modules (double-click node)">${ICON.pivot}Pivot</button>
        <button class="btn sm" data-act="deep" title="Pivot and keep auto-pivoting from here (resets depth to 0)">${ICON.deep}Deep pivot</button>
        <select class="btn sm" data-act="runmod" style="max-width:150px"><option value="">Run module…</option>${modulesFor(n.type).map((m) => `<option value="${m.name}">${esc(m.label)}</option>`).join("")}</select>` : ""}
        <button class="btn sm ghost" data-act="focus" title="Show only this node's neighbourhood">${ICON.focus}</button>
        <button class="btn sm ghost" data-act="addlinked" title="Add a linked indicator">${ICON.plus}</button>
        <button class="btn sm ghost" data-act="hide" title="Hide from graph">${ICON.hide}</button>
        <button class="btn sm ghost" data-act="remove" title="Remove from scan">${ICON.trash}</button>
      </div>
    </div>
    <div class="tabs" style="top:0">
      ${["intel", "relations", "lookup", "raw"].map((t) => `<button data-tab="${t}" class="${S.tab === t ? "on" : ""}">${{ intel: "Intel", relations: "Relations", lookup: "Lookup", raw: "Raw" }[t]}<em>${{ intel: Object.keys(res).length + busy.size, relations: edges.length, lookup: links.length, raw: "" }[t]}</em></button>`).join("")}
    </div>
    <div class="d-body">${S.tab === "intel" ? intelHTML(n, res, busy) : S.tab === "relations" ? relationsHTML(n, edges) : S.tab === "lookup" ? lookupHTML(n, links) : `<pre class="raw">${esc(JSON.stringify({ node: n, results: res }, null, 2))}</pre>`}</div>`;
  box.scrollTop = scrollTop;
}
function modulesFor(type) { return S.meta.modules.filter((m) => m.types.includes(type)).sort((a, b) => a.label.localeCompare(b.label)); }
function kvHTML(summary) {
  return `<dl class="kv">${summary.map(([k, v]) => `<dt>${esc(k)}</dt><dd class="${v === true ? "yes" : ""}">${esc(v === true ? "yes" : v === false ? "no" : v)}</dd>`).join("")}</dl>`;
}
function tablesHTML(tables) {
  return tables.map((t, i) => `<details class="tbl" ${i === 0 && t.rows.length <= 8 ? "open" : ""}><summary>${esc(t.title)} <em>${t.total}${t.total > t.rows.length ? ` (showing ${t.rows.length})` : ""}</em></summary>
    <div class="tbl-wrap"><table><thead><tr>${t.columns.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${t.rows.map((r) => `<tr>${r.map((c) => `<td title="${esc(c)}">${/^https?:\/\//.test(c) ? `<a href="${esc(c)}" target="_blank" rel="noopener noreferrer">${esc(c)}</a>` : esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div></details>`).join("");
}
const SRC_STATUS = {
  ok: { label: "With data", cls: "ok" },
  error: { label: "Failed", cls: "err" },
  ratelimited: { label: "Rate limited", cls: "warn" },
  notfound: { label: "No data", cls: "none" },
  skipped: { label: "Needs API key", cls: "key" },
};
function reasonText(r) {
  if (r.status === "skipped") return "API key not configured";
  let m = (r.message || (r.status === "notfound" ? "No data" : "")).replace(/^\w*Error:\s*/, "");
  m = m.replace(/^HTTP (\d{3}) from [^:]+:\s*/, "HTTP $1 · ");
  return m;
}
function srcRow(m, r) {
  const st = SRC_STATUS[r.status] || SRC_STATUS.error;
  const msg = reasonText(r);
  return `<div class="src-row ${st.cls}" title="${esc(r.message || "")}">
    <i class="src-dot"></i><span class="src-name">${esc(modLabel(m))}</span>
    <span class="src-msg">${esc(msg)}</span>
    <button class="icon-btn src-retry" data-rerun="${m}" title="Run again">${ICON.redo}</button></div>`;
}
function srcGroup(key, title, rows, open, extra = "") {
  if (!rows.length) return "";
  const isOpen = S.srcOpen?.[key] ?? open;
  return `<details class="src-group" data-group="${key}" ${isOpen ? "open" : ""}><summary><span>${title}</span><em>${rows.length}</em></summary>
    <div class="src-list">${rows.join("")}</div>${extra}</details>`;
}
// split one indicator's module results into display buckets
function sortResults(res) {
  const entries = Object.entries(res);
  const rank = (r) => (VRANK[r.verdict] || 0) * 10 + (r.entities?.length ? 1 : 0);
  return {
    entries,
    good: entries.filter(([, r]) => r.status === "ok").sort((a, b) => rank(b[1]) - rank(a[1])),
    failed: entries.filter(([, r]) => r.status === "error" || r.status === "ratelimited"),
    empty: entries.filter(([, r]) => r.status === "notfound"),
    nokey: entries.filter(([, r]) => r.status === "skipped"),
  };
}
function cardHTML(m, r) {
  const col = S.collapsed.has(m);
  const meta = [r.ts ? (r.cached ? "cache · " : "") + ago(r.ts) : "", r.elapsed != null && !r.cached ? `${r.elapsed}s` : ""].filter(Boolean).join(" · ");
  return `<div class="card ${r.verdict || ""} ${col ? "collapsed" : ""}" data-mod="${m}" id="card-${m}">
    <div class="card-h" data-toggle="${m}">${ICON.chev}<b title="${esc(modLabel(m))}">${esc(modLabel(m))}</b>${r.verdict ? vbadge(r.verdict, r.score) : ""}<small title="${r.ts ? `Looked up ${esc(fmtTime(r.ts))}` : ""}${r.cached ? " · served from cache — ↻ to refresh" : ""}">${meta}</small>
    <button class="icon-btn card-act" data-rerun="${m}" title="Run again (bypass cache)">${ICON.redo}</button></div>
    <div class="card-b">${r.summary.length ? kvHTML(r.summary) : ""}${r.message ? `<div class="msg">${esc(r.message)}</div>` : ""}
    ${r.tags?.length ? `<div class="tags">${r.tags.map((t) => `<span class="tag">${esc(t)}</span>`).join("")}</div>` : ""}
    ${tablesHTML(r.tables || [])}
    ${r.links?.length || r.entities?.length ? `<div class="card-foot">${(r.links || []).map((l) => `<a href="${esc(l.url)}" target="_blank" rel="noopener noreferrer">${esc(l.label)} ↗</a>`).join("")}${r.entities?.length ? `<span class="linked">${r.entities.length} linked indicator${r.entities.length > 1 ? "s" : ""}</span>` : ""}</div>` : ""}</div></div>`;
}
function otherSourcesHTML({ failed, empty, nokey }) {
  if (!failed.length && !empty.length && !nokey.length) return "";
  return `<div class="src-other">` +
    srcGroup("failed", "Failed", failed.map(([m, r]) => srcRow(m, r)), true) +
    srcGroup("empty", "No data", empty.map(([m, r]) => srcRow(m, r)), false) +
    srcGroup("nokey", "Needs API key", nokey.map(([m, r]) => srcRow(m, r)), false,
      `<div class="src-cta"><button class="btn xs" data-open-settings="keys">Add API keys</button><button class="btn xs ghost" data-open-settings="modules">Disable these modules</button></div>`) +
    `</div>`;
}
function runningHTML(busy) {
  return busy.size ? `<div class="src-running"><span class="spinner"></span>${[...busy.keys()].map((m) => `<span>${esc(modLabel(m))}</span>`).join("")}</div>` : "";
}
function intelHTML(n, res, busy) {
  const b = sortResults(res);
  const { entries, good, failed, empty, nokey } = b;
  let html = "";
  if (entries.length || busy.size) {
    const seg = (cls, n_, label) => n_ ? `<span class="sum-item ${cls}"><i></i><b>${n_}</b>${label}</span>` : "";
    html += `<div class="src-sum">
      <div class="sum-bar">${[["ok", good.length], ["err", failed.length], ["none", empty.length], ["key", nokey.length]].map(([c, v]) => v ? `<i class="${c}" style="flex:${v}"></i>` : "").join("")}</div>
      <div class="sum-items">${seg("ok", good.length, "with data")}${seg("err", failed.length, "failed")}${seg("none", empty.length, "no data")}${seg("key", nokey.length, "need key")}${busy.size ? `<span class="sum-item run"><i></i><b>${busy.size}</b>running</span>` : ""}</div></div>`;
  }
  html += runningHTML(busy);
  html += good.map(([m, r]) => cardHTML(m, r)).join("");
  if (!good.length && !busy.size) html += `<div class="empty-note">${entries.length ? "No source returned data for this indicator." : S.meta.types[n.type]?.pivotable ? (n.noise ? "Noise indicator — not auto-pivoted. Use <b>Pivot</b> to look it up anyway." : "Not scanned yet. Click <b>Pivot</b> or double-click the node to run all enabled modules.") : "Informational node — nothing to look up. See the Lookup tab for manual searches."}</div>`;
  return html + otherSourcesHTML(b);
}

// ------------------------------------------------------------------ scan report (main view)
const VLABEL = { malicious: "Malicious", suspicious: "Suspicious", clean: "Clean" };
// the indicator the report is about: the selected one, else the first scanned IOC
function subjectId() {
  if (S.selected && S.nodes.has(S.selected)) return S.selected;
  const seeds = [...S.nodes.values()].filter((n) => n.root);
  return seeds.length === 1 ? seeds[0].id : null;   // several IOCs: the combined summary
}
function tally(res) {
  const t = { malicious: 0, suspicious: 0, clean: 0, info: 0, nodata: 0, nokey: 0, failed: 0 };
  for (const r of Object.values(res)) {
    if (r.status === "ok") t[VLABEL[r.verdict] ? r.verdict : "info"]++;
    else if (r.status === "notfound") t.nodata++;
    else if (r.status === "skipped") t.nokey++;
    else t.failed++;
  }
  return t;
}
/* Overall risk: one 0-100 score per IOC from the per-source verdicts.
   Any malicious verdict sets a floor of 50 (suspicious: 25); the share of rated
   sources that flag the IOC (suspicious counts half) fills the rest. */
const GRADES = [[80, "critical", "Critical"], [60, "high", "High"], [35, "medium", "Medium"], [1, "low", "Low"], [0, "clean", "Clean"]];
function risk(res) {
  const t = tally(res || {}), rated = t.malicious + t.suspicious + t.clean;
  if (!rated) return { score: null, grade: "unknown", label: "Unrated", t, rated };
  const floor = t.malicious ? 50 : t.suspicious ? 25 : 0;
  const score = Math.round(floor + (100 - floor) * ((t.malicious + 0.5 * t.suspicious) / rated));
  const [, grade, label] = GRADES.find(([min]) => score >= min);
  return { score, grade, label, t, rated };
}
const riskOf = (id) => risk(S.results.get(id));
function riskBadge(rk, big = false) {
  return `<span class="risk g-${rk.grade} ${big ? "big" : ""}" title="${rk.rated ? `${rk.t.malicious} malicious · ${rk.t.suspicious} suspicious · ${rk.t.clean} clean of ${rk.rated} sources with a verdict` : "No source gave a verdict yet"}"><b>${rk.score ?? "–"}</b><span>${esc(rk.label)}</span></span>`;
}
// how old a lookup is; cached results keep the time they were first fetched
function ago(ts) {
  if (!ts) return "";
  const s = Math.max(0, Date.now() / 1000 - ts);
  return s < 60 ? "just now" : s < 3600 ? `${Math.round(s / 60)}m ago` : s < 86400 ? `${Math.round(s / 3600)}h ago` : `${Math.round(s / 86400)}d ago`;
}
function ageHTML(r) {
  if (!r?.ts) return "";
  return `<span class="age ${r.cached ? "cached" : ""}" title="Looked up ${esc(fmtTime(r.ts))}${r.cached ? " · served from cache (Re-scan skips the cache)" : ""}">${ago(r.ts)}${r.cached ? " · cache" : ""}</span>`;
}
function freshness(res) {
  const list = Object.values(res || {}).filter((r) => r.ts);
  if (!list.length) return null;
  return { oldest: Math.min(...list.map((r) => r.ts)), cached: list.filter((r) => r.cached).length, total: list.length };
}
function detailText(r) {
  if (r.status !== "ok") return reasonText(r);
  const kv = (r.summary || []).slice(0, 2).map(([k, v]) => `${k}: ${v === true ? "yes" : v === false ? "no" : v}`);
  return kv.join(" · ") || r.message || (r.tags || []).slice(0, 4).join(", ");
}
function scoreRing(t) {
  const rated = t.malicious + t.suspicious + t.clean, flagged = t.malicious + t.suspicious;
  const pct = (x) => (rated ? (x / rated) * 100 : 0);
  const a = pct(t.malicious), b = a + pct(t.suspicious), c = b + pct(t.clean);
  const bg = rated ? `conic-gradient(var(--mal) 0 ${a}%, var(--sus) ${a}% ${b}%, var(--ok) ${b}% ${c}%, var(--panel3) ${c}% 100%)` : "var(--panel3)";
  return `<div class="ring" style="background:${bg}"><div><b>${rated ? flagged : "–"}</b><small>${rated ? `/ ${rated}` : "no verdicts"}</small></div></div>`;
}
function reportEmptyHTML() {
  const keys = Object.keys(S.settings?.api_keys || {}).length;
  const enabled = S.meta ? S.meta.modules.filter((m) => (S.settings.modules?.[m.name]?.enabled ?? m.enabled)).length : 0;
  return `<div class="empty rep-empty">
    <svg viewBox="0 0 200 200" class="web-art"><g fill="none" stroke="currentColor">
      <circle cx="100" cy="100" r="18" stroke-width="1"/><circle cx="100" cy="100" r="42" stroke-width=".8" opacity=".7"/>
      <circle cx="100" cy="100" r="68" stroke-width=".6" opacity=".45"/><circle cx="100" cy="100" r="94" stroke-width=".5" opacity=".25"/>
      <path d="M100 4v192M4 100h192M32 32l136 136M168 32 32 168" stroke-width=".6" opacity=".45"/></g>
      <circle cx="100" cy="100" r="5" fill="currentColor"/></svg>
    <h1>Scan an IOC.</h1>
    <p>Paste an IP, domain, URL, file hash, email, username, ASN or CVE above. ARACHNE checks it against every enabled source and builds one report: a verdict from each service, the details behind it, and any related indicators you can pivot on.</p>
    <div class="examples">${CFG.examples.map(([k, v]) => `<button data-ex="${esc(v)}"><b>${k}</b>${esc(v)}</button>`).join("")}</div>
    <p class="hint">${enabled} of ${S.meta?.modules.length || 0} sources enabled · ${keys} of ${S.meta?.api_keys.length || 0} API keys configured · <a href="#" data-open-settings="keys">Add API keys</a></p>
  </div>`;
}
function renderReport() {
  const box = $("#report"), wrap = $("#reportWrap");
  const st = wrap.scrollTop;
  // keep typing in the triage filter while results stream in
  const f = document.activeElement?.dataset?.sumfilter !== undefined ? document.activeElement.selectionStart : null;
  box.innerHTML = reportHTML();
  wrap.scrollTop = st;
  if (f != null) { const i = $("[data-sumfilter]", box); if (i) { i.focus(); i.setSelectionRange(f, f); } }
}
function seedNodes() { return [...S.nodes.values()].filter((n) => n.root); }
function iocBarHTML(cur) {
  // IOCs in this scan: the submitted ones, then any related indicator that has been scanned since
  const scanned = [...S.nodes.values()].filter((x) => x.root || S.results.has(x.id) || S.busy.get(x.id)?.size);
  const multi = seedNodes().length > 1;
  if (scanned.length < 2) return "";
  scanned.sort((a, c) => (c.root - a.root) || ((riskOf(c.id).score ?? -1) - (riskOf(a.id).score ?? -1)));
  // a long bulk list lives in the summary table instead of chips
  const chips = scanned.length > 14 ? scanned.filter((x) => x.id === cur?.id) : scanned;
  return `<div class="rep-iocs"><span class="rep-lbl">IOCs in this scan</span>${multi ? `<button class="rep-ioc ${!cur ? "on" : ""}" data-summary title="Combined report for every submitted IOC">${ICON.select}All ${seedNodes().length} IOCs</button>` : ""}${chips.map((x) => {
    const rk = riskOf(x.id);
    return `<button class="rep-ioc ${x.id === cur?.id ? "on" : ""}" data-goto="${esc(x.id)}" title="${esc(x.value)} · ${esc(rk.label)}${rk.score != null ? " " + rk.score : ""}"><i class="g-${rk.grade}"></i><span class="ty" style="color:${tc(x.type)}">${esc(glyph(x.type))}</span>${esc(shortLabel(x))}</button>`;
  }).join("")}${chips.length < scanned.length ? `<span class="msg">+${scanned.length - chips.length} more in the table</span>` : ""}</div>`;
}
function reportHTML() {
  if (!S.scanId) return reportEmptyHTML();
  if (!S.selected && seedNodes().length > 1) return summaryHTML();
  const id = subjectId(), n = id && S.nodes.get(id);
  if (!n) return `<div class="rep"><div class="src-running"><span class="spinner"></span>Starting scan…</div></div>`;
  const res = S.results.get(n.id) || {}, busy = S.busy.get(n.id) || new Map();
  const t = tally(res), b = sortResults(res), rk = risk(res), fr = freshness(res);
  const piv = S.meta.types[n.type]?.pivotable;
  const done = Object.keys(res).length;

  const head = `<div class="rep-head g-${rk.grade}">
    <div class="rep-id">
      <div class="d-top">${tchip(n.type)}${n.root ? '<span class="vbadge">submitted</span>' : '<span class="vbadge">related</span>'}${n.noise ? '<span class="vbadge" title="Matches the noise filter">noise</span>' : ""}${n.private ? '<span class="vbadge">private</span>' : ""}</div>
      <div class="d-val rep-val"><span>${esc(n.value)}</span><button class="icon-btn" data-copy="${esc(n.value)}" title="Copy">${ICON.copy}</button></div>
      ${n.label && n.label !== n.value ? `<div class="d-sub">${esc(n.label)}</div>` : ""}
      <div class="rep-verdict">${riskBadge(rk, true)}<span class="rep-vscore">${rk.rated ? `overall risk from ${rk.rated} source verdict${rk.rated === 1 ? "" : "s"}` : done || busy.size ? "waiting for a source to give a verdict" : ""}</span></div>
      ${n.tags.length ? `<div class="tags">${n.tags.slice(0, 16).map((x) => `<span class="tag">${esc(x)}</span>`).join("")}${n.tags.length > 16 ? `<span class="tag">+${n.tags.length - 16}</span>` : ""}</div>` : ""}
      <div class="d-actions">
        ${piv ? `<button class="btn sm" data-rescan="${esc(n.id)}" title="Run every enabled source again, skipping the cache">${ICON.redo}Re-scan (skip cache)</button>
        <select class="btn sm" data-runmod="${esc(n.id)}" style="max-width:170px"><option value="">Run one source…</option>${modulesFor(n.type).map((m) => `<option value="${m.name}">${esc(m.label)}</option>`).join("")}</select>` : ""}
        <button class="btn sm ghost" data-view="graph" title="Open the pivot graph">${ICON.pivot}Graph</button>
      </div>
    </div>
    <div class="rep-score">${scoreRing(t)}<span>sources flag this IOC</span>
      <div class="rep-progress">${busy.size ? `<span class="spinner"></span>${done} of ${done + busy.size} sources answered` : `${done} source${done === 1 ? "" : "s"} queried`}</div>
      ${fr ? `<div class="rep-fresh ${fr.cached ? "cached" : ""}" title="Oldest result looked up ${esc(fmtTime(fr.oldest))}">Results from ${ago(fr.oldest)}${fr.cached ? ` · ${fr.cached} cached` : ""}</div>` : ""}</div>
  </div>`;

  const tile = (cls, v, label) => `<div class="rep-tile ${cls} ${v ? "" : "zero"}"><b>${v}</b><span>${label}</span></div>`;
  const tiles = `<div class="rep-tiles">${tile("mal", t.malicious, "Malicious")}${tile("sus", t.suspicious, "Suspicious")}${tile("ok", t.clean, "Clean")}${tile("", t.info, "Info only")}${tile("", t.nodata, "No data")}${tile("", t.nokey, "Needs key")}${tile("err", t.failed, "Failed")}</div>`;

  // one row per source, worst verdict first
  const order = (r) => r.status === "ok" ? 10 + (VRANK[r.verdict] || 0) : r.status === "notfound" ? 3 : r.status === "skipped" ? 1 : 2;
  const rows = Object.entries(res).sort((a, c) => order(c[1]) - order(a[1]) || modLabel(a[0]).localeCompare(modLabel(c[0])));
  const stCls = { ok: "ok", notfound: "none", skipped: "key", error: "err", ratelimited: "warn" };
  const table = `<div class="rep-sec"><h3>Source verdicts <em>${rows.length + busy.size}</em></h3>
    <div class="tbl-wrap rep-tbl"><table><thead><tr><th>Source</th><th>Result</th><th>Score</th><th>Detail</th><th>Age</th><th></th></tr></thead><tbody>
    ${[...busy.keys()].map((m) => `<tr class="running"><td>${esc(modLabel(m))}</td><td><span class="spinner"></span></td><td></td><td class="dim">running…</td><td></td><td></td></tr>`).join("")}
    ${rows.map(([m, r]) => {
      const lab = r.status === "ok" ? (r.verdict && r.verdict !== "info" ? vbadge(r.verdict) : '<span class="vbadge">info</span>') : `<span class="src-st ${stCls[r.status] || "err"}"><i class="src-dot"></i>${esc((SRC_STATUS[r.status] || SRC_STATUS.error).label)}</span>`;
      return `<tr ${r.status === "ok" ? `data-jump="${m}" class="jump"` : ""}><td>${esc(modLabel(m))}</td><td>${lab}</td><td>${r.score != null ? esc(r.score) : ""}</td><td class="dim" title="${esc(detailText(r))}">${esc(detailText(r))}</td>
        <td>${ageHTML(r)}</td><td><button class="icon-btn src-retry" data-rerun="${m}" title="Run again, skipping the cache">${ICON.redo}</button></td></tr>`;
    }).join("")}
    </tbody></table></div>${!rows.length && !busy.size ? `<div class="empty-note">${piv ? `Not scanned yet. <button class="btn xs" data-scan="${esc(n.id)}">Scan it</button>` : "Informational indicator — nothing to look up. Use the manual lookups instead."}</div>` : ""}</div>`;

  const findings = `<div class="rep-sec"><h3>Findings <em>${b.good.length}</em></h3>${runningHTML(busy)}
    ${b.good.map(([m, r]) => cardHTML(m, r)).join("") || (done && !busy.size ? '<div class="empty-note">No source returned data for this IOC.</div>' : "")}
    ${otherSourcesHTML(b)}</div>`;

  return `<div class="rep">${iocBarHTML(n)}${head}${tiles}${table}<div class="rep-cols"><div>${findings}</div><div>${relatedHTML(n)}${manualHTML(n)}</div></div></div>`;
}
// combined triage report for a bulk scan: every submitted IOC, riskiest first
function summaryRows() {
  const rows = seedNodes().map((n) => ({ n, rk: riskOf(n.id), busy: S.busy.get(n.id)?.size || 0, fr: freshness(S.results.get(n.id)) }));
  return rows.sort((a, b) => ((b.rk.score ?? -1) - (a.rk.score ?? -1)) || a.n.value.localeCompare(b.n.value));
}
function summaryHTML() {
  const seeds = summaryRows();
  const q = (S.sumFilter || "").toLowerCase(), flaggedOnly = !!S.sumFlagged;
  const shown = seeds.filter(({ n, rk }) => (!q || n.value.toLowerCase().includes(q) || n.tags.some((x) => x.toLowerCase().includes(q))) && (!flaggedOnly || (rk.score ?? 0) >= 35));
  const count = (g) => seeds.filter((s) => s.rk.grade === g).length;
  const running = seeds.reduce((a, s) => a + s.busy, 0);
  const tile = (g, label) => `<div class="rep-tile g-${g} ${count(g) ? "" : "zero"}"><b>${count(g)}</b><span>${label}</span></div>`;
  const types = {}; for (const { n } of seeds) types[n.type] = (types[n.type] || 0) + 1;
  return `<div class="rep">${iocBarHTML(null)}
    <div class="rep-head sum-head"><div class="rep-id">
      <div class="d-top"><span class="vbadge">bulk scan</span>${Object.entries(types).map(([k, v]) => `<span class="tchip" style="color:${tc(k)};border-color:${hexA(tc(k), 0.45)};background:${hexA(tc(k), 0.1)}">${v} ${esc(v === 1 ? typeLabel(k) : CFG.plural[k] || typeLabel(k))}</span>`).join("")}</div>
      <div class="d-val rep-val"><span>${seeds.length} IOCs</span></div>
      <div class="rep-vscore" style="margin-top:6px">${running ? `<span class="spinner"></span> ${running} lookups running · ` : ""}${count("critical") + count("high")} need attention (high or critical risk)</div>
      <div class="d-actions"><button class="btn sm" data-rescanall title="Run every enabled source again on all submitted IOCs, skipping the cache">${ICON.redo}Re-scan all (skip cache)</button>
        <button class="btn sm ghost" data-copyflagged title="Copy every IOC rated medium risk or higher">${ICON.copy}Copy flagged IOCs</button></div>
    </div></div>
    <div class="rep-tiles">${tile("critical", "Critical")}${tile("high", "High")}${tile("medium", "Medium")}${tile("low", "Low")}${tile("clean", "Clean")}${tile("unknown", "Unrated")}</div>
    <div class="rep-sec"><h3>Triage <em>${shown.length}${shown.length !== seeds.length ? ` of ${seeds.length}` : ""}</em>
      <span class="sum-tools"><input class="inp" data-sumfilter placeholder="Filter by value or tag…" value="${esc(S.sumFilter || "")}"><label class="switch"><input type="checkbox" data-sumflagged ${flaggedOnly ? "checked" : ""}><i></i><span>Medium risk and above</span></label></span></h3>
    <div class="tbl-wrap rep-tbl sum-tbl"><table><thead><tr><th>Risk</th><th>IOC</th><th>Type</th><th>Flagged by</th><th>Tags</th><th>Age</th></tr></thead><tbody>
    ${shown.map(({ n, rk, busy, fr }) => `<tr class="jump" data-goto="${esc(n.id)}"><td>${riskBadge(rk)}</td><td class="ioc">${esc(n.value)}</td><td><span style="color:${tc(n.type)}">${esc(typeLabel(n.type))}</span></td>
      <td>${busy ? `<span class="spinner"></span> ` : ""}${rk.rated ? `${rk.t.malicious + rk.t.suspicious} / ${rk.rated}` : busy ? "" : "–"}</td>
      <td class="dim" title="${esc(n.tags.join(", "))}">${esc(n.tags.slice(0, 6).join(", "))}</td><td>${fr ? `<span class="age ${fr.cached ? "cached" : ""}">${ago(fr.oldest)}${fr.cached ? " · cache" : ""}</span>` : ""}</td></tr>`).join("")}
    </tbody></table></div>${!shown.length ? '<div class="empty-note">No IOCs match the filter.</div>' : ""}</div></div>`;
}
// indicators the sources linked to this IOC - the way into pivoting
function relatedHTML(n) {
  const kids = new Map();
  for (const e of S.edges.values()) {
    const oid = e.source === n.id ? e.target : e.target === n.id ? e.source : null;
    const o = oid && S.nodes.get(oid);
    if (o && !kids.has(o.id)) kids.set(o.id, { o, rel: e.rel });
  }
  const list = [...kids.values()];
  const pivotable = (o) => S.meta.types[o.type]?.pivotable;
  const unscanned = list.filter(({ o }) => pivotable(o) && !S.results.has(o.id) && !S.busy.get(o.id)?.size);
  const groups = new Map();
  for (const k of list) { if (!groups.has(k.o.type)) groups.set(k.o.type, []); groups.get(k.o.type).push(k); }
  const typeOrder = Object.keys(CFG.glyph);
  const body = [...groups.entries()].sort((a, c) => typeOrder.indexOf(a[0]) - typeOrder.indexOf(c[0])).map(([type, items]) => {
    items.sort((a, c) => ((VRANK[c.o.verdict] || 0) - (VRANK[a.o.verdict] || 0)) || a.o.value.localeCompare(c.o.value));
    const shown = items.slice(0, 40);
    return `<div class="rel-group"><div class="rel-h"><i style="background:${tc(type)}"></i>${esc(CFG.plural[type] || typeLabel(type))}<em>${items.length}</em></div>` +
      shown.map(({ o, rel }) => {
        const busy = S.busy.get(o.id)?.size, scanned = S.results.has(o.id);
        const act = !pivotable(o) ? "" : busy ? '<span class="spinner"></span>' : scanned ? (o.verdict ? vbadge(o.verdict) : '<span class="rel-tag">scanned</span>')
          : `<button class="btn xs" data-scan="${esc(o.id)}" title="Look this indicator up with every enabled source">Scan</button>`;
        return `<div class="rel rep-rel" data-goto="${esc(o.id)}" title="${esc(rel.replace(/_/g, " "))}"><span class="dir" style="color:${o.verdict ? CFG.verdictColors[o.verdict] || "var(--dim)" : "var(--dim)"}">●</span>
          <span class="val" ${o.verdict ? `style="color:${CFG.verdictColors[o.verdict] || "inherit"}"` : ""}>${esc(o.label && o.type === "account" ? o.label : o.value)}</span>${act}</div>`;
      }).join("") + (items.length > shown.length ? `<div class="msg" style="padding:5px 12px">+${items.length - shown.length} more in the graph</div>` : "") + "</div>";
  }).join("");
  return `<div class="rep-sec"><h3>Related indicators <em>${list.length}</em></h3>
    ${list.length ? `<div class="rep-pivot">${unscanned.length ? `<button class="btn sm" data-scanall="${esc(n.id)}" title="Scan every related indicator listed here">${ICON.pivot}Pivot: scan all ${unscanned.length}</button>` : ""}<button class="btn sm ghost" data-view="graph">${ICON.select}View graph</button></div>${body}`
      : `<div class="msg">${Object.keys(S.results.get(n.id) || {}).length ? "No related indicators were found." : "Related indicators appear here as sources respond."}</div>`}</div>`;
}
function manualHTML(n) {
  const links = lookupLinks().filter((l) => l.types.includes(n.type));
  if (!links.length) return "";
  return `<div class="rep-sec"><h3>Manual lookups <em>${links.length}</em></h3><div class="lookup-grid">${links.map((l) => `<a href="${esc(fillTpl(l.url, n.value))}" target="_blank" rel="noopener noreferrer">${esc(l.name)}${ICON.link}</a>`).join("")}</div></div>`;
}
function setView(v) {
  if (v !== "graph") v = "report";
  S.view = v;
  $("#main").className = "view-" + v;
  $$("#viewSeg [data-view]").forEach((b) => b.classList.toggle("on", b.dataset.view === v));
  closeMenus();
  if (v === "graph" && S.cy) {
    S.cy.resize();
    applyFilters();
    if (S.needLayout) { S.needLayout = false; runLayout({ fit: true, randomize: S.firstLayout }); S.firstLayout = false; }
    else if (S.cy.nodes().nonempty()) S.cy.fit(S.cy.elements(":visible"), 50);
  }
  renderDetails();
}
// lay the graph out without showing it (exports from the report view)
function ensureLaidOut() {
  if (!S.needLayout || !S.cy) return;
  S.needLayout = false; S.firstLayout = false;
  runLayout({ offscreen: true, randomize: true });
}
function relationsHTML(n, edges) {
  if (!edges.length) return '<div class="msg">No links.</div>';
  const groups = new Map();
  for (const e of edges) {
    const out = e.source === n.id, o = S.nodes.get(out ? e.target : e.source);
    if (!o) continue;
    if (!groups.has(o.type)) groups.set(o.type, []);
    groups.get(o.type).push({ out, o, rel: e.rel, mods: e.modules });
  }
  const order = Object.keys(CFG.glyph);
  return [...groups.entries()].sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0])).map(([type, list]) => {
    list.sort((a, b) => ((VRANK[b.o.verdict] || 0) - (VRANK[a.o.verdict] || 0)) || a.rel.localeCompare(b.rel));
    return `<div class="rel-group"><div class="rel-h"><i style="background:${tc(type)}"></i>${esc(typeLabel(type))}<em>${list.length}</em></div>` + list.map(({ out, o, rel, mods }) =>
      `<div class="rel" data-goto="${esc(o.id)}" title="${esc(mods.map(modLabel).join(", "))}"><span class="dir">${out ? "→" : "←"}</span>
        <span class="val" ${o.verdict ? `style="color:${CFG.verdictColors[o.verdict]}"` : ""}>${esc(o.label && o.type === "account" ? o.label : o.value)}</span><span class="rel-tag">${esc(rel.replace(/_/g, " "))}</span></div>`).join("") + "</div>";
  }).join("");
}
function lookupHTML(n, links) {
  if (!links.length) return '<div class="msg">No lookup links for this type. Add some in Settings › Lookup links.</div>';
  return `<div class="lookup-grid">${links.map((l) => `<a href="${esc(fillTpl(l.url, n.value))}" target="_blank" rel="noopener noreferrer">${esc(l.name)}${ICON.link}</a>`).join("")}</div>
    <p class="msg" style="margin-top:12px">Manual pivots open in your browser. Edit this list in Settings › Lookup links.</p>`;
}
function overviewHTML() {
  if (!S.scanId) {
    const keys = Object.keys(S.settings?.api_keys || {}).length;
    const enabled = S.meta ? S.meta.modules.filter((m) => (S.settings.modules?.[m.name]?.enabled ?? m.enabled)).length : 0;
    return `<div class="d-body overview"><h3>Ready</h3>
      <dl class="kv"><dt>Modules enabled</dt><dd>${enabled} / ${S.meta?.modules.length || 0}</dd><dt>API keys configured</dt><dd>${keys} / ${S.meta?.api_keys.length || 0}</dd>
      <dt>Pivoting</dt><dd>${$("#autoPivot").checked ? `on · depth ${$("#depthSel").value}` : "off"}</dd><dt>Node limit</dt><dd>${S.settings?.pivot?.max_nodes}</dd></dl>
      <p class="msg" style="margin-top:14px">Many sources work without keys (DNS, RDAP, crt.sh, Shodan InternetDB, OTX, ip-api, SANS ISC, Mnemonic PDNS, Gravatar, GitHub, username enumeration…). Add keys for VirusTotal, AbuseIPDB, abuse.ch and others to unlock threat-intel verdicts.</p>
      <p style="margin-top:12px"><button class="btn sm" data-open-settings="keys">Configure API keys</button> <button class="btn sm ghost" data-open-settings="modules">Modules</button></p>
      <h3>Tips</h3><div class="msg" style="line-height:1.8">• Double-click a node to pivot on it<br>• Right-click for module menu, lookups &amp; hiding<br>• Paste several indicators separated by commas or new lines<br>• <b>/</b> focus search · <b>F</b> fit · <b>L</b> layout · <b>P</b> pivot selected · <b>Del</b> hide selected · <b>Esc</b> deselect</div></div>`;
  }
  const nodes = [...S.nodes.values()];
  const flagged = nodes.filter((n) => VRANK[n.verdict] >= 2).sort((a, b) => (VRANK[b.verdict] - VRANK[a.verdict]) || ((b.score || 0) - (a.score || 0)));
  const seeds = nodes.filter((n) => n.root);
  const st = { ok: 0, notfound: 0, skipped: 0, error: 0, ratelimited: 0 };
  const skippedMods = new Set();
  for (const r of S.results.values()) for (const [m, x] of Object.entries(r)) { st[x.status] = (st[x.status] || 0) + 1; if (x.status === "skipped") skippedMods.add(m); }
  const tagc = {}; for (const n of nodes) for (const t of n.tags) tagc[t] = (tagc[t] || 0) + 1;
  const total = nodes.length || 1, mal = nodes.filter((n) => n.verdict === "malicious").length, sus = nodes.filter((n) => n.verdict === "suspicious").length, cl = nodes.filter((n) => n.verdict === "clean").length;
  const row = (n) => `<div class="rel" data-goto="${esc(n.id)}"><span class="dir" style="color:${n.verdict ? CFG.verdictColors[n.verdict] : "var(--dim)"}">●</span><span class="ty tchip" style="font-size:8.5px;padding:1px 3px;text-align:center;color:${tc(n.type)};border-color:${hexA(tc(n.type), 0.4)}">${esc(glyph(n.type))}</span><span class="val">${esc(n.value)}</span></div>`;
  return `<div class="d-body overview">
    <h3>Scan</h3><dl class="kv"><dt>Seeds</dt><dd>${seeds.length}</dd><dt>Status</dt><dd>${esc(S.status)}</dd><dt>Started</dt><dd>${esc(fmtTime(S.created))}</dd><dt>Lookups</dt><dd>${st.ok} hit · ${st.notfound} empty · ${st.skipped} skipped · ${st.error + st.ratelimited} errors</dd></dl>
    <div class="bar"><i style="width:${(mal / total) * 100}%;background:var(--mal)"></i><i style="width:${(sus / total) * 100}%;background:var(--sus)"></i><i style="width:${(cl / total) * 100}%;background:var(--ok)"></i></div>
    <div class="msg">${mal} malicious · ${sus} suspicious · ${cl} clean · ${total - mal - sus - cl} unrated</div>
    <h3>Seeds</h3>${seeds.map(row).join("")}
    <h3>Flagged indicators (${flagged.length})</h3>${flagged.slice(0, 25).map(row).join("") || '<div class="msg">Nothing flagged yet.</div>'}
    ${Object.keys(tagc).length ? `<h3>Tags</h3><div class="tags">${Object.entries(tagc).sort((a, b) => b[1] - a[1]).slice(0, 40).map(([t, c]) => `<span class="tag" data-search="${esc(t)}" style="cursor:pointer">${esc(t)} <span style="color:var(--dim)">${c}</span></span>`).join("")}</div>` : ""}
    ${skippedMods.size ? `<h3>Missing API keys</h3><div class="msg">${[...skippedMods].map(modLabel).map(esc).join(", ")}</div><p><button class="btn sm" data-open-settings="keys" style="margin-top:8px">Add keys</button></p>` : ""}
  </div>`;
}

// ------------------------------------------------------------------ actions
async function pivot(id, opts = {}) {
  if (!S.scanId) return;
  const n = S.nodes.get(id); if (!n) return;
  if (!S.meta.types[n.type]?.pivotable) return toast(`${typeLabel(n.type)} nodes are informational`, "warn");
  try {
    const r = await api(`/api/scan/${S.scanId}/expand`, { body: { node_id: id, ...opts } });
    toast(r.scheduled ? `${r.scheduled} lookup${r.scheduled > 1 ? "s" : ""} scheduled for ${n.value}` : "Already looked up — use ↻ on a source, or Run module, to refresh", r.scheduled ? "info" : "warn");
  } catch (e) { toast(e.message, "error"); }
}
async function scanMany(ids) {
  if (!S.scanId || !ids.length) return;
  let n = 0;
  for (const id of ids) {
    try { n += (await api(`/api/scan/${S.scanId}/expand`, { body: { node_id: id } })).scheduled || 0; } catch (e) { toast(e.message, "error"); return; }
  }
  toast(`${n} lookup${n === 1 ? "" : "s"} scheduled across ${ids.length} indicator${ids.length === 1 ? "" : "s"}`);
}
// run every enabled source again, skipping the cache
async function rescan(ids) {
  if (!S.scanId || !ids.length) return;
  let n = 0;
  for (const id of ids) {
    try { n += (await api(`/api/scan/${S.scanId}/expand`, { body: { node_id: id, force: true } })).scheduled || 0; } catch (e) { toast(e.message, "error"); return; }
  }
  toast(`Re-scanning without cache: ${n} lookup${n === 1 ? "" : "s"}${ids.length > 1 ? ` across ${ids.length} IOCs` : ""}`);
}
async function removeNodes(ids) {
  try { await api(`/api/scan/${S.scanId}/remove`, { body: { node_ids: ids } }); } catch (e) { toast(e.message, "error"); }
}
function hideNode(id) { S.hiddenNodes.add(id); if (S.selected === id) select(null); applyFilters(); renderList(); }
function focusNode(id) {
  const el = S.cy.getElementById(id); if (el.empty()) return;
  const nb = el.closedNeighborhood();
  S.cy.animate({ fit: { eles: nb, padding: 80 }, duration: 400 });
}
async function addIndicator(parent) {
  const pn = parent && S.nodes.get(parent);
  const v = await promptDialog({ title: pn ? "Add linked indicator" : "Add indicator", label: pn ? `Will be linked to ${pn.value}` : "Added to the current graph as a new seed", placeholder: "IP, domain, email, username…" });
  if (!v) return;
  try {
    const r = await api(`/api/scan/${S.scanId}/add`, { body: { value: v, parent: parent || null } });
    if (r.invalid?.length) toast("Not recognised: " + r.invalid.join(", "), "warn");
  } catch (e) { toast(e.message, "error"); }
}
function promptDialog({ title, label, placeholder, value = "" }) {
  return new Promise((resolve) => {
    $("#promptTitle").textContent = title;
    $("#promptBody").innerHTML = `<form class="prompt-f"><div class="msg">${esc(label || "")}</div><input class="inp" style="background:var(--bg2);border:1px solid var(--line2);border-radius:7px;padding:9px 11px;font:13px var(--mono)" placeholder="${esc(placeholder || "")}" value="${esc(value)}"><div class="row" style="justify-content:flex-end"><button type="button" class="btn ghost" data-cancel>Cancel</button><button class="btn primary">OK</button></div></form>`;
    const m = $("#promptModal"), f = $("form", m), inp = $("input", f);
    const done = (v) => { m.classList.remove("open"); resolve(v); };
    f.onsubmit = (e) => { e.preventDefault(); done(inp.value.trim()); };
    $("[data-cancel]", f).onclick = () => done(null);
    m.onclose = () => resolve(null);
    m.classList.add("open"); setTimeout(() => inp.focus(), 30);
  });
}

// ------------------------------------------------------------------ context menus
function menu(items, ev, title) {
  const box = $("#ctxMenu");
  const build = (list) => list.map((it, i) => it === "sep" ? "<hr>" : it.sub ? `<div class="sub"><button>${it.icon || ""}${esc(it.label)}</button><div class="ctx">${build(it.sub)}</div></div>`
    : `<button data-i="${registry.push(it.action) - 1}">${it.icon || ""}${esc(it.label)}</button>`).join("");
  const registry = [];
  box.innerHTML = (title ? `<div class="ctx-h">${esc(title)}</div>` : "") + build(items);
  box.classList.add("open");
  const x = Math.min(ev.clientX, innerWidth - box.offsetWidth - 230), y = Math.min(ev.clientY, innerHeight - box.offsetHeight - 10);
  box.style.left = Math.max(4, x) + "px"; box.style.top = Math.max(4, y) + "px";
  box.onclick = (e) => { const b = e.target.closest("[data-i]"); if (!b) return; closeMenus(); registry[+b.dataset.i](); };
}
function closeMenus() { $("#ctxMenu").classList.remove("open"); $("#exportMenu").classList.remove("open"); }
function nodeMenu(id, ev) {
  const n = S.nodes.get(id); if (!n) return;
  const piv = S.meta.types[n.type]?.pivotable;
  const links = lookupLinks().filter((l) => l.types.includes(n.type));
  const items = [];
  if (piv) {
    items.push({ label: "Pivot (all enabled modules)", icon: ICON.pivot, action: () => pivot(id) });
    items.push({ label: "Deep pivot (auto-pivot onward)", icon: ICON.deep, action: () => pivot(id, { deep: true }) });
    items.push({ label: "Run module", icon: ICON.run, sub: modulesFor(n.type).map((m) => ({ label: m.label, action: () => pivot(id, { modules: [m.name], force: true }) })) });
    items.push({ label: "Re-run all (bypass cache)", icon: ICON.redo, action: () => pivot(id, { force: true }) });
    items.push("sep");
  }
  items.push({ label: "Copy value", icon: ICON.copy, action: () => copy(n.value) });
  if (links.length) items.push({ label: "Open in…", icon: ICON.link, sub: links.map((l) => ({ label: l.name, action: () => window.open(fillTpl(l.url, n.value), "_blank", "noopener") })) });
  items.push({ label: "Focus neighbourhood", icon: ICON.focus, action: () => focusNode(id) });
  items.push({ label: "Show only this type", icon: ICON.select, action: () => { S.search = ""; S.hiddenTypes = new Set(Object.keys(CFG.glyph).filter((t) => t !== n.type)); applyFilters(); renderList(); } });
  items.push({ label: "Add linked indicator…", icon: ICON.plus, action: () => addIndicator(id) });
  items.push("sep");
  items.push({ label: "Hide", icon: ICON.hide, action: () => hideNode(id) });
  items.push({ label: "Remove from scan", icon: ICON.trash, action: () => removeNodes([id]) });
  menu(items, ev, n.value);
}
function groupMenu(gid, ev) {
  const g = S.cy.getElementById(gid);
  const ids = g.children().map((c) => c.id());
  const collapsed = S.collapsedGroups.has(gid);
  menu([
    { label: collapsed ? "Expand group" : "Collapse group", icon: ICON.focus, action: () => toggleGroup(gid) },
    { label: `Pivot all ${ids.length}`, icon: ICON.pivot, action: () => ids.forEach((id) => pivot(id)) },
    { label: "Copy values", icon: ICON.copy, action: () => copy(ids.map((id) => S.nodes.get(id)?.value).filter(Boolean).join("\n")) },
    "sep",
    { label: `Hide all ${ids.length}`, icon: ICON.hide, action: () => { ids.forEach((id) => S.hiddenNodes.add(id)); applyFilters(); renderList(); } },
    { label: "Remove from scan", icon: ICON.trash, action: () => removeNodes(ids) },
  ], ev, g.data("label"));
}
async function clearAll() {
  if (!S.nodes.size && !S.scanId) return toast("The web is already empty");
  const running = S.status === "running";
  if (!(await confirmDialog({ title: "Clear the web?", ok: "Clear all",
    body: "Removes every node from the graph so you can start fresh." + (running ? " The running scan will be stopped." : "") + " The scan stays available in History." }))) return;
  if (S.scanId && running) { try { await api(`/api/scan/${S.scanId}/stop`, { body: {} }); } catch { /* ignore */ } }
  resetScan();
  history.replaceState(null, "", location.pathname);
  $("#seedInput").value = ""; updateDetect(); $("#seedInput").focus();
  toast("Web cleared");
}
function confirmDialog({ title, body, ok = "OK" }) {
  return new Promise((resolve) => {
    $("#promptTitle").textContent = title;
    $("#promptBody").innerHTML = `<div class="prompt-f"><p class="confirm-body">${esc(body)}</p>
      <div class="row" style="justify-content:flex-end"><button class="btn ghost" data-no>Cancel</button><button class="btn danger" data-yes>${esc(ok)}</button></div></div>`;
    const m = $("#promptModal");
    const done = (v) => { m.classList.remove("open"); m.onclose = null; resolve(v); };
    $("[data-yes]", m).onclick = () => done(true);
    $("[data-no]", m).onclick = () => done(false);
    m.onclose = () => resolve(false);
    m.classList.add("open"); setTimeout(() => $("[data-yes]", m).focus(), 30);
  });
}
function bgMenu(ev) {
  const items = [
    { label: "Fit to screen", icon: ICON.focus, action: () => S.cy.fit(undefined, 50) },
    { label: "Re-run layout", icon: ICON.redo, action: () => runLayout({ fit: true, randomize: true }) },
  ];
  if (S.scanId) items.push({ label: "Add indicator…", icon: ICON.plus, action: () => addIndicator(null) });
  if (S.hiddenNodes.size) items.push({ label: `Show ${S.hiddenNodes.size} hidden`, icon: ICON.select, action: () => { S.hiddenNodes.clear(); applyFilters(); renderList(); } });
  items.push({ label: S.ui.groupByType ? "Ungroup neighbours" : "Group neighbours by type", icon: ICON.select, action: () => saveUI({ groupByType: !S.ui.groupByType }) });
  items.push({ label: "Clear all…", icon: ICON.trash, action: clearAll });
  items.push({ label: "Reset filters", icon: ICON.select, action: () => { S.hiddenTypes.clear(); S.hiddenVerdicts.clear(); S.search = ""; $("#listSearch").value = ""; applyFilters(); renderList(); } });
  menu(items, ev);
}

// ------------------------------------------------------------------ scans
// ------------------------------------------------------------------ bulk scan
const BULK_MAX = 500;
function bulkTokens(text) {
  return [...new Set(String(text || "").split(/[\s,;|"'<>]+/).map((s) => s.trim()).filter(Boolean))];
}
const bulkPreview = debounce(async () => {
  const toks = bulkTokens($("#bulkText").value), go = $("#bulkGo");
  S.bulkSeeds = [];
  if (!toks.length) { $("#bulkInfo").textContent = ""; $("#bulkPreview").innerHTML = ""; go.disabled = true; go.textContent = "Scan"; return; }
  let r;
  try { r = await api("/api/detect", { body: { value: toks.slice(0, 5000).join("\n") } }); } catch (e) { $("#bulkInfo").textContent = e.message; return; }
  const seen = new Set(), skipUser = $("#bulkSkipUser").checked;
  let users = 0;
  const seeds = r.seeds.filter(([t, v]) => {
    if (seen.has(t + "|" + v)) return false;
    seen.add(t + "|" + v);
    if (skipUser && t === "username") { users++; return false; }
    return true;
  });
  S.bulkSeeds = seeds.slice(0, BULK_MAX);
  const counts = {}; for (const [t] of S.bulkSeeds) counts[t] = (counts[t] || 0) + 1;
  $("#bulkPreview").innerHTML = Object.entries(counts).map(([t, c]) => `<span class="chip"><i class="dot" style="background:${tc(t)}"></i>${esc(CFG.plural[t] || typeLabel(t))}<em>${c}</em></span>`).join("");
  $("#bulkInfo").textContent = [`${seeds.length} IOC${seeds.length === 1 ? "" : "s"} recognised`, r.invalid.length ? `${r.invalid.length} ignored` : "",
    users ? `${users} username${users === 1 ? "" : "s"} skipped` : "", seeds.length > BULK_MAX ? `only the first ${BULK_MAX} will be scanned` : ""].filter(Boolean).join(" · ");
  go.disabled = !S.bulkSeeds.length;
  go.textContent = S.bulkSeeds.length ? `Scan ${S.bulkSeeds.length} IOC${S.bulkSeeds.length === 1 ? "" : "s"}` : "Scan";
}, 250);
function openBulk() {
  $("#bulkModal").classList.add("open");
  bulkPreview();
  setTimeout(() => $("#bulkText").focus(), 30);
}
function loadBulkFile(file) {
  if (!file) return;
  if (file.size > 5e6) return toast("That file is over 5 MB", "warn");
  file.text().then((txt) => { const ta = $("#bulkText"); ta.value = (ta.value.trim() ? ta.value.trim() + "\n" : "") + txt; bulkPreview(); });
}
async function runBulk() {
  if (!S.bulkSeeds?.length) return;
  $("#bulkModal").classList.remove("open");
  await startScan(false, S.bulkSeeds.map(([, v]) => v).join("\n"));
}

async function startScan(add = false, bulkValue = null) {
  const value = bulkValue ?? $("#seedInput").value.trim();
  if (!value) { $("#seedInput").focus(); return; }
  const type = bulkValue ? "auto" : $("#typeSel").value;
  if (add && S.scanId) {
    try {
      const r = await api(`/api/scan/${S.scanId}/add`, { body: { value, type } });
      if (r.invalid?.length) toast("Not recognised: " + r.invalid.join(", "), "warn");
      $("#seedInput").value = ""; updateDetect();
    } catch (e) { toast(e.message, "error"); }
    return;
  }
  try {
    const r = await api("/api/scan", { body: { value, type, overrides: { depth: +$("#depthSel").value, auto: $("#autoPivot").checked } } });
    resetScan();
    S.scanId = r.id; S.created = Date.now() / 1000; S.title = r.seeds.length > 1 ? `Bulk scan (${r.seeds.length} IOCs)` : value;
    history.replaceState(null, "", "#scan=" + r.id);
    if (r.invalid?.length) toast("Ignored (not recognised): " + r.invalid.join(", "), "warn");
    setStatus("running");
    connect(r.id, 0);
    renderDetails();
  } catch (e) { toast(e.message, "error", 5000); }
}
async function loadScan(id) {
  try {
    const snap = await api(`/api/scan/${id}`);
    resetScan();
    S.scanId = snap.id; S.created = snap.created; S.title = snap.title;
    for (const n of snap.nodes) { S.nodes.set(n.id, n); S.pendingNodes.push(n); }
    for (const e of snap.edges) { S.edges.set(e.id, e); S.pendingEdges.push(e); }
    for (const [nid, r] of Object.entries(snap.results || {})) S.results.set(nid, r);
    S.stats = snap.stats || {};
    history.replaceState(null, "", "#scan=" + id);
    flush();
    setStatus(snap.status);
    renderStats();
    runLayout({ fit: true, randomize: true }); S.firstLayout = false;
    connect(id, snap.event_index || 0);
    renderList(); renderDetails();
  } catch (e) { toast("Could not load scan: " + e.message, "error"); history.replaceState(null, "", "#"); }
}
async function openHistory() {
  const list = await api("/api/scans");
  const box = $("#historyList");
  box.innerHTML = list.length ? list.map((s) => `<div class="hist" data-load="${s.id}"><div><b>${esc(s.title || s.id)}</b><small>${esc(fmtTime(s.created))} · ${esc(s.status)}</small></div>
    <div class="nums"><span>${s.nodes} nodes</span><span class="m">${s.malicious} mal</span><span class="s">${s.suspicious} sus</span></div>
    <button class="icon-btn" data-del="${s.id}" title="Delete">${ICON.trash}</button></div>`).join("") : '<div class="msg">No saved scans yet. Scans are saved automatically when they finish.</div>';
  $("#historyModal").classList.add("open");
}

// ------------------------------------------------------------------ exports
function csvCell(v) { v = String(v ?? ""); return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v; }
async function doExport(kind) {
  if (!S.scanId) return toast("Run a scan first", "warn");
  const base = `arachne-${(S.title || S.scanId).replace(/[^a-z0-9.@-]+/gi, "_").slice(0, 40)}`;
  const nodes = [...S.nodes.values()];
  if (kind === "json") return download(base + ".json", JSON.stringify(await api(`/api/scan/${S.scanId}`), null, 2), "application/json");
  if (kind === "csv") {
    // one row per scanned indicator and source
    const rows = [["indicator_type", "indicator", "submitted", "overall_verdict", "source", "status", "verdict", "score", "detail"]];
    for (const n of reportNodes()) {
      for (const [m, r] of Object.entries(S.results.get(n.id) || {}).sort((a, b) => modLabel(a[0]).localeCompare(modLabel(b[0])))) {
        rows.push([n.type, n.value, n.root, n.verdict || "", modLabel(m), r.status, r.verdict || "", r.score ?? "", detailText(r)]);
      }
    }
    return download(base + "-verdicts.csv", rows.map((r) => r.map(csvCell).join(",")).join("\n"), "text/csv");
  }
  if (kind === "iocs") {
    const order = ["ipv4", "ipv6", "domain", "url", "email", "hash", "asn", "cve", "username", "malware"];
    let out = `# ARACHNE IOC export — ${S.title}\n# ${new Date().toISOString()}\n`;
    for (const t of order) {
      const list = nodes.filter((n) => n.type === t).sort((a, b) => (VRANK[b.verdict] || 0) - (VRANK[a.verdict] || 0));
      if (!list.length) continue;
      out += `\n## ${typeLabel(t)} (${list.length})\n` + list.map((n) => n.value + (n.verdict && n.verdict !== "clean" ? `\t# ${n.verdict}` : "")).join("\n") + "\n";
    }
    return download(base + "-iocs.txt", out, "text/plain");
  }
  if (kind === "png") { ensureLaidOut(); return download(base + ".png", S.cy.png({ full: true, scale: 2, bg: "#050506", output: "blob" })); }
  if (kind === "report") return download(base + "-report.html", buildReport(), "text/html");
}
// indicators that were actually looked up: submitted IOCs first, then pivots
function reportNodes() {
  return [...S.nodes.values()].filter((n) => n.root || S.results.has(n.id))
    .sort((a, b) => (b.root - a.root) || ((VRANK[b.verdict] || 0) - (VRANK[a.verdict] || 0)) || a.value.localeCompare(b.value));
}
function buildReport() {
  const scanned = reportNodes(), scannedIds = new Set(scanned.map((n) => n.id));
  const related = [...S.nodes.values()].filter((n) => !scannedIds.has(n.id))
    .sort((a, b) => ((VRANK[b.verdict] || 0) - (VRANK[a.verdict] || 0)) || a.type.localeCompare(b.type) || a.value.localeCompare(b.value));
  const vc = (v) => (v && CFG.verdictColors[v]) || "#6b6b75";
  const section = (n) => {
    const res = S.results.get(n.id) || {}, t = tally(res);
    const rated = t.malicious + t.suspicious + t.clean;
    const rows = Object.entries(res).sort((a, b) => (VRANK[b[1].verdict] || 0) - (VRANK[a[1].verdict] || 0) || modLabel(a[0]).localeCompare(modLabel(b[0])));
    const good = rows.filter(([, r]) => r.status === "ok" && r.summary.length);
    return `<section class="ioc"><div class="ioc-h"><div><span class="ty">${esc(typeLabel(n.type))}${n.root ? "" : " · related"}</span><h3>${esc(n.value)}</h3></div>
      <div class="vd" style="color:${vc(n.verdict)};border-color:${vc(n.verdict)}">${esc(VLABEL[n.verdict] || "No verdict")}<small>${rated ? `${t.malicious + t.suspicious} / ${rated} sources flag it` : "no source gave a verdict"}</small></div></div>
      ${n.tags.length ? `<p class="meta">Tags: ${esc(n.tags.join(", "))}</p>` : ""}
      <table><tr><th>Source</th><th>Result</th><th>Score</th><th>Detail</th></tr>${rows.map(([m, r]) => `<tr><td>${esc(modLabel(m))}</td><td class="v" style="color:${r.status === "ok" ? vc(r.verdict) : "#80808a"}">${esc(r.status === "ok" ? r.verdict || "info" : (SRC_STATUS[r.status] || SRC_STATUS.error).label)}</td><td>${esc(r.score ?? "")}</td><td>${esc(detailText(r))}</td></tr>`).join("")}</table>
      ${good.length ? `<details><summary>Full findings from ${good.length} source${good.length === 1 ? "" : "s"}</summary>${good.map(([m, r]) =>
        `<div class="src"><h4>${esc(modLabel(m))}${r.verdict ? ` — <span style="color:${vc(r.verdict)}">${r.verdict}</span>` : ""}</h4><dl>${r.summary.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl></div>`).join("")}</details>` : ""}</section>`;
  };
  let img = "";
  if (related.length) { ensureLaidOut(); img = S.cy.png({ full: true, scale: 1.5, bg: "#050506", maxWidth: 2400 }); }
  const cnt = (v) => scanned.filter((n) => n.verdict === v).length;
  return `<!doctype html><html><head><meta charset="utf-8"><title>ARACHNE scan report — ${esc(S.title)}</title><style>
  body{background:#050506;color:#e4e4e7;font:13px/1.5 Inter,Segoe UI,sans-serif;margin:0;padding:32px;max-width:1200px;margin:auto}
  h1{font:700 22px Consolas,monospace;letter-spacing:.06em}h2{font:600 12px Consolas,monospace;letter-spacing:.14em;text-transform:uppercase;color:#80808a;margin-top:34px;border-bottom:1px solid #1f1f25;padding-bottom:6px}
  .meta{color:#80808a}.tiles{display:flex;gap:10px;margin:18px 0;flex-wrap:wrap}.tile{background:#0e0e11;border:1px solid #1f1f25;border-radius:8px;padding:10px 16px}.tile b{display:block;font:600 22px Consolas,monospace}
  .ioc{background:#0a0a0c;border:1px solid #1f1f25;border-radius:10px;padding:16px 18px;margin:12px 0}.ioc-h{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:10px}
  .ioc-h h3{margin:2px 0 0;font:700 16px Consolas,monospace;word-break:break-all}.ty{font:600 10px Consolas,monospace;letter-spacing:.12em;text-transform:uppercase;color:#80808a}
  .vd{font:700 14px Consolas,monospace;text-transform:uppercase;letter-spacing:.08em;border:1px solid;border-radius:8px;padding:6px 12px;text-align:right;white-space:nowrap}.vd small{display:block;font:400 11px Inter,sans-serif;text-transform:none;letter-spacing:0;color:#80808a}
  img{max-width:100%;border:1px solid #1f1f25;border-radius:10px}table{border-collapse:collapse;width:100%;font:12px Consolas,monospace}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #1f1f25;vertical-align:top}th{color:#80808a}
  td.v{font-weight:700;text-transform:uppercase;font-size:11px}details{background:#0e0e11;border:1px solid #1f1f25;border-radius:8px;padding:8px 12px;margin:10px 0 0}summary{cursor:pointer;font-family:Consolas,monospace;color:#b4b4bb}
  .src h4{margin:10px 0 4px;font-size:12px}dl{display:grid;grid-template-columns:220px 1fr;gap:2px 10px;margin:0;font-size:12px}dt{color:#80808a}dd{margin:0;font-family:Consolas,monospace;word-break:break-word}</style></head><body>
  <h1>ARACHNE · IOC SCAN REPORT</h1><div class="meta">IOCs: ${esc(scanned.filter((n) => n.root).map((n) => n.value).join(", "))}<br>Generated ${esc(new Date().toLocaleString())}</div>
  <div class="tiles"><div class="tile"><b>${scanned.length}</b>IOCs scanned</div><div class="tile"><b style="color:#ef4444">${cnt("malicious")}</b>malicious</div><div class="tile"><b style="color:#f59e0b">${cnt("suspicious")}</b>suspicious</div><div class="tile"><b style="color:#22c55e">${cnt("clean")}</b>clean</div><div class="tile"><b>${related.length}</b>related indicators</div></div>
  <h2>Results by IOC</h2>${scanned.map(section).join("")}
  ${related.length ? `<h2>Related indicators</h2><table><tr><th>Type</th><th>Value</th><th>Verdict</th><th>Found by</th></tr>${related.map((n) => `<tr><td>${esc(typeLabel(n.type))}</td><td>${esc(n.value)}</td><td style="color:${vc(n.verdict)}">${n.verdict || "—"}</td><td>${esc(n.source ? modLabel(n.source) : "")}</td></tr>`).join("")}</table>
  <h2>Pivot graph</h2><img src="${img}">` : ""}
  </body></html>`;
}

// ------------------------------------------------------------------ input detection
const updateDetect = debounce(async () => {
  const v = $("#seedInput").value.trim(), hint = $("#detectHint");
  if (!v || $("#typeSel").value !== "auto") { hint.textContent = ""; hint.className = "detect-hint"; return; }
  try {
    const r = await api("/api/detect", { body: { value: v } });
    hint.className = "detect-hint" + (r.seeds.length ? "" : " bad");
    hint.textContent = r.seeds.length === 1 ? typeLabel(r.seeds[0][0]) : r.seeds.length ? `${r.seeds.length} seeds` : "unrecognised";
    if (r.invalid.length && r.seeds.length) hint.textContent += ` · ${r.invalid.length} invalid`;
  } catch { /* ignore */ }
}, 220);

// ------------------------------------------------------------------ bindings
function bind() {
  $("#scanForm").onsubmit = (e) => { e.preventDefault(); startScan(false); };
  $("#addBtn").onclick = () => startScan(true);
  $("#stopBtn").onclick = () => S.scanId && api(`/api/scan/${S.scanId}/stop`, { body: {} });
  $("#seedInput").oninput = updateDetect;
  $("#typeSel").onchange = updateDetect;
  $("#historyBtn").onclick = openHistory;
  $("#settingsBtn").onclick = () => openSettings();
  $("#emptySettings").onclick = (e) => { e.preventDefault(); openSettings("keys"); };
  $("#exportBtn").onclick = (e) => { e.stopPropagation(); $("#exportMenu").classList.toggle("open"); };
  $("#exportMenu").onclick = (e) => { const b = e.target.closest("[data-export]"); if (b) { closeMenus(); doExport(b.dataset.export); } };
  $("#logToggle").onclick = () => $("#logbar").classList.toggle("open");
  $("#layoutSel").onchange = (e) => { saveUI({ layout: e.target.value }); runLayout({ fit: true, randomize: true }); };
  $("#bulkBtn").onclick = openBulk;
  $("#bulkText").oninput = bulkPreview;
  $("#bulkSkipUser").onchange = bulkPreview;
  $("#bulkFile").onchange = (e) => { loadBulkFile(e.target.files[0]); e.target.value = ""; };
  $("#bulkGo").onclick = runBulk;
  $("#bulkText").ondragover = (e) => e.preventDefault();
  $("#bulkText").ondrop = (e) => { if (e.dataTransfer.files[0]) { e.preventDefault(); loadBulkFile(e.dataTransfer.files[0]); } };
  $("#bulkText").onkeydown = (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) runBulk(); };
  $("#autoPivot").onchange = () => { $("#depthWrap").hidden = !$("#autoPivot").checked; if (!S.scanId) renderDetails(); };
  $("#viewSeg").onclick = (e) => { const b = e.target.closest("[data-view]"); if (b) setView(b.dataset.view); };
  $("#report").onclick = (e) => {
    const t = e.target;
    const ex = t.closest("[data-ex]"); if (ex) { $("#seedInput").value = ex.dataset.ex; updateDetect(); $("#seedInput").focus(); return; }
    const os = t.closest("[data-open-settings]"); if (os) { e.preventDefault(); return openSettings(os.dataset.openSettings); }
    const vw = t.closest("[data-view]"); if (vw) return setView(vw.dataset.view);
    const cp = t.closest("[data-copy]"); if (cp) return copy(cp.dataset.copy);
    const rr = t.closest("[data-rerun]"); if (rr) { e.stopPropagation(); return pivot(subjectId(), { modules: [rr.dataset.rerun], force: true }); }
    const rs = t.closest("[data-rescan]"); if (rs) return pivot(rs.dataset.rescan, { force: true });
    const sc = t.closest("[data-scan]"); if (sc) { e.stopPropagation(); return scanMany([sc.dataset.scan]); }
    const sa = t.closest("[data-scanall]");
    if (sa) {
      const id = sa.dataset.scanall, ids = new Set();
      for (const ed of S.edges.values()) { const o = ed.source === id ? ed.target : ed.target === id ? ed.source : null; if (o) ids.add(o); }
      return scanMany([...ids].filter((x) => { const o = S.nodes.get(x); return o && S.meta.types[o.type]?.pivotable && !S.results.has(x) && !S.busy.get(x)?.size; }));
    }
    const jp = t.closest("[data-jump]");
    if (jp) { const c = $(`#card-${CSS.escape(jp.dataset.jump)}`); if (c) { S.collapsed.delete(jp.dataset.jump); c.classList.remove("collapsed"); c.scrollIntoView({ behavior: "smooth", block: "start" }); c.classList.add("flash"); setTimeout(() => c.classList.remove("flash"), 900); } return; }
    const tg = t.closest("[data-toggle]"); if (tg) { const m = tg.dataset.toggle; S.collapsed.has(m) ? S.collapsed.delete(m) : S.collapsed.add(m); tg.parentElement.classList.toggle("collapsed"); return; }
    if (t.closest("[data-summary]")) return select(null);
    if (t.closest("[data-rescanall]")) return rescan(seedNodes().map((n) => n.id));
    if (t.closest("[data-copyflagged]")) {
      const v = summaryRows().filter(({ rk }) => (rk.score ?? 0) >= 35).map(({ n }) => n.value);
      return v.length ? copy(v.join("\n")) : toast("No IOCs at medium risk or above", "warn");
    }
    if (t.closest("[data-sumfilter], .sum-tools")) return;
    const go = t.closest("[data-goto]"); if (go) return select(go.dataset.goto);
  };
  $("#report").addEventListener("input", debounce((e) => { if (e.target.dataset.sumfilter !== undefined) { S.sumFilter = e.target.value.trim(); renderReport(); } }, 200));
  $("#report").onchange = (e) => {
    if (e.target.dataset.sumflagged !== undefined) { S.sumFlagged = e.target.checked; return renderReport(); }
    const s = e.target.closest("[data-runmod]"); if (s && s.value) { pivot(s.dataset.runmod, { modules: [s.value], force: true }); s.value = ""; }
  };
  // keep "5m ago" labels current
  setInterval(() => { if (S.view === "report" && S.scanId && !$(".modal.open") && document.activeElement?.dataset?.sumfilter === undefined) renderReport(); }, 60000);
  $("#report").addEventListener("toggle", (e) => {
    const g = e.target.closest?.("[data-group]"); if (g) (S.srcOpen ||= {})[g.dataset.group] = g.open;
  }, true);
  $(".graph-tools").onclick = (e) => {
    const t = e.target.closest("[data-tool]")?.dataset.tool; if (!t) return;
    if (t === "fit") S.cy.animate({ fit: { eles: S.cy.elements(":visible"), padding: 50 }, duration: 350 });
    if (t === "layout") runLayout({ fit: true, randomize: true });
    if (t === "labels") saveUI({ showLabels: !S.ui.showLabels });
    if (t === "edgelabels") saveUI({ showEdgeLabels: !S.ui.showEdgeLabels });
    if (t === "noise") saveUI({ showNoise: !S.ui.showNoise });
    if (t === "unhide") { S.hiddenNodes.clear(); applyFilters(); renderList(); }
    if (t === "addnode") S.scanId ? addIndicator(S.selected) : toast("Start a scan first", "warn");
    if (t === "group") { saveUI({ groupByType: !S.ui.groupByType }); if (S.ui.autoLayout) relayoutSoon(); }
    if (t === "collapse") {
      const gs = S.cy.nodes("[?group]").map((g) => g.id());
      const all = gs.length && gs.every((g) => S.collapsedGroups.has(g));
      gs.forEach((g) => (all ? S.collapsedGroups.delete(g) : S.collapsedGroups.add(g)));
      applyFilters(); relayoutSoon();
    }
    if (t === "clear") clearAll();
  };
  $("#left").onclick = (e) => {
    const ent = e.target.closest(".ent"); if (ent) return select(ent.dataset.id);
    const lg = e.target.closest("[data-lg]");
    if (lg) { const k = lg.dataset.lg; S.listCollapsed.has(k) ? S.listCollapsed.delete(k) : S.listCollapsed.add(k); return renderList(); }
    const gm = e.target.closest("[data-listgroup]");
    if (gm) return saveUI({ listGroup: gm.dataset.listgroup });
    const tchip = e.target.closest("[data-type]");
    if (tchip) {
      const t = tchip.dataset.type;
      if (e.shiftKey) { const all = [...new Set([...S.nodes.values()].map((n) => n.type))]; S.hiddenTypes = new Set(all.filter((x) => x !== t)); }
      else S.hiddenTypes.has(t) ? S.hiddenTypes.delete(t) : S.hiddenTypes.add(t);
      applyFilters(); renderList(); return;
    }
    const vchip = e.target.closest("[data-verdict]");
    if (vchip) { const v = vchip.dataset.verdict; S.hiddenVerdicts.has(v) ? S.hiddenVerdicts.delete(v) : S.hiddenVerdicts.add(v); applyFilters(); renderList(); }
  };
  $("#left").ondblclick = (e) => { const ent = e.target.closest(".ent"); if (ent) { focusNode(ent.dataset.id); } };
  $("#left").oncontextmenu = (e) => { const ent = e.target.closest(".ent"); if (ent) { e.preventDefault(); select(ent.dataset.id); nodeMenu(ent.dataset.id, e); } };
  $("#listSearch").oninput = debounce((e) => { S.search = e.target.value.trim(); renderList(); applySearchHL(); }, 150);
  $("#details").onclick = (e) => {
    const t = e.target;
    const tab = t.closest("[data-tab]"); if (tab) { S.tab = tab.dataset.tab; return renderDetails(); }
    const go = t.closest("[data-goto]"); if (go) return select(go.dataset.goto);
    const os = t.closest("[data-open-settings]"); if (os) { e.preventDefault(); return openSettings(os.dataset.openSettings); }
    const rr = t.closest("[data-rerun]"); if (rr) { e.preventDefault(); e.stopPropagation(); return pivot(S.selected, { modules: [rr.dataset.rerun], force: true }); }
    const tg = t.closest("[data-toggle]"); if (tg) { const m = tg.dataset.toggle; S.collapsed.has(m) ? S.collapsed.delete(m) : S.collapsed.add(m); tg.parentElement.classList.toggle("collapsed"); return; }
    const sr = t.closest("[data-search]"); if (sr) { S.search = sr.dataset.search; $("#listSearch").value = S.search; renderList(); applySearchHL(); return; }
    const act = t.closest("[data-act]")?.dataset.act; if (!act || act === "runmod") return;
    if (act === "tags") { S.allTags = !S.allTags; return renderDetails(); }
    const id = S.selected;
    ({ copy: () => copy(S.nodes.get(id).value), pivot: () => pivot(id), deep: () => pivot(id, { deep: true }), focus: () => focusNode(id),
      hide: () => hideNode(id), remove: () => removeNodes([id]), addlinked: () => addIndicator(id) })[act]?.();
  };
  $("#details").addEventListener("toggle", (e) => {
    const g = e.target.closest?.("[data-group]"); if (g) (S.srcOpen ||= {})[g.dataset.group] = g.open;
  }, true);
  $("#details").onchange = (e) => { if (e.target.dataset.act === "runmod" && e.target.value) { pivot(S.selected, { modules: [e.target.value], force: true }); e.target.value = ""; } };
  $("#historyList").onclick = async (e) => {
    const del = e.target.closest("[data-del]");
    if (del) { e.stopPropagation(); await api(`/api/scans/${del.dataset.del}`, { method: "DELETE" }); if (S.scanId === del.dataset.del) resetScan(); return openHistory(); }
    const l = e.target.closest("[data-load]"); if (l) { $("#historyModal").classList.remove("open"); loadScan(l.dataset.load); }
  };
  document.addEventListener("click", (e) => { if (!e.target.closest(".ctx") && !e.target.closest(".dropdown")) closeMenus(); });
  $$(".modal").forEach((m) => m.addEventListener("mousedown", (e) => {
    if (e.target === m || e.target.closest("[data-close]")) { m.classList.remove("open"); m.onclose?.(); }
  }));
  document.addEventListener("keydown", (e) => {
    const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName);
    if (e.key === "Escape") { closeMenus(); const open = $(".modal.open"); if (open) { open.classList.remove("open"); open.onclose?.(); } else if (!typing) select(null); return; }
    if (typing || $(".modal.open")) return;
    if (e.key === "/") { e.preventDefault(); $("#seedInput").focus(); }
    else if (e.key === "v") setView(S.view === "graph" ? "report" : "graph");
    else if (e.key === "f" && S.view === "graph") S.cy.animate({ fit: { eles: S.cy.elements(":visible"), padding: 50 }, duration: 350 });
    else if (e.key === "l" && S.view === "graph") runLayout({ fit: true, randomize: true });
    else if (e.key === "p" && S.selected) pivot(S.selected);
    else if ((e.key === "Delete" || e.key === "h") && S.selected) hideNode(S.selected);
  });
}

// ------------------------------------------------------------------ boot
async function init() {
  try {
    [S.meta, S.settings] = await Promise.all([api("/api/meta"), api("/api/settings")]);
  } catch (e) {
    document.body.innerHTML = `<div style="padding:40px;font-family:monospace">Cannot reach the ARACHNE server: ${esc(e.message)}</div>`;
    return;
  }
  S.modules = Object.fromEntries(S.meta.modules.map((m) => [m.name, m]));
  $("#typeSel").innerHTML = '<option value="auto">AUTO</option>' + Object.entries(S.meta.types).filter(([, t]) => t.pivotable).map(([k, t]) => `<option value="${k}">${esc(t.label)}</option>`).join("");
  $("#depthSel").value = String(Math.min(4, Math.max(1, S.settings.pivot?.depth ?? 1)));
  $("#autoPivot").checked = !!S.settings.pivot?.auto;
  $("#depthWrap").hidden = !$("#autoPivot").checked;
  if (typeof cytoscape === "undefined") {
    toast("Graph library failed to load (no internet?). Check your connection and reload.", "error", 15000);
    return;
  }
  initGraph();
  applyUI();
  bind();
  // deep links: #scan=<id>&view=<report|graph>&node=<node id>&tab=<tab>&settings=<tab>
  const hp = new URLSearchParams(location.hash.slice(1));
  setView(hp.get("view") || "report");
  if (/^[a-f0-9]+$/.test(hp.get("scan") || "")) await loadScan(hp.get("scan"));
  if (hp.get("groups") === "collapsed") { S.cy.nodes("[?group]").forEach((g) => S.collapsedGroups.add(g.id())); applyFilters(); runLayout({ fit: true, randomize: true }); }
  if (hp.get("node") && S.nodes.has(hp.get("node"))) { S.tab = hp.get("tab") || S.tab; select(hp.get("node"), false); }
  if (hp.get("settings")) openSettings(hp.get("settings"));
}
document.addEventListener("DOMContentLoaded", init);
