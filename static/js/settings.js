"use strict";
/* Settings modal. Depends on globals from app.js. */

const SET_TABS = [
  ["keys", "API Keys", '<svg viewBox="0 0 24 24"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3M17 6l3 3M14 9l2 2"/></svg>'],
  ["modules", "Modules", '<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>'],
  ["pivot", "Pivoting", '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><circle cx="4" cy="5" r="2"/><circle cx="20" cy="5" r="2"/><circle cx="12" cy="21" r="2"/><path d="M6 6l4 4M18 6l-4 4M12 15v4"/></svg>'],
  ["noise", "Noise filter", '<svg viewBox="0 0 24 24"><path d="M3 5h18l-7 8v6l-4 2v-8z"/></svg>'],
  ["sites", "Username sites", '<svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg>'],
  ["links", "Lookup links", '<svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/></svg>'],
  ["appearance", "Appearance", '<svg viewBox="0 0 24 24"><circle cx="13.5" cy="6.5" r="1.5"/><circle cx="17.5" cy="10.5" r="1.5"/><circle cx="8.5" cy="7.5" r="1.5"/><circle cx="6.5" cy="12.5" r="1.5"/><path d="M12 2a10 10 0 0 0 0 20c1 0 1.7-.8 1.7-1.7 0-.4-.2-.8-.4-1.1-.3-.3-.4-.7-.4-1.1 0-.9.8-1.7 1.7-1.7h2A5.4 5.4 0 0 0 22 11c0-5-4.5-9-10-9z"/></svg>'],
  ["network", "Network & cache", '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>'],
  ["backup", "Backup & reset", '<svg viewBox="0 0 24 24"><path d="M12 3v12m0 0-4-4m4 4 4-4M4 17v3h16v-3"/></svg>'],
];
let setTab = "keys";
let modSearch = "";

function openSettings(tab) {
  if (tab) setTab = tab;
  $("#settingsNav").innerHTML = SET_TABS.map(([k, l, i]) => `<button data-stab="${k}" class="${k === setTab ? "on" : ""}">${i}${l}</button>`).join("");
  renderSettingsTab();
  $("#settingsModal").classList.add("open");
}
function flashSaved() { const s = $("#savedInd"); s.classList.add("show"); clearTimeout(s._t); s._t = setTimeout(() => s.classList.remove("show"), 1400); }
async function patchSettings(patch, rerender = false) {
  try {
    const ui = S.settings.ui;
    S.settings = await api("/api/settings", { body: patch });
    S.settings.ui = S.settings.ui || ui;
    flashSaved();
    if (patch.pivot) {
      if ("depth" in patch.pivot) $("#depthSel").value = String(Math.min(4, Math.max(1, patch.pivot.depth)));
      if ("auto" in patch.pivot) { $("#autoPivot").checked = !!patch.pivot.auto; $("#depthWrap").hidden = !patch.pivot.auto; }
    }
    if (rerender) renderSettingsTab();
    if (!S.scanId) renderDetails();
  } catch (e) { toast("Save failed: " + e.message, "error"); }
}
const sw = (k, on, extra = "") => `<label class="switch"><input type="checkbox" data-k="${k}" ${on ? "checked" : ""} ${extra}><i></i></label>`;
const field = (label, help, control) => `<div class="field"><label>${label}${help ? `<small>${help}</small>` : ""}</label><div class="row">${control}</div></div>`;
const num = (k, v, min, max, extra = "") => `<input class="inp num" type="number" data-k="${k}" data-num value="${v ?? ""}" ${min != null ? `min="${min}"` : ""} ${max != null ? `max="${max}"` : ""} ${extra}>`;
const keySet = (id) => !!S.settings.api_keys?.[id]?.set;
const modCfg = (m) => S.settings.modules?.[m.name] || {};

function renderSettingsTab() {
  $$("#settingsNav button").forEach((b) => b.classList.toggle("on", b.dataset.stab === setTab));
  const body = $("#settingsBody");
  body.innerHTML = ({ keys: tabKeys, modules: tabModules, pivot: tabPivot, noise: tabNoise, sites: tabSites, links: tabLinks,
    appearance: tabAppearance, network: tabNetwork, backup: tabBackup })[setTab]();
  body.scrollTop = 0;
  if (setTab === "network") api("/api/cache").then((r) => { const e = $("#cacheCount"); if (e) e.textContent = `${r.entries} cached results`; });
}

// ------------------------------------------------------------------ tabs
function tabKeys() {
  const n = S.meta.api_keys.filter((k) => keySet(k.id)).length;
  return `<h3>API Keys</h3><p class="lead">Keys are stored locally in <span class="mono">data/settings.json</span> and only sent to their own provider. ${n} of ${S.meta.api_keys.length} configured. Modules without a required key are skipped automatically.</p>
    <div class="toolbar"><button class="btn sm" data-act-set="exportApiKeys" ${n ? "" : "disabled"} title="Download your keys as a JSON file to keep somewhere safe">Export keys</button>
      <label class="btn sm ghost" title="Load keys from a file exported here (or a settings export that includes keys)">Import keys<input type="file" accept=".json,application/json" id="importKeysFile" hidden></label>
      <span class="msg">The export is plain text. Store it outside the ARACHNE folder and don't share it.</span></div>` +
    S.meta.api_keys.map((k) => {
      const mods = S.meta.modules.filter((m) => m.keys.includes(k.id));
      const cur = S.settings.api_keys?.[k.id];
      return `<div class="keyrow" data-key="${k.id}">
        <div class="kl"><b><span class="dot-set ${cur?.set ? "on" : ""}"></span>${esc(k.label)}</b>${k.help ? `<small>${esc(k.help)}</small>` : ""}<a href="${esc(k.url)}" target="_blank" rel="noopener noreferrer">Get a key ↗</a>
          <div class="mods">${mods.map((m) => `<span>${esc(m.label)}</span>`).join("")}</div>
          ${cur?.same_as?.length ? `<span class="key-warn">⚠ Same value as the ${esc(cur.same_as.map((o) => S.meta.api_keys.find((x) => x.id === o)?.label || o).join(", "))} key — probably pasted into the wrong field.</span>` : ""}</div>
        <div class="key-in"><input class="inp" type="password" autocomplete="off" spellcheck="false" placeholder="${cur?.set ? esc(cur.preview) + "  (saved — type to replace)" : "not set"}" data-keyinput="${k.id}">
          <button class="icon-btn" data-reveal title="Show / hide"><svg viewBox="0 0 24 24"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg></button></div>
        <div class="row"><button class="btn sm" data-savekey="${k.id}">Save</button>${cur?.set ? `<button class="btn sm ghost" data-clearkey="${k.id}">Clear</button>` : ""}</div></div>`;
    }).join("");
}

function keyPill(m) {
  if (!m.keys.length) return '<span class="pill free">no key needed</span>';
  const has = m.keys.every(keySet);
  if (has) return '<span class="pill have">key set</span>';
  return m.key_required ? '<span class="pill need">needs key</span>' : '<span class="pill opt">key optional</span>';
}
function tabModules() {
  const cats = {};
  for (const m of S.meta.modules) (cats[m.category] ||= []).push(m);
  const enabledN = S.meta.modules.filter((m) => modCfg(m).enabled ?? m.enabled).length;
  return `<h3>Modules</h3><p class="lead">${S.meta.modules.length} lookup modules, ${enabledN} enabled. <b>Enabled</b> modules run on seeds and manual pivots; <b>On pivots</b> controls whether they also run on automatically discovered indicators. Rate limits are requests/minute per provider (blank = unlimited).</p>
    <div class="toolbar"><input class="inp" id="modSearch" placeholder="Filter modules…" value="${esc(modSearch)}">
      <button class="btn sm" data-bulk="on">Enable all</button><button class="btn sm" data-bulk="keyed">Enable only usable</button><button class="btn sm ghost" data-bulk="off">Disable all</button><button class="btn sm ghost" data-bulk="reset">Reset to defaults</button></div>
    <div id="modList">` +
    Object.entries(cats).sort().map(([cat, mods]) => `<h4>${esc(cat)}</h4>` + mods.map((m) => {
      const c = modCfg(m), en = c.enabled ?? m.enabled, pv = c.pivot ?? m.pivot, rate = "rate" in c ? c.rate : m.rate;
      const hay = (m.label + " " + m.desc + " " + m.name + " " + m.types.join(" ")).toLowerCase();
      return `<div class="modrow ${en ? "" : "off"}" data-mod="${m.name}" ${modSearch && !hay.includes(modSearch.toLowerCase()) ? "hidden" : ""} data-hay="${esc(hay)}">
        <div class="mtop">${sw(`mod.${m.name}.enabled`, en)}<b>${esc(m.label)}</b><span class="grow"></span>
          <span class="types">${m.types.map((t) => `<span style="color:${tc(t)};border-color:${hexA(tc(t), 0.4)}">${esc(typeLabel(t))}</span>`).join("")}</span>${keyPill(m)}${m.active ? '<span class="pill active">active</span>' : ""}</div>
        <div class="mdesc">${esc(m.desc)}</div>
        <div class="mmeta"><label class="row" title="Also run on auto-pivoted indicators">${sw(`mod.${m.name}.pivot`, pv)} On pivots</label>
          <label class="row">Rate ${num(`mod.${m.name}.rate`, rate, 0, 6000, 'placeholder="∞" style="width:80px"')} /min</label>
          ${m.options.map((o) => `<label class="row" title="${esc(o.label)}">${sw(`mod.${m.name}.${o.id}`, c[o.id] ?? o.default)} ${esc(o.label.split(" - ")[0])}</label>`).join("")}
          <span class="grow" style="flex:1"></span>
          <input class="inp" style="width:210px;padding:4px 8px;font-size:11.5px" placeholder="${esc(m.sample || "test value")}" data-testval="${m.name}">
          <button class="btn xs" data-test="${m.name}">Test</button></div>
        <div class="test-out" data-testout="${m.name}"></div></div>`;
    }).join("")).join("") + "</div>";
}
function tabPivot() {
  const p = S.settings.pivot;
  const types = Object.entries(S.meta.types).filter(([, t]) => t.pivotable);
  return `<h3>Pivoting</h3><p class="lead">By default a scan only looks up the IOCs you submit, and lists the related indicators each source finds so you can scan them from the report. With auto-pivot on, every related indicator at depth ≤ the pivot depth is looked up automatically with the modules marked “On pivots”.</p>
    ${field("Auto-pivot by default", "Start scans with the Pivot switch on", sw("pivot.auto", p.auto))}
    ${field("Pivot depth", "Hops from the scanned IOC that are auto-expanded. Each level can multiply node count.", num("pivot.depth", p.depth, 1, 8))}
    ${field("Max nodes per scan", "Hard cap on graph size", num("pivot.max_nodes", p.max_nodes, 10, 20000))}
    ${field("Max children per lookup", "Max related indicators a single module may add (subdomains, resolutions…)", num("pivot.max_children", p.max_children, 1, 500))}
    ${field("Auto-pivot types", "Which indicator types are expanded automatically", `<div class="type-toggles" data-k="pivot.types">${types.map(([k, t]) => `<span data-t="${k}" class="${p.types.includes(k) ? "on" : ""}" style="color:${tc(k)};border-color:${hexA(tc(k), 0.5)}">${esc(t.label)}</span>`).join("")}</div>`)}
    ${field("Shared-hosting threshold", "IPs whose passive DNS shows more hostnames than this are tagged shared-hosting and their neighbours aren't added (0 = off)", num("pivot.shared_host_threshold", p.shared_host_threshold, 0, 10000))}
    ${field("Skip noise", "Don't auto-pivot indicators matching the noise filter (CDNs, big providers, role mailboxes)", sw("pivot.skip_noise", p.skip_noise))}
    ${field("Skip private IPs", "Don't look up RFC1918 / loopback / reserved addresses", sw("pivot.skip_private", p.skip_private))}
    ${field("Only pivot from flagged", "Only auto-pivot children of indicators rated suspicious or malicious — great for tight threat hunts", sw("pivot.only_flagged", p.only_flagged))}`;
}
function tabNoise() {
  return `<h3>Noise filter</h3><p class="lead">Indicators matching these entries still appear (dimmed) but are never auto-pivoted. One per line. Domains match themselves and all subdomains; words without a dot match anywhere in a hostname (e.g. <span class="mono">awsdns</span>); IPs/CIDRs match addresses; <span class="mono">user:name</span> matches usernames. Lines starting with # are comments.</p>
    <textarea id="noiseText" spellcheck="false">${esc((S.settings.noise || []).join("\n"))}</textarea>
    <div class="row" style="margin-top:10px"><button class="btn primary sm" data-act-set="saveNoise">Save</button><button class="btn sm ghost" data-act-set="resetNoise">Reset to defaults</button></div>`;
}
function tabSites() {
  const cfg = S.settings.username_sites || { disabled: [], custom: [] };
  const dis = new Set(cfg.disabled || []);
  return `<h3>Username sites</h3><p class="lead">Sites checked by the Username Enumeration module. Toggle built-ins or add your own — use <span class="mono">{u}</span> where the username goes.</p>
    <h4>Built-in (${S.meta.sites.length})</h4><div class="grid-list">${S.meta.sites.map((s) => `<div class="site">${sw("site." + s.name, !dis.has(s.name), `data-site="${esc(s.name)}"`)}<span>${esc(s.name)}</span><small>${esc(s.cat)}</small></div>`).join("")}</div>
    <h4>Custom sites</h4>
    ${(cfg.custom || []).map((c, i) => `<div class="link-row" style="grid-template-columns:150px 1fr 160px 30px"><b>${esc(c.name)}</b><span class="mono" style="font-size:11.5px;color:var(--muted)">${esc(c.url)}</span><small class="mono">${esc(c.check)}${c.match ? `: ${esc(c.match)}` : ""}</small><button class="icon-btn" data-delsite="${i}">✕</button></div>`).join("") || '<p class="msg">None yet.</p>'}
    <div class="link-row" style="grid-template-columns:150px 1fr 130px 160px auto;margin-top:10px">
      <input class="inp" id="csName" placeholder="Name"><input class="inp" id="csUrl" placeholder="https://example.com/user/{u}">
      <select id="csCheck"><option value="status">HTTP 200</option><option value="present">text present</option><option value="absent">text absent</option></select>
      <input class="inp" id="csMatch" placeholder="match text (optional)"><button class="btn sm" data-act-set="addSite">Add</button></div>`;
}
function tabLinks() {
  const links = lookupLinks();
  const types = Object.keys(CFG.glyph);
  return `<h3>Lookup links</h3><p class="lead">Quick-pivot links shown in the node Lookup tab and right-click menu. Placeholders: <span class="mono">{value}</span> raw, <span class="mono">{enc}</span> URL-encoded, <span class="mono">{b64}</span> base64.</p>
    <div id="linkRows">${links.map((l) => linkRow(l, types)).join("")}</div>
    <div class="row" style="margin-top:10px"><button class="btn sm" data-act-set="addLink">Add link</button><button class="btn primary sm" data-act-set="saveLinks">Save</button><button class="btn sm ghost" data-act-set="resetLinks">Reset to defaults</button></div>`;
}
function linkRow(l, types) {
  return `<div class="link-row"><input class="inp" data-ln="name" value="${esc(l.name)}" placeholder="Name"><input class="inp" data-ln="url" value="${esc(l.url)}" placeholder="https://…{value}">
    <div class="type-toggles">${types.map((t) => `<span data-t="${t}" class="${l.types.includes(t) ? "on" : ""}" style="color:${tc(t)};border-color:${hexA(tc(t), 0.5)}">${esc(CFG.glyph[t])}</span>`).join("")}</div>
    <button class="icon-btn" data-dellink>✕</button></div>`;
}
function tabAppearance() {
  const u = S.ui;
  return `<h3>Appearance</h3><p class="lead">Customise the look of the web. Changes apply instantly.</p>
    ${field("Accent colour", "Buttons, highlights, progress", `<input type="color" data-k="ui.accent" value="${esc(u.accent)}"><span class="mono msg">${esc(u.accent)}</span>`)}
    ${field("Monochrome nodes", "Grey nodes; only verdicts are coloured", sw("ui.monochrome", u.monochrome))}
    ${field("Node size", "", `<input type="range" min="18" max="64" data-k="ui.nodeSize" data-num value="${u.nodeSize}"><span class="mono msg">${u.nodeSize}px</span>`)}
    ${field("Label size", "", `<input type="range" min="7" max="16" data-k="ui.labelSize" data-num value="${u.labelSize}"><span class="mono msg">${u.labelSize}px</span>`)}
    ${field("Node labels", "", sw("ui.showLabels", u.showLabels))}
    ${field("Edge labels", "Relationship names on every link (always shown on hover)", sw("ui.showEdgeLabels", u.showEdgeLabels))}
    ${field("Show noise nodes", "", sw("ui.showNoise", u.showNoise))}
    ${field("Group neighbours by type", "Wrap same-type leaf indicators hanging off one node (e.g. 16 domains on an IP) in a collapsible box", sw("ui.groupByType", u.groupByType))}
    ${field("Minimum group size", "Smallest number of siblings that forms a group", num("ui.groupMin", u.groupMin, 2, 50))}
    ${field("Indicator list grouping", "", `<select data-k="ui.listGroup" style="width:200px">${[["type", "By type"], ["source", "By source node"], ["none", "No grouping"]].map(([k, l]) => `<option value="${k}" ${(u.listGroup || "type") === k ? "selected" : ""}>${l}</option>`).join("")}</select>`)}
    ${field("Default layout", "", `<select data-k="ui.layout" style="width:200px">${["fcose", "concentric", "breadthfirst", "cose", "circle", "grid"].map((l) => `<option value="${l}" ${u.layout === l ? "selected" : ""}>${{ fcose: "Force", concentric: "Rings by depth", breadthfirst: "Tree", cose: "Organic", circle: "Circle", grid: "Grid" }[l]}</option>`).join("")}</select>`)}
    ${field("Live re-layout", "Re-arrange the web as new indicators stream in", sw("ui.autoLayout", u.autoLayout))}
    ${field("Animate layout", "", sw("ui.animate", u.animate))}
    ${field("Dot-grid background", "", sw("ui.grid", u.grid))}
    <h4>Type colours</h4><div class="colors">${Object.keys(CFG.glyph).map((t) => `<label><input type="color" data-tcolor="${t}" value="${esc(tc(t) === "#a1a1aa" && u.monochrome ? CFG.typeColors[t] : (u.typeColors || {})[t] || CFG.typeColors[t])}">${esc(typeLabel(t))}</label>`).join("")}</div>
    <div class="row" style="margin-top:10px"><button class="btn sm ghost" data-act-set="resetColors">Reset colours</button><button class="btn sm ghost" data-act-set="resetUI">Reset all appearance</button></div>`;
}
function tabNetwork() {
  const n = S.settings.network, c = S.settings.cache;
  return `<h3>Network & cache</h3><p class="lead">Request behaviour for all modules.</p>
    ${field("Request timeout", "Seconds", num("network.timeout", n.timeout, 3, 300))}
    ${field("Concurrent lookups", "Worker threads shared by all scans", num("network.concurrency", n.concurrency, 1, 64))}
    ${field("Parallel per provider", "Max simultaneous requests to one provider (rate-limited providers always use 1)", num("network.provider_parallel", n.provider_parallel, 1, 32))}
    ${field("HTTP(S) proxy", "e.g. http://127.0.0.1:8080 (Burp) — blank for system default", `<input class="inp" data-k="network.proxy" value="${esc(n.proxy)}" placeholder="http://host:port">`)}
    ${field("User-Agent", "Blank = modern Chrome UA", `<input class="inp" data-k="network.user_agent" value="${esc(n.user_agent)}">`)}
    ${field("DNS-over-HTTPS resolver", "", `<select data-k="network.doh" style="width:200px"><option value="google" ${n.doh === "google" ? "selected" : ""}>Google (dns.google)</option><option value="cloudflare" ${n.doh === "cloudflare" ? "selected" : ""}>Cloudflare (1.1.1.1)</option></select>`)}
    ${field("Verify TLS certificates", "Turn off only behind an intercepting proxy (corporate SSL inspection, Burp) that breaks certificate checks", sw("network.verify_tls", n.verify_tls !== false))}
    ${field("Allow active modules", "⚠ Active modules (HTTP Probe) connect directly to the target from your IP. Leave off for passive-only OSINT.", sw("network.allow_active", n.allow_active))}
    <h4>Result cache</h4>
    ${field("Cache results", "Reuse module results for repeat lookups (saves API quota)", sw("cache.enabled", c.enabled))}
    ${field("Cache lifetime", "Hours", num("cache.ttl_hours", c.ttl_hours, 0, 8760))}
    ${field("Clear cache", `<span id="cacheCount"></span>`, '<button class="btn sm" data-act-set="clearCache">Clear now</button>')}`;
}
function tabBackup() {
  return `<h3>Backup & reset</h3><p class="lead">Export your configuration to move it between machines.</p>
    ${field("Export settings", "JSON file", '<button class="btn sm" data-act-set="exportNoKeys">Without API keys</button><button class="btn sm ghost" data-act-set="exportKeys">Including API keys</button>')}
    ${field("Import settings", "Merges into current settings", '<input type="file" accept=".json,application/json" id="importFile" class="inp" style="width:auto">')}
    <h4>Reset</h4>
    ${field("Reset a section", "", ["modules", "pivot", "noise", "network", "cache", "username_sites", "ui"].map((s) => `<button class="btn xs" data-reset="${s}">${s}</button>`).join(" "))}
    ${field("Reset everything", "Keeps API keys", '<button class="btn sm danger" data-reset="all">Reset all settings</button>')}`;
}

// ------------------------------------------------------------------ events
function setPath(path, val) {
  const [sec, ...rest] = path.split(".");
  if (sec === "ui") return saveUI({ [rest[0]]: val }).then(flashSaved);
  if (sec === "mod") {
    const [name, key] = rest;
    if (key === "enabled") $(`.modrow[data-mod="${name}"]`)?.classList.toggle("off", !val);
    return patchSettings({ modules: { [name]: { [key]: val } } });
  }
  if (sec === "site") return;
  return patchSettings({ [sec]: { [rest[0]]: val } });
}
function readVal(el) {
  if (el.type === "checkbox") return el.checked;
  if ("num" in el.dataset) return el.value === "" ? null : Number(el.value);
  return el.value;
}
function bindSettings() {
  $("#settingsNav").onclick = (e) => { const b = e.target.closest("[data-stab]"); if (b) { setTab = b.dataset.stab; renderSettingsTab(); } };
  const body = $("#settingsBody");
  body.addEventListener("change", (e) => {
    const el = e.target;
    if (el.dataset.site !== undefined) {
      const cfg = S.settings.username_sites || {}, dis = new Set(cfg.disabled || []);
      el.checked ? dis.delete(el.dataset.site) : dis.add(el.dataset.site);
      return patchSettings({ username_sites: { disabled: [...dis], custom: cfg.custom || [] } });
    }
    if (el.dataset.tcolor) return saveUI({ typeColors: Object.assign({}, S.ui.typeColors, { [el.dataset.tcolor]: el.value }) }).then(flashSaved);
    if (el.id === "importFile" && el.files[0]) {
      el.files[0].text().then(async (txt) => {
        try { const j = JSON.parse(txt); await patchSettings(j, true); S.settings = await api("/api/settings"); applyUI(); toast("Settings imported"); }
        catch (err) { toast("Import failed: " + err.message, "error"); }
      });
      return;
    }
    if (el.id === "importKeysFile" && el.files[0]) {
      el.files[0].text().then(async (txt) => {
        try {
          const r = await api("/api/keys/import", { body: JSON.parse(txt) });
          S.settings = await api("/api/settings"); applyUI(); renderSettingsTab(); flashSaved();
          toast(`${r.imported} key${r.imported === 1 ? "" : "s"} imported${r.unchanged ? `, ${r.unchanged} already set` : ""}${r.ignored?.length ? ` · ignored: ${r.ignored.join(", ")}` : ""}`);
        } catch (err) { toast("Import failed: " + (err instanceof SyntaxError ? "not a valid JSON file" : err.message), "error", 5000); }
      });
      el.value = "";
      return;
    }
    if (el.dataset.k) setPath(el.dataset.k, readVal(el));
  });
  body.addEventListener("input", (e) => {
    const el = e.target;
    if (el.type === "range") { el.nextElementSibling.textContent = el.value + "px"; }
    if (el.id === "modSearch") {
      modSearch = el.value.trim().toLowerCase();
      $$(".modrow").forEach((r) => { r.hidden = !!modSearch && !r.dataset.hay.includes(modSearch); });
    }
  });
  body.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.dataset.keyinput) $(`[data-savekey="${e.target.dataset.keyinput}"]`).click(); });
  body.addEventListener("click", async (e) => {
    const t = e.target;
    const rv = t.closest("[data-reveal]"); if (rv) { const i = rv.previousElementSibling; i.type = i.type === "password" ? "text" : "password"; return; }
    const sk = t.closest("[data-savekey]");
    if (sk) {
      const id = sk.dataset.savekey, v = $(`[data-keyinput="${id}"]`).value.trim();
      if (!v) return toast("Enter a key first", "warn");
      await patchSettings({ api_keys: { [id]: v } }, true); toast("Key saved"); return;
    }
    const ck = t.closest("[data-clearkey]"); if (ck) { await patchSettings({ api_keys: { [ck.dataset.clearkey]: null } }, true); return; }
    const tt = t.closest(".type-toggles span");
    if (tt) {
      tt.classList.toggle("on");
      const wrap = tt.parentElement;
      if (wrap.dataset.k === "pivot.types") patchSettings({ pivot: { types: $$("span.on", wrap).map((s) => s.dataset.t) } });
      return;
    }
    const test = t.closest("[data-test]");
    if (test) {
      const name = test.dataset.test, out = $(`[data-testout="${name}"]`), val = $(`[data-testval="${name}"]`).value.trim();
      out.innerHTML = '<span class="st running">running</span>';
      try {
        const r = await api(`/api/modules/${name}/test`, { body: { value: val || null } });
        out.innerHTML = `<div class="card"><div class="card-h"><b>${esc(r.value)}</b><span class="st ${r.status}">${r.status}</span>${r.verdict ? vbadge(r.verdict, r.score) : ""}<small>${r.elapsed}s</small></div>
          <div class="card-b">${r.message ? `<div class="msg">${esc(r.message)}</div>` : ""}${r.summary?.length ? kvHTML(r.summary) : ""}${tablesHTML(r.tables || [])}${r.entities?.length ? `<div class="msg" style="margin-top:6px">→ ${r.entities.length} linked: ${esc(r.entities.slice(0, 8).map((x) => x.value).join(", "))}${r.entities.length > 8 ? "…" : ""}</div>` : ""}</div></div>`;
      } catch (err) { out.innerHTML = `<div class="msg" style="color:var(--mal)">${esc(err.message)}</div>`; }
      return;
    }
    const bulk = t.closest("[data-bulk]");
    if (bulk) {
      const mode = bulk.dataset.bulk, patch = {};
      for (const m of S.meta.modules) {
        if (mode === "reset") patch[m.name] = null;
        else if (mode === "on") patch[m.name] = { enabled: true };
        else if (mode === "off") patch[m.name] = { enabled: false };
        else patch[m.name] = { enabled: !m.active && (!m.key_required || m.keys.every(keySet)) };
      }
      return patchSettings({ modules: patch }, true);
    }
    const rs = t.closest("[data-reset]");
    if (rs) {
      if (!confirm(`Reset ${rs.dataset.reset === "all" ? "ALL settings (API keys kept)" : rs.dataset.reset} to defaults?`)) return;
      S.settings = await api("/api/settings/reset", { body: { section: rs.dataset.reset } });
      applyUI(); flashSaved(); toast("Reset done"); return;
    }
    const ds = t.closest("[data-delsite]");
    if (ds) {
      const cfg = S.settings.username_sites || {}, custom = [...(cfg.custom || [])];
      custom.splice(+ds.dataset.delsite, 1);
      return patchSettings({ username_sites: { disabled: cfg.disabled || [], custom } }, true);
    }
    const dl = t.closest("[data-dellink]"); if (dl) { dl.parentElement.remove(); return; }
    const act = t.closest("[data-act-set]")?.dataset.actSet;
    if (!act) return;
    if (act === "saveNoise") return patchSettings({ noise: $("#noiseText").value.split("\n").map((s) => s.trim()).filter(Boolean) });
    if (act === "resetNoise") return patchSettings({ noise: S.meta.default_noise }, true);
    if (act === "addSite") {
      const name = $("#csName").value.trim(), url = $("#csUrl").value.trim(), check = $("#csCheck").value, match = $("#csMatch").value;
      if (!name || !url.includes("{u}")) return toast("Name and a URL containing {u} are required", "warn");
      if (check !== "status" && !match) return toast("Text checks need match text", "warn");
      const cfg = S.settings.username_sites || {};
      return patchSettings({ username_sites: { disabled: cfg.disabled || [], custom: [...(cfg.custom || []), { name, url, check, match }] } }, true);
    }
    if (act === "addLink") { $("#linkRows").insertAdjacentHTML("beforeend", linkRow({ name: "", url: "", types: [] }, Object.keys(CFG.glyph))); return; }
    if (act === "saveLinks") {
      const links = $$("#linkRows .link-row").map((r) => ({ name: $('[data-ln="name"]', r).value.trim(), url: $('[data-ln="url"]', r).value.trim(), types: $$(".type-toggles span.on", r).map((s) => s.dataset.t) }))
        .filter((l) => l.name && l.url && l.types.length);
      await saveUI({ links }); flashSaved(); toast(`${links.length} links saved`); return;
    }
    if (act === "resetLinks") { await saveUI({ links: null }); renderSettingsTab(); return; }
    if (act === "resetColors") { await saveUI({ typeColors: {} }); renderSettingsTab(); return; }
    if (act === "resetUI") { S.settings = await api("/api/settings/reset", { body: { section: "ui" } }); applyUI(); renderSettingsTab(); return; }
    if (act === "clearCache") { const r = await api("/api/cache/clear", { body: {} }); toast(`Cleared ${r.cleared} cached results`); renderSettingsTab(); return; }
    if (act === "exportApiKeys") {
      const d = await api("/api/keys/export");
      download("arachne-api-keys.json", JSON.stringify(d, null, 2), "application/json");
      toast(`Exported ${Object.keys(d.keys).length} keys. Keep the file outside the ARACHNE folder.`, "info", 5000);
      return;
    }
    if (act === "exportNoKeys" || act === "exportKeys") {
      const d = await api("/api/settings/export?keys=" + (act === "exportKeys" ? 1 : 0));
      download(`arachne-settings${act === "exportKeys" ? "-with-keys" : ""}.json`, JSON.stringify(d, null, 2), "application/json");
    }
  });
}
document.addEventListener("DOMContentLoaded", bindSettings);
