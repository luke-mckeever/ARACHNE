"use strict";
/* Paste-anything IOC extraction for the bulk scan dialog ("Extract from text" tab).
   Paste an email, a threat report, logs or a web page: every IP, domain, URL, email, file hash, CVE and ASN in
   it is pulled out (defanged ones too), duplicates are merged, and the analyst picks which ones to scan. Private
   IPs, well-known domains and anything on the user's own "always leave out" list start unticked. Runs entirely
   in the browser, so the local app and the website behave the same. Loaded after app.js and uses its helpers. */

const XT = (() => {
  // ccTLDs (ISO 3166 + uk/eu/su/ac) and generic TLDs. Free text is full of things like "app.js", "System.Net" and
  // "config.json", so a "domain" only counts when it ends in a real TLD.
  const CC = new Set(("ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz " +
    "ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga gd ge " +
    "gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp " +
    "kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng " +
    "ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr " +
    "ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw").split(" "));
  const GTLD = new Set(("com net org info biz name pro mobi asia tel travel jobs cat coop aero museum int edu gov mil arpa " +
    "xyz top club online site shop store live tech space website fun icu cyou buzz monster rest bond sbs cfd click link work " +
    "world today life email digital network cloud host hosting server services solutions support systems company agency " +
    "group global center media news blog page app dev io ai one zone vip win bid loan date download review stream racing " +
    "party science trade webcam men cricket accountant faith gdn lol xin kim ltd inc llc gmbh bar pw wang ren ink red blue " +
    "pink black green team tools pub social chat studio design art photo pics video tube games game casino bet poker money " +
    "finance financial capital bank cash credit fund exchange market markets trading investments insure insurance tax " +
    "realty properties estate land house homes rent cars car auto bike law legal lawyer attorney health care clinic doctor " +
    "dental hospital fit fitness yoga beauty hair fashion style clothing shoes jewelry gift gifts love dating sexy porn " +
    "adult xxx sex lgbt city town country uno ninja guru expert academy school college university education training " +
    "courses institute foundation charity church community events tickets tours holiday vacations voyage cruise flights " +
    "hotel restaurant cafe pizza bio eco energy solar farm garden kitchen menu wine beer vodka coffee tea food recipes " +
    "plus best cool fail lat moe nyc london berlin paris tokyo wiki help how wtf now new run fyi sale deals discount promo " +
    "codes coupons cheap direct express fast free onl quest surf win9 mom baby kids family pet dog meme " +
    "google microsoft apple amazon azure windows office android chrome gmail youtube yahoo play docs drive " +
    "zip mov foo bot boo dad phd prof esq nexus rsvp day ing meet page new channel here").split(" "));
  const TLDOK = (t) => CC.has(t) || GTLD.has(t);
  // two-label names that are far more often a file than a site in reports: "invoice.zip", "run.sh", "setup.py"
  const FILEISH = new Set("zip mov sh py md pl ps rs so ws cs js".split(" "));
  // first labels of Java/Android package names: "com.example.app", "org.apache.commons"
  const PKG = new Set("com org net android androidx java javax kotlin".split(" "));
  // well-known services that show up in almost every email and report (signatures, tracking, schemas)
  const WELL_KNOWN = new Set(("google.com googleapis.com gstatic.com google-analytics.com googletagmanager.com doubleclick.net " +
    "youtube.com gmail.com microsoft.com microsoftonline.com office.com office365.com outlook.com live.com hotmail.com msn.com " +
    "bing.com windows.com windowsupdate.com azure.com skype.com apple.com icloud.com amazon.com cloudflare.com github.com " +
    "linkedin.com facebook.com instagram.com twitter.com x.com w3.org schema.org mozilla.org wikipedia.org example.com " +
    "example.net example.org mitre.org virustotal.com adobe.com digicert.com verisign.com letsencrypt.org globalsign.com " +
    "sectigo.com apache.org python.org gravatar.com").split(" "));
  const MULTI = new Set("co.uk org.uk ac.uk gov.uk com.au net.au org.au co.nz co.jp co.kr com.br com.cn co.in co.za com.mx com.tr co.il com.sg".split(" "));

  const reg = (d) => { const p = d.split("."); return p.length > 2 && MULTI.has(p.slice(-2).join(".")) ? p.slice(-3).join(".") : p.slice(-2).join("."); };

  // Defanged notation, refanged in place anywhere in the text (the search box version only handles one value):
  // hxxp(s):// h**p h[tt]p fxp:// [.] (.) {.} [dot] \. [@] [at] (at) [:] [://] [/]
  function refangText(s) {
    return s
      .replace(/[ \t]*[\[({][ \t]*(?:\.|dot)[ \t]*[\])}][ \t]*/gi, ".")
      .replace(/[ \t]*[\[({][ \t]*(?:@|at)[ \t]*[\])}][ \t]*/gi, "@")
      .replace(/[\[({]\s*:\s*\/\s*\/\s*[\])}]/g, "://")
      .replace(/[\[({]\s*:\s*[\])}]/g, ":")
      .replace(/[\[({]\s*\/\s*[\])}]/g, "/")
      .replace(/\\\./g, ".")
      .replace(/\bh(?:xx|\*\*|tt|\[tt\]|\[xx\])p(s?)(?=:)/gi, "http$1")
      .replace(/\bfxp(s?)(?=:)/gi, "ftp$1");
  }
  // Undo the encodings that hide IOCs in a raw email or saved web page: quoted-printable soft line breaks and
  // =XX escapes, and HTML entities such as &amp; and &#46;.
  function decode(s) {
    if (/=\r?\n/.test(s) && /quoted-printable/i.test(s)) {
      s = s.replace(/=\r?\n/g, "").replace(/=([0-9A-F]{2})/g, (m, x) => String.fromCharCode(parseInt(x, 16)));
    }
    return s.replace(/&(?:amp|lt|gt|quot|apos|#(\d{1,5})|#x([0-9a-f]{1,4}));/gi, (m, d, x) =>
      d ? String.fromCharCode(+d) : x ? String.fromCharCode(parseInt(x, 16)) : { "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'" }[m.toLowerCase()]);
  }

  function ipv4Ok(v) { return v.split(".").every((o) => +o <= 255 && !(o.length > 1 && o[0] === "0")); }
  function ipv6Norm(v) {
    try { const h = new URL(`http://[${v}]/`).hostname; return h.slice(1, -1); } catch { return null; }
  }
  function privateIp(t, v) {
    if (t === "ipv4") {
      const [a, b, c] = v.split(".").map(Number);
      return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 192 && b === 0 && (c === 0 || c === 2)) ||
        (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113);
    }
    const x = v.toLowerCase();
    return x === "::" || x === "::1" || /^f[cd]/.test(x) || /^fe[89ab]/.test(x) || /^ff/.test(x) || /^2001:db8(:|$)/.test(x) || x.startsWith("::ffff:");
  }
  // why a domain-like string doesn't count at all (null = it's a domain)
  function domainOk(d) {
    const p = d.split(".");
    if (p.length < 2 || !TLDOK(p[p.length - 1])) return false;
    if (p.some((l) => !l || l.length > 63 || l.startsWith("-") || l.endsWith("-"))) return false;
    return d.length <= 253;
  }
  function domainFlag(d) {
    const p = d.split(".");
    if (p.length === 2 && FILEISH.has(p[1])) return "file";
    if (p.length >= 3 && PKG.has(p[0])) return "package";
    return null;
  }

  // Strip what usually follows a URL in prose: a full stop, comma, closing quote or an unbalanced bracket.
  function trimUrl(u) {
    for (;;) {
      const last = u.slice(-1);
      if (/[.,;:!?'"*>]/.test(last)) { u = u.slice(0, -1); continue; }
      if (last === ")" && (u.match(/\(/g) || []).length < (u.match(/\)/g) || []).length) { u = u.slice(0, -1); continue; }
      if (last === "]" && !u.includes("[")) { u = u.slice(0, -1); continue; }
      return u;
    }
  }
  function urlNorm(u) {
    const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/is.exec(u);
    if (!m) return null;
    let auth = m[2].toLowerCase();
    if (/[^\x00-\x7f]/.test(auth)) { try { auth = new URL(`http://${auth}/`).host; } catch { return null; } } // IDN -> punycode
    const host = auth.replace(/^[^@]*@/, "").replace(/:\d+$/, "");
    if (!host) return null;
    if (/^\[.*\]$/.test(host)) { if (!ipv6Norm(host.slice(1, -1))) return null; }
    else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { if (!ipv4Ok(host)) return null; }
    else if (!domainOk(host.replace(/\.$/, ""))) return null;
    return { value: `${m[1].toLowerCase()}://${auth}${m[3]}`, host: host.replace(/^\[|\]$/g, "").replace(/\.$/, "") };
  }

  const MAX_ITEMS = 5000;
  // -> { items: [{ type, value, count, ctx, flag }], truncated }. flag: null | private | known | file | package
  function extract(input) {
    const text = refangText(decode(String(input || "")));
    const items = new Map();
    let truncated = false;
    const add = (type, value, at, flag = null) => {
      const k = type + "|" + value;
      const it = items.get(k);
      if (it) { it.count++; return; }
      if (items.size >= MAX_ITEMS) { truncated = true; return; }
      const ctx = text.slice(Math.max(0, at - 50), at + value.length + 50).replace(/\s+/g, " ").trim();
      items.set(k, { type, value, count: 1, ctx, flag });
    };
    // URLs, emails and domain-like strings are found on a copy where each match is blanked out once taken, so the
    // domain inside a URL or an email isn't listed again on its own. Hashes are looked for in the full text, so a
    // hash in a sandbox or VirusTotal link still shows up.
    let rest = text, spans = [];
    const blank = (m, off) => spans.push([off, m.length]);
    const masked = () => { // same length as the text, so match positions still point at the context
      const out = []; let at = 0;
      for (const [off, len] of spans.sort((a, b) => a[0] - b[0])) { if (off < at) continue; out.push(rest.slice(at, off), " ".repeat(len)); at = off + len; }
      out.push(rest.slice(at)); spans = [];
      return out.join("");
    };
    for (const m of text.matchAll(/\b(?:https?|ftps?|wss?):\/\/[^\s"'<>`{}|\\^]+/gi)) {
      const raw = trimUrl(m[0]), n = urlNorm(raw);
      blank(m[0], m.index);
      if (!n) continue;
      const ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(n.host) ? "ipv4" : n.host.includes(":") ? "ipv6" : null;
      add("url", n.value, m.index, ip && privateIp(ip, n.host) ? "private" : !ip && WELL_KNOWN.has(reg(n.host)) ? "known" : null);
    }
    rest = masked();
    for (const m of rest.matchAll(/(?<![\w.%+-])[a-z0-9][a-z0-9._%+-]{0,63}@((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?![\w-])/gi)) {
      blank(m[0], m.index);
      if (domainOk(m[1].toLowerCase())) add("email", m[0].toLowerCase(), m.index);
    }
    rest = masked();
    // a domain followed by a path ("evil[.]com/gate.php" in a report) is a URL without its scheme
    for (const m of rest.matchAll(/(?<![\w@.\/:-])((?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62})(\/[^\s"'<>`{}|\\^]*)?(?![\w-])/gi)) {
      const d = m[1].toLowerCase();
      if (!domainOk(d)) continue;
      blank(m[0], m.index);
      const flag = WELL_KNOWN.has(reg(d)) ? "known" : domainFlag(d);
      const path = m[2] ? trimUrl(m[2]) : "";
      if (path.length > 1 && !flag) { const n = urlNorm("http://" + d + path); if (n) { add("url", n.value, m.index); continue; } }
      add("domain", d, m.index, flag);
    }
    rest = masked();
    for (const m of rest.matchAll(/(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w-]|\.\d)/g)) {
      if (ipv4Ok(m[1])) add("ipv4", m[1], m.index, privateIp("ipv4", m[1]) ? "private" : null);
    }
    for (const m of rest.matchAll(/(?<![\w:.])((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})(?![\w:.])/gi)) {
      const c = m[1];
      if (c.length < 3 || !/::|(?:[0-9a-f]{1,4}:){7}/i.test(c) || /^:[^:]|[^:]:$/.test(c)) continue; // 10:30:45 isn't an address
      const v = ipv6Norm(c);
      if (v && v !== "::") add("ipv6", v, m.index, privateIp("ipv6", v) ? "private" : null);
    }
    for (const m of text.matchAll(/(?<![0-9a-z])([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-z])/gi)) {
      const v = m[1].toLowerCase();
      if (/[a-f]/.test(v) && /\d/.test(v) && !/^(.)\1+$/.test(v)) add("hash", v, m.index);
    }
    for (const m of text.matchAll(/\bCVE-\d{4}-\d{4,7}\b/gi)) add("cve", m[0].toUpperCase(), m.index);
    for (const m of text.matchAll(/\bASN?(\d{1,10})\b/g)) if (+m[1] > 0) add("asn", "AS" + m[1], m.index);
    return { items: [...items.values()], truncated };
  }

  // the user's own "always leave out" list: values, domains (which also cover their subdomains) and IPs
  function excluded(list, it) {
    if (!list.size) return false;
    if (list.has(it.value.toLowerCase())) return true;
    let host = it.type === "domain" ? it.value : it.type === "email" ? it.value.split("@").pop() : null;
    if (it.type === "url") { const n = urlNorm(it.value); host = n && n.host; }
    if (!host) return false;
    const p = host.split(".");
    for (let i = 0; i < p.length - 1; i++) if (list.has(p.slice(i).join("."))) return true;
    return false;
  }

  return { extract, refangText, decode, excluded, privateIp, domainOk };
})();

// ------------------------------------------------------------------ dialog
const XT_ORDER = ["url", "domain", "ipv4", "ipv6", "email", "hash", "cve", "asn"];
const XT_REASON = { private: "private IP", known: "well-known", file: "file name?", package: "package name?", mine: "on your list" };
const XS = { items: [], picked: new Map(), types: new Set(), text: null };
const xtStore = {
  get(k, d) { try { const v = localStorage.getItem("arachne.extract." + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("arachne.extract." + k, JSON.stringify(v)); } catch { /* private window */ } },
};
const xtExcl = () => new Set(String($("#extractExclText").value || "").split(/[\s,;]+/).map((s) => XT.refangText(s.trim().toLowerCase()).replace(/^\*\./, "")).filter(Boolean));
function bulkMode() { return $("#bulkMode .on")?.dataset.mode || "list"; }
function setBulkMode(mode, keep = true) {
  $$("#bulkMode button").forEach((b) => b.classList.toggle("on", b.dataset.mode === mode));
  $$("#bulkModal [data-for]").forEach((el) => { el.hidden = el.dataset.for !== mode; });
  $("#bulkModal h2").textContent = mode === "extract" ? "Extract IOCs" : "Bulk scan";
  $("#bulkText").placeholder = mode === "extract" ? $("#bulkText").dataset.phx : $("#bulkText").dataset.phl;
  $("#bulkPreview").classList.toggle("xchips", mode === "extract");
  $("#bulkModal .bulk").classList.toggle("xmode", mode === "extract");
  $("#bulkModal .modal-box").classList.toggle("xwide", mode === "extract");
  if (keep) xtStore.set("mode", mode);
  XS.text = null;
  bulkPreview();
}
// text that reads like an email or a report rather than a list of IOCs
function looksLikeProse(t) {
  const lines = t.split(/\n/).filter((l) => l.trim());
  if (!lines.length) return false;
  const words = lines.reduce((n, l) => n + l.trim().split(/\s+/).length, 0);
  return words / lines.length > 4 || /^(?:received|from|subject|message-id|return-path|dkim-signature):/im.test(t);
}
function xtDefault(it, excl) {
  if (excl && XT.excluded(excl, it)) return "mine";
  if (it.flag === "private" && $("#xtPrivate").checked) return "private";
  if (it.flag === "known" && $("#xtKnown").checked) return "known";
  if (it.flag === "file" || it.flag === "package") return it.flag;
  return null;
}
function extractPreview() {
  const text = $("#bulkText").value, go = $("#bulkGo");
  if (text !== XS.text) {
    XS.text = text;
    const r = XT.extract(text);
    XS.items = r.items.sort((a, b) => XT_ORDER.indexOf(a.type) - XT_ORDER.indexOf(b.type));
    XS.truncated = r.truncated;
    const keys = new Set(r.items.map((it) => it.type + "|" + it.value));
    XS.picked = new Map([...XS.picked].filter(([k]) => keys.has(k)));
  }
  const excl = xtExcl();
  const shown = (it) => !XS.types.size || XS.types.has(it.type);
  for (const it of XS.items) { it.why = xtDefault(it, excl); const k = it.type + "|" + it.value; it.on = XS.picked.has(k) ? XS.picked.get(k) : !it.why; }
  const sel = XS.items.filter((it) => it.on);
  S.bulkSeeds = sel.slice(0, BULK_MAX).map((it) => [it.type, it.value]);
  go.dataset.values = S.bulkSeeds.map(([, v]) => bulkValue(v)).join("\n");
  const counts = {}, on = {};
  for (const it of XS.items) { counts[it.type] = (counts[it.type] || 0) + 1; if (it.on) on[it.type] = (on[it.type] || 0) + 1; }
  $("#bulkPreview").innerHTML = XS.items.length ? XT_ORDER.filter((t) => counts[t]).map((t) => `<button type="button" class="chip${XS.types.size && !XS.types.has(t) ? " off" : ""}" data-xtype="${t}" title="${esc(window.t("Show only {what} (click again to show all)", { what: window.t(CFG.plural[t] || typeLabel(t)) }))}"><i class="dot" style="background:${tc(t)}"></i>${esc(CFG.plural[t] || typeLabel(t))}<em>${on[t] || 0}/${counts[t]}</em></button>`).join("") : "";
  const list = $("#extractList"), rows = XS.items.filter(shown), top = list.scrollTop;
  list.hidden = !XS.items.length;
  list.innerHTML = XS.items.length ? `<div class="xl-tools"><span>${rows.length} shown</span><button type="button" class="btn xs ghost" data-xall="1">Tick all</button><button type="button" class="btn xs ghost" data-xall="0">Untick all</button></div>` +
    rows.slice(0, 1500).map((it) => {
      const k = esc(it.type + "|" + it.value);
      return `<label class="xrow${it.on ? "" : " off"}" title="${esc(it.ctx)}"><input type="checkbox" data-xk="${k}"${it.on ? " checked" : ""}>` +
        `<i class="dot" style="background:${tc(it.type)}"></i><span class="xty" style="color:${tc(it.type)}">${esc(typeLabel(it.type))}</span>` +
        `<span class="xv mono">${esc(it.value)}</span>${it.why ? `<span class="tag xwhy">${esc(window.t(XT_REASON[it.why]))}</span>` : ""}${it.count > 1 ? `<em>×${it.count}</em>` : ""}` +
        `${it.why === "mine" ? "" : `<button type="button" class="icon-btn xs" data-xex="${k}" title="Always leave this out"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/></svg></button>`}</label>`;
    }).join("") + (rows.length > 1500 ? `<p class="msg">…and ${rows.length - 1500} more (filter by type to see them)</p>` : "") : "";
  list.scrollTop = top;
  const left = XS.items.length - sel.length, why = {};
  for (const it of XS.items) if (!it.on && it.why) why[it.why] = (why[it.why] || 0) + 1;
  $("#bulkInfo").textContent = !text.trim() ? "" : !XS.items.length ? window.t("No IOCs found in this text") : [
    window.t(XS.items.length === 1 ? "{n} IOC found" : "{n} IOCs found", { n: XS.items.length }), window.t("{n} ticked", { n: sel.length }),
    left ? window.t("{n} left out", { n: left }) + (Object.keys(why).length ? ` (${Object.entries(why).map(([w, n]) => `${n} ${window.t(XT_REASON[w])}`).join(", ")})` : "") : "",
    sel.length > BULK_MAX ? window.t("only the first {n} will be scanned", { n: BULK_MAX }) : "", XS.truncated ? window.t("list cut at 5,000") : ""].filter(Boolean).join(" · ");
  $("#extractExcl summary em").textContent = excl.size ? `(${excl.size})` : "";
  $("#xtCopy").disabled = $("#xtCopyDef").disabled = !sel.length;
  go.disabled = !S.bulkSeeds.length;
  go.textContent = S.bulkSeeds.length ? `Scan ${S.bulkSeeds.length} IOC${S.bulkSeeds.length === 1 ? "" : "s"}` : "Scan";
}
// /api/scan splits its input on new lines, commas and semicolons, so a URL keeps those percent-encoded
function bulkValue(v) { return /^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? v.replace(/,/g, "%2C").replace(/;/g, "%3B") : v; }
function xtCopy(defanged) {
  const v = XS.items.filter((it) => it.on).map((it) => defanged ? defang(it.value, it.type) : it.value);
  navigator.clipboard.writeText(v.join("\n")).then(() => toast(`Copied ${v.length}${defanged ? " defanged" : ""} IOC${v.length === 1 ? "" : "s"}`), () => toast("Copy failed", "error"));
}
function xtExclude(k) {
  const it = XS.items.find((x) => x.type + "|" + x.value === k);
  if (!it) return;
  let v = it.value;
  if (it.type === "url") v = (/^[a-z]+:\/\/([^/?#:]+)/i.exec(v) || [])[1] || v;
  const ta = $("#extractExclText");
  ta.value = (ta.value.trim() ? ta.value.trim() + "\n" : "") + v;
  xtStore.set("exclude", ta.value);
  XS.picked.delete(k);
  toast(window.t("{value} will be left out from now on", { value: v }));
  extractPreview();
}
function bindExtract() {
  const ta = $("#bulkText");
  ta.dataset.phl = ta.placeholder;
  ta.dataset.phx = "Paste an email (headers too), a threat report, logs or a web page…";
  $("#extractExclText").value = xtStore.get("exclude", "");
  $("#xtPrivate").checked = xtStore.get("private", true);
  $("#xtKnown").checked = xtStore.get("known", true);
  $("#bulkMode").onclick = (e) => { const b = e.target.closest("[data-mode]"); if (b) setBulkMode(b.dataset.mode); };
  ta.addEventListener("paste", () => setTimeout(() => {
    if (bulkMode() === "list" && looksLikeProse(ta.value)) { setBulkMode("extract"); toast("That looks like an email or a report, so ARACHNE is extracting the IOCs from it"); }
  }, 0));
  $("#xtPrivate").onchange = (e) => { xtStore.set("private", e.target.checked); XS.picked.clear(); extractPreview(); };
  $("#xtKnown").onchange = (e) => { xtStore.set("known", e.target.checked); XS.picked.clear(); extractPreview(); };
  $("#extractExclText").oninput = debounce(() => { xtStore.set("exclude", $("#extractExclText").value); extractPreview(); }, 300);
  $("#xtCopy").onclick = () => xtCopy(false);
  $("#xtCopyDef").onclick = () => xtCopy(true);
  $("#bulkPreview").addEventListener("click", (e) => {
    const c = e.target.closest("[data-xtype]");
    if (!c) return;
    const t = c.dataset.xtype;
    if (XS.types.size === 1 && XS.types.has(t)) XS.types.clear(); else { XS.types.clear(); XS.types.add(t); }
    extractPreview();
  });
  $("#extractList").addEventListener("click", (e) => {
    const x = e.target.closest("[data-xex]");
    if (x) { e.preventDefault(); return xtExclude(x.dataset.xex); }
    const a = e.target.closest("[data-xall]");
    if (a) {
      for (const it of XS.items) if (!XS.types.size || XS.types.has(it.type)) XS.picked.set(it.type + "|" + it.value, a.dataset.xall === "1");
      extractPreview();
    }
  });
  $("#extractList").addEventListener("change", (e) => {
    const k = e.target.dataset.xk;
    if (k) { XS.picked.set(k, e.target.checked); extractPreview(); }
  });
  setBulkMode(xtStore.get("mode", "list"), false);
}
function openExtract() { setBulkMode("extract"); openBulk(); }
