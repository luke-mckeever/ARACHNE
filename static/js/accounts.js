"use strict";
/* Accounts found: turns "account" indicators (a profile a username or email has on some platform) into
   platform cards with the platform's icon, and gives account nodes in the graph the same icon.
   Icons are bundled (static/js/platform-icons.js, Simple Icons, CC0) so nothing is fetched from the
   platforms themselves: works offline and under a strict Content-Security-Policy. Platforms without an
   icon get a letter tile in their brand colour (or a colour picked from the name). */
(() => {
  const root = typeof window !== "undefined" ? window : globalThis;
  const LIST = root.PLATFORM_ICONS || [];
  const key = (s) => String(s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const INDEX = new Map();
  for (const p of LIST) for (const k of p.k || []) if (!INDEX.has(k)) INDEX.set(k, p);

  const TLDS = new Set(["com", "org", "net", "io", "me", "app", "co", "uk", "fm", "to", "tv", "gg", "dev", "social", "ru", "de", "jp", "cc", "xyz", "site", "info"]);
  function hostKeys(url) {
    let host;
    try { host = new URL(url).hostname.toLowerCase().replace(/^www\./, ""); } catch { return []; }
    const parts = host.split(".");
    const out = [key(host)];
    // second-level label first (news.ycombinator.com -> ycombinator, user.blogspot.com -> blogspot), then the rest
    for (let i = parts.length - 2; i >= 0; i--) if (!TLDS.has(parts[i]) || i === 0) out.push(key(parts[i]));
    return out;
  }
  const pretty = (s) => String(s).replace(/_/g, " ").replace(/\s+/g, " ").trim().replace(/^\w/, (c) => c.toUpperCase());

  // { name, handle, hex, path (null = letter tile), known } for an account node ({ value: profile URL, label: "Platform: handle" })
  function match(node) {
    const label = String(node?.label || ""), url = String(node?.value || "");
    const cut = label.indexOf(": ");
    const site = cut > 0 ? label.slice(0, cut) : "";
    let handle = cut > 0 ? label.slice(cut + 2) : label && label !== url ? label : "";
    if (!handle) {
      try { const u = new URL(url); handle = decodeURIComponent(u.pathname.split("/").filter(Boolean).pop() || u.searchParams.get("id") || u.hostname); } catch { handle = url; }
    }
    let p = site && INDEX.get(key(site));
    if (!p) for (const k of hostKeys(url)) if ((p = INDEX.get(k))) break;
    if (p) return { name: p.n, handle, hex: "#" + p.h, path: p.p || null, known: true };
    let name = site ? pretty(site) : "";
    if (!name) { try { name = new URL(url).hostname.replace(/^www\./, ""); } catch { name = "Account"; } }
    return { name, handle, hex: hueColour(name), path: null, known: false };
  }
  function hueColour(s) {
    let h = 0;
    for (const c of String(s)) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    return hslHex(h % 360, 0.5, 0.42);
  }
  function hslHex(h, s, l) {
    const f = (n) => { const k = (n + h / 30) % 12, a = s * Math.min(l, 1 - l); return Math.round(255 * (l - a * Math.max(-1, Math.min(k - 3, 9 - k, 1)))).toString(16).padStart(2, "0"); };
    return "#" + f(0) + f(8) + f(4);
  }
  // dark ink on light brand colours (Snapchat yellow), white on everything else
  function ink(hex) {
    const v = parseInt(String(hex).replace("#", ""), 16);
    const [r, g, b] = [v >> 16 & 255, v >> 8 & 255, v & 255].map((c) => { c /= 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.45 ? "#111114" : "#ffffff";
  }
  const escA = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const letter = (name) => (String(name).match(/[\p{L}\p{N}]/u) || ["?"])[0].toUpperCase();
  // the path data is ours (generated file), the colours are validated hex - safe to put in markup
  const safeHex = (h) => (/^#[0-9a-f]{6}$/i.test(h) ? h : "#55555e");

  // icon tile as HTML (cards)
  function iconHTML(m, cls = "") {
    const bg = safeHex(m.hex), fg = ink(bg);
    const inner = m.path
      ? `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="${escA(m.path)}"/></svg>`
      : `<b>${escA(letter(m.name))}</b>`;
    return `<span class="pf-ic ${cls}" style="background:${bg};color:${fg}" aria-hidden="true">${inner}</span>`;
  }
  // icon as an image for the graph (Cytoscape background-image)
  const imgCache = new Map();
  function graphImage(m) {
    const ck = m.name + m.hex;
    if (!imgCache.has(ck)) {
      const bg = safeHex(m.hex), fg = ink(bg);
      const glyph = m.path
        ? `<path transform="translate(24 24) scale(2.1667)" fill="${fg}" d="${escA(m.path)}"/>`
        : `<text x="50" y="54" font-family="Inter,Segoe UI,Arial,sans-serif" font-weight="700" font-size="48" fill="${fg}" text-anchor="middle" dominant-baseline="middle">${escA(letter(m.name))}</text>`;
      const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><circle cx="50" cy="50" r="50" fill="${bg}"/>${glyph}</svg>`;
      imgCache.set(ck, "data:image/svg+xml;utf8," + encodeURIComponent(svg));
    }
    return imgCache.get(ck);
  }

  const api = { match, iconHTML, graphImage, ink, count: LIST.length };
  root.Accounts = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})();
