"use strict";
/* ARACHNE interface languages.

   The page is written in English. When another language is chosen, this script loads /i18n/<lang>.json
   (an object of "English text": "translation") and translates the page as it is drawn: text, and the
   title / placeholder / aria-label attributes. Keys can hold:
     {name}        a placeholder for any text, e.g. "via {src}": "vía {src}"; {a} {b} {c} {d} {n} {m} only
                   match numbers, e.g. "{n} links": "{n} enlaces"
     <0>..</0>     an inline element inside a sentence (the first child element is <0>, the next <1>, ...),
                   e.g. "Click <0>Pivot</0> to look it up": "Haz clic en <0>Pivot</0> para buscarlo"
   Indicator values, source data, logs and code are never translated (see SKIP).
   Scripts can call t("English text", { name: value }) for text that isn't in the page, such as dialogs.
   The choice is kept in the browser (localStorage "arachne.lang"); with none, the browser's language is used. */
(() => {
  const LANGS = [
    ["en", "English"], ["es", "Español"], ["de", "Deutsch"], ["fr", "Français"], ["pt", "Português"],
    ["it", "Italiano"], ["nl", "Nederlands"], ["pl", "Polski"], ["ja", "日本語"], ["zh", "简体中文"], ["ko", "한국어"],
  ];
  const CODES = LANGS.map((l) => l[0]);
  const KEY = "arachne.lang";
  const store = { get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch { /* private mode */ } } };

  function browserLang() {
    for (const l of navigator.languages || [navigator.language || "en"]) {
      const base = String(l).toLowerCase().split("-")[0];
      if (CODES.includes(base)) return base;
    }
    return "en";
  }
  const chosen = store.get(KEY);
  const lang = CODES.includes(chosen) ? chosen : browserLang();
  const debug = store.get("arachne.i18n.debug") === "1";
  document.documentElement.lang = lang;

  // ---- dictionary: loaded synchronously so text drawn by the first scripts is already translated
  const exact = new Map(), pats = [];
  let loaded = false;
  const NUM = new Set(["a", "b", "c", "d", "n", "m"]);   // these placeholders only match numbers
  const norm = (s) => s.replace(/\s+/g, " ").trim();
  if (lang !== "en") {
    try {
      const x = new XMLHttpRequest();
      const v = (document.currentScript && /[?&]v=([^&]+)/.exec(document.currentScript.src)) || null;
      x.open("GET", `/i18n/${lang}.json${v ? "?v=" + v[1] : ""}`, false);
      x.send();
      if (x.status === 200) {
        const d = JSON.parse(x.responseText);
        for (const [k, val] of Object.entries(d)) {
          if (k.startsWith("_") || typeof val !== "string" || !val) continue;
          const nk = norm(k);
          if (/\{\w+\}/.test(nk)) {
            const names = [];
            const re = nk.split(/(\{\w+\})/).map((part) => {
              const m = /^\{(\w+)\}$/.exec(part);
              if (m) { names.push(m[1]); return NUM.has(m[1]) ? "(\\d[\\d.,]*)" : "(.+?)"; }
              return part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
            }).join("");
            pats.push({ re: new RegExp("^" + re + "$", "s"), names, to: val });
          }
          exact.set(nk, val);
        }
        loaded = true;
      }
    } catch (e) { console.warn("ARACHNE: language file not loaded", e); }
  }
  const active = (loaded && (exact.size || pats.length)) || debug;

  const missing = new Set();
  const miss = new Map();          // text with no translation (bounded, so lookups stay cheap)
  function lookup(s) {
    const e = exact.get(s);
    if (e !== undefined) return e;
    if (miss.has(s)) return null;
    for (const p of pats) {
      const m = p.re.exec(s);
      if (m) {
        let out = p.to;
        p.names.forEach((n, i) => { out = out.split("{" + n + "}").join(exact.get(m[i + 1]) ?? m[i + 1]); });
        return out;
      }
    }
    if (miss.size > 4000) miss.clear();
    miss.set(s, 1);
    if (debug) missing.add(s);
    return null;
  }
  function fill(s, vars) {
    if (vars) for (const [k, v] of Object.entries(vars)) s = s.split("{" + k + "}").join(String(v));
    return s;
  }
  // t("English", {vars}) -> translated text
  function t(s, vars) {
    const k = norm(String(s));
    let out = null;
    if (active && /\p{L}/u.test(k)) {
      if (vars) out = exact.get(k) ?? null;          // with vars the key keeps its {placeholders}
      else out = lookup(k);
    }
    return fill(out ?? String(s), vars);
  }

  // ---- translating the page
  const SKIP = "script,style,textarea,pre,code,kbd,samp,svg,.mono,.notranslate,[translate=no],[contenteditable],.d-val,.val,.tag,.log-line,#logLast,.raw,.kv dd,.tbl td,.src-msg";
  const ATTRS = ["title", "placeholder", "aria-label"];
  const LEAF_OK = /^(B|I|EM|STRONG|SPAN|A|SMALL|U|SUB|SUP|CODE|KBD|MARK|BR)$/;
  const hasLetters = (s) => /\p{L}/u.test(s);

  function trTextNode(node) {
    const raw = node.nodeValue;
    if (!raw || !hasLetters(raw)) return;
    const s = norm(raw);
    const tr = lookup(s);
    if (tr != null && tr !== s) {
      const lead = /^\s*/.exec(raw)[0], trail = /\s*$/.exec(raw)[0];
      node.nodeValue = lead + tr + trail;
    }
  }
  function trAttrs(el) {
    for (const a of ATTRS) {
      const v = el.getAttribute(a);
      if (v && hasLetters(v)) { const tr = lookup(norm(v)); if (tr != null && tr !== v) el.setAttribute(a, tr); }
    }
    if (el.tagName === "INPUT" && (el.type === "button" || el.type === "submit") && el.value && hasLetters(el.value)) {
      const tr = lookup(norm(el.value)); if (tr != null) el.value = tr;
    }
  }
  // a sentence with inline elements: "Click <0>Pivot</0> to ..." - the elements are kept (with their
  // listeners), only moved and given their translated text
  function trMixed(el) {
    const kids = [...el.childNodes];
    let key = "", idx = 0, words = false, inner = false;
    const els = [];
    for (const k of kids) {
      if (k.nodeType === 3) { key += k.nodeValue; if (hasLetters(k.nodeValue)) words = true; }
      else if (k.nodeType === 1) {
        if (!LEAF_OK.test(k.tagName) || k.firstElementChild) return false;
        if (k.tagName === "BR" || !k.textContent.trim()) { key += `<${idx}/>`; }
        else { key += `<${idx}>${k.textContent}</${idx}>`; if (hasLetters(k.textContent)) inner = true; }
        els.push(k); idx++;
      } else if (k.nodeType !== 8) return false;
    }
    if (!words || !inner) return false;
    const tr = lookup(norm(key));
    if (tr == null) return false;
    const frag = document.createDocumentFragment();
    const re = /<(\d+)\/>|<(\d+)>([\s\S]*?)<\/\2>/g;
    let last = 0, m;
    const used = new Set();
    while ((m = re.exec(tr))) {
      if (m.index > last) frag.appendChild(document.createTextNode(tr.slice(last, m.index)));
      const i = +(m[1] ?? m[2]), node = els[i];
      if (node && !used.has(i)) {
        used.add(i);
        if (m[3] !== undefined && node.textContent !== m[3]) node.textContent = m[3];
        frag.appendChild(node);
      }
      last = re.lastIndex;
    }
    if (last < tr.length) frag.appendChild(document.createTextNode(tr.slice(last)));
    el.replaceChildren(frag);
    return true;
  }
  function walk(el) {
    if (el.nodeType === 3) { trTextNode(el); return; }
    if (el.nodeType !== 1) return;
    if (el.tagName === "SELECT" && el.hasAttribute("data-i18n-picker")) fillPicker(el);
    if (!active) { el.querySelectorAll?.("select[data-i18n-picker]").forEach(fillPicker); return; }
    if (el.matches(SKIP)) return;
    trAttrs(el);
    let mixed = false;
    if (el.firstElementChild && el.firstChild !== el.lastChild) mixed = trMixed(el);
    for (const c of [...el.childNodes]) {
      if (c.nodeType === 3) { if (!mixed) trTextNode(c); }
      else if (c.nodeType === 1) walk(c);
    }
  }
  const skipped = (node) => {
    const p = node.nodeType === 1 ? node : node.parentElement;
    return !p || !!p.closest(SKIP);
  };

  // ---- language pickers: any <select data-i18n-picker> gets the list and switches language on change
  function fillPicker(sel) {
    if (sel.dataset.i18nFilled) return;
    sel.dataset.i18nFilled = "1";
    sel.classList.add("notranslate");
    sel.setAttribute("translate", "no");
    if (!sel.getAttribute("aria-label")) sel.setAttribute("aria-label", t("Language"));
    sel.innerHTML = "";
    const auto = sel.hasAttribute("data-i18n-auto"), picked = CODES.includes(store.get(KEY));
    if (auto) {
      const o = document.createElement("option");
      o.value = "auto"; o.textContent = t("Follow the browser");
      if (!picked) o.selected = true;
      sel.appendChild(o);
    }
    for (const [c, name] of LANGS) {
      const o = document.createElement("option");
      o.value = c; o.textContent = name; o.lang = c;
      if (c === lang && (picked || !auto)) o.selected = true;
      sel.appendChild(o);
    }
  }
  document.addEventListener("change", (e) => {
    const sel = e.target.closest?.("select[data-i18n-picker]");
    if (sel) sel.value === "auto" ? (CODES.includes(store.get(KEY)) && (store.set(KEY, null), location.reload())) : setLang(sel.value);
  });
  function setLang(code) {
    if (!CODES.includes(code) || (code === lang && store.get(KEY) === code)) return;
    store.set(KEY, code);
    location.reload();
  }

  // ---- watch the page: everything drawn later (reports, dialogs, toasts) is translated as it appears
  const obs = new MutationObserver((recs) => {
    for (const r of recs) {
      if (r.type === "childList") {
        for (const n of r.addedNodes) {
          if (n.nodeType === 3) { if (active && !skipped(n)) trTextNode(n); }
          else if (n.nodeType === 1 && !(active && n.parentElement && skipped(n.parentElement))) walk(n);
        }
      } else if (!active) continue;
      else if (r.type === "characterData") { if (!skipped(r.target)) trTextNode(r.target); }
      else if (r.type === "attributes" && !skipped(r.target)) trAttrs(r.target);
    }
    obs.takeRecords();   // our own changes
  });
  obs.observe(document.documentElement, { childList: true, subtree: true, characterData: active, attributes: active, attributeFilter: active ? ATTRS : undefined });
  document.addEventListener("DOMContentLoaded", () => { walk(document.body); obs.takeRecords(); });

  window.t = t;
  window.I18N = {
    lang, langs: LANGS.slice(), set: setLang, t,
    // the chosen language, or "" when following the browser
    choice: () => (CODES.includes(store.get(KEY)) ? store.get(KEY) : ""),
    auto: () => { store.set(KEY, null); location.reload(); },
    translate: (el) => walk(el || document.body),
    missing: () => [...missing].sort(),
  };
})();
