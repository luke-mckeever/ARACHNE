"use strict";
/* ARACHNE detection rules: turn the IOCs of a scan into Sigma, YARA, Suricata, Snort rules and Splunk, Microsoft Sentinel
   and Elastic queries that can be copied into other tools. Runs in the browser; nothing is sent anywhere.

   Every value is checked against a strict pattern for its type before it goes into a rule, and escaped for the rule
   language, so an odd value from a source (quotes, semicolons, new lines) can't break or change a rule. Values that
   don't pass are left out and listed. The rules match the real (refanged) values; titles, messages and comments show
   the defanged form, so nothing in them is clickable. */
(function (root) {
  const TYPES = ["ipv4", "ipv6", "domain", "url", "hash", "email"];
  const FORMATS = [
    { id: "sigma", label: "Sigma", ext: "yml", mime: "application/yaml", covers: ["ipv4", "ipv6", "domain", "url", "hash"],
      hint: "Sigma rules (one per indicator type). Convert them for your SIEM with sigma-cli or pySigma." },
    { id: "yara", label: "YARA", ext: "yar", mime: "text/plain", covers: ["hash", "domain", "url", "ipv4", "ipv6", "email"],
      hint: "YARA rules: file hashes (hash module) and the indicators as strings inside files or memory." },
    { id: "suricata", label: "Suricata", ext: "rules", mime: "text/plain", covers: ["ipv4", "ipv6", "domain", "url", "hash"],
      hint: "Suricata 6/7 rules. Change the SID range if it clashes with your own rules." },
    { id: "snort", label: "Snort 2.9", ext: "rules", mime: "text/plain", covers: ["ipv4", "ipv6", "domain", "url"],
      hint: "Snort 2.9 rules (Snort 3 can load them after snort2lua). Snort 2 has no file hash rules." },
    { id: "splunk", label: "Splunk SPL", ext: "spl", mime: "text/plain", covers: TYPES,
      hint: "One Splunk search using CIM field names. Narrow index=* to your own indexes." },
    { id: "sentinel", label: "Sentinel KQL", ext: "kql", mime: "text/plain", covers: TYPES,
      hint: "Microsoft Sentinel / Defender XDR hunting query (KQL). Tables you don't have are skipped." },
    { id: "elastic", label: "Elastic KQL", ext: "txt", mime: "text/plain", covers: TYPES,
      hint: "Kibana Query Language with ECS field names, for Discover or a custom query rule." },
  ];
  const TYPE_LABEL = { ipv4: "IPv4 address", ipv6: "IPv6 address", domain: "Domain", url: "URL", hash: "File hash", email: "Email address" };
  // "3 IPv4 addresses", "1 file hash"
  const countOf = (t, n) => { const l = TYPE_LABEL[t].replace(/^(Domain|File|Email)/, (w) => w.toLowerCase()); return `${n} ${n === 1 ? l : l.replace(/(ss|sh)$/, "$1e") + "s"}`; };
  const HASH_KIND = { 32: "md5", 40: "sha1", 64: "sha256" };

  // ------------------------------------------------------------ checking values
  const RE_LABEL = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;
  function okDomain(d) {
    if (!d || d.length > 253 || !d.includes(".")) return false;
    const parts = d.split(".");
    if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(parts[parts.length - 1])) return false;
    return parts.every((p) => RE_LABEL.test(p));
  }
  function okIPv4(v) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
    return !!m && m.slice(1).every((o) => +o <= 255 && (o === "0" || o[0] !== "0"));
  }
  function okIPv6(v) {
    if (!/^[0-9a-f:.]{2,45}$/.test(v) || !v.includes(":") || (v.match(/::/g) || []).length > 1) return false;
    let groups = v.split(":");
    const last = groups[groups.length - 1];
    if (last.includes(".")) { if (!okIPv4(last)) return false; groups = groups.slice(0, -1).concat(["0", "0"]); }
    if (groups.some((g) => g.length > 4)) return false;
    const filled = groups.filter((g) => g !== "").length;
    return v.includes("::") ? filled < 8 : groups.length === 8 && filled === 8;
  }
  const PRINTABLE = /^[\x21-\x7e\u00a0-\uffff]+$/; // no spaces, tabs, new lines or control characters
  // URL: scheme, host (with optional user info / port), the rest (path, query, fragment)
  function splitUrl(v) {
    const m = /^(https?|ftp):\/\/([^/?#]+)([/?#].*)?$/i.exec(v);
    if (!m || !PRINTABLE.test(v)) return null;
    let host = m[2].slice(m[2].lastIndexOf("@") + 1).toLowerCase(), port = "";
    const pm = /^(\[[0-9a-f:.]+\]|[^:]+)(?::(\d{1,5}))?$/.exec(host);
    if (!pm) return null;
    host = pm[1]; port = pm[2] || "";
    const bare = host.replace(/^\[|\]$/g, "");
    const kind = okIPv4(bare) ? "ipv4" : okIPv6(bare) ? "ipv6" : okDomain(host) ? "domain" : null;
    if (!kind) return null;
    const path = (m[3] || "").replace(/#.*$/, "");
    return { scheme: m[1].toLowerCase(), host: bare, hostKind: kind, port, path };
  }
  // One clean indicator, or null. Values come from the scanner already normalised and refanged; this is a guard.
  function clean(type, value) {
    let v = String(value ?? "").trim();
    if (!v || v.length > 2048) return null;
    if (type === "ipv4") return okIPv4(v) ? { type, value: v } : null;
    if (type === "ipv6") { v = v.toLowerCase().replace(/^\[|\]$/g, ""); return okIPv6(v) ? { type, value: v } : null; }
    if (type === "domain") { v = v.toLowerCase().replace(/\.$/, ""); return okDomain(v) ? { type, value: v } : null; }
    if (type === "hash") { v = v.toLowerCase(); const k = /^[0-9a-f]+$/.test(v) && HASH_KIND[v.length]; return k ? { type, value: v, kind: k } : null; }
    if (type === "email") {
      v = v.toLowerCase().replace(/^mailto:/, "");
      const i = v.lastIndexOf("@");
      return i > 0 && /^[a-z0-9.!#$%&*+/=?^_`{|}~-]{1,64}$/.test(v.slice(0, i)) && okDomain(v.slice(i + 1)) ? { type, value: v } : null;
    }
    if (type === "url") { const u = splitUrl(v); return u ? { type, value: v, url: u } : null; }
    return null;
  }

  // ------------------------------------------------------------ helpers
  function defang(v, type) {
    v = String(v);
    const dots = (x) => x.replace(/\./g, "[.]");
    if (type === "url") {
      const m = /^([a-z][a-z0-9+.\-]*):\/\/([^/?#]*)(.*)$/is.exec(v);
      return m ? `${m[1].replace(/^http/i, "hxxp").replace(/^ftp/i, "fxp")}://${dots(m[2])}${m[3]}` : v;
    }
    if (type === "email") { const i = v.lastIndexOf("@"); return i < 0 ? v : v.slice(0, i) + "[@]" + dots(v.slice(i + 1)); }
    if (type === "ipv6") return v.replace(/:/g, "[:]");
    if (type === "ipv4" || type === "domain") return dots(v);
    return v;
  }
  // a 128-bit hash of a string, as a version-4-shaped UUID: the same IOCs give the same rule IDs every time
  function uuidOf(str) {
    let h1 = 1779033703, h2 = 3144134277, h3 = 1013904242, h4 = 2773480762;
    for (let i = 0; i < str.length; i++) {
      const k = str.charCodeAt(i);
      h1 = h2 ^ Math.imul(h1 ^ k, 597399067); h2 = h3 ^ Math.imul(h2 ^ k, 2869860233);
      h3 = h4 ^ Math.imul(h3 ^ k, 951274213); h4 = h1 ^ Math.imul(h4 ^ k, 2716044179);
    }
    h1 = Math.imul(h3 ^ (h1 >>> 18), 597399067); h2 = Math.imul(h4 ^ (h2 >>> 22), 2869860233);
    h3 = Math.imul(h1 ^ (h3 >>> 17), 951274213); h4 = Math.imul(h2 ^ (h4 >>> 19), 2716044179);
    const hex = [h1 ^ h2 ^ h3 ^ h4, h2 ^ h1, h3 ^ h1, h4 ^ h1].map((x) => (x >>> 0).toString(16).padStart(8, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-${"89ab"[parseInt(hex[16], 16) & 3]}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
  }
  const utf8 = (s) => (typeof TextEncoder !== "undefined" ? [...new TextEncoder().encode(s)] : [...Buffer.from(s, "utf8")]);
  const hex2 = (b) => b.toString(16).padStart(2, "0").toUpperCase();
  // text that is safe in a comment or message: printable ASCII, nothing a rule language treats specially
  const plain = (s, max = 160) => {
    s = String(s).replace(/[^\x20-\x7e]/g, "?").replace(/["'\\;|`]/g, "_").replace(/\*\//g, "*_");
    return s.length > max ? s.slice(0, max - 3) + "..." : s;
  };
  const dateParts = (d) => [d.getUTCFullYear(), String(d.getUTCMonth() + 1).padStart(2, "0"), String(d.getUTCDate()).padStart(2, "0")];
  const verdictOf = (list) => (list.some((i) => i.verdict === "malicious") ? "malicious" : list.some((i) => i.verdict === "suspicious") ? "suspicious" : "");
  const note = (i) => [i.verdict, i.score !== null && i.score !== undefined && i.score !== "" ? `risk ${i.score}` : ""].filter(Boolean).join(", ");

  // ------------------------------------------------------------ input
  // iocs: [{ type, value, verdict?, score? }]. Returns the indicators by type, plus what was left out.
  function prepare(iocs) {
    const by = Object.fromEntries(TYPES.map((t) => [t, []])), seen = new Set(), unsupported = {}, invalid = [];
    for (const raw of iocs || []) {
      if (!raw || !raw.type) continue;
      if (!TYPES.includes(raw.type)) { unsupported[raw.type] = (unsupported[raw.type] || 0) + 1; continue; }
      const c = clean(raw.type, raw.value);
      if (!c) { invalid.push({ type: raw.type, value: plain(raw.value, 80) }); continue; }
      const k = c.type + "|" + c.value;
      if (seen.has(k)) continue;
      seen.add(k);
      by[c.type].push({ ...c, verdict: raw.verdict || "", score: raw.score ?? null });
    }
    return { by, unsupported, invalid, count: seen.size };
  }

  // ------------------------------------------------------------ Sigma
  const yq = (s) => "'" + String(s).replace(/'/g, "''") + "'";
  const sigmaVal = (s) => yq(String(s).replace(/\\/g, "\\\\").replace(/\*/g, "\\*").replace(/\?/g, "\\?"));
  function sigmaRule(ctx, key, title, desc, logsource, detection, fps, tags, items) {
    const level = verdictOf(items) === "malicious" ? "high" : "medium";
    const lines = [
      `title: ${yq(title)}`,
      `id: ${uuidOf("sigma|" + key + "|" + items.map((i) => i.value).sort().join(","))}`,
      "status: experimental",
      `description: ${yq(desc)}`,
      `author: ${yq(ctx.author)}`,
      `date: ${ctx.date}`,
      "tags:", ...tags.map((t) => `    - ${t}`),
      "logsource:", ...Object.entries(logsource).map(([k, v]) => `    ${k}: ${v}`),
      "detection:", ...detection,
      "falsepositives:", ...fps.map((f) => `    - ${yq(f)}`),
      `level: ${level}`,
    ];
    return items.map((i) => `# ${plain(defang(i.value, i.type))}${note(i) ? ` (${note(i)})` : ""}`).join("\n") + "\n" + lines.join("\n");
  }
  function sigma(P, ctx) {
    const out = [], src = ctx.source;
    const ips = [...P.by.ipv4, ...P.by.ipv6];
    if (ips.length) out.push(sigmaRule(ctx, "ip", `ARACHNE - connection to flagged IP addresses (${src})`,
      `Network connections to ${ips.length} IP address${ips.length === 1 ? "" : "es"} that ARACHNE flagged (${src}).`,
      { category: "network_connection" },
      ["    selection:", "        DestinationIp:", ...ips.map((i) => `            - ${sigmaVal(i.value)}`), "    condition: selection"],
      ["Shared hosting, CDN or cloud addresses that also serve legitimate sites"], ["attack.command-and-control", "attack.t1071"], ips));
    const doms = P.by.domain;
    if (doms.length) out.push(sigmaRule(ctx, "domain", `ARACHNE - DNS lookup of flagged domains (${src})`,
      `DNS queries for ${doms.length} domain${doms.length === 1 ? "" : "s"} (and their subdomains) that ARACHNE flagged (${src}).`,
      { category: "dns_query" },
      ["    selection_domain:", "        QueryName:", ...doms.map((i) => `            - ${sigmaVal(i.value)}`),
        "    selection_subdomain:", "        QueryName|endswith:", ...doms.map((i) => `            - ${sigmaVal("." + i.value)}`),
        "    condition: 1 of selection_*"],
      ["Legitimate use of a domain that was compromised or shares infrastructure"], ["attack.command-and-control", "attack.t1071.004"], doms));
    const urls = P.by.url;
    if (urls.length) {
      const det = [];
      urls.forEach((i, n) => {
        det.push(`    selection_url${n + 1}:`, `        cs-host: ${sigmaVal(i.url.host)}`);
        if (i.url.path && i.url.path !== "/") det.push(`        c-uri|contains: ${sigmaVal(i.url.path)}`);
      });
      det.push("    condition: 1 of selection_url*");
      out.push(sigmaRule(ctx, "url", `ARACHNE - web request to flagged URLs (${src})`,
        `Proxy requests to ${urls.length} URL${urls.length === 1 ? "" : "s"} that ARACHNE flagged (${src}). HTTPS URLs are only visible with TLS inspection.`,
        { category: "proxy" }, det, ["A legitimate page on the same host and path"], ["attack.command-and-control", "attack.t1071.001"], urls));
    }
    const hs = P.by.hash;
    if (hs.length) out.push(sigmaRule(ctx, "hash", `ARACHNE - process started from a flagged file (${src})`,
      `A process whose file hash ARACHNE flagged (${src}) was started (Sysmon-style Hashes field: MD5=, SHA1=, SHA256=).`,
      { category: "process_creation", product: "windows" },
      ["    selection:", "        Hashes|contains:", ...hs.map((i) => `            - ${sigmaVal(i.kind.toUpperCase() + "=" + i.value)}`), "    condition: selection"],
      ["Unlikely"], ["attack.execution", "attack.t1204.002"], hs));
    if (!out.length) return "";
    return `# Sigma rules generated by ARACHNE from "${plain(src)}" on ${ctx.date}. Test them before turning on alerts.\n` + out.join("\n---\n") + "\n";
  }

  // ------------------------------------------------------------ YARA
  // a YARA text string: printable ASCII as is (with \\ and \"), everything else as \xHH
  const yaraStr = (s) => '"' + utf8(String(s)).map((b) => (b === 0x22 ? '\\"' : b === 0x5c ? "\\\\" : b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "\\x" + hex2(b))).join("") + '"';
  function yara(P, ctx) {
    const meta = (desc) => ["    meta:", `        description = ${yaraStr(desc)}`, `        author = ${yaraStr(ctx.author)}`,
      `        date = ${yaraStr(ctx.date)}`, `        source = ${yaraStr("ARACHNE: " + plain(ctx.source, 200))}`];
    const rules = [], name = ctx.ruleName, src = plain(ctx.source);
    const hs = P.by.hash;
    if (hs.length) {
      rules.push([`rule ${name}_file_hashes`, "{", ...meta(`Files whose hash ARACHNE flagged (${hs.length})`), "    condition:",
        hs.map((i, n) => `        hash.${i.kind}(0, filesize) == ${yaraStr(i.value)}${n < hs.length - 1 ? " or" : ""}${note(i) ? ` // ${note(i)}` : ""}`).join("\n"), "}"].join("\n"));
    }
    const strs = [];
    const add = (prefix, list, mods) => list.forEach((i, n) => strs.push(`        $${prefix}${n + 1} = ${yaraStr(i.value)} ${mods} // ${plain(defang(i.value, i.type))}`));
    add("domain", P.by.domain, "ascii wide nocase fullword");
    add("url", P.by.url, "ascii wide nocase");
    add("ip", [...P.by.ipv4, ...P.by.ipv6], "ascii wide fullword");
    add("email", P.by.email, "ascii wide nocase fullword");
    if (strs.length) {
      rules.push([`rule ${name}_network_indicators`, "{", ...meta(`Files or memory that contain indicators ARACHNE flagged (${strs.length})`),
        "    strings:", ...strs, "    condition:", "        any of them", "}"].join("\n"));
    }
    if (!rules.length) return "";
    return `// YARA rules generated by ARACHNE from "${src}" on ${ctx.date}.\n` + (hs.length ? 'import "hash"\n\n' : "\n") + rules.join("\n\n") + "\n";
  }

  // ------------------------------------------------------------ Suricata and Snort
  // a content string: printable ASCII as is, everything a rule parser treats specially (and non-ASCII) as |HH|
  const content = (s) => '"' + utf8(String(s)).map((b) => (b >= 0x20 && b < 0x7f && !'";\\|:'.includes(String.fromCharCode(b)) ? String.fromCharCode(b) : "|" + hex2(b) + "|")).join("").replace(/\|\|/g, " ") + '"';
  const msg = (s) => `"${plain(s, 200)}"`;
  const ipList = (i) => (i.type === "ipv6" ? `[${i.value}]` : i.value);
  function ids(P, ctx, snort) {
    let sid = ctx.sid;
    const rules = [], meta = `metadata:created_at ${ctx.date.replace(/-/g, "_")};`;
    const tail = () => `classtype:trojan-activity; sid:${sid++}; rev:1;`;
    const label = (i) => `${plain(defang(i.value, i.type), 120)}${i.verdict ? ` (${i.verdict})` : ""}`;
    const section = (title) => rules.push(`\n# ${title}`);
    const ips = [...P.by.ipv4, ...P.by.ipv6];
    if (ips.length) {
      section(`IP addresses (${ips.length}): traffic to or from the address`);
      for (const i of ips) rules.push(`alert ip $HOME_NET any <> ${ipList(i)} any (msg:${msg("ARACHNE flagged IP " + label(i))}; ${tail()}${snort ? "" : " " + meta})`);
    }
    if (P.by.domain.length) {
      section(`Domains (${P.by.domain.length}): DNS lookups and TLS connections, subdomains included`);
      for (const i of P.by.domain) {
        if (snort) {
          const wire = i.value.split(".").map((l) => "|" + hex2(l.length) + "|" + l).join("") + "|00|";
          rules.push(`alert udp $HOME_NET any -> any 53 (msg:${msg("ARACHNE flagged domain " + label(i) + " - DNS query")}; content:"${wire.replace(/\|\|/g, " ")}"; nocase; fast_pattern; ${tail()})`);
          rules.push(`alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:${msg("ARACHNE flagged domain " + label(i) + " - TLS SNI")}; flow:to_server,established; content:"|16 03|"; depth:2; content:${content(i.value)}; nocase; distance:0; ${tail()})`);
        } else {
          rules.push(`alert dns $HOME_NET any -> any any (msg:${msg("ARACHNE flagged domain " + label(i) + " - DNS query")}; dns.query; dotprefix; content:${content("." + i.value)}; nocase; endswith; ${tail()} ${meta})`);
          rules.push(`alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:${msg("ARACHNE flagged domain " + label(i) + " - TLS SNI")}; flow:established,to_server; tls.sni; dotprefix; content:${content("." + i.value)}; nocase; endswith; ${tail()} ${meta})`);
        }
      }
    }
    if (P.by.url.length) {
      section(`URLs (${P.by.url.length}): plain HTTP requests (HTTPS needs TLS inspection)`);
      for (const i of P.by.url) {
        const u = i.url, path = u.path && u.path !== "/" ? u.path : "";
        if (snort) {
          rules.push(`alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:${msg("ARACHNE flagged URL " + label(i))}; flow:to_server,established; content:${content(u.host)}; http_header; nocase;${path ? ` content:${content(path)}; http_uri; nocase;` : ""} ${tail()})`);
        } else {
          rules.push(`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:${msg("ARACHNE flagged URL " + label(i))}; flow:established,to_server; http.host; content:${content(u.host)}; endswith;${path ? ` http.uri; content:${content(path)}; startswith;` : ""} ${tail()} ${meta})`);
        }
      }
    }
    if (P.by.hash.length) {
      if (snort) {
        section(`File hashes (${P.by.hash.length}): not included - Snort 2 has no hash rules (use the Suricata or YARA rules)`);
      } else {
        const kinds = ["md5", "sha1", "sha256"].filter((k) => P.by.hash.some((i) => i.kind === k));
        section(`File hashes (${P.by.hash.length}): files sent over HTTP, SMTP, FTP, SMB or NFS. Suricata reads the hashes from list files:`);
        for (const k of kinds) {
          rules.push(`# save these lines as arachne-${k}.txt in your rules folder:`);
          for (const i of P.by.hash.filter((x) => x.kind === k)) rules.push(`#   ${i.value}`);
          rules.push(`alert http any any -> any any (msg:${msg("ARACHNE flagged file (" + k.toUpperCase() + " list)")}; file${k}:arachne-${k}.txt; ${tail()} ${meta})`);
        }
      }
    }
    if (!rules.length) return "";
    return `# ${snort ? "Snort 2.9" : "Suricata"} rules generated by ARACHNE from "${plain(ctx.source)}" on ${ctx.date}.\n` +
      `# SIDs ${ctx.sid}-${sid - 1}: change them if they clash with your own local rules.\n` + rules.join("\n").replace(/^\n/, "") + "\n";
  }

  // ------------------------------------------------------------ Splunk
  const spl = (s) => '"' + String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  const inList = (field, vals) => `${field} IN (${vals.map(spl).join(", ")})`;
  function splunk(P, ctx) {
    const parts = [], ips = [...P.by.ipv4, ...P.by.ipv6].map((i) => i.value);
    const doms = P.by.domain.flatMap((i) => [i.value, "*." + i.value]);
    if (ips.length) parts.push(...["src_ip", "dest_ip", "src"].map((f) => inList(f, ips)));
    if (ips.length || doms.length) parts.push(inList("dest", [...ips, ...doms]));
    if (doms.length) parts.push(...["query", "url_domain"].map((f) => inList(f, doms)));
    const urls = P.by.url.map((i) => "*" + i.url.host + (i.url.port ? ":" + i.url.port : "") + (i.url.path || "") + "*");
    if (urls.length) parts.push(inList("url", urls));
    const hs = P.by.hash.map((i) => i.value);
    if (hs.length) parts.push(...["file_hash", "process_hash"].map((f) => inList(f, hs)));
    for (const k of ["md5", "sha1", "sha256"]) {
      const list = P.by.hash.filter((i) => i.kind === k).map((i) => i.value);
      if (list.length) parts.push(inList(k, list));
    }
    const ems = P.by.email.map((i) => i.value);
    if (ems.length) parts.push(...["src_user", "sender", "recipient"].map((f) => inList(f, ems)));
    if (!parts.length) return "";
    return `\`\`\` ARACHNE: ${P.count} indicators from "${plain(ctx.source).replace(/`/g, "")}", ${ctx.date}. CIM field names; narrow index=* to your indexes. \`\`\`\n` +
      `index=* earliest=-30d (\n    ${parts.join("\n    OR ")}\n)\n| table _time, index, sourcetype, host, src, src_ip, dest, dest_ip, query, url, file_hash, src_user, recipient\n`;
  }

  // ------------------------------------------------------------ Microsoft Sentinel / Defender (KQL)
  const kq = (s) => '"' + String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  const dyn = (vals) => `dynamic([${vals.map(kq).join(", ")}])`;
  function sentinel(P, ctx) {
    const lets = [], legs = [], T = "| where TimeGenerated > ago(lookback)";
    const ips = [...P.by.ipv4, ...P.by.ipv6].map((i) => i.value);
    if (ips.length) {
      lets.push(`let IOC_IP = ${dyn(ips)};`);
      legs.push(`(CommonSecurityLog ${T} | where DestinationIP in (IOC_IP) or SourceIP in (IOC_IP) | extend IOC = iff(DestinationIP in (IOC_IP), DestinationIP, SourceIP))`,
        `(DeviceNetworkEvents ${T} | where RemoteIP in (IOC_IP) | extend IOC = RemoteIP)`,
        `(AzureDiagnostics ${T} | where column_ifexists("DestinationIp", "") in (IOC_IP) or column_ifexists("SourceIp", "") in (IOC_IP) | extend IOC = coalesce(column_ifexists("DestinationIp", ""), column_ifexists("SourceIp", "")))`);
    }
    const doms = P.by.domain.map((i) => i.value);
    if (doms.length) {
      lets.push(`let IOC_Domain = ${dyn(doms)};`);
      legs.push(`(DnsEvents ${T} | where Name has_any (IOC_Domain) | extend IOC = Name)`,
        `(DeviceNetworkEvents ${T} | where RemoteUrl has_any (IOC_Domain) | extend IOC = RemoteUrl)`,
        `(DeviceEvents ${T} | where ActionType == "DnsQueryResponse" | extend Q = tostring(parse_json(AdditionalFields).DnsQueryString) | where Q has_any (IOC_Domain) | extend IOC = Q)`);
    }
    const urls = P.by.url.map((i) => i.value);
    if (urls.length) {
      lets.push(`let IOC_Url = ${dyn(urls)};`);
      legs.push(`(UrlClickEvents ${T} | where Url in~ (IOC_Url) | extend IOC = Url)`,
        `(EmailUrlInfo ${T} | where Url in~ (IOC_Url) | extend IOC = Url)`,
        `(DeviceNetworkEvents ${T} | where RemoteUrl in~ (IOC_Url) | extend IOC = RemoteUrl)`);
    }
    const hs = P.by.hash.map((i) => i.value);
    if (hs.length) {
      lets.push(`let IOC_Hash = ${dyn(hs)};`);
      for (const t of ["DeviceFileEvents", "DeviceProcessEvents", "DeviceImageLoadEvents"]) {
        legs.push(`(${t} ${T} | where SHA256 in~ (IOC_Hash) or SHA1 in~ (IOC_Hash) or MD5 in~ (IOC_Hash) | extend IOC = case(SHA256 in~ (IOC_Hash), SHA256, SHA1 in~ (IOC_Hash), SHA1, MD5))`);
      }
      legs.push(`(EmailAttachmentInfo ${T} | where SHA256 in~ (IOC_Hash) | extend IOC = SHA256)`);
    }
    const ems = P.by.email.map((i) => i.value);
    if (ems.length) {
      lets.push(`let IOC_Email = ${dyn(ems)};`);
      legs.push(`(EmailEvents ${T} | where SenderFromAddress in~ (IOC_Email) or RecipientEmailAddress in~ (IOC_Email) | extend IOC = iff(SenderFromAddress in~ (IOC_Email), SenderFromAddress, RecipientEmailAddress))`);
    }
    if (!legs.length) return "";
    return `// ARACHNE: ${P.count} indicators from "${plain(ctx.source)}", ${ctx.date}. Microsoft Sentinel / Defender XDR hunting query.\n` +
      `// Tables you don't have are skipped (union isfuzzy=true).\nlet lookback = 30d;\n${lets.join("\n")}\nunion isfuzzy=true\n    ${legs.join(",\n    ")}\n` +
      `| extend Device = coalesce(column_ifexists("DeviceName", ""), column_ifexists("Computer", ""))\n| project TimeGenerated, Type, IOC, Device\n| sort by TimeGenerated desc\n`;
  }

  // ------------------------------------------------------------ Elastic (Kibana Query Language, ECS fields)
  const eq = (s) => '"' + String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  const eor = (field, vals) => `${field} : (${vals.join(" or ")})`;
  function elastic(P) {
    const parts = [], ips = [...P.by.ipv4, ...P.by.ipv6].map((i) => eq(i.value));
    if (ips.length) parts.push(...["source.ip", "destination.ip"].map((f) => eor(f, ips)));
    // unquoted *.domain is a wildcard; validated domains only contain letters, digits, "-", "_" and "."
    const doms = P.by.domain.flatMap((i) => [eq(i.value), "*." + i.value]);
    if (doms.length) parts.push(...["dns.question.name", "url.domain", "destination.domain", "tls.client.server_name"].map((f) => eor(f, doms)));
    const urls = P.by.url.map((i) => eq(i.value));
    if (urls.length) parts.push(...["url.full", "url.original"].map((f) => eor(f, urls)));
    for (const k of ["md5", "sha1", "sha256"]) {
      const hs = P.by.hash.filter((i) => i.kind === k).map((i) => eq(i.value));
      if (hs.length) parts.push(...[`file.hash.${k}`, `process.hash.${k}`].map((f) => eor(f, hs)));
    }
    const ems = P.by.email.map((i) => eq(i.value));
    if (ems.length) parts.push(...["email.from.address", "email.to.address", "user.email"].map((f) => eor(f, ems)));
    return parts.length ? parts.join("\nor ") + "\n" : "";
  }

  const BUILD = { sigma, yara, suricata: (P, c) => ids(P, c, false), snort: (P, c) => ids(P, c, true), splunk, sentinel, elastic };

  // generate(iocs, { format, source, author, sid, date }) -> { text, count, covered, skipped, unsupported, invalid }
  function generate(iocs, opts = {}) {
    const f = FORMATS.find((x) => x.id === opts.format) || FORMATS[0];
    const P = prepare(iocs);
    const d = opts.date instanceof Date ? opts.date : new Date();
    const source = String(opts.source || "ARACHNE scan").slice(0, 200) || "ARACHNE scan";
    const slug = plain(source, 60).replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 40);
    const ctx = {
      source, author: plain(opts.author || "ARACHNE", 80), date: dateParts(d).join("-"),
      sid: Math.max(1, Math.min(4000000000, parseInt(opts.sid, 10) || 9100001)),
      ruleName: ("ARACHNE_" + (slug || "scan") + "_" + uuidOf(source + "|" + P.count).slice(0, 8)).replace(/__+/g, "_"),
    };
    const text = BUILD[f.id](P, ctx);
    const covered = f.covers.reduce((n, t) => n + P.by[t].length, 0);
    const skipped = TYPES.filter((t) => !f.covers.includes(t) && P.by[t].length).map((t) => ({ type: t, label: TYPE_LABEL[t], count: P.by[t].length }));
    return { format: f, text, count: P.count, covered, skipped, unsupported: P.unsupported, invalid: P.invalid, byType: Object.fromEntries(TYPES.map((t) => [t, P.by[t].length])) };
  }

  const api = { FORMATS, TYPES, TYPE_LABEL, countOf, generate, prepare, clean, defang, uuidOf };
  if (typeof module === "object" && module.exports) module.exports = api;
  root.ArachneRules = api;
})(typeof window !== "undefined" ? window : globalThis);

/* ------------------------------------------------------------ the "Detection rules" window (browser only)
   ArachneRules.open(iocs, { source, title }) shows it; the scanner calls it from Export > Detection rules with the
   scan's indicators, and other pages (such as saved cases on the website) can call it with their own list. */
(function () {
  if (typeof document === "undefined") return;
  const R = window.ArachneRules;
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const say = (m, k) => { try { toast(m, k); } catch { /* toast() comes from app.js */ } }; // eslint-disable-line no-undef
  const PREF = "arachne.rules";
  const pref = { get() { try { return JSON.parse(localStorage.getItem(PREF) || "{}"); } catch { return {}; } },
    set(v) { try { localStorage.setItem(PREF, JSON.stringify({ ...pref.get(), ...v })); } catch { /* private mode */ } } };
  let modal = null, state = null;

  function build() {
    modal = document.createElement("div");
    modal.className = "modal";
    modal.id = "rulesModal";
    modal.innerHTML = `<div class="modal-box lg rules-box">
      <div class="modal-h"><h2>Detection rules</h2><button class="icon-btn" data-close title="Close"><svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg></button></div>
      <div class="rules-bar">
        <div class="rules-fmts" role="tablist">${R.FORMATS.map((f) => `<button type="button" role="tab" data-fmt="${f.id}">${esc(f.label)}</button>`).join("")}</div>
      </div>
      <div class="rules-opts">
        <label>Indicators <select data-scope>
          <option value="flagged">Malicious and suspicious</option><option value="malicious">Malicious only</option><option value="all">All</option>
        </select></label>
        <label class="rules-sid">First SID <input type="number" data-sid min="1" max="4000000000" step="1"></label>
        <span class="rules-sp"></span>
        <button type="button" class="btn sm" data-copy>Copy</button>
        <button type="button" class="btn sm primary" data-dl>Download</button>
      </div>
      <div class="rules-info" data-info></div>
      <pre class="rules-code" data-code tabindex="0"></pre>
    </div>`;
    document.body.appendChild(modal);
    modal.addEventListener("mousedown", (e) => { if (e.target === modal) close(); });
    modal.querySelector("[data-close]").onclick = close;
    // Escape closes this window first, even when it was opened from another window (such as a saved case)
    window.addEventListener("keydown", (e) => { if (e.key === "Escape" && modal.classList.contains("open")) { e.stopImmediatePropagation(); e.preventDefault(); close(); } }, true);
    modal.querySelector(".rules-fmts").onclick = (e) => { const b = e.target.closest("[data-fmt]"); if (b) { state.format = b.dataset.fmt; pref.set({ format: state.format }); render(); } };
    modal.querySelector("[data-scope]").onchange = (e) => { state.scope = e.target.value; render(); };
    modal.querySelector("[data-sid]").onchange = (e) => { const v = parseInt(e.target.value, 10); if (v > 0) { state.sid = v; pref.set({ sid: v }); } render(); };
    modal.querySelector("[data-copy]").onclick = () => {
      if (!state.out.text) return say("Nothing to copy", "warn");
      navigator.clipboard.writeText(state.out.text).then(() => say(`${state.out.format.label} copied`), () => say("Copy failed", "error"));
    };
    modal.querySelector("[data-dl]").onclick = () => {
      if (!state.out.text) return say("Nothing to download", "warn");
      const f = state.out.format, base = "arachne-" + String(state.source).replace(/[^a-z0-9.@-]+/gi, "_").slice(0, 40);
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([state.out.text], { type: f.mime }));
      a.download = `${base}-${f.id}.${f.ext}`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    };
  }
  function close() { if (modal) modal.classList.remove("open"); }
  function pick() {
    const all = state.iocs;
    if (state.scope === "all") return all;
    return all.filter((i) => i.verdict === "malicious" || (state.scope === "flagged" && i.verdict === "suspicious"));
  }
  function render() {
    const list = pick();
    const out = state.out = R.generate(list, { format: state.format, source: state.source, sid: state.sid });
    modal.querySelectorAll("[data-fmt]").forEach((b) => { b.classList.toggle("on", b.dataset.fmt === state.format); b.setAttribute("aria-selected", b.dataset.fmt === state.format); });
    modal.querySelector("[data-scope]").value = state.scope;
    modal.querySelector(".rules-sid").style.display = state.format === "suricata" || state.format === "snort" ? "" : "none";
    modal.querySelector("[data-sid]").value = state.sid;
    const bits = [];
    const types = Object.entries(out.byType).filter(([, n]) => n).map(([t, n]) => R.countOf(t, n));
    bits.push(`<b>${out.covered}</b> of ${list.length} indicator${list.length === 1 ? "" : "s"} in these rules${types.length ? ` (${esc(types.join(", "))})` : ""}.`);
    if (out.skipped.length) bits.push(`${esc(out.format.label)} has no rule for ${esc(out.skipped.map((s) => R.countOf(s.type, s.count)).join(", "))}.`);
    const un = Object.entries(out.unsupported);
    if (un.length) bits.push(`Not used: ${esc(un.map(([t, n]) => `${n} ${t}`).join(", "))} (no rule type for these).`);
    if (out.invalid.length) bits.push(`Left out ${out.invalid.length} value${out.invalid.length === 1 ? "" : "s"} that didn't look valid: <code>${esc(out.invalid.slice(0, 3).map((i) => i.value).join(", "))}</code>${out.invalid.length > 3 ? "…" : ""}.`);
    bits.push(`<span class="rules-hint">${esc(out.format.hint)} Generated rules are a starting point: test them before turning on alerts.</span>`);
    modal.querySelector("[data-info]").innerHTML = bits.join(" ");
    const code = modal.querySelector("[data-code]");
    code.textContent = out.text || (list.length ? `No ${out.format.label} rules for these indicator types.` :
      state.scope === "all" ? "No indicators to build rules from." : "Nothing in this scan was flagged. Choose \"All\" under Indicators to build rules from every indicator.");
    code.classList.toggle("empty", !out.text);
  }
  // iocs: [{ type, value, verdict, score }]
  R.open = function (iocs, opts = {}) {
    if (!modal) build();
    const p = pref.get(), flagged = iocs.some((i) => i.verdict === "malicious" || i.verdict === "suspicious");
    state = { iocs, source: opts.source || "ARACHNE scan", format: R.FORMATS.some((f) => f.id === p.format) ? p.format : "sigma",
      scope: opts.scope || (flagged ? "flagged" : "all"), sid: p.sid || 9100001, out: null };
    document.body.appendChild(modal); // last in the page, so it shows above a window it was opened from
    modal.querySelector(".modal-h h2").textContent = opts.title || "Detection rules";
    render();
    modal.classList.add("open");
    setTimeout(() => modal.querySelector(`[data-fmt="${state.format}"]`).focus(), 30);
  };
})();
