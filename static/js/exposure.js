"use strict";
/* Exposure Results: what an IP (or the IPs behind a domain or URL) has open to the internet and how vulnerable it is.
   The data comes from the "exposure" source (osint/modules/exposure.py): Shodan InternetDB for open ports and known
   CVEs, Shodan CVEDB to rank each CVE (CVSS severity, EPSS exploit chance, CISA KEV). Passive: the target is never
   contacted. This file adds the "Exposure Results" button to each report and the window it opens. */
(() => {
  const MOD = "exposure";
  const TYPES = ["ipv4", "ipv6", "domain", "url"];
  const SHOW = 15;   // vulnerabilities shown per IP before "Show all"

  // Well-known ports: service name, risk if open to the whole internet (high / medium / low), and why it matters.
  const PORTS = {
    21: ["FTP", "medium", "File transfer that often sends passwords unencrypted; anonymous login is a common leak."],
    22: ["SSH", "low", "Remote login. Normal for servers, but a constant target for password guessing."],
    23: ["Telnet", "high", "Unencrypted remote login. Should never face the internet; a favourite of IoT botnets."],
    25: ["SMTP", "low", "Mail server."],
    53: ["DNS", "medium", "If it answers anyone's queries (open resolver) it can be abused for DDoS amplification."],
    69: ["TFTP", "high", "Password-less file transfer; often leaks device configurations."],
    80: ["HTTP", "low", "Website without encryption."],
    102: ["Siemens S7", "high", "Industrial control system protocol. Exposing it lets anyone talk to the PLC."],
    110: ["POP3", "low", "Mail retrieval."],
    111: ["RPCbind", "medium", "Lists other RPC services; used for reconnaissance and DDoS amplification."],
    123: ["NTP", "low", "Time server; old versions can be abused for DDoS amplification."],
    135: ["Windows RPC", "high", "Windows remote procedure calls. Should never face the internet."],
    137: ["NetBIOS", "high", "Windows name service; leaks machine and domain names."],
    139: ["NetBIOS session", "high", "Old Windows file sharing. Should never face the internet."],
    143: ["IMAP", "low", "Mail retrieval."],
    161: ["SNMP", "high", "Device management; default community strings leak or change the whole configuration."],
    389: ["LDAP", "high", "Directory service (often Active Directory). Leaks users and can be abused for DDoS."],
    443: ["HTTPS", "low", "Encrypted website."],
    445: ["SMB", "high", "Windows file sharing. Used by WannaCry and many ransomware gangs to spread."],
    465: ["SMTPS", "low", "Mail submission."],
    500: ["IKE (IPsec VPN)", "low", "VPN gateway."],
    502: ["Modbus", "high", "Industrial control protocol with no login at all."],
    587: ["SMTP submission", "low", "Mail submission."],
    623: ["IPMI", "high", "Server management (BMC). Known flaws leak password hashes."],
    631: ["IPP printing", "medium", "Printer service; recent CUPS flaws allow remote code execution."],
    636: ["LDAPS", "medium", "Encrypted directory service. Usually internal only."],
    873: ["rsync", "high", "File sync; often allows downloading whole directories without a password."],
    993: ["IMAPS", "low", "Encrypted mail retrieval."],
    995: ["POP3S", "low", "Encrypted mail retrieval."],
    1080: ["SOCKS proxy", "medium", "Proxy; if open, attackers can route traffic through it."],
    1194: ["OpenVPN", "low", "VPN gateway."],
    1433: ["Microsoft SQL Server", "high", "Database. Should never face the internet; brute-forced constantly."],
    1521: ["Oracle database", "high", "Database. Should never face the internet."],
    1723: ["PPTP VPN", "medium", "Old VPN protocol with broken encryption."],
    1883: ["MQTT", "medium", "IoT messaging; often has no login and leaks device data."],
    1900: ["UPnP / SSDP", "high", "Home-router discovery. Abused for DDoS amplification and port opening."],
    2049: ["NFS", "high", "Network file shares; can expose whole disks."],
    2082: ["cPanel", "medium", "Hosting control panel login."],
    2083: ["cPanel (SSL)", "medium", "Hosting control panel login."],
    2375: ["Docker API", "high", "Unencrypted Docker control. Anyone can run containers; mass-exploited by cryptominers."],
    2376: ["Docker API (TLS)", "medium", "Docker control. Safe only with client certificates."],
    2379: ["etcd", "high", "Kubernetes key store; can leak every cluster secret."],
    3128: ["HTTP proxy", "medium", "Proxy; if open, attackers can route traffic through it."],
    3306: ["MySQL", "high", "Database. Should never face the internet."],
    3389: ["Remote Desktop (RDP)", "high", "The most common way ransomware gangs break in. Put it behind a VPN."],
    4444: ["Often Metasploit", "medium", "Default port for Metasploit and many reverse shells; worth a closer look."],
    4500: ["IPsec NAT-T", "low", "VPN gateway."],
    5000: ["Web app / UPnP", "low", "Often a development web server or a NAS admin page."],
    5060: ["SIP", "medium", "Internet telephony; abused for toll fraud."],
    5432: ["PostgreSQL", "high", "Database. Should never face the internet."],
    5601: ["Kibana", "medium", "Log dashboard; often open without a login."],
    5900: ["VNC", "high", "Remote desktop, often with a weak or no password."],
    5984: ["CouchDB", "high", "Database; old versions allow remote code execution."],
    5985: ["WinRM", "high", "Windows remote management. Should never face the internet."],
    5986: ["WinRM (HTTPS)", "high", "Windows remote management. Should never face the internet."],
    6379: ["Redis", "high", "Database that usually has no password; mass-exploited by cryptominers."],
    6443: ["Kubernetes API", "medium", "Cluster control plane."],
    7547: ["TR-069", "high", "ISP router management; used by the Mirai botnet."],
    8080: ["HTTP (alternative)", "low", "Website or admin panel on a non-standard port."],
    8086: ["InfluxDB", "high", "Database, often without a login."],
    8291: ["MikroTik Winbox", "high", "Router management; exploited by botnets."],
    8443: ["HTTPS (alternative)", "low", "Website or admin panel on a non-standard port."],
    8888: ["HTTP (alternative)", "low", "Often a notebook or admin panel."],
    9000: ["Web admin / PHP-FPM", "medium", "Often an admin panel (Portainer) or PHP backend."],
    9100: ["Printer (JetDirect)", "medium", "Raw printing; anyone can print or read the device."],
    9200: ["Elasticsearch", "high", "Search database; one of the biggest sources of data leaks."],
    10000: ["Webmin", "medium", "Server admin panel; several remote code execution flaws."],
    10250: ["Kubelet", "high", "Kubernetes node agent; can allow running commands in containers."],
    11211: ["Memcached", "high", "Cache with no login; record DDoS amplification source."],
    20000: ["DNP3", "high", "Industrial control protocol (power and water)."],
    27017: ["MongoDB", "high", "Database. Thousands have been wiped and ransomed."],
    44818: ["EtherNet/IP", "high", "Industrial control protocol."],
    47808: ["BACnet", "high", "Building automation (heating, access control)."],
    50050: ["Cobalt Strike team server", "high", "Default Cobalt Strike team server port: a strong sign of attacker infrastructure."],
  };
  const RISK_ORDER = { high: 3, medium: 2, low: 1 };
  const RISK_LABEL = { high: "Should not be public", medium: "Check it", low: "Normal" };

  const modOn = () => !!S.meta?.modules?.some((m) => m.name === MOD);
  const resultOf = (id) => S.results.get(id)?.[MOD];
  const busyOf = (id) => !!S.busy.get(id)?.has?.(MOD);
  let openId = null, showAll = new Set();

  function severity(cvss) {
    if (cvss == null) return null;
    return cvss >= 9 ? "critical" : cvss >= 7 ? "high" : cvss >= 4 ? "medium" : cvss > 0 ? "low" : null;
  }
  function counts(d) {
    const hosts = d?.hosts || [], cves = d?.cves || {};
    const ports = new Set(), vulns = new Set();
    let risky = 0;
    for (const h of hosts) {
      for (const p of h.ports || []) { ports.add(p); if (PORTS[p]?.[1] === "high") risky++; }
      for (const v of h.vulns || []) vulns.add(v);
    }
    const all = [...vulns];
    return {
      ports: ports.size, vulns: all.length, risky,
      kev: all.filter((v) => cves[v]?.kev).length,
      critical: all.filter((v) => severity(cves[v]?.cvss) === "critical").length,
    };
  }

  // the button on each IP, domain and URL report
  function button(n) {
    if (!n || !TYPES.includes(n.type) || !modOn()) return "";
    const r = resultOf(n.id);
    let badge = "";
    if (busyOf(n.id)) badge = '<span class="spinner"></span>';
    else if (r?.status === "ok" && r.data) {
      const c = counts(r.data);
      const bad = c.kev || c.critical || c.risky;
      badge = `<span class="expo-badge ${bad ? "bad" : c.ports || c.vulns ? "warn" : ""}">${c.ports} ${c.ports === 1 ? "port" : "ports"} · ${c.vulns} ${c.vulns === 1 ? "vuln" : "vulns"}</span>`;
    } else if (r && r.status === "notfound") badge = '<span class="expo-badge">no data</span>';
    return `<button class="btn sm expo-btn" data-expo="${esc(n.id)}" title="Open ports and known vulnerabilities (passive, from Shodan)">${ICON.expo}Exposure Results${badge}</button>`;
  }

  function modal() {
    let m = document.getElementById("expoModal");
    if (m) return m;
    m = document.createElement("div");
    m.className = "modal";
    m.id = "expoModal";
    m.innerHTML = `<div class="modal-box lg expo-box"><div class="modal-h"><h2>Exposure Results</h2>
      <button class="icon-btn" data-close><svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg></button></div>
      <div class="modal-b" id="expoBody"></div></div>`;
    document.body.append(m);
    m.onclose = () => { openId = null; };   // app.js closes any open window on Escape
    m.addEventListener("click", (e) => {
      if (e.target === m || e.target.closest("[data-close]")) return close();
      const all = e.target.closest("[data-expo-all]");
      if (all) { showAll.add(all.dataset.expoAll); return render(); }
      if (e.target.closest("[data-expo-run]")) return run(true);
    });
    return m;
  }
  function close() { document.getElementById("expoModal")?.classList.remove("open"); openId = null; }
  function open(id) {
    openId = id;
    showAll = new Set();
    modal().classList.add("open");
    if (!resultOf(id) && !busyOf(id)) run(false);
    render();
  }
  function run(force) {
    if (!openId) return;
    if (!S.ready) { render(); return; }
    pivot(openId, { modules: [MOD], force });
  }

  const pct = (x) => x == null ? "" : `${(x * 100).toFixed(x >= 0.1 ? 0 : 1)}%`;
  function cpeLabel(c) {
    const p = String(c).replace(/^cpe:(2\.3:|\/)/, "").split(":");
    return [p[1], p[2], p[3]].filter((x) => x && x !== "*" && x !== "-").join(" ").replace(/_/g, " ") || c;
  }

  function hostHTML(h, cves, many) {
    const ports = [...(h.ports || [])].sort((a, b) => (RISK_ORDER[PORTS[b]?.[1]] || 1) - (RISK_ORDER[PORTS[a]?.[1]] || 1) || a - b);
    const vulns = h.vulns || [];
    const shown = showAll.has(h.ip) ? vulns : vulns.slice(0, SHOW);
    const head = many ? `<h3 class="expo-ip"><span translate="no">${esc(h.ip)}</span>${(h.hostnames || []).length ? `<small translate="no">${esc(h.hostnames.slice(0, 4).join(", "))}${h.hostnames.length > 4 ? " …" : ""}</small>` : ""}</h3>` : "";
    if (!h.known) return `${head}<div class="empty-note">Shodan has no record of this IP. It may have no open ports, or Shodan hasn't scanned it recently.</div>`;
    const portRows = ports.map((p) => {
      const [name, risk, why] = PORTS[p] || ["Unknown service", "low", ""];
      const rk = PORTS[p] ? risk : "unknown";
      return `<tr><td translate="no"><b>${p}</b></td><td>${esc(name)}</td><td><span class="expo-risk ${rk}">${PORTS[p] ? RISK_LABEL[risk] : "Unknown"}</span></td><td class="expo-why">${esc(why)}</td></tr>`;
    }).join("");
    const vulnRows = shown.map((v) => {
      const i = cves[v], sev = severity(i?.cvss);
      return `<tr><td translate="no"><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v)}" target="_blank" rel="noopener noreferrer">${esc(v)}</a></td>
        <td>${i ? (sev ? `<span class="expo-sev ${sev}">${sev}</span> <span class="dim" translate="no">${Number(i.cvss).toFixed(1)}</span>` : '<span class="dim">–</span>') : '<span class="dim">not ranked</span>'}</td>
        <td translate="no">${i?.epss != null ? `<span class="expo-epss" style="--w:${Math.max(2, Math.round(i.epss * 100))}%">${pct(i.epss)}</span>` : ""}</td>
        <td>${i?.kev ? '<span class="expo-kev">Exploited</span>' : ""}${i?.ransomware ? ' <span class="expo-kev rw">Ransomware</span>' : ""}</td>
        <td class="expo-sum" translate="no"><div title="${esc(i?.summary || "")}">${esc(i?.summary || "")}</div></td></tr>`;
    }).join("");
    return `${head}
      <div class="expo-grid">
        <div class="rep-sec"><h3>Open ports <em>${ports.length}</em></h3>
          ${ports.length ? `<div class="tbl-wrap rep-tbl"><table><thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Why it matters</th></tr></thead><tbody>${portRows}</tbody></table></div>`
            : '<div class="empty-note">No open ports seen.</div>'}
          ${(h.cpes || []).length ? `<div class="expo-sw"><span class="rep-lbl">Software seen</span>${h.cpes.slice(0, 20).map((c) => `<span class="tag" translate="no" title="${esc(c)}">${esc(cpeLabel(c))}</span>`).join("")}</div>` : ""}
          ${(h.tags || []).length ? `<div class="expo-sw"><span class="rep-lbl">Shodan tags</span>${h.tags.map((x) => `<span class="tag" translate="no">${esc(x)}</span>`).join("")}</div>` : ""}
        </div>
        <div class="rep-sec"><h3>Vulnerabilities <em>${vulns.length}</em><span class="expo-sort">most dangerous first</span></h3>
          ${vulns.length ? `<div class="tbl-wrap rep-tbl expo-vulns"><table><thead><tr><th>CVE</th><th>Severity</th><th title="EPSS: the chance this vulnerability is exploited in the next 30 days">Exploit chance</th><th title="Listed in CISA's Known Exploited Vulnerabilities catalogue">In the wild</th><th>Summary</th></tr></thead><tbody>${vulnRows}</tbody></table></div>
            ${vulns.length > shown.length ? `<button class="btn xs" data-expo-all="${esc(h.ip)}">Show all ${vulns.length}</button>` : ""}`
            : '<div class="empty-note">No known vulnerabilities for the software seen on this IP.</div>'}
        </div>
      </div>`;
  }

  function render() {
    const body = document.getElementById("expoBody");
    if (!body || !openId) return;
    const n = S.nodes.get(openId);
    if (!n) { body.innerHTML = '<div class="empty-note">This indicator is no longer in the scan.</div>'; return; }
    const r = resultOf(openId), busy = busyOf(openId);
    const top = `<div class="expo-top"><div><div class="d-top">${tchip(n.type)}</div><div class="d-val rep-val"><span translate="no">${esc(n.value)}</span></div>
      ${r?.data?.host && r.data.hosts?.length ? `<div class="msg"><span>IPs checked</span> <span translate="no">${esc(r.data.hosts.map((h) => h.ip).join(", "))}</span></div>` : ""}</div>
      ${r && !busy ? `<button class="btn sm ghost" data-expo-run title="Ask Shodan again, skipping the cache">${ICON.redo}Check again</button>` : ""}</div>`;
    const note = '<p class="expo-note">Passive check: this is what Shodan\'s scanners last saw (usually within the past week), from Shodan InternetDB, with each vulnerability ranked by Shodan CVEDB. ARACHNE never scans the target itself. Vulnerabilities are matched on the software version Shodan saw, so some may already be patched.</p>';
    let main;
    if (busy) main = '<div class="src-running"><span class="spinner"></span>Checking open ports and vulnerabilities…</div>';
    else if (!r) main = S.ready ? '<div class="src-running"><span class="spinner"></span>Starting…</div>' : '<div class="empty-note">Available when the scan finishes.</div>';
    else if (r.status === "notfound") main = `<div class="empty-note">${esc(r.message || "No data")}</div>`;
    else if (r.status !== "ok") main = `<div class="empty-note"><span>Couldn't check exposure.</span> <span translate="no">${esc(typeof reasonText === "function" ? reasonText(r) : r.message || r.status)}</span> <button class="btn xs" data-expo-run>Try again</button></div>`;
    else {
      const d = r.data || {}, c = counts(d), hosts = d.hosts || [];
      const tile = (cls, v, label) => `<div class="rep-tile ${cls} ${v ? "" : "zero"}"><b>${v}</b><span>${label}</span></div>`;
      main = `<div class="rep-tiles expo-tiles">${tile("", c.ports, "Open ports")}${tile("mal", c.risky, "Risky services")}${tile("sus", c.vulns, "Vulnerabilities")}${tile("mal", c.critical, "Critical")}${tile("mal", c.kev, "Exploited in the wild")}</div>
        ${hosts.map((h) => hostHTML(h, d.cves || {}, hosts.length > 1)).join("")}
        ${d.unranked ? `<p class="msg">${d.unranked === 1 ? "1 older vulnerability is listed but not ranked (only the newest 40 are ranked per check)." : `${d.unranked} older vulnerabilities are listed but not ranked (only the newest 40 are ranked per check).`}</p>` : ""}
        <div class="links">${hosts.map((h) => `<a href="https://www.shodan.io/host/${encodeURIComponent(h.ip)}" target="_blank" rel="noopener noreferrer" translate="no">Shodan ${esc(h.ip)}${ICON.link}</a>`).join("")}</div>`;
    }
    body.innerHTML = top + main + note;
  }

  // keep the button badge and an open window up to date as results arrive
  function refresh() { if (openId) render(); }

  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-expo]");
    if (b) { e.preventDefault(); e.stopPropagation(); open(b.dataset.expo); }
  });

  window.Exposure = { button, open, refresh, counts, PORTS };
})();
