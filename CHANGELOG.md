# Changelog

All notable changes to ARACHNE. Versions follow [Semantic Versioning](https://semver.org/):

- **Patch** (2.3.0 → 2.3.1): bug fixes only.
- **Minor** (2.3.0 → 2.4.0): new features, nothing removed or changed in a way that breaks how you use it.
- **Major** (2.x → 3.0.0): a big change in how ARACHNE works.

Each release is tagged in git as `vX.Y.Z`. The running version is shown at the bottom right of the app and printed when the server starts.

## [2.7.1] - 2026-11-15

### Fixed (phones and narrow screens)
- **Extract from text**: the bulk scan window now stays full screen on phones in "Extract from text" mode (it used to shrink into a floating box with the page showing behind it).
- **Detection rules**: when there's nothing to build rules from, the window no longer loses its title bar and format tabs (desktop too). On phones the indicator picker gets its own row, with Copy and Download side by side.
- **Threat intel**: the This scan / Timeline / Library tabs move to their own full-width row on phones, so the window title isn't cut off and longer translations fit.
- **Report**: no longer runs a few pixels wider than the screen on small phones (360 px) or with longer translations, which cut off the right edge of cards and the "ATT&CK view" button.
- **Source verdicts**: on phones each source is a compact two-line row (name, result and score, then detail and age) with the re-run button in reach, instead of a table wider than the screen.

## [2.7.0] - 2026-11-15

### Added
- The interface is available in 11 languages: English, Spanish, German, French, Portuguese, Italian, Dutch, Polish, Japanese, Chinese (Simplified) and Korean. ARACHNE follows the browser's language by default; pick another under **Settings → Appearance → Interface language** or from the start screen. Data from sources (IOC values, source names, raw findings) is never translated.
- `tools/check_i18n.py` checks that every language file has the same phrases and the same placeholders.

### Notes
- The translations were written by AI and haven't been checked by native speakers yet. Corrections are welcome: they live in `static/i18n/<language>.json`.
- Still in English for now: the activity log messages, module names and descriptions, and exported reports, and the new Detection rules and Threat intel windows (they arrived at the same time and will be translated in a later release).

## [2.6.0] - 2026-11-15

### Added
- MITRE ATT&CK and threat actor profiles, built in and offline (MITRE ATT&CK Enterprise + MISP Galaxy, `static/intel/threat-kb.json`, rebuilt with `tools/build_threat_kb.py`).
- New indicator types: Threat actor, ATT&CK technique and Campaign. Search detects ATT&CK IDs (`T1059.001`, `G0016`, `S0154`, `C0022`); pick the type to scan an actor or family by name.
- New source "MITRE ATT&CK & Threat Actors" (no key): for a malware family, the actors, campaigns and techniques known to use it; for an actor, its aliases, country, suspected sponsor, targets, malware and techniques; plus technique and campaign lookups.
- Report: "Threat context" for an IOC (linked malware, actors that sources attributed it to, known users of the malware, campaigns, technique count) and a Profile button on malware / actor / technique / campaign indicators.
- Threat intel window (shield button or `I`): an ATT&CK matrix for the whole scan, the scan's timeline (every date the sources reported, plus the linked campaigns), and a library of profile pages with search. Deep links: `#intel=G0016`, `#intel=scan`, `#intel=timeline`.

### Changed
- AlienVault OTX adds the adversaries and ATT&CK techniques its pulses name as linked indicators (they were only tags before).

## [2.5.0] - 2026-11-15

### Added
- Detection rules: Export > Detection rules turns the scan's indicators into Sigma, YARA, Suricata and Snort 2.9 rules, and Splunk SPL, Microsoft Sentinel KQL and Elastic KQL queries, with Copy and Download. Choose malicious and suspicious, malicious only, or all indicators, and the first SID for Suricata/Snort.
- Every value is checked against its type and escaped for each rule language, so an odd value can't break a rule; values that don't pass are left out and listed. Rule titles, messages and comments show indicators defanged. Rule IDs are stable, so regenerating gives the same rules.
- Generator tests: `node tests/rules.test.mjs`.

## [2.4.0] - 2026-11-15

### Added
- Extract IOCs from text: a new "Extract from text" tab in the bulk scan dialog (shortcut X, or the link on the start screen). Paste an email with its headers, a threat report, logs or a web page, or load the file (.eml, .html, .txt, .log and more), and every IP, domain, URL, email, file hash, CVE and ASN in it is pulled out, including defanged ones (hxxp, [.], [at], [dot] and the rest). Quoted-printable emails and HTML entities are decoded first.
- Review before scanning: duplicates are merged with a count, each IOC can be ticked or unticked, a type filter shows one type at a time, and hovering a row shows where it was found. Private and reserved IPs, well-known sites and things that look like file or package names (invoice.zip, com.example.app) start unticked, with the reason shown.
- "Always leave out" list for your own domains, mail servers and IPs (a domain covers its subdomains and the URLs and emails on it), saved in the browser. Each row has a button to add it.
- Copy or copy defanged the ticked IOCs straight from the dialog.
- Pasting an email or a report into the IOC list tab switches to "Extract from text" by itself.

### Fixed
- Bulk scans no longer split a URL that contains a comma or a semicolon into two values.

## [2.3.0] - 2026-11-14

### Added
- Search accepts defanged IOCs (`hxxp://`, `[.]`, `[@]` and similar) and refangs them before scanning.
- Copy and export IOCs defanged: "Copy all IOCs (defanged)" and "IOC list (TXT, defanged)".
- "Copy all IOCs" in the Export menu.
- Keyboard shortcuts list (press `?`).
- Version number at the bottom right of the app.

### Changed
- Pivoting and the graph are available once a scan has finished; the Pivot switch next to the search bar is gone.
- The "IOC Scanner" name is dropped: the app is just ARACHNE (an old saved tagline is updated automatically).

## [2.2.0] - 2026-11-08

### Added
- Mobile layout for phones: bottom navigation, a details sheet on the graph, long-press menus.
- PDF and STIX 2.1 export; risk score in every export.
- Stop scripts (`stop.bat` / `stop.sh`).
- "Stop all scans".

### Fixed
- Email search crash on Python older than 3.9.
- Module errors across several IOC types.
- Only http(s) links are kept in module results.

### Removed
- Criminal IP and HackerTarget sources.
- Gravatar API key option (the public profile API is used instead).

## [2.1.0] - 2026-10-30

### Added
- Overall risk score, bulk scanning and result freshness with re-scan.

## [2.0.1] - 2026-10-30

### Added
- API key import and export in Settings.

## [2.0.0] - 2026-10-30

### Changed
- ARACHNE is a scanner first and a pivoting tool second: one indicator in, one report from every source.

## [1.1.0] - 2026-10-23

- First tracked version.
