# Changelog

All notable changes to ARACHNE. Versions follow [Semantic Versioning](https://semver.org/):

- **Patch** (2.3.0 → 2.3.1): bug fixes only.
- **Minor** (2.3.0 → 2.4.0): new features, nothing removed or changed in a way that breaks how you use it.
- **Major** (2.x → 3.0.0): a big change in how ARACHNE works.

Each release is tagged in git as `vX.Y.Z`. The running version is shown at the bottom right of the app and printed when the server starts.

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
