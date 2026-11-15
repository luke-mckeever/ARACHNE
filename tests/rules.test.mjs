// Tests for static/js/rules.js (detection rule generator). Run: node tests/rules.test.mjs  (Node 18+, no packages)
// The rules were also checked with the real tools: yara-x, pySigma, suricata -T (7.0), snort -T (2.9), Kusto.Language.
import { createRequire } from "node:module";
import assert from "node:assert/strict";
const R = createRequire(import.meta.url)("../static/js/rules.js");

const IOCS = [
  { type: "ipv4", value: "185.220.101.4", verdict: "malicious", score: 90 },
  { type: "ipv6", value: "2001:db8::25", verdict: "suspicious" },
  { type: "domain", value: "evil-login.example.com", verdict: "malicious" },
  { type: "url", value: 'http://bad.example.net:8080/a?x="b;c|d\\e*', verdict: "malicious" },
  { type: "hash", value: "44d88612fea8a8f36de82e1278abb02f", verdict: "malicious" },
  { type: "hash", value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", verdict: "malicious" },
  { type: "email", value: "x@evil-login.example.com", verdict: "malicious" },
];
const DATE = new Date("2026-11-15T00:00:00Z");
let n = 0;
const test = (name, fn) => { fn(); n++; console.log("ok -", name); };

test("every format produces output", () => {
  for (const f of R.FORMATS) {
    const o = R.generate(IOCS, { format: f.id, source: "t", date: DATE });
    assert.ok(o.text.length > 50, f.id);
    assert.equal(o.count, 7);
  }
});
test("output is the same every time (stable rule IDs)", () => {
  for (const f of R.FORMATS) assert.equal(R.generate(IOCS, { format: f.id, date: DATE }).text, R.generate(IOCS, { format: f.id, date: DATE }).text);
});
test("values that could break a rule are left out", () => {
  const bad = [
    { type: "domain", value: 'evil.com"; sid:1; drop' }, { type: "url", value: "http://x.com/a\nalert ip any any" },
    { type: "ipv4", value: "999.1.1.1" }, { type: "hash", value: "abc" }, { type: "email", value: "a b@c.com" },
    { type: "ipv6", value: "1::2::3" }, { type: "url", value: "javascript:alert(1)" },
  ];
  for (const f of R.FORMATS) {
    const o = R.generate(bad, { format: f.id, date: DATE });
    assert.equal(o.text, "", f.id);
    assert.equal(o.invalid.length, bad.length, f.id);
  }
});
test("unsupported types are counted, duplicates merged", () => {
  const o = R.generate([...IOCS, IOCS[0], { type: "cve", value: "CVE-2024-1" }, { type: "username", value: "bob" }], { format: "splunk" });
  assert.equal(o.count, 7);
  assert.deepEqual(o.unsupported, { cve: 1, username: 1 });
});
test("Suricata: special characters are hex-escaped, one SID per rule, defanged messages", () => {
  const t = R.generate(IOCS, { format: "suricata", sid: 5000, date: DATE }).text;
  assert.match(t, /content:"\/a\?x=\|22\|b\|3B\|c\|7C\|d\|5C\|e\*"/);
  const sids = [...t.matchAll(/sid:(\d+);/g)].map((m) => +m[1]);
  assert.deepEqual(sids, sids.map((_, i) => 5000 + i));
  for (const line of t.split("\n").filter((l) => l.startsWith("alert"))) {
    const m = /msg:"([^"]*)"/.exec(line);
    assert.ok(m && !/evil-login\.example\.com|185\.220\.101\.4/.test(m[1]), "msg must be defanged: " + line);
  }
  assert.match(t, /filesha256:arachne-sha256\.txt/);
});
test("Snort: DNS name in wire format, no hash rules", () => {
  const t = R.generate(IOCS, { format: "snort", date: DATE }).text;
  assert.match(t, /content:"\|0A\|evil-login\|07\|example\|03\|com\|00\|"/);
  assert.doesNotMatch(t, /filemd5|filesha/);
});
test("YARA: hash conditions joined with or before comments, strings escaped", () => {
  const t = R.generate(IOCS, { format: "yara", date: DATE }).text;
  assert.match(t, /^import "hash"$/m);
  assert.match(t, /hash\.md5\(0, filesize\) == "44d88612fea8a8f36de82e1278abb02f" or \/\//);
  assert.match(t, /"http:\/\/bad\.example\.net:8080\/a\?x=\\"b;c\|d\\\\e\*"/);
  assert.match(t, /^rule ARACHNE_\w+_file_hashes$/m);
});
test("Sigma: YAML-quoted, wildcards escaped, subdomains included", () => {
  const t = R.generate(IOCS, { format: "sigma", date: DATE }).text;
  assert.equal(t.split("\n---\n").length, 4); // IP, domain, URL, hash
  assert.match(t, /c-uri\|contains: '\/a\\\?x="b;c\|d\\\\e\\\*'/);
  assert.match(t, /- '\.evil-login\.example\.com'/);
  assert.match(t, /^id: [0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/m);
});
test("Splunk, Sentinel and Elastic: quotes and backslashes escaped", () => {
  for (const f of ["splunk", "sentinel", "elastic"]) {
    const t = R.generate(IOCS, { format: f, date: DATE }).text;
    assert.ok(t.includes('x=\\"b;c|d\\\\e*'), f);
  }
  assert.match(R.generate(IOCS, { format: "elastic" }).text, /\*\.evil-login\.example\.com/);
  assert.match(R.generate(IOCS, { format: "sentinel" }).text, /^union isfuzzy=true$/m);
});
test("refanged values only: no defanged text in match fields", () => {
  const t = R.generate(IOCS, { format: "splunk", date: DATE }).text;
  assert.doesNotMatch(t.split("\n").slice(1).join("\n"), /\[\.\]|hxxp/);
});
console.log(`\n${n} tests passed`);
