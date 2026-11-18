// Tests for static/js/accounts.js (platform cards for found accounts). Run: node tests/accounts.test.mjs  (Node 18+, no packages)
import { createRequire } from "node:module";
import assert from "node:assert/strict";
const require = createRequire(import.meta.url);
globalThis.window = globalThis;
require("../static/js/platform-icons.js");
const A = require("../static/js/accounts.js");
const SITES = require("node:fs").readFileSync(new URL("../osint/sites.py", import.meta.url), "utf8");

let n = 0;
const test = (name, fn) => { fn(); n++; console.log("ok -", name); };
const m = (value, label) => A.match({ value, label });

test("every built-in username site gets an icon or a brand colour", () => {
  const names = [...SITES.matchAll(/"name": "([^"]+)"/g)].map((x) => x[1]);
  assert.ok(names.length > 30);
  for (const s of names) {
    const r = m("https://example.org/x", `${s}: alice`);
    assert.ok(r.known, `no platform entry for ${s}`);
    assert.equal(r.handle, "alice");
  }
});
test("site names, short names and Keybase proof types map to the right platform", () => {
  assert.equal(m("https://news.ycombinator.com/user?id=pg", "HN: pg").name, "Hacker News");
  assert.equal(m("https://twitter.com/jack", "twitter: jack").name, "X");
  assert.equal(m("https://x.com/jack", "X: jack").name, "X");
  assert.equal(m("https://hub.docker.com/u/a", "Docker Hub: a").name, "Docker Hub");
  assert.equal(m("https://mastodon.social/@a", "Mastodon.social: a").name, "Mastodon");
  assert.equal(m("https://news.ycombinator.com/user?id=pg", "hackernews: pg").name, "Hacker News");
});
test("unknown names fall back to the URL's host, then to a letter tile", () => {
  assert.equal(m("https://alice.blogspot.com/", "").name, "Blogger");
  assert.equal(m("https://github.com/alice", "Some Mirror: alice").name, "GitHub");
  const u = m("https://obscure-forum.example/u/alice", "Obscure Forum: alice");
  assert.equal(u.known, false);
  assert.equal(u.name, "Obscure Forum");
  assert.equal(u.path, null);
  assert.match(u.hex, /^#[0-9a-f]{6}$/);
  assert.equal(m("https://obscure-forum.example/u/bob", "").handle, "bob");
  assert.equal(m("https://obscure-forum.example/u/bob", "").name, "obscure-forum.example");
});
test("icon markup is escaped and coloured for contrast", () => {
  const html = A.iconHTML(m("https://x.example", '<img src=x onerror=1>: a'));
  assert.ok(!html.includes("<img"), html);
  assert.equal(A.ink("#FFFC00"), "#111114");
  assert.equal(A.ink("#181717"), "#ffffff");
  assert.match(A.iconHTML(m("https://github.com/a", "GitHub: a")), /<svg viewBox="0 0 24 24"/);
});
test("graph image is a data: SVG (no network, CSP-safe)", () => {
  const img = A.graphImage(m("https://github.com/a", "GitHub: a"));
  assert.ok(img.startsWith("data:image/svg+xml;utf8,"));
  assert.ok(decodeURIComponent(img).includes("<circle"));
  assert.ok(!/https?:\/\/(?!www\.w3\.org)/.test(decodeURIComponent(img)));
});
console.log(`${n} tests passed`);
