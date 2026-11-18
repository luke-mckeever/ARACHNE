// Builds static/js/platforms.js: the brand icons shown on "Accounts found" cards and account nodes in the graph.
// Icons come from Simple Icons (https://simpleicons.org, CC0 1.0). Download the package once, then run:
//   npm pack simple-icons@15.0.0 && tar xzf simple-icons-15.0.0.tgz
//   node tools/build_platforms.mjs package
// Platforms Simple Icons has no icon for get a brand colour only (a letter tile is drawn instead).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const pkg = process.argv[2];
if (!pkg) { console.error("usage: node tools/build_platforms.mjs <path to the unpacked simple-icons package>"); process.exit(1); }
const si = JSON.parse(fs.readFileSync(path.join(pkg, "package.json"), "utf8"));
const data = JSON.parse(fs.readFileSync(path.join(pkg, "data", "simple-icons.json"), "utf8"));
const byTitle = new Map(data.map((i) => [i.title.toLowerCase(), i]));
const slugOf = (t) => t.toLowerCase().replace(/\+/g, "plus").replace(/\./g, "dot").replace(/&/g, "and")
  .normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]/g, "");

// [Simple Icons title, display name (optional), extra match keys: site names, domains, Keybase proof types…]
const ICONS = [
  ["GitHub"], ["GitLab"], ["Bitbucket"], ["Gitea"], ["Codeberg"], ["SourceForge"], ["Docker", "Docker Hub", "dockerhub"],
  ["npm", null, "npmjs"], ["PyPI"], ["RubyGems"], ["Packagist"], ["Replit", null, "repl"], ["dev.to", "DEV", "devto", "dev"],
  ["Hashnode"], ["Y Combinator", "Hacker News", "hackernews", "hn", "ycombinator"], ["Codewars"], ["LeetCode"], ["HackerRank"],
  ["HackerEarth"], ["Exercism"], ["Codeforces"], ["CodeChef"], ["Topcoder"], ["CodePen"], ["JSFiddle"], ["Glitch"],
  ["Stack Overflow", null, "stackoverflow"], ["Stack Exchange", null, "stackexchange"], ["Hugging Face", null, "huggingface"],
  ["Kaggle"], ["Indie Hackers", null, "indiehackers"], ["Product Hunt", null, "producthunt"], ["Lobsters", null, "lobste"],
  ["Keybase"], ["Gravatar"], ["About.me", null, "about"], ["Linktree", null, "linktr"], ["Calendly"],
  ["Mastodon", null, "mastodonsocial", "fediverse"], ["Bluesky", null, "bsky"], ["X", null, "twitter"], ["Threads"],
  ["Facebook", null, "fb"], ["Instagram"], ["Reddit"], ["Tumblr"], ["Pinterest"], ["Snapchat"], ["TikTok"], ["VK"],
  ["Telegram", null, "t", "tme"], ["WhatsApp"], ["Signal"], ["Discord"], ["Slack"], ["Matrix"], ["Viber"], ["LINE"],
  ["Xing"], ["Plurk"], ["Quora"], ["Flipboard"], ["Foursquare"], ["Tripadvisor"], ["Naver"], ["Bilibili"], ["Habr"], ["Mail.Ru", null, "mail"],
  ["Blogger", null, "blogspot"], ["WordPress"], ["Medium"], ["Substack"], ["Wikipedia"], ["Pastebin"], ["Wattpad"],
  ["Archive of Our Own", null, "ao3", "archiveofourown"], ["Fandom"], ["Instructables"], ["Goodreads"],
  ["YouTube"], ["Twitch"], ["Kick"], ["Rumble"], ["Odysee"], ["Vimeo"], ["SoundCloud"], ["Mixcloud"], ["Bandcamp"],
  ["Spotify"], ["Last.fm", null, "last", "lastfm"], ["Genius"], ["Discogs"], ["Flickr"], ["500px"], ["Unsplash"], ["Imgur"], ["Giphy"],
  ["Dribbble"], ["Behance"], ["DeviantArt"], ["Pixiv"], ["Patreon"], ["Ko-fi", null, "kofi"], ["Buy Me A Coffee", null, "buymeacoffee"],
  ["Gumroad"], ["Kickstarter"], ["Etsy"], ["eBay"], ["Fiverr"], ["Upwork"], ["PayPal"], ["Venmo"], ["Cash App", null, "cashapp", "cash"],
  ["Steam", null, "steamcommunity"], ["PlayStation", null, "psn"], ["Roblox"], ["Itch.io", null, "itch"], ["Chess.com", null, "chess"],
  ["Lichess"], ["MyAnimeList"], ["AniList"], ["Letterboxd"], ["Trakt"], ["Untappd"], ["Strava"], ["Duolingo"], ["Trello"],
  ["TryHackMe"], ["Hack The Box", null, "hackthebox"], ["HackerOne"], ["Bugcrowd"], ["Tinder"], ["Google", null, "gmail"], ["Apple"],
];
// brand colours for platforms Simple Icons has no icon for
const COLOUR_ONLY = [
  ["LinkedIn", "0A66C2"], ["Speedrun.com", "FFB400", "speedrun"], ["Xbox", "107C10"], ["Skype", "00AFF0"], ["Weibo", "E6162D"],
  ["OK.ru", "EE8208", "odnoklassniki", "ok"], ["Yandex", "FC3F1D"], ["Gab", "21CF7A"], ["Truth Social", "5448EE", "truthsocial"],
  ["BitChute", "EF4137"], ["Pikabu", "8AC858"], ["Crates.io", "FFC832", "crates"], ["Microsoft", "5E5E5E", "live", "outlook"],
];

const out = [];
const seen = new Set();
const keyOf = (s) => String(s).toLowerCase().replace(/[^a-z0-9]/g, "");
function keys(list) {
  const k = [...new Set(list.filter(Boolean).map(keyOf))].filter((x) => x && !seen.has(x));
  k.forEach((x) => seen.add(x));
  return k;
}
for (const [title, name, ...extra] of ICONS) {
  const i = byTitle.get(title.toLowerCase());
  if (!i) { console.error(`not in Simple Icons ${si.version}: ${title}`); process.exit(1); }
  out.push({ n: name || title, h: i.hex, p: fs.readFileSync(path.join(pkg, "icons", (i.slug || slugOf(title)) + ".svg"), "utf8").match(/ d="([^"]+)"/)[1],
    k: keys([title, name, ...extra, ...(i.aliases?.aka || [])]) });
}
for (const [title, hex, ...extra] of COLOUR_ONLY) out.push({ n: title, h: hex, k: keys([title, ...extra]) });

const here = path.dirname(fileURLToPath(import.meta.url));
const js = `// GENERATED by tools/build_platforms.mjs - do not edit by hand.
// Brand icons: Simple Icons ${si.version} (https://simpleicons.org), CC0 1.0. Trademarks belong to their owners.
window.PLATFORM_ICONS = ${JSON.stringify(out).replace(/\},\{/g, "},\n{")};
`;
fs.writeFileSync(path.join(here, "..", "static", "js", "platform-icons.js"), js);
console.log(`${out.length} platforms (${out.filter((x) => x.p).length} with icons), ${(js.length / 1024).toFixed(1)} KB`);
