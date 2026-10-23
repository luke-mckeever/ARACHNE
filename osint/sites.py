"""Username enumeration site list.

check: "status"  -> exists when HTTP 200 (404/410 = missing)
       "present" -> exists when `match` text is in the body
       "absent"  -> exists when `match` text is NOT in the body (and HTTP 200)
`profile` is the human URL shown in the graph (defaults to `url`).
"""

SITES = [
    {"name": "GitHub", "cat": "Dev", "url": "https://api.github.com/users/{u}", "profile": "https://github.com/{u}", "check": "status"},
    {"name": "GitLab", "cat": "Dev", "url": "https://gitlab.com/api/v4/users?username={u}", "profile": "https://gitlab.com/{u}", "check": "present", "match": "\"id\":"},
    {"name": "Bitbucket", "cat": "Dev", "url": "https://api.bitbucket.org/2.0/workspaces/{u}", "profile": "https://bitbucket.org/{u}/", "check": "status"},
    {"name": "Docker Hub", "cat": "Dev", "url": "https://hub.docker.com/v2/users/{u}/", "profile": "https://hub.docker.com/u/{u}", "check": "status"},
    {"name": "npm", "cat": "Dev", "url": "https://registry.npmjs.org/-/user/org.couchdb.user:{u}", "profile": "https://www.npmjs.com/~{u}", "check": "status"},
    {"name": "Replit", "cat": "Dev", "url": "https://replit.com/@{u}", "check": "status"},
    {"name": "DEV.to", "cat": "Dev", "url": "https://dev.to/api/users/by_username?url={u}", "profile": "https://dev.to/{u}", "check": "status"},
    {"name": "Hacker News", "cat": "Dev", "url": "https://hacker-news.firebaseio.com/v0/user/{u}.json", "profile": "https://news.ycombinator.com/user?id={u}", "check": "absent", "match": "null"},
    {"name": "Codewars", "cat": "Dev", "url": "https://www.codewars.com/api/v1/users/{u}", "profile": "https://www.codewars.com/users/{u}", "check": "status"},
    {"name": "Keybase", "cat": "Identity", "url": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", "profile": "https://keybase.io/{u}", "check": "present", "match": "\"basics\""},
    {"name": "Gravatar", "cat": "Identity", "url": "https://api.gravatar.com/v3/profiles/{u}", "profile": "https://gravatar.com/{u}", "check": "status"},
    {"name": "About.me", "cat": "Identity", "url": "https://about.me/{u}", "check": "status"},
    {"name": "Mastodon.social", "cat": "Social", "url": "https://mastodon.social/api/v1/accounts/lookup?acct={u}", "profile": "https://mastodon.social/@{u}", "check": "status"},
    {"name": "Bluesky", "cat": "Social", "url": "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social", "profile": "https://bsky.app/profile/{u}.bsky.social", "check": "status"},
    {"name": "Telegram", "cat": "Social", "url": "https://t.me/{u}", "check": "present", "match": "tgme_page_title"},
    {"name": "Snapchat", "cat": "Social", "url": "https://www.snapchat.com/add/{u}", "check": "status"},
    {"name": "Blogger", "cat": "Blog", "url": "https://{u}.blogspot.com/", "check": "status"},
    {"name": "Substack", "cat": "Blog", "url": "https://substack.com/api/v1/user/{u}/public_profile", "profile": "https://substack.com/@{u}", "check": "status"},
    {"name": "Wikipedia", "cat": "Blog", "url": "https://en.wikipedia.org/w/api.php?action=query&list=users&ususers={u}&format=json", "profile": "https://en.wikipedia.org/wiki/User:{u}", "check": "absent", "match": "\"missing\""},
    {"name": "Pastebin", "cat": "Paste", "url": "https://pastebin.com/u/{u}", "check": "status"},
    {"name": "Vimeo", "cat": "Media", "url": "https://vimeo.com/{u}", "check": "status"},
    {"name": "SoundCloud", "cat": "Media", "url": "https://soundcloud.com/{u}", "check": "status"},
    {"name": "Flickr", "cat": "Media", "url": "https://www.flickr.com/people/{u}/", "check": "status"},
    {"name": "Last.fm", "cat": "Media", "url": "https://www.last.fm/user/{u}", "check": "status"},
    {"name": "Dribbble", "cat": "Creative", "url": "https://dribbble.com/{u}", "check": "status"},
    {"name": "Behance", "cat": "Creative", "url": "https://www.behance.net/{u}", "check": "status"},
    {"name": "DeviantArt", "cat": "Creative", "url": "https://www.deviantart.com/{u}", "check": "status"},
    {"name": "Patreon", "cat": "Creative", "url": "https://www.patreon.com/{u}", "check": "status"},
    {"name": "BuyMeACoffee", "cat": "Creative", "url": "https://www.buymeacoffee.com/{u}", "check": "status"},
    {"name": "Steam", "cat": "Gaming", "url": "https://steamcommunity.com/id/{u}", "check": "absent", "match": "The specified profile could not be found"},
    {"name": "Chess.com", "cat": "Gaming", "url": "https://api.chess.com/pub/player/{u}", "profile": "https://www.chess.com/member/{u}", "check": "status"},
    {"name": "Lichess", "cat": "Gaming", "url": "https://lichess.org/api/user/{u}", "profile": "https://lichess.org/@/{u}", "check": "status"},
    {"name": "Speedrun.com", "cat": "Gaming", "url": "https://www.speedrun.com/api/v1/users/{u}", "profile": "https://www.speedrun.com/users/{u}", "check": "status"},
    {"name": "Duolingo", "cat": "Other", "url": "https://www.duolingo.com/2017-06-30/users?username={u}", "profile": "https://www.duolingo.com/profile/{u}", "check": "present", "match": "\"username\""},
    {"name": "Trello", "cat": "Other", "url": "https://trello.com/1/Members/{u}", "profile": "https://trello.com/u/{u}", "check": "status"},
    {"name": "TryHackMe", "cat": "Security", "url": "https://tryhackme.com/api/user/exist/{u}", "profile": "https://tryhackme.com/p/{u}", "check": "present", "match": "\"success\":true"},
    {"name": "HackerOne", "cat": "Security", "url": "https://hackerone.com/{u}?type=user", "check": "status"},
    {"name": "BugCrowd", "cat": "Security", "url": "https://bugcrowd.com/{u}", "check": "status"},
]
