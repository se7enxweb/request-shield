# An Exponential site

**Situation:** a site on Exponential (the CMS: siteaccesses, URL aliases, the
admin interface, `content/search`). It gets what every CMS gets: scrapers
counting through node numbers, scanners asking for `settings/site.ini`, bots
posting to every address and hammering the search, password guessing on the
login. The kernel answers each of them after 20–150 ms of PHP and database
work.

![An Exponential site gets three rule files and one line in config.php; the shield answers scanners, floods and stray forms before the kernel starts](../diagrams/exponential.svg)

**With the shield:** three rule files in
[`examples/exponential/`](../../examples/exponential/), and one line in
Exponential's `config.php`. Every rule has an ID (`EXP-…`) and a description.
The sections below give the reason for each.

| File | What it is |
|---|---|
| [`exponential.rules`](../../examples/exponential/exponential.rules) | the frontend: system URLs, internal files, forms, search, pace. Included by one of the two below, not loaded on its own |
| [`exponential-admin-uri.rules`](../../examples/exponential/exponential-admin-uri.rules) | **the main file when the admin is the siteaccess `/admin`** (URI matching: `www.example.org/admin/…`) |
| [`exponential-admin-host.rules`](../../examples/exponential/exponential-admin-host.rules) | **the main file when the admin has a host of its own** (`admin.example.org`) |
| [`config.php`](../../examples/exponential/config.php) | the integration: one `Shield::protectFile()` |

**To click through:** `php -S 127.0.0.1:8095 examples/exponential/router.php`
starts a pretend Exponential site behind these rules (the `/admin` variant,
switched on), with every case of this page as a numbered test
([README](../../examples/exponential/README.md#the-click-demo)).

## Switching it on

1. `composer require cjw-network/request-shield`.
2. Copy the three `.rules` files to `settings/request-shield/`. The web
   server never hands out `settings/`; the shield refuses it as well
   (`EXP-INTERNAL`).
3. Take `config.php` over into Exponential's `config.php` (next to
   `index.php`, read by `autoload.php` on every request). Name the main file
   for your admin. The shield then runs before the kernel, and before the
   HTTP cache's early exit, so cached pages are protected too.
4. Adapt three things to the site (each one is a single line in
   `exponential.rules`):
   - `EXP-MODULES`: the URI siteaccesses that may stand in front
     (`(/(ger|eng))?`). Write your own, or delete the group for host matching.
   - `EXP-POST`: the modules of your extensions that take forms.
   - `host` and `trust`: the site's names and the load balancer.
5. **The files ship in monitor mode** (`set mode monitor`): every decision is
   logged as it would be taken, and nobody is refused. Read the log (or the
   live view, `/rs/waf/live`) for a few days, while editors work and the
   search is used, then switch to `set mode enforce`. `EXP-BAN` and
   `EXP-STRICT` stay watched (`monitor` in front) until their log lines are
   clean.

`bin/request-shield check settings/request-shield/exponential-admin-uri.rules`
reads everything and names any mistake by file and line.
`bin/request-shield test settings/request-shield/exponential-admin-uri.rules`
decides the **examples next to every rule** (`expect` lines, 72 of them,
[examples](../features/RSF05-04-rule-examples.md)): run it after every change to the
rules, before the deploy. Add your own site's addresses as examples, above
all near misses (a page alias that must not be refused).
`bin/request-shield trace … "GET https://www.example.org/content/view/full/2"`
shows how one request would be decided, and by which rule.

## 1. System URLs in the frontend

| Rule | What | Why |
|---|---|---|
| `EXP-SYSVIEW` | `/content/view/…` → 404 (any case, behind any siteaccess, `index.php` and `layout/set/…`) | Every page has its URL alias. `/content/view/full/<node>` is the same page under a number. Visitors never see those links, but **scrapers count through them**: 1, 2, 3 … every node, also those no menu links to (hidden pages, old campaigns). Each number is also a second address for a page, which a cache keeps twice and a search engine reads as duplicate content. |
| `EXP-SYSVIEW-OK` | except `/content/view/sitemap/<n>` and `/tagcloud/<n>` | The page header of ezwebin and ezdemo links the sitemap and the tag cloud by their system URL. |
| `EXP-MODULES` | `setup`, `class`, `section`, `role`, `state`, `workflow`, `trigger`, `visual`, `package`, `infocollector`, `url`, `ezinfo`, `collaboration`, `pdf` → 404 | Modules only the admin uses. In the frontend they answer a login form or "access denied", which tells a scanner that the site is Exponential and where to try. Anchored at the root (with the URI siteaccesses), so a page alias like `/shop/package` stays untouched. |
| `EXP-INTERNAL`, `EXP-INI` | `settings/`, `kernel/`, `lib/`, `var/<site>/cache`, `var/<site>/log` …, `*.ini`, `*.ini.append.php`, `*.tpl` → 404 | The web server's rules keep them away already. A request for them that still reaches `index.php` comes only from someone who tries, so it is refused and counted for `EXP-BAN`. |
| `EXP-DOWNLOAD` | `.zip`, `.tar.gz`, `.sql` … allowed under `content/download/` and `var/*/storage/` | The built-in `SCAN-BACKUP` refuses backup and archive names anywhere. On an Exponential site these are files editors upload. |
| `EXP-VIEWPARAMS` | `/(offset)/`, `/(limit)/`, `/(year)/`, `/(month)/`, `/(day)/`: numbers only, up to 6 digits | View parameters are part of the path, so no query rule sees them. `/(offset)/1'or1` is an attack, `/(offset)/a1`, `/(offset)/a2` … fills the cache with copies of one page, and `/(offset)/99999999` counts through lists. Other view parameters of the site (`(tag)`, `(sort)`) can be added to the list. |

**Checked against a real installation:** the frontend of an Exponential test
site (demo content, five siteaccesses) was crawled. All 163 links its pages
generate pass, and none is a `content/view` address except the sitemap. The only
refused forms were those of the **debug toolbar**, which posts to
`setup/cachetoolbar`. It is shown only with debug output on, which a live site
does not have. On a development machine, add your address:
`unblock [EXP-MODULES] for 192.0.2.10`.

## 2. Forms

| Rule | What | Why |
|---|---|---|
| `EXP-POST` | a POST only to `user/login`, `user/register`, `content/action`, `content/edit`, `content/collectedinfo`, `comment/`, `shop/`, `ezjscore/`, `newsletter/` …, else 405 | Exponential takes forms at a few module addresses only, and never at a page's alias. A bot posting to every address it finds (comment spam, form fuzzing) gets 405 before the kernel starts. Extensions with forms of their own add their module here. |
| `EXP-LOGIN` | `user/login`, `user/register`, `user/forgotpassword`, `user/password`: the browser check first, a pass from the last 15 minutes | Password guessing and fake registrations come from scripts. The check is an invisible task the browser solves in about a second; a script has to solve it again and again, from every address. A person notices a short "one moment" once. The admin's login (`/admin/user/login`, or `/user/login` on the admin's host) is matched by the same rule. |
| `EXP-FORMS` | `content/action` (information collection, the contact forms), `content/tipafriend`, `comment/add`, `newsletter/subscribe`: the check, once per half hour | These send mail or store content: the spam target. A POST without a pass gets the check page, and the form is **sent again by itself**, so nothing typed is lost. Instead of the page, the check can sit inside the form and be solved while the visitor types ([the widget](../features/RSF03-03-browser-check-in-the-form.md), one line in the form's template). |
| `EXP-API` | `ezjscore/`, `/api/`: a check is JSON with a header, not a page | AJAX calls cannot show a page; they get the task in a header. |
| `EXP-ORIGIN`, `EXP-ORIGIN-X` | a form (POST, PUT, PATCH, DELETE) only from the website's own pages (`Origin`, else `Referer`): another website 403, neither header the browser check; not for payment providers' callbacks (`paypal/notify_url`) | A foreign page must not send a form in a visitor's name (cross-site request forgery). Exponential's own form tokens (`ezformtoken`) protect signed-in users; this covers every form, the anonymous ones too ([forms from the website](../features/RSF02-04-forms-from-the-website.md)). Not a bot defence: a script sets the headers as it likes. |

## 3. Search

| Rule | What | Why |
|---|---|---|
| `EXP-SEARCH-Q` | the fields of `content/search` and `content/advancedsearch` with their types: `SearchText` text, `SubTreeArray` number, **`SearchDate` −1 or 1–5** (all, a day, a week, a month, three months, a year), `SearchTimestamp` number, `SearchPageLimit` number … | The search is the page bots probe most. With the types, `SearchDate=9` or `SubTreeArray=x` is refused (404, once `query strict` is on), and only `SearchText` goes to the attack patterns. The time filter can only take values the search knows. |
| `EXP-SEARCHES` | 10 searches a minute per visitor (searching, paging through results), then the browser check; solved, the counter starts again | A search is the most expensive page: no cache, a full-text query against the database. A person rarely searches ten times a minute; a bot that does pays with a check. Written inside the search's `match` block, the budget counts only requests to the search ([an area's budget](../features/RSF03-01-budgets.md#a-budget-for-one-area)); reading pages does not use it up. |
| `EXP-CACHE-Q` | a cache keeps addresses without a query only | Search results and links with tracking tags (`?utm_source=…`) are answered but marked uncacheable. View parameters are part of the path, so lists stay cacheable. With `cache-ignore @tracking` the shield takes the tracking tags out before Exponential's HTTP cache looks up the page: a campaign link gets the kept page instead of a render ([fewer keys](../features/RSF04-01-cacheable-definition.md#query-parameters-in-the-key-ignored-unknown)). |
| `EXP-SEARCH-CHECK` (commented out) | every searcher checked once an hour | For an attack from thousands of addresses, which no per-visitor budget catches. Take the `#` away while it lasts. |

## 4. The admin

The two main files differ only here.

**The admin is `/admin`** (`exponential-admin-uri.rules`), in one `match /admin/**` block:

| Rule | What | Why |
|---|---|---|
| `EXP-ADMIN-SYS` | system URLs and the admin modules allowed under `/admin` | The admin works with them (`/admin/content/view/full/2`, `/admin/class/…`). |
| `EXP-ADMIN-POST` | a POST anywhere under `/admin` | Editors save on many addresses. |
| `EXP-ADMIN-CHECK` | the browser check for every request without a valid pass | An editor is checked once per pass and never notices it again. Everyone else is checked before the admin's login form even appears. |
| `EXP-ADMIN-Q` | every parameter known, free text scanned for attacks | The admin has many parameters. `query strict` must not refuse them, and the attack patterns still look at every value. |
| `EXP-ADMIN-NET` (commented out) | the office's network only | Where editors work from known addresses (or a VPN), the strongest rule: nobody else ever reaches the admin. |

One host serves visitors and editors, so the pass lasts as long for both
(2 hours). An editor whose pass ends while editing is checked when they next
save, and the form is sent again by itself. If you want a working day without
a check, set `pass-ttl 8h` in this file; it then applies to visitors too.

**The admin has its own host** (`exponential-admin-host.rules`), in a `site
admin.example.org` block: the same rules (`EXP-AH-…`) for the whole host, and
`pass-ttl 8h` for editors only. The block is picked by the web server's
server name, never by the visitor's `Host` header. The frontend host keeps its
rules unchanged: there, `/admin/content/view/…` is refused like any system URL.

### The admin's background requests

The admin loads parts of its pages with a script, in the background. Today
that is the admin4 mega menu: opening "Setup" or "Users" fetches
`/admin/user/megamenu/<tab>` and puts the answer into the menu. Tomorrow it is
every ezjscore call, the log viewer's live tail, the layout editor's API and
the autosave of a draft.

Such a request cannot show the check page or run it. If the shield answered it
with the page, the script would put a check page into the menu, or say "The
Setup menu could not be loaded." In monitor mode every one of them is also a
"would check" line in the log.

So a check never answers a background request with the page:

- **With a pass** (the editor passed the check when the admin page loaded),
  the request goes through, as every request with a pass.
- **Without one** (no check yet, or the pass ran out in the middle of a working
  session), it gets the check as JSON: 429, `Content-Type: application/json`,
  the task in the `Request-Shield-Challenge` header, no HTML. The page's
  script sees that it got no fragment and can reload the page. The reload is a
  navigation: it gets the check page, and the editor goes on with a new pass.

The shield knows a background request by the browser's `Sec-Fetch-Dest: empty`
and by `X-Requested-With: XMLHttpRequest`. Both main files also name the mega
menu's path with `api-path`, for a client that sends neither:

| Rule | What | Why |
|---|---|---|
| `EXP-ADMIN-BG` / `EXP-AH-BG` | `api-path /admin/user/megamenu/**` (on the admin host `/user/megamenu/**`) | The mega menu's panels are fragments for a script: a check for them comes as JSON, never as the page. |

Its examples prove it: `expect GET /admin/user/megamenu/setup with pass
answered`, and without a pass `json-check`, the check as JSON. Add the paths of
your own background calls to the same line, `api-path` takes several.

**Updating a site's rules:** with a shield from this version on, a background
request is answered so without any change. Copy the `EXP-ADMIN-BG` line (or
`EXP-AH-BG` in the admin's `site` block) from the example into your main file.
`request-shield test <main file>` then shows the new examples passing.

## 5. Pace, bans and everything else

| Rule | What | Why |
|---|---|---|
| `EXP-PACE` | past 120 pages a minute per visitor the check; past 300 the check again, then the counter starts anew | Images, CSS and JavaScript come from the web server, so one page view is one request through PHP. 120 pages a minute is no person. |
| `EXP-BAN` (watched first) | 10 refusals in 10 minutes → an hour off the site | System URLs, admin modules, internal files, made-up view parameters: who collects ten refusals is scanning. Verified search engines are never banned. Watched first, because old links to `content/view` from other websites can cause refusals too. |
| `EXP-STRICT` (watched first) | any other query parameter → 404 | The frontend takes hardly any parameters: the search and the marketing tags (`@tracking`). Everything else is an attack tool's or a cache filler's. The log shows first what it would refuse. |
| `@attacks` | SQL injection, scripts, paths … in the query and the headers → 403 | The reviewed attack patterns. They are the largest part of the cost (below); without `include @attacks`, about 11 µs less per request. |
| `pass-ttl 2h`, `store-dir`, `log` | | A passed check lasts two hours. Counters, the generated secret and the log stay outside the document root (`EXP_VAR`). |

## What it costs

Measured on PHP 8.4 with OPcache, a page by alias (best of three runs over
20,000 requests):

| | per request |
|---|---|
| a minimal rule file (the built-in rules only) | ~20 µs |
| these rules | ~40–49 µs |
| of that, `@attacks` | ~11 µs |
| a refused system URL (`EXP-SYSVIEW`) | ~28 µs, and the kernel never starts |

A rendered Exponential page takes 20–150 ms, so the rules add about 0.03 %.
A hit in Exponential's HTTP cache takes 0.4–1 ms; there the rules add about 3–5 %. Exponential 6's own cache (`exphttpcache`) is the
page cache here; the shield's `http-cache` stays off, and the shield's
statistics show its hits and misses from `X-Exp-Cache`
([the HTTP cache](../features/RSF04-03-http-cache.md#exponential-6-its-own-http-cache)).

## Limits

- **Only what reaches PHP:** images, CSS, JavaScript and `var/storage` are
  served by the web server, and the shield never sees them.
- **Wrong passwords** are not counted: the shield sees the login form being
  sent, not whether the password was right. The check before the login makes
  guessing expensive. Locking an account is Exponential's job.
- **The site's own adjustments** (more URI siteaccesses, an extension's
  modules or view parameters) have to be added to the rules. The monitor run
  shows what is missing.
