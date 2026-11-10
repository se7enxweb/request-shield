# cjw-network/request-shield

[![Tests](https://github.com/cjw-network/request-shield/actions/workflows/tests.yml/badge.svg)](https://github.com/cjw-network/request-shield/actions/workflows/tests.yml)
[![Static analysis and security](https://github.com/cjw-network/request-shield/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/cjw-network/request-shield/actions/workflows/static-analysis.yml)
![PHP](https://img.shields.io/badge/php-8.0%20%E2%80%93%208.5-777bb4)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

**A mini web application firewall for PHP. Harden any PHP website in minutes —
even on simple shared hosting.**

AI crawlers, scrapers and automated attacks no longer hit only big sites. Every
such request makes your website do real work — start the software, ask the
database, build the page. Enough of them and the site slows down or goes
offline, and junk requests can fill your page cache so that real visitors wait.

request-shield is a small gatekeeper that looks at every request **before** your
website starts. Real visitors pass in a few millionths of a second. Everything
else:

- **Junk is turned away** — scanners hunting for password files, broken or
  oversized requests never reach your site.
- **Your cache stays clean** — made-up addresses and parameters are answered,
  but never stored.
- **Floods are slowed down** — whoever asks too often has to wait; suspicious
  clients prove they are a real browser with an invisible check, no puzzles to
  click ([how the browser check works, in plain words](docs/explained/browser-check.md)).
- **Doors stay shut** — an admin area only for your office, a form only where
  it belongs; your CMS can ask for the browser check when content is sent —
  or run it inside the form while the visitor types — and nobody loses what
  they typed.
- **Unwelcome addresses stay out** — keep an address out for a week with one
  command, let the office in, and ban for a while whoever keeps knocking
  ([IP lists and automatic bans](docs/features/RSF01-02-ip-lists.md)); a live view shows
  what is stopped right now, and why ([live and lists](docs/features/RSF06-02-live-and-lists.md)).
- **Search engines stay welcome** — Google, Bing and others are recognised and
  let through.
- **Readable rules** — one per line, in a plain text file; every refusal names
  the line that caused it, and an optional log shows what was turned away.
- **See what it does** — a page shows the active rules in plain words, how
  often each one decided, and what happens to any address you try, step by
  step.

All parts at a glance, each with the one line that switches it:
[the parts of request-shield](docs/explained/parts.md).

No extra server, no subscription, no data sent to anyone: one PHP library —
upload, include, done.

![How request-shield sits in front of a site: visitors, the shield in microseconds, your site; junk, requests not for them, suspicious and too fast ones are answered by the shield itself](docs/explained/overview.svg)

*What it is not:* protection against attacks so large that they overload the
network or the web server itself — that remains the job of your hoster or a CDN.

**See it in 30 seconds:** `php -S 127.0.0.1:8080 examples/demo/router.php`, then
open http://127.0.0.1:8080/ — a mini site with one example per feature,
including the invisible browser check ([examples/demo](examples/demo/README.md)).
Or the short tour: `php -S 127.0.0.1:8090 examples/showcase/router.php` — one
page, German and English, the rules beside what they mean, and every example a
real request you send yourself ([examples/showcase](examples/showcase/README.md)).

## How it works

It runs **before the application** — before the framework, its autoloader and
its database — and decides in a few microseconds whether a request reaches the
application, and whether the answer may be cached.

- **Trusted proxies:** `X-Forwarded-For`, `-Proto` and `-Host` are believed only
  from your load balancer or reverse proxy, and removed from `$_SERVER`
  otherwise, so neither the shield nor the application can be told another
  client, scheme or host.
- **Hard rejects:** methods, sizes, broken or traversing paths, unknown hosts and
  the paths only scanners ask for (`/.env`, `/.git/`, backups, `phpinfo.php`, …)
  never reach the application.
- **A definition of what may be cached:** URLs outside it are answered, but
  marked uncacheable, so random paths and parameters cannot fill a page cache.
- **Budgets per client** (an IPv4 address, an IPv6 /64): requests per window,
  and budgets the application counts itself (cache misses, failed sign-ins).
  Above a threshold a client can be challenged, above the limit it gets
  `429 Too Many Requests` with `Retry-After`.
- **Access rules:** paths only for some addresses (`restrict /admin/** to …`),
  methods only on some paths (`allow POST /contact`) — matched as the
  application routes the path, so `//admin` or `/%61dmin` do not get past.
- **Rule files and a log:** the settings one rule per line, from several files
  (a CMS extension ships its own); every decision names its rule
  (`[SITE-10]`, or `site.rules:12`); an optional log of what was stopped or
  flagged. The built-in blocks are rule files too (`rules/`), versioned; a
  site that changes one is told when an update changes it underneath.
- **No dependencies, no services:** counters in APCu, or in plain files on hosting
  without APCu. PHP ≥ 8.0 (the Red Hat Enterprise Linux 9 baseline).
- **Fail safe:** whatever breaks inside the shield — a store it cannot write,
  an adapter's hook that throws — the request reaches the application, marked
  uncached, and PHP's error log gets one line a minute. A rule file that does
  not compile after a deploy leaves the last good rules in force. The shield's
  own answers (a refusal, the check page) are not affected
  ([ADR 0007](docs/adr/0007-fail-safe-pass-through.md)).

It turns an expensive request (framework, database, rendering: 100–200 ms) into
a cheap one (well under 0.1 ms). It does not replace protection in front of PHP
(the hoster's, a CDN's, CloudLinux, Imunify360): a flood still occupies web
server and PHP slots, just very briefly.

## Status

- **0.1.0:** the core.
- **0.2.0:** the browser challenge (proof of work), settings checked once and
  compiled for OPcache, documentation, CI.
- **0.3.0:** rule files, access rules, rule IDs, the log, the active rules
  page, attack rules, match blocks, the check inside the form, earning back a
  spent budget (forms and APIs), the demo; PHP 8.0.
- **0.4.0:** known query parameters and their types, `query strict`,
  `@tracking` ([docs](docs/features/RSF02-05-known-parameters.md)); modes — monitor
  first, strict under attack, `monitor` for single rules, `challenge …
  max-age` ([docs](docs/features/RSF05-03-modes.md)); known crawlers — search engines
  and AI crawlers verified by their published address lists or DNS, allowed,
  checked or refused per kind ([docs](docs/features/RSF01-04-known-crawlers.md));
  statistics — requests, rules, status codes, pages not found and who links
  to them, what each crawler did — kept per hour, `bin/request-shield stats`
  ([docs](docs/features/RSF06-03-statistics.md)); plugins — the core is the firewall,
  the statistics are its first plugin, and your own hang on the same two hooks
  ([docs](docs/features/RSF06-04-plugins.md)); rules per website (`site` blocks); IP
  lists — `deny`, `exempt … until`, list files kept from the command line —
  and automatic, temporary bans ([docs](docs/features/RSF01-02-ip-lists.md)); the live
  view and the lists in the dashboard — what is stopped right now, with the
  reason and where it came from, an address kept out with one click and a
  comment ([docs](docs/features/RSF06-02-live-and-lists.md)); public blocklists
  (Spamhaus DROP, DShield, blocklist.de, Tor, cloud ranges …) fetched by cron,
  each with its own action, and exported for a firewall
  ([docs](docs/features/RSF01-03-blocklist-feeds.md)); the dashboard's
  firewall pages, an HTTP API and an HTTP cache (a page per role) as plugins;
  one file to deploy, with `init`, `verify` and `self-update`.
- **Next:** adapters for
  Exponential, WordPress and Ibexa; exporting the rules to nginx, Apache and
  Varnish.

Documentation: [docs/](docs/README.md) — features, use cases, proposals,
architecture decisions. Privacy and the GDPR: [docs/privacy.md](docs/privacy.md). Changes: [CHANGELOG.md](CHANGELOG.md).

## Installation

### Without Composer (shared hosting)

Three steps: put the directory somewhere **outside** the document root, write
the rules to `request-shield.rules` next to `bootstrap.php` (or to
`config/request-shield.rules`; a PHP array in `config/request-shield.php`
works too, see `config/request-shield.dist.php`), and prepend it:

```ini
; .user.ini in the document root (PHP-FPM, LiteSpeed LSAPI)
auto_prepend_file = /home/you/request-shield/bootstrap.php
```

```apache
# .htaccess (Apache mod_php, LiteSpeed)
php_value auto_prepend_file /home/you/request-shield/bootstrap.php
```

`php bin/request-shield check request-shield.rules` tells you the rules are
in order, and what this hosting can do (the tier: APCu, files, or stateless).
The shield keeps its compiled settings, counters and secret in
`.request-shield/` next to the rules — which is why both belong outside the
document root. The settings file can also be named by a constant or an environment
variable, `REQUEST_SHIELD_CONFIG` (a `.rules` or a `.php` file; then nothing
else is looked for). Without any settings file the shield does nothing.

### With Composer

```bash
composer require cjw-network/request-shield
```

and call it first thing in the front controller:

```php
CjwNetwork\RequestShield\Shield::protectFile(__DIR__ . '/../config/request-shield.rules');
```

`protectFile()` checks the settings once and keeps them compiled for OPcache;
`protect($array)` checks them on every call. An adapter passes its
extensions' rule files as `sources`.

- **WordPress:** at the top of `wp-config.php`, or as `auto_prepend_file`.
- **Ibexa / Symfony:** at the top of `public/index.php`.
- **Exponential:** in `config.php`, before the HTTP cache's early exit.

## Configuration

As a rule file ([all rules](docs/features/RSF05-01-rule-files.md)):

```text
trust        10.0.0.0/8
host         www.example.org example.org
cache-query  page
limit        requests 600/min
limit        misses 60/min on-demand
restrict     /admin/** to 192.0.2.0/24
challenge    /login
set          log /var/log/request-shield.log
```

`php bin/request-shield check|show|reload site.rules` checks it, shows the
rules in effect with their origins, or makes every server read it again;
`trace site.rules "GET https://…/wp-login.php"` shows what happens to a
request, check by check; `version [site.rules]` says what is installed (the
version, PHP, APCu, the store in use, the rule sets' versions). The same as a
page for the admin area: [the active rules page](docs/features/RSF06-01-active-rules-page.md).

Or as a PHP array — every key, with its default, is in `src/Config.php`;
`config/request-shield.dist.php` is a starting point:

```php
return [
    'trustedProxies' => ['10.0.0.0/8'],
    'hosts' => ['www.example.org', 'example.org'],
    'cacheable' => ['query' => ['page'], 'paths' => null],
    'budgets' => [
        'requests' => ['limit' => 600, 'window' => 60],
        'misses' => ['limit' => 60, 'window' => 60, 'onDemand' => true],
    ],
];
```

## Using the decision in the application

```php
$decision = CjwNetwork\RequestShield\Shield::current();   // or $_SERVER['REQUEST_SHIELD']
if ($decision && !$decision->cacheable()) {
    // answer normally, but do not store the page
}
```

A page cache that misses can count the miss against the client:

```php
// after protect()/protectFile(): the same settings and request
if (!CjwNetwork\RequestShield\Shield::active()->consume('misses')->passes()) {
    // too many renders from this client: answer 429, or a stale copy
}
```

## Cost

`php -d apc.enable_cli=1 bench/overhead.php` — a passing request with eleven
headers behind a trusted proxy, every check on:

| PHP 8.1 | per passing request |
|---|---|
| checks, APCu store (tier S2) | ~12 µs |
| checks, file store (tier S1, the shared-hosting norm) | ~42 µs |
| settings: rule files (compiled, APCu) / PHP file | ~5.5 / ~8 µs |
| settings compiled on every request (tier S0: nowhere to write) | + ~30 µs |
| challenge page / solution check / pass cookie (challenged clients only) | ~12 / ~9 / ~5 µs |

The tiers ([settings](docs/features/RSF05-02-settings.md#what-this-installation-can-do-the-tiers)):
PHP ≥ 8.0 is the only requirement; a writable directory and APCu make it
faster. `request-shield check site.rules` says which tier a hosting gives.

## Tests and checks

```bash
php tests/run.php            # no framework needed, PHP 8.0+
composer install && composer phpstan && composer taint
```

The tests include an end-to-end run through PHP's built-in server with
`auto_prepend_file`, and the challenge page's own script run in Node against
the PHP check. CI runs them on every supported PHP version, with and without
APCu, plus PHPStan (level max) and Psalm's taint analysis.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) (and [AGENTS.md](AGENTS.md) for AI
coding agents). Security issues: [SECURITY.md](SECURITY.md).

## Copyright & license

Copyright (C) 2026 JAC Systeme GmbH, part of [CJW Network](https://cjw-network.com).
Released under the MIT license, see `LICENSE`.
