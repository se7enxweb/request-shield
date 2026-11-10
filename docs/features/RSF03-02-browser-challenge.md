# RSF03-02 The browser challenge (proof of work)

*In plain words, for site owners: [the browser check, explained](../explained/browser-check.md).*

## Languages

The check page and the shield's own answers (a pause, "not found", "no
access") are in the visitor's language: the one their browser asks for
(`Accept-Language`) among those there are texts for — **English and German
built in** — else English; `language: 'de'` (`set language de`) fixes one.
Own texts per language: `'texts' => ['de.title' => '…', 'title' => '…']`
(`set text.de.title …`; without a language for all). Those answers carry
`Vary: Accept-Language`.

## What it does

A client past a budget's `challengeAt` gets, instead of the page, a small page
(about 5 KB, no external resource, nothing to click) whose script solves an
**ALTCHA-compatible proof of work**: find the number `n` with
`sha256(salt . n) == challenge`. It puts the solution in a cookie and reloads;
the shield checks it (one hash, one HMAC), sets a **pass cookie** and lets the
request through. With the pass cookie the client is not challenged again until
it expires (the hard `limit` still applies).

![A visitor without a pass gets a small task; a real browser solves it in a moment and holds a pass for an hour](../diagrams/browser-challenge.svg)

- **Difficulty grows** from `difficulty.min` at the threshold to
  `difficulty.max` at the limit (`maxnumber`; the browser needs `maxnumber / 2`
  hashes on average: about 0.1–0.25 s at the threshold).
- **Stateless:** challenge and pass cookie are signed (HMAC) with `secret`;
  the pass cookie is bound to the client bucket and (by default) its
  User-Agent. Solutions are single-use and expire (`solutionTtl`).
- **The site's own check page:** a plugin with the `Pages` capability draws it
  (`challenge`: it gets the task, the solution field's name, the texts, the form
  to send again, home and logo; [plugins](RSF06-04-plugins.md#capabilities-what-a-plugin-can-do-for-the-pages)) -- headers and cookies stay the shield's.
- **Small on the wire:** the pass cookie is `rsp=2.<expires base36>.<tag>.<mac>`
  (43 bytes of value, a 64-bit client tag and a 128-bit MAC, base64url); the
  browser sends it with every request while the pass lasts. The solution
  travels once, in `rss`. `rs` = RequestShield; `cookie` and `solution-cookie`
  set other names.
- **Forms are checked and sent again:** a POST that meets the check gets the
  check page carrying the form's fields, which sends them again once solved —
  nothing typed is lost. Forms with files, or larger than 256 KB, cannot be
  carried: the page asks to send them again (the check inside the form avoids
  that). APIs (JSON, `api-path`) get the task as a header.
- **Background requests never get the page:** a page's script that loads
  something with `fetch()` or `XMLHttpRequest` cannot show the check page or
  run it. The browser marks such a request (`Sec-Fetch-Dest: empty`), and
  libraries do (`X-Requested-With: XMLHttpRequest`). Without a pass it gets
  the check as an API does: 429, JSON, the task in `Request-Shield-Challenge`,
  no HTML. The script can tell that from the fragment it asked for, and reload
  the page, which runs the check. With a pass it goes through as before.
  A navigation (`Sec-Fetch-Dest: document`) keeps the page. A client that only
  sends the headers gets the JSON task: no way past the check.
- **Known crawlers** — search engines and AI crawlers that behave — are
  never given the check: verified by their operators' published address
  lists or by DNS, never by the name they send
  ([known crawlers](RSF01-04-known-crawlers.md)). A site can check or refuse them by
  kind or one by one.
- **Always-checked paths** (`alwaysPaths`): a login or admin page checks every
  visitor once per pass cookie, whatever the budgets say, for every method — a
  bot cannot POST to a login it never loaded (a POST without a pass gets the check first).
- **Exempt paths** (APIs, feeds) are never challenged.
- Without JavaScript or cookies the page says what is missing; after three
  failed attempts in a tab it stops instead of looping.

## How it looks

A ring around the site's logo: while the browser works, the ring fills with
its progress and a dot circles the logo; when it is done, the logo gives way to
a smile, and the page goes on at once (a browser keeps showing it until the
next one arrives, so the smile is seen while that loads — nobody waits for an
animation). If the check cannot finish (no cookies, a loop), a calm "!" in
amber, with the reason below. Dark mode follows the visitor's system;
`prefers-reduced-motion` stops the circling and the fading — the ring still
fills. Without JavaScript nothing moves. For screen readers the ring is
decoration (`aria-hidden`); the sentence below it is a live status
(`role="status"`, which is `aria-live="polite"` by itself): it is read when the page opens,
and again when it changes — the reason when the check cannot finish.

```text
set challenge-logo logo.svg       # the site's own logo in the middle (default: a plain shield)
```

- Inline SVG and CSS only: no image, no font, no extra request. The page grew
  from 6.2 KB (3.1 KB gzip) to 8.7 KB (4.1 KB gzip); building it takes as long
  as before (~11 µs, PHP 8.1 with OPcache).
- The logo file is read **once, when the settings are compiled**, checked and
  inlined — never per request (with settings from a PHP array, `Settings::load()`
  keeps it that way; `protect([...])` would read it each time).
- It must be the site's own and trusted. It is checked strictly anyway, since
  an SVG can carry scripts: at most 16 KB, well-formed XML with `<svg>` at its
  root, no DOCTYPE, no `<script>`, `<foreignObject>`, `<iframe>`, `<object>`,
  `<embed>` or `<style>` (it would style the whole page — `svgo
  --enable=inlineStyles` turns one into attributes), no `on…=` handlers, links
  only to `#…` inside it, no `javascript:`, no `url()` other than `url(#…)`,
  no `@import`, no animation that changes a link. A refused logo is an error
  naming the line (`site.rules:4: challenge-logo: the logo is refused -- …`).
  Its IDs get a prefix, so it never takes over the page's own; it is scaled
  into the ring by its `viewBox` (or `width`/`height`).


## No internet needed — and a DMZ

The check itself makes **no connection to anyone**: the task, its signature,
the check of the answer and the pass cookie are all made on the site's own
server with its own secret; the browser gets everything from the site. It works
in a closed network, a DMZ, without any outside service.

The **only** contact with the outside is DNS, to verify a crawler that has no
published address list, or is not on it (Yandex, Baidu, Amazonbot; Google and
Bing also by DNS): only for a request that would get the check **and** names
such a crawler, and remembered for a day per address. Without a DNS
server that answers (a DMZ), such a lookup waits for the resolver's timeout; so
at most `dns-lookups` new lookups a minute are made for all requests together
(default 30) — past that, a claimed crawler counts as not verified at once and
nothing is remembered, so a flood of fake crawlers cannot make requests wait.

In a DMZ without DNS: `set crawler-verify ranges` — crawlers are verified by
their published address lists only, a comparison on the server: Google, Bing,
Apple, DuckDuckGo, OpenAI, Anthropic, Perplexity, Common Crawl. Those only DNS
can verify are then ordinary visitors (checked where the site checks). The
lists come with each release; `php bin/request-shield crawlers <site.rules>
update` fetches newer ones where there is internet, and `store-dir/crawlers/`
is deployed like any other file ([known crawlers](RSF01-04-known-crawlers.md#without-internet-a-dmz)).
`set dns-lookups 0` or a short resolver timeout (`options timeout:1 attempts:1`
in `/etc/resolv.conf`) also keep DNS from making anyone wait.

## Use cases

- Scrapers and simple bots: they either run the script (and pay CPU per
  address) or stop.
- A login form: bots that try passwords must first pass the check for each
  address (`alwaysPaths`).
- Burst traffic from one address that is not malicious: a person solves once
  and does not notice.

## Every form and every endpoint: `challenge POST`

`challenge <paths>` checks every visitor there, whatever the method. With
methods first, only those are checked:

```text
challenge POST **                          # every form sent, every endpoint posted to -- not the pages
challenge POST PUT PATCH DELETE /api/**    # the API's writing methods
match /shop/** {
  challenge POST                           # in a block: the methods, the paths are the block's
}
```

- **A form without a pass** gets the check page, which sends the form again by
  itself once the check is done -- with every field. Files and forms over
  256 KB are not carried: the visitor is asked to go back and send it again,
  with a pass by then ([details](RSF03-04-app-challenges.md)); for upload
  forms, the check inside the form is better
  ([RSF03-03](RSF03-03-browser-check-in-the-form.md)). Whoever passed a check
  in the last hour (`pass-ttl`) notices nothing.
- **An API** (`api-path`) gets the task as JSON in a header instead of the
  page; a client that cannot solve it gets 429.
- **The pages that show the forms** (a GET) stay as they are: cached, never
  checked by this rule.
- The same paths written again decide anew: `challenge /contact` after
  `challenge POST /contact` checks every method there.
- **Cost:** one comparison of the method where a path matches; a GET pays
  nothing more than before.
- `post-origin same` and `challenge POST **` go together: a form from another
  website is refused (403), one from the site needs a pass.

## Configuration

```php
'budgets' => ['requests' => ['limit' => 600, 'window' => 60, 'challengeAt' => 120]],
'challenge' => [
    'secret' => 'at least 32 characters, the same on every server',   // null: made once in storeDir
    'passTtl' => 3600, 'solutionTtl' => 300,
    'difficulty' => ['min' => 50000, 'max' => 500000],
    'bindUserAgent' => true,
    'searchEngines' => true,            // false: none; or pattern => host suffixes
    'exemptPaths' => ['#^/api/#', '#\.(xml|rss|json)$#'],
    'alwaysPaths' => ['#^/(login|admin)(/|$)#', '#^/#'],   // checked for every visitor
    'alwaysMethods' => ['#^/#' => ['POST']],      // ... here only a POST (challenge POST **)
    'texts' => ['lang' => 'de', 'title' => 'Einen Moment bitte', 'text' => '…'],
],
```

## Cost

Only for challenged clients: page about 12 µs, solution check about 9 µs,
pass cookie check about 5 µs. The passing path does not change.

Bytes: the pass cookie is 47 bytes with its name (`rsp=…`), sent by the
browser with every request while the pass lasts; the check page is about
8.7 KB, 4.1 KB gzipped, once; the headers the shield adds to the check page
are 71 bytes, to the answer that hands out the pass 168 bytes (two
`Set-Cookie` lines). A passing request gets no header and no cookie from the
shield unless `debug-header` is on. The limits are numbers in
`tests/WireBytesTest.php`; `bench/overhead.php` prints the sizes.

## Limits

A determined attacker with real browsers pays the CPU and passes; the point is
the cost per address, not a wall. The script is plain ES5 with its own
SHA-256 (`crypto.subtle` only exists on HTTPS pages); it is tested in Node
against the PHP check.

## Examples from the demo

What the demo's rules decide for this feature -- the same lines `request-shield test` checks and the demo's front page shows (`php -S 127.0.0.1:8080 examples/demo/router.php`).

<!-- examples: docs/tools/sync-examples.php from examples/demo/request-shield.rules -- do not edit; run the tool. -->
**RSF03-02 · The browser check**

A page where every visitor is checked, as a login would be: the invisible check once, then the page. The checkout asks for a fresh pass.

| Request | The rules decide | |
|---|---|---|
| `/challenge` | the invisible browser check · rule DEMO-LOGIN — from another address (198.51.100.7) | A page that always checks the browser |
| `/challenge` | the site answers it — from another address (198.51.100.7), with a pass | with a pass: the page |
| `/checkout` | the invisible browser check · rule DEMO-CHECKOUT — from another address (198.51.100.7) | A checkout: only a fresh pass |
| `/checkout` | the site answers it — from another address (198.51.100.7), with a pass | a pass from a moment ago |
| `/reset` | look at it | Forget my pass: the check comes back on /challenge |
<!-- /examples -->
