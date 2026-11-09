# Write the rules for an application

For an AI agent fitting a starter rule file (`request-shield init`, see
[install.md](install.md)) to one site. Work in **monitor mode** the whole
time: a rule that is wrong is only logged. Every line you add gets an ID of
the file's namespace (`[SITE-…]`), a comment saying why, and at least one
`expect` line below it ([write-rule-examples.md](write-rule-examples.md)).
The full vocabulary is in [rule-files.md](../features/RSF05-01-rule-files.md); a rule
you are not sure of is better left out -- the starter is safe as it is.

## What to look at, and what it becomes

Read the application's routes, its templates' forms and links, its
configuration and, if there is one, its access log. Then, finding by finding:

| You find | You write | Ask the owner? |
|---|---|---|
| the site's domain names (vhost, `.env`, the CMS's site URL) | `[SITE-HOST] host www.example.org example.org` | only when unsure which names are live |
| a load balancer or CDN in front (`X-Forwarded-For` arrives) | `trust <its addresses>` -- the proxy's, from the hoster | **yes**, never guess |
| pages any visitor may get from a cache: the front page, articles, the sitemap | `[SITE-CACHE] cache-path / /news/** /sitemap.xml` | no |
| query parameters the code reads (`$_GET['page']`, the router's `?q=`) | `[SITE-PARAMS] query page int  q text  sort word` | no |
| query parameters with a fixed set of values | a pattern for the value -- see the line below the table | no |
| every parameter the site reads is listed | `[SITE-STRICT] query strict` -- only now does an unknown parameter or a wrong type get 404 (the marketing tags of `@tracking` stay allowed) | no |
| forms: where each one posts | `[SITE-FORMS] allow POST /contact /search /login` -- a POST anywhere else gets 405 | no |
| forms that must come from the site's own pages | `[SITE-ORIGIN] post-origin same` -- a form sent without `Origin` and `Referer` gets the browser check, so a POST example then needs `header Origin:https://<the site>` | no |
| a login page | `[SITE-LOGIN] challenge /login` (every visitor shows a browser first) | no |
| an admin or editor area | `[SITE-ADMIN] restrict /admin/** to <ranges>` | **yes**: only with the ranges the owner gives; else leave it to the application's login |
| an API that machines call (JSON, tokens) | `[SITE-API] api-path /api/**` and, if it is called often, `challenge-exempt /api/**` | no |
| a search, an expensive page | `[SITE-SEARCH] limit searches 10/min at /search` -- the eleventh in a minute gets 429 | no |
| paths only attackers ask for that the starter misses (an old installer) | `[SITE-OLD] block /install/**` -- hidden files, backups, database tools, CGI, project or key files (composer.json, id_rsa), copies of .env, stored keys and credential files (.env.production, .aws, credentials.json) are in the scanner rules already | no |
| the site is **not** WordPress | `include @wordpress` (the starter has it, except for `--app=wordpress`) | no |

A parameter with a fixed set of values, as a pattern (the line exactly as
written here):

```
[SITE-LANG] query lang /(de|en)/
```

What not to write: no `exempt` for "our office" without the owner's ranges;
no `deny` for addresses found in a log (a log is not proof); no `block` for a
path the application serves; no `set secret` (the shield makes one); no
`stats` or dashboard lines unless the owner asks for them.

## Paths

`/news/**` is `/news` and everything below it; `/page/*` one segment;
`**/admin/**` an `admin` directory anywhere; `*.sql` that ending anywhere.
Behind a front controller the request path may start with `/index.php/…`:
write `**/admin/**` rather than `/admin/**` there.

## Examples, the near miss included

Below each rule, what it decides -- and one address that looks alike and must
pass:

```
[SITE-FORMS] allow POST /contact /search
expect POST /contact          answered
expect POST /send             405 by SITE-FORMS
[SITE-PARAMS] query page int  q text
expect GET /news?page=2       answered
[SITE-STRICT] query strict
expect GET /news?page=two     404 by SITE-STRICT
expect GET /?utm_source=x     answered
```

`test` decides every example with all the rules: an example below one rule
can be caught by another (a POST example by `post-origin`, a path by the
scanner rules). Then the failure names the other rule -- adjust the example,
not the rule.

Use the site's real public paths, and only documentation addresses
(`from 198.51.100.7`). `request-shield test` decides every line with the
rules switched on, as `enforce` would.

## Then

Run `check` and `test` ([check.md](check.md)) after every few lines, not at
the end: an error names the file and line. When both exit 0, go on with
step 6 of [install.md](install.md).
