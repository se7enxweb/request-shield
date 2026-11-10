# RSF02-02 Blocked paths

## What it does

![A scanner's request for a blocked path is answered by the shield with 404; every other request reaches the site](../diagrams/blocked-paths.svg)

Some addresses are asked for only by scanners: `/.env`, `/.git/config`,
`/backup.sql`, `/phpinfo.php`, `/phpmyadmin/`. The shield refuses them with
"not found" (404) before the site runs -- the scanner learns nothing, the site
spends nothing, and the log names the rule.

Every site has the shipped sets `@scanners` (`rules/scanners.rules`) and
`@devtools` (`rules/devtools.rules`), read before its own rules. A site that
is **not** WordPress adds `include @wordpress`: WordPress's folders and
scripts are the most scanned paths there are. All three are rule files like a site's
own -- with IDs, descriptions, revisions and examples (`expect`) that
`request-shield test` checks.

## Use cases

- **Every site:** hidden files, backups, test scripts, database tools,
  project or key files (composer.json, id_rsa), copies of `.env`, stored
  keys and credential files (.env.production, .aws, credentials.json) are
  never part of a public site; scanners try them all day.
- **A site that is not WordPress:** `include @wordpress` turns away the
  requests for `/wp-login.php` and `/wp-admin/` that make up a large share of
  all attack traffic.
- **Every site, too: other software's tools.** `@devtools` turns away the
  requests for `/package.json`, `/actuator/env`, `/_profiler`,
  `/server-status`, `/swagger-ui.html` and `main.js.map` -- what a scanner
  asks for to learn what a site runs on. A site that serves one of them
  through PHP -- a Symfony site in development has `/_profiler`, an API its
  `/swagger-ui` -- takes that one rule back (`unblock [DEV-APIDOCS@1]`),
  opens it for some addresses, or takes back the whole set (`unblock
  @devtools`).
- **A path of the site's own that only attackers ask for:** an old installer,
  a forgotten admin tool -- `block /install/**`.

## Configuration

```text
include @wordpress                                 # this is not WordPress
unblock [DEV-APIDOCS@1]                            # this site shows its API's description (@devtools is built in)
[SITE-OLD] block /install/** /phpmyadmin/**        # paths of your own

replace [SCAN-BACKUP@1] block *.sql *.bak          # one rule written differently, its ID kept
unblock [SCAN-CGI@1]                               # one shipped rule taken back
[SITE-DL] unblock [SCAN-BACKUP@1] at /downloads/**  # open at some paths only
[SITE-FILES] unblock [SCAN-HIDDEN@1] at /admin/files/** for 192.0.2.0/24   # … and only for some addresses
```

The order matters: an `unblock … at` opens the rule as it stands at that line.
A `replace` written after it puts a new rule in its place, and the opening no
longer applies -- write `replace` first.

Paths are globs (`/news/**`, `*.sql`, `**/admin/**`) or, with `regex`, regular
expressions ([rule files](RSF05-01-rule-files.md#paths)). The `@1` is the
revision a site reviewed -- when an update changes the rule, `check` says so.
A path that leaves the site's folder (`/files/%2e%2e/secret`) is refused
before any of these, as a broken request (400, [hard rejects](RSF02-01-hard-rejects.md)).

The shipped rules:

| Rule | Set | Refuses |
|---|---|---|
| `SCAN-HIDDEN` | `@scanners` | hidden files and folders: .env, .git, .htpasswd, editor settings |
| `SCAN-BACKUP` | `@scanners` | backups, dumps and archives: .bak, .old, .sql, .zip, .tar.gz, .log … |
| `SCAN-TEST` | `@scanners` | test and info scripts: phpinfo.php, info.php, test.php |
| `SCAN-DBTOOL` | `@scanners` | database and test tools: phpMyAdmin, Adminer, PHPUnit |
| `SCAN-CGI` | `@scanners` | cgi-bin, and .well-known except certificates, security.txt and password change |
| `SCAN-CONFIG` | `@scanners` | project and key files: composer.json, composer.lock, web.config, docker-compose.yml, .npmrc, id_rsa (also id_dsa, id_ecdsa, id_ed25519 and their .pub) -- a scanner asks for them to learn what the site runs on; the web server sends a file that exists without PHP, so the rule spares the site's front controller the ones that do not |
| `SCAN-SECRETS` | `@scanners` | copies of .env and stored keys: .env.production, .env.local, .env_1 (a name after `.env`), the folders and files where cloud, container and other tools keep their keys (.aws, .azure, .gcloud, .ssh, .docker, .kube, .terraform, .netrc, .pgpass, .my.cnf, .s3cfg, .boto, .pypirc, .vault-token, .git-credentials, .gitconfig, .envrc, .bash_history, .cursor, .claude), and the server's own .htaccess and .user.ini -- `SCAN-HIDDEN` has `.env` itself; `/tools/.envoy`, `/tags/.net` and `/.dockerignore` pass |
| `SCAN-KEYS` | `@scanners` | credential files and key stores: credentials, secrets, service-account, client_secret, aws-credentials, private-key as .json, .yml, .env, .pem, .key, .txt, .ini … (credentials.json, config/serviceAccountKey.json, secrets.yml); private.key, server.key; and by their extension .pem, .p12, .pfx, .jks, .keystore, .ppk, .kdbx, .tfvars, .tfstate -- a Keynote file (`/slides/quarter.key`), a certificate to hand out (`/downloads/root-ca.crt`) and `/credentials-guide` pass; a site that hands out a `.pem` through PHP opens it with `unblock [SCAN-KEYS@1] at /downloads/**` |
| `WP-FOLDERS` | `@wordpress` | WordPress folders: /wp-admin, /wp-includes, /wp-content |
| `WP-SCRIPTS` | `@wordpress` | WordPress scripts: wp-login.php, xmlrpc.php, wp-config.php |
| `DEV-BUILD` | `@devtools` | build files: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml, Dockerfile, Makefile, Gemfile, requirements.txt, go.mod, Cargo.toml, phpunit.xml, tsconfig.json, webpack.config.js (also vite, next, nuxt) -- `/manifest.json` and `/package-tours` pass |
| `DEV-APPCONFIG` | `@devtools` | other software's settings files: php.ini, appsettings.json, application.yml, application.properties, database.yml, parameters.yml, settings.local.yml, settings.py |
| `DEV-DEBUG` | `@devtools` | debug and status pages at the root: Symfony's profiler (/_profiler, /_wdt), Laravel's Telescope, Horizon, Ignition and debug bar, Spring's actuator, Jolokia, the H2 console, /debug/pprof, server-status, server-info, elmah.axd, the JBoss and Tomcat consoles -- `/shop/telescope` and `/horizon-2030` pass |
| `DEV-APIDOCS` | `@devtools` | API consoles and descriptions at the root: swagger-ui, swagger.json, openapi.json, api-docs (also /v2/api-docs), graphiql -- `/docs/openapi.json` passes |
| `DEV-SOURCE` | `@devtools` | source maps (main.js.map, style.css.map) and a development server's own addresses: /@fs/, /@vite/, /__vite_ping, /__webpack_hmr, /sockjs-node |

## Cost

All blocked paths together are one regular expression, built when the rules
are compiled: one match per request, part of the 2--3 µs a passing request's
decision takes ([cost](../../README.md#cost)). More patterns make that
expression longer, not the number of matches.

## Limits

- **The shield sees what reaches PHP.** On a site without a front controller
  the web server answers a path that is no PHP file -- `/.env` -- itself; the
  shield never sees it (found when the install guide was followed,
  [dry run](../llm/install-dryrun.md)). Sites that send every request to one
  `index.php` (WordPress and most CMS) get the full effect; elsewhere the web
  server's own rules (`location ~ /\.` in nginx, `RedirectMatch 404 /\.` in
  Apache) cover the files that are not PHP.
- **404, not 403**, on purpose: a scanner cannot tell a refused path from one
  that is not there.

## Examples from the demo

What the demo's rules decide for this feature -- the same lines `request-shield test` checks and the demo's front page shows (`php -S 127.0.0.1:8080 examples/demo/router.php`).

<!-- examples: docs/tools/sync-examples.php from examples/demo/request-shield.rules -- do not edit; run the tool. -->
**RSF02-02 · Paths only attackers ask for**

Hidden files, backups, database tools: refused before the site runs, with "not found" -- the scanner learns nothing.

| Request | The rules decide | |
|---|---|---|
| `/.env` | "not found" (404) — the site never sees it · rule SCAN-HIDDEN — from another address (198.51.100.7) | What a scanner looks for |
| `/backup.sql` | "not found" (404) — the site never sees it · rule SCAN-BACKUP — from another address (198.51.100.7) | A backup |
| `/files/.env` | the site answers it — from 127.0.0.1 | The admin's file reader: hidden files open at /files/ only, from this machine |
| `/files/.env` | "not found" (404) — the site never sees it · rule SCAN-HIDDEN — from another address (198.51.100.7) | the same address from anywhere else |
<!-- /examples -->
