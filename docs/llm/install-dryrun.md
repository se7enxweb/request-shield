# The install guide, followed literally: a dry run

[install.md](install.md) was followed step by step in a container, as an
agent would follow it, on 2026-10-04 (0031 step E.7). Two passes: the first
found what the guide left out, the guide was changed, the second ran it again
from a fresh container and went through.

## The setup

- **Container:** `php:8.0-apache` -- PHP 8.0.30 (the baseline), Apache
  2.4.56 with `mod_php`, Debian, no APCu.
- **The site:** three PHP files in `/var/www/html` -- `index.php`,
  `news.php` (reads `?page=`), `contact.php` (a form that posts to itself).
  No front controller.
- **The download:** there is no published release yet. The files the
  release workflow makes -- `request-shield.php` built from commit `625336f`
  (build `dryrun 625336f`, the version still `0.4.0-dev`) and `SHA256SUMS` --
  were served from the host, and the guide's GitHub address was replaced by
  that server's. No `.minisig`: the releases are signed once the release key
  exists (0031 step H.2a).

## What the first pass found

1. **The `.minisig` download fails with 404** until the releases are signed.
   The guide now says that is expected.
2. **The shield's directory was not writable for PHP.** The directory made
   in step 1 belonged to root; PHP runs as `www-data`. The shield still let
   every request through -- fail safe, as it should -- but compiled the rules
   on every request, kept no counters and wrote no log, and said nothing on
   the page. `check`, run as root, reported "writable". The guide now makes
   `.request-shield/` with mode 700 for the PHP user, and runs `check` as
   that user: then it reports tier `S0` and "not writable" when it is wrong.
3. **`/.env` never reached the shield.** On a site without a front
   controller, Apache answers a path that is no PHP file itself;
   `auto_prepend_file` runs only for PHP. The guide's step 7 now asks for an
   attack pattern on a PHP page and explains why.
4. **A wrong lead, recorded so nobody follows it:** the first pass took the
   missing log for an `.htaccess` that Apache ignores and changed
   `AllowOverride`. This image allows `.htaccess` already
   (`docker-php.conf`: `AllowOverride All`); items 2 and 3 were the whole
   cause. The guide keeps its note -- a stock Debian Apache has
   `AllowOverride None` for `/var/www/` -- and gained the check that would
   have shown it at once: a temporary page printing `auto_prepend_file` and
   the shield's decision.

Also changed: `ps` lists `root` (Apache's parent) next to the PHP user; the
log's columns in [check.md](check.md) (a reason in quotes has spaces, so the
rule is read with `grep -o 'rule=…'`); in [write-rules.md](write-rules.md)
five example lines that `test` showed to be wrong -- written there before the
dry run, each now checked.

## The second pass

Fresh container, the guide as it is now, every command and its output. Step
8 is the report to the owner, which this page is.

```text
## 1. Find the places
$ grep -h DocumentRoot /etc/apache2/sites-enabled/*.conf
	DocumentRoot /var/www/html
[exit 0]

$ apache2ctl -M 2>/dev/null | grep php
 php_module (shared)
[exit 0]

$ curl -s -o /dev/null http://localhost/; ps -o user= -C apache2,httpd,php-fpm | sort -u
root
www-data
[exit 0]

$ ls /var/www/html; mkdir -p /var/www/request-shield
contact.php
index.php
news.php
[exit 0]

## 2. Download and verify
$ cd /var/www/request-shield && curl -fsSLO http://host.docker.internal:18900/request-shield.php; curl -fsSLO http://host.docker.internal:18900/SHA256SUMS; curl -fsSLO http://host.docker.internal:18900/request-shield.php.minisig; php request-shield.php verify request-shield.php
curl: (22) The requested URL returned error: 404 File not found
checksum: ok (request-shield.php sha256:806c91cacb2ad93d7b20775c62abc19e7948139419d3c990864371cc37f20111)
signature: not checked -- this build has no release key yet; the checksum only shows the download is complete, not who made it
[exit 0]

$ cd /var/www/request-shield && php request-shield.php version | head -1
request-shield 0.4.0-dev (dryrun 625336f)
[exit 0]

## 3. Start the rules
$ cd /var/www/request-shield && php request-shield.php init --app=plain --docroot=/var/www/html --out=/var/www/request-shield/request-shield.rules
written: /var/www/request-shield/request-shield.rules (plain, monitor mode)
next: add the site's rules, then  request-shield check /var/www/request-shield/request-shield.rules  and  request-shield test /var/www/request-shield/request-shield.rules
[exit 0]

$ mkdir -m 700 /var/www/request-shield/.request-shield && chown www-data: /var/www/request-shield/.request-shield && su -s /bin/sh www-data -c 'php /var/www/request-shield/request-shield.php check /var/www/request-shield/request-shield.rules'
ok: 1 file(s) + built-in rules, 20 blocked patterns, 1 budget(s), 21 attack patterns; rule sets SCAN 2026.11.1, CRAWL 2026.10.1, WP 2026.10.1, TRACK 2026.10.1, ATK 2026.10.2, SITE 1
tier: S1 -- APCu is not available to the CLI (the web server may differ; apc.enable_cli=1 switches it on here); store-dir /var/www/request-shield/.request-shield/store is writable; the compiled settings' directory /var/www/request-shield/.request-shield is writable
[exit 0]

## 4. Fit the rules to the site
$ grep -n "^\[SITE-\|^expect" /var/www/request-shield/request-shield.rules
17:[SITE-HOST]  host localhost
20:expect GET /wp-login.php         404 by WP-SCRIPTS     # a WordPress script on a site that has none
22:expect GET /?utm_source=mail     answered              # a campaign tag
25:[SITE-PACE]  limit requests 60/min challenge-at 30     # per visitor: the browser check past 30 a minute
26:expect GET /                     answered              # the front page
27:expect GET /.env                 404 by SCAN-HIDDEN    # a hidden file (the built-in scanners rules)
29:[SITE-SHIELD]  restrict **/rs/** to 127.0.0.1 ::1      # the shield's own pages: only this machine
30:expect GET /rs/waf/live          403 by SITE-SHIELD
33:[SITE-PARAMS] query page int
34:expect GET /news.php?page=2       answered
35:[SITE-FORMS]  allow POST /contact.php
36:expect POST /contact.php          answered
37:expect POST /index.php            405 by SITE-FORMS
[exit 0]

## 5. Check
$ su -s /bin/sh www-data -c 'php /var/www/request-shield/request-shield.php check /var/www/request-shield/request-shield.rules' | grep -E '^(ok|warning|tier)'
ok: 1 file(s) + built-in rules, 20 blocked patterns, 1 budget(s), 21 attack patterns; rule sets SCAN 2026.11.1, CRAWL 2026.10.1, WP 2026.10.1, TRACK 2026.10.1, ATK 2026.10.2, SITE 1
tier: S1 -- APCu is not available to the CLI (the web server may differ; apc.enable_cli=1 switches it on here); store-dir /var/www/request-shield/.request-shield/store is writable; the compiled settings' directory /var/www/request-shield/.request-shield is writable
[exit 0]

$ php /var/www/request-shield/request-shield.php test /var/www/request-shield/request-shield.rules | tail -1
32 examples: 32 pass.
[exit 0]

## 6. Switch it on (Apache with mod_php: .htaccess)
$ echo "php_value auto_prepend_file /var/www/request-shield/request-shield.php" > /var/www/html/.htaccess
[exit 0]

$ echo '<?php echo ini_get("auto_prepend_file"), " | ", $_SERVER["REQUEST_SHIELD"] ?? "(not run)", PHP_EOL;' > /var/www/html/rs-on.php && curl -s http://localhost/rs-on.php
/var/www/request-shield/request-shield.php | allow
[exit 0]

(Already on: this image's docker-php.conf allows .htaccess for /var/www/. The change below -- the step for a stock Debian Apache -- was not needed here; it is kept to show the page answers the same after it.)
$ sed -i "/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride Options/" /etc/apache2/apache2.conf && apache2ctl -k graceful; sleep 1; curl -s http://localhost/rs-on.php; rm /var/www/html/rs-on.php
AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 172.17.0.2. Set the 'ServerName' directive globally to suppress this message
/var/www/request-shield/request-shield.php | allow
[exit 0]

## 7. See it work
$ curl -s -o /dev/null -w '%{http_code}\n' 'http://localhost/'
200
[exit 0]

$ curl -s -o /dev/null -w '%{http_code}\n' 'http://localhost/index.php?q=%3Cscript%3Ealert(1)%3C/script%3E'
200
[exit 0]

$ php /var/www/request-shield/request-shield.php trace /var/www/request-shield/request-shield.rules 'GET http://localhost/index.php?q=%3Cscript%3Ealert(1)%3C/script%3E' | grep -E '✕|This visitor'
  ✕ Attack patterns                   refused: cross-site scripting: <script>, <iframe> in the address  [ATK-XSS-TAG]
This visitor sees the page — monitor mode; enforced, it gets no access (403) — the site never sees it. Decided by ATK-XSS-TAG.
[exit 0]

$ tail -n 5 /var/www/request-shield/.request-shield/shield.log
2026-10-03T22:27:09+00:00 127.0.0.0/24 monitor-reject 403 "attack" rule=ATK-XSS-TAG "GET http://localhost/index.php?q=%3Cscript%3Ealert(1)%3C/script%3E" "curl/7.74.0"
[exit 0]

$ ls -la /var/www/request-shield /var/www/request-shield/.request-shield
/var/www/request-shield:
total 980
drwxr-xr-x 3 root     root       4096 Oct  3 22:27 .
drwxr-xr-x 1 root     root       4096 Oct  3 22:26 ..
drwx------ 2 www-data www-data   4096 Oct  3 22:27 .request-shield
-rw-r--r-- 1 root     root        176 Oct  3 22:26 SHA256SUMS
-rw-r--r-- 1 root     root     977033 Oct  3 22:26 request-shield.php
-rw-r--r-- 1 root     root       1918 Oct  3 22:27 request-shield.rules

/var/www/request-shield/.request-shield:
total 400
drwx------ 2 www-data www-data   4096 Oct  3 22:27 .
drwxr-xr-x 3 root     root       4096 Oct  3 22:27 ..
-rw------- 1 www-data www-data 396823 Oct  3 22:27 settings-ca386778eb958f395ee370eae8b1ea7c.php
-rw-r----- 1 www-data www-data    167 Oct  3 22:27 shield.log
[exit 0]
```

## After the review

The review of this step changed four lines of the guide after the second
pass: step 1 finds the PHP user with `ps -eo user=,comm= | grep -E
'php-fpm|apache2|httpd|nginx'` (the old `ps -C` missed `php-fpm8.x` and
nginx) and, for php-fpm, the pool's `user`; step 5 runs `check` as the PHP
user, as the second pass above already did; the check page uses the document
root from step 1; in write-rules.md the `query lang /(de|en)/` line moved out
of the table (a Markdown table escapes the `|`, and the escaped line copied
literally matched nothing -- now checked with `test`). The new `ps` line, run
in the same image:

```text
$ ps -eo user=,comm= | grep -E 'php-fpm|apache2|httpd|nginx' | sort -u
root     apache2
www-data apache2
```

## Result

Every step did what the guide says. The site answers as before; the log
shows what monitor mode would have refused (`ATK-XSS-TAG` for a script in
the query); `check` (as the PHP user) and `test` exit 0; the shield's
files belong to root, only `.request-shield/` to the PHP user. Not covered
here: php-fpm with `.user.ini`, nginx, a front-controller site where
`/.env` does reach PHP, the signature check (no release key yet) and the
real download address.
