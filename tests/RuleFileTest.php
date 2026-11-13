<?php

declare(strict_types=1);

use CjwNetwork\RequestShield\Request;
use CjwNetwork\RequestShield\Rules\Pattern;
use CjwNetwork\RequestShield\Rules\RuleFile;
use CjwNetwork\RequestShield\Rules\RuleFileException;
use CjwNetwork\RequestShield\Settings;
use CjwNetwork\RequestShield\Shield;
use CjwNetwork\RequestShield\Store\MemoryStore;

/** A directory with the given files; returns its path. */
function ruleDir(array $files): string
{
    $dir = sys_get_temp_dir() . '/rshield-rules-' . getmypid() . '-' . mt_rand();
    foreach ($files as $name => $text) {
        @mkdir(dirname("$dir/$name"), 0700, true);
        file_put_contents("$dir/$name", $text);
    }
    return $dir;
}

function rulesFrom(string $text): Settings
{
    $dir = ruleDir(['site.rules' => $text]);
    try {
        return Settings::from(RuleFile::read(["$dir/site.rules"])['config']);
    } finally {
        exec('rm -rf ' . escapeshellarg($dir));
    }
}

/** The rule text must fail, with a message starting "$at: " and containing $part. */
function rulesFail(array $files, string $at, string $part): void
{
    $dir = ruleDir($files);
    try {
        RuleFile::read(["$dir/site.rules"]);
    } catch (RuleFileException $e) {
        truthy(strncmp($e->getMessage(), "$at: ", strlen($at) + 2) === 0, "starts with $at: " . $e->getMessage());
        truthy(strpos($e->getMessage(), $part) !== false, "says \"$part\": " . $e->getMessage());
        return;
    } finally {
        exec('rm -rf ' . escapeshellarg($dir));
    }
    throw new TestFailure("accepted: " . json_encode($files));
}

/** Where a built-in rule is written: "built-in scanners.rules:<line>". */
function shippedAt(string $id): string
{
    foreach (['scanners', 'wordpress'] as $name) {
        foreach (file(dirname(__DIR__) . "/rules/$name.rules") ?: [] as $i => $line) {
            if (preg_match('/^\[' . preg_quote($id, '/') . '(@\d+)?\]/', $line)) {
                return "built-in $name.rules:" . ($i + 1);
            }
        }
    }
    return '?';
}

function decideFor(Settings $s, string $path, array $server = []): string
{
    $shield = new Shield($s, new MemoryStore());
    $d = $shield->decide(Request::fromServer($server + ['REQUEST_URI' => $path, 'REMOTE_ADDR' => '198.51.100.7', 'HTTP_HOST' => 'www.example.org'], $s->trustedProxies), 1000.0);
    return trim($d->action . ' ' . $d->reason);
}

return [
    'RSF02-03 an address range: a prefix no longer than its address -- 1.2.3.4/99 is a mistake, not a range that matches nobody' => function (): void {
        foreach (['restrict /x/** to 1.2.3.4/99', 'restrict /x/** to 2001:db8::/129', 'trust 10.0.0.0/33'] as $line) {
            $dir = ruleDir(['site.rules' => "$line\n"]);
            try {
                RuleFile::read(["$dir/site.rules"]);
                throw new TestFailure("accepted: $line");
            } catch (RuleFileException $e) {
                truthy(strpos($e->getMessage(), 'is not an address or a range') !== false, $e->getMessage());
            } finally {
                exec('rm -rf ' . escapeshellarg($dir));
            }
        }
        same(['10.0.0.0/32'], rulesFrom("trust 10.0.0.0/32\n")->trustedProxies, 'the longest prefix is fine');
    },
    'RSF05-01 patterns: * within a segment, ** across, ? one character; no leading /: anywhere' => function (): void {
        $cases = [
            ['/wp-admin/**', '/wp-admin', true], ['/wp-admin/**', '/wp-admin/x/y.php', true], ['/wp-admin/**', '/wp-adminx', false],
            ['/page/*', '/page/about', true], ['/page/*', '/page/a/b', false], ['/page/*', '/page', false],
            ['*.sql', '/dump.sql', true], ['*.sql', '/a/b/dump.sql', true], ['*.sql', '/dump.sqlx', false],
            ['/file?.txt', '/file1.txt', true], ['/file?.txt', '/file12.txt', false], ['/file?.txt', '/file/.txt', false],
            ['/', '/', true], ['/', '/x', false], ['/a.b', '/aXb', false], ['/(x)', '/(x)', true],
            ['**/admin/**', '/admin', true], ['**/admin/**', '/demo/admin/x', true], ['**/admin/**', '/demo/administrator', false],
        ];
        foreach ($cases as [$glob, $path, $match]) {
            same($match, preg_match(Pattern::fromGlob($glob), $path) === 1, "$glob ~ $path");
        }
        same(1, preg_match(Pattern::fromRegex('^/a#b'), '/a#b'), 'a # in a regex');
    },
    'RSF05-01 the format: every keyword fills its setting' => function (): void {
        $s = rulesFrom(<<<'RULES'
            # a comment
            host        www.example.org Example.org     # trailing comment
            trust       10.0.0.0/8 2001:db8::/32
            method      put
            block       /wp-admin/**  *.sql
            block regex ^/(phpmyadmin|adminer)
            cache-query page offset
            cache-path  /  /news/**
            limit       requests 600/min challenge-at 300
            limit       misses   60/min  on-demand
            limit       burst    20/10s
            challenge   /login
            challenge-exempt /api/**
            exempt      192.0.2.50
            set         debug-header on
            set         pass-ttl 30m
            set         ipv6-prefix 56
            set         store file
            set         text.title Einen Moment, bitte
            RULES);
        same(['www.example.org', 'example.org'], $s->hosts);
        same(['10.0.0.0/8', '2001:db8::/32'], $s->trustedProxies);
        same(['GET', 'HEAD', 'POST', 'OPTIONS', 'PUT'], $s->methods);
        truthy(in_array('#^/wp\-admin(?:/.*)?$#', $s->blockedPaths, true), 'glob block');
        truthy(in_array('#^/(phpmyadmin|adminer)#', $s->blockedPaths, true), 'regex block');
        truthy(count($s->blockedPaths) === 3 + count(\CjwNetwork\RequestShield\Config::defaults()['blockedPaths']), 'added to the built-in paths');
        same(['page', 'offset'], $s->cacheableQuery);
        same(['#^/$#', '#^/news(?:/.*)?$#'], $s->cacheablePaths);
        same([600, 60, 300, false], [$s->budgets['requests']->limit, $s->budgets['requests']->window, $s->budgets['requests']->challengeAt, $s->budgets['requests']->onDemand]);
        same([60, 60, true], [$s->budgets['misses']->limit, $s->budgets['misses']->window, $s->budgets['misses']->onDemand]);
        same([20, 10], [$s->budgets['burst']->limit, $s->budgets['burst']->window]);
        same(['#^/login$#'], $s->challenge->alwaysPaths);
        same(['#^/api(?:/.*)?$#'], $s->challenge->exemptPaths);
        same(['127.0.0.1', '::1', '192.0.2.50'], $s->exemptIps);
        same(true, $s->debugHeader);
        same(1800, $s->challenge->passTtl);
        same(56, $s->ipv6Prefix);
        same('file', $s->store);
        same(['title' => 'Einen Moment, bitte'], $s->challenge->texts);
    },
    'RSF05-01 taking back: none, any, unblock, no-limit' => function (): void {
        $s = rulesFrom("block /x/**\nunblock /x/**\nunblock @scanners\nunblock @devtools\nexempt none 192.0.2.1\nno-limit requests\ncache-path /a\ncache-path any\nmethod none GET\n");
        same([], $s->blockedPaths, 'the built-in sets and the block taken back');
        same(['192.0.2.1'], $s->exemptIps, 'none empties the defaults too');
        same([], $s->budgets, 'no-limit switches the default budget off');
        same(null, $s->cacheablePaths, 'any: every path');
        same(['GET'], $s->methods);
        same([], rulesFrom("cache-query none\n")->cacheableQuery, 'none: no parameter');
        truthy(count(rulesFrom("block @wordpress\n")->blockedPaths) === count(\CjwNetwork\RequestShield\Config::defaults()['blockedPaths']) + 2, 'the WordPress set');
    },
    'RSF05-01 the decisions follow the rules' => function (): void {
        $s = rulesFrom("host www.example.org\nblock /wp-admin/**\ncache-path / /page/*\ncache-query page\nchallenge /login\n");
        same('reject blocked path', decideFor($s, '/wp-admin/install.php'));
        same('reject blocked path', decideFor($s, '/backup.sql'), 'the scanner paths stay');
        same('allow', decideFor($s, '/page/about?page=2'));
        same('allow-uncached path not cacheable', decideFor($s, '/page/a/b'));
        same('allow-uncached query parameter', decideFor($s, '/?utm=1'));
        same('challenge always', decideFor($s, '/login'));
        same('reject host', decideFor($s, '/', ['HTTP_HOST' => 'evil.example']));
    },
    'RSF05-01 environment variables: ${NAME}, ${NAME:-default}, an error when unset' => function (): void {
        putenv('RSHIELD_TEST_SECRET=' . str_repeat('s', 40));
        same(str_repeat('s', 40), rulesFrom("set secret \${RSHIELD_TEST_SECRET}\n")->challenge->secret);
        putenv('RSHIELD_TEST_SECRET');
        rulesFail(['site.rules' => "set secret \${RSHIELD_TEST_SECRET}\n"], 'site.rules:1', 'RSHIELD_TEST_SECRET is not set');
        same('/srv/x', rulesFrom("set store-dir \${RSHIELD_TEST_DIR:-/srv/x}\n")->storeDir, 'a default');
        $dir = ruleDir(['site.rules' => "set store-dir \${RSHIELD_TEST_DIR:-/srv/x}\n"]);
        try {
            same('/srv/x', Settings::load("$dir/site.rules", "$dir/cache")->storeDir);
            putenv('RSHIELD_TEST_DIR=/srv/y');
            same('/srv/y', Settings::load("$dir/site.rules", "$dir/cache")->storeDir, 'rebuilt when the variable changes');
        } finally {
            putenv('RSHIELD_TEST_DIR');
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF05-01 errors name file and line' => function (): void {
        rulesFail(['site.rules' => "host a.example\n\nblok /x\n"], 'site.rules:3', 'unknown rule "blok" (did you mean "block"?)');
        rulesFail(['site.rules' => "block regex ^/(a\n"], 'site.rules:1', 'not a valid regular expression');
        rulesFail(['site.rules' => "limit requests 600/fortnight\n"], 'site.rules:1', 'not a rate');
        rulesFail(['site.rules' => "limit requests 600/min challenge-at\n"], 'site.rules:1', 'limit <name>');
        rulesFail(['site.rules' => "set debug-header maybe\n"], 'site.rules:1', 'on or off');
        rulesFail(['site.rules' => "set debug-heder on\n"], 'site.rules:1', 'did you mean "debug-header"');
        rulesFail(['site.rules' => "set pass-ttl soon\n"], 'site.rules:1', 'a duration');
        rulesFail(['site.rules' => "set text.titel x\n"], 'site.rules:1', 'unknown text');
        rulesFail(['site.rules' => "trust 10.0.0/8x\n"], 'site.rules:1', 'not an address');
        rulesFail(['site.rules' => "block @joomla\n"], 'site.rules:1', 'unknown set');
        rulesFail(['site.rules' => "challenge @scanners\n"], 'site.rules:1', 'only works with block');
        rulesFail(['site.rules' => "unblock /never-blocked\n"], 'site.rules:1', 'nothing to unblock');
        rulesFail(['site.rules' => "host\n"], 'site.rules:1', 'needs at least one value');
        rulesFail(['site.rules' => "include rules.d/10.rules\n", 'rules.d/10.rules' => "host a\nmethod GET!\n"], 'rules.d/10.rules:2', 'not a method');
    },
    'RSF05-01 the settings check still applies: a short secret' => function (): void {
        $dir = ruleDir(['site.rules' => "set secret tooshort\n"]);
        try {
            Settings::load("$dir/site.rules", "$dir/cache");
            throw new TestFailure('accepted a short secret');
        } catch (InvalidArgumentException $e) {
            truthy(strpos($e->getMessage(), 'challenge.secret') !== false, $e->getMessage());
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF05-01 include: in alphabetical order, relative to the file, not above it, no loops' => function (): void {
        $dir = ruleDir([
            'site.rules' => "include rules.d/*.rules\nblock /site\n",
            'rules.d/90-late.rules' => "limit x 9/min\n",
            'rules.d/10-early.rules' => "limit x 1/min\nblock /early\n",
            'rules.d/50-other.txt' => "this is not read\n",
        ]);
        try {
            $read = RuleFile::read(["$dir/site.rules"]);
            $s = Settings::from($read['config']);
            same(9, $s->budgets['x']->limit, 'the later file wins');
            same(['#^/early$#', '#^/site$#'], array_slice($s->blockedPaths, -2), 'in the order read');
            same('rules.d/90-late.rules:1', $s->origin('budgets', 'x'), 'origin relative to the main file');
            same('site.rules:2', $s->origin('blockedPaths', '#^/site$#'));
            same('SCAN-HIDDEN', $s->origin('blockedPaths', \CjwNetwork\RequestShield\Config::scannerPaths()[0]));
            truthy(isset($read['seen']["$dir/rules.d"]), 'the include directory is watched');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
        rulesFail(['site.rules' => "include ../../etc/*.rules\n"], 'site.rules:1', 'is outside');
        rulesFail(['site.rules' => "include missing.rules\n"], 'site.rules:1', 'cannot read');
        rulesFail(['site.rules' => "include a.rules\n", 'a.rules' => "include site.rules\n"], 'a.rules:1', 'includes itself');
        $empty = rulesFrom("include none.d/*.rules\n");
        truthy($empty->budgets !== [], 'a glob matching nothing is fine');
    },
    'RSF05-01 sources: several files, the main file last' => function (): void {
        $dir = ruleDir([
            'site.rules' => "limit x 5/min\n",
            'ext/shop/settings/request-shield.rules' => "limit x 1/min\nchallenge /shop/checkout\n",
            'ext/blog/settings/request-shield.rules' => "cache-path /blog/**\n",
        ]);
        try {
            $s = Settings::load("$dir/site.rules", "$dir/cache", ["$dir/ext/*/settings/request-shield.rules"]);
            same(5, $s->budgets['x']->limit, 'the site has the last word');
            same(['#^/shop/checkout$#'], $s->challenge->alwaysPaths);
            same('ext/shop/settings/request-shield.rules:2', $s->origin('challenge.alwaysPaths', '#^/shop/checkout$#'));
            same(['#^/blog(?:/.*)?$#'], $s->cacheablePaths);
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF05-01 load(): compiled once; a change in any file is noticed (recheck 0)' => function (): void {
        $dir = ruleDir(['site.rules' => "set recheck 0\ninclude rules.d/*.rules\n", 'rules.d/a.rules' => "host a.example\n"]);
        try {
            same(['a.example'], Settings::load("$dir/site.rules", "$dir/cache")->hosts);
            same(1, count(glob("$dir/cache/settings-*.php")), 'compiled');
            // Another size: mtime has whole seconds, so a change of the same
            // size within the same second is not seen (documented).
            file_put_contents("$dir/rules.d/a.rules", "host bb.example\n");
            same(['bb.example'], Settings::load("$dir/site.rules", "$dir/cache")->hosts, 'an included file changed');
            file_put_contents("$dir/rules.d/b.rules", "host c.example\n");
            touch("$dir/rules.d", time() + 2);
            same(['bb.example', 'c.example'], Settings::load("$dir/site.rules", "$dir/cache")->hosts, 'a file added to the include directory');
            // A broken edit is an error, not the old settings quietly kept.
            file_put_contents("$dir/rules.d/b.rules", "hots cc.example\n");
            try {
                Settings::load("$dir/site.rules", "$dir/cache");
                throw new TestFailure('a broken file was accepted');
            } catch (RuleFileException $e) {
                truthy(strpos($e->getMessage(), 'rules.d/b.rules:1') !== false, $e->getMessage());
            }
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF05-01 load(): with APCu, other files are checked only every "recheck" seconds; the main file without it' => function (): void {
        $dir = ruleDir(['site.rules' => "set recheck 60\ninclude rules.d/*.rules\n", 'rules.d/a.rules' => "host a.example\n"]);
        try {
            same(['a.example'], Settings::load("$dir/site.rules", "$dir/cache")->hosts);
            file_put_contents("$dir/rules.d/a.rules", "host bb.example\n");
            $apcu = function_exists('apcu_enabled') && apcu_enabled();
            same(['a.example'], Settings::load("$dir/site.rules", "$dir/cache")->hosts,
                $apcu ? 'within the interval: not even a stat()' : 'without APCu: only the main file is checked');
            file_put_contents("$dir/site.rules", "set recheck 60\ninclude rules.d/*.rules\n# touched\n");
            if ($apcu) {
                apcu_clear_cache();
            }
            same(['bb.example'], Settings::load("$dir/site.rules", "$dir/cache")->hosts, 'the main file changed: everything read again');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF02-03 restrict: paths only for some addresses; //, %61, case and /./ do not get past it' => function (): void {
        $s = rulesFrom("restrict /admin/** /api/** to 192.0.2.0/24 2001:db8::/32\n");
        $from = static fn (string $ip, string $path): string => decideFor($s, $path, ['REMOTE_ADDR' => $ip]);
        foreach (['/admin', '/admin/', '/admin/users', '//admin/', '/%61dmin/', '/ADMIN/x', '/./admin/', '/api/v1'] as $path) {
            same('reject restricted', $from('198.51.100.7', $path), "outside: $path");
        }
        same('allow-uncached path not cacheable', rulesFrom("cache-path /\nrestrict /admin/** to 192.0.2.0/24\n") !== null ? decideFor(rulesFrom("cache-path /\nrestrict /admin/** to 192.0.2.0/24\n"), '/administrator') : '', 'a longer name is another path');
        same('allow', $from('192.0.2.10', '/admin/users'), 'inside the range');
        same('allow', $from('2001:db8::5', '//admin/'), 'IPv6 range');
        // Behind a trusted proxy: the address it vouches for, not the header anyone sends.
        $p = rulesFrom("trust 10.0.0.1\nrestrict /admin/** to 192.0.2.0/24\n");
        same('allow', decideFor($p, '/admin/', ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '192.0.2.10']));
        same('reject restricted', decideFor($p, '/admin/', ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_X_FORWARDED_FOR' => '192.0.2.10']), 'a forged header');
        rulesFail(['site.rules' => "restrict /admin/**\n"], 'site.rules:1', 'restrict <paths> to');
        rulesFail(['site.rules' => "restrict /admin/** to office\n"], 'site.rules:1', 'not an address');
    },
    'RSF02-03 allow: a method only on some paths, anywhere else 405' => function (): void {
        $s = rulesFrom("allow POST /edit /contact\nallow PUT DELETE /api/**\n");
        same(['GET', 'HEAD', 'POST', 'OPTIONS', 'PUT', 'DELETE'], $s->methods, 'the methods are allowed at all');
        $as = static fn (string $method, string $path): string => decideFor($s, $path, ['REQUEST_METHOD' => $method]);
        same('allow-uncached method', $as('POST', '/edit'));
        same('allow-uncached method', $as('POST', '//Contact'), 'as the application routes it');
        same('reject method not allowed here', $as('POST', '/page/about'));
        same('reject method not allowed here', $as('PUT', '/edit'));
        same('allow-uncached method', $as('DELETE', '/api/items/5'));
        same('allow', $as('GET', '/page/about'), 'other methods are not affected');
        rulesFail(['site.rules' => "allow POST\n"], 'site.rules:1', 'allow <METHODS> <paths>');
    },
    'RSF05-05 the rule behind a decision: file and line, default, built-in, or the setting' => function (): void {
        $dir = ruleDir(['site.rules' => "# comment\nblock /x/**\nrestrict /admin/** to 192.0.2.1\nallow POST /edit\nlimit requests 2/min\nchallenge /login\n"]);
        try {
            $s = Settings::load("$dir/site.rules", "$dir/cache");
            $explain = static function (string $path, array $server = []) use ($s): ?string {
                $shield = new Shield($s, new MemoryStore());
                $r = Request::fromServer($server + ['REQUEST_URI' => $path, 'REMOTE_ADDR' => '198.51.100.7']);
                return $shield->explain($shield->decide($r, 1000.0), $r);
            };
            same('site.rules:2', $explain('/x/y'));
            same('SCAN-HIDDEN', $explain('/.env'));
            same('SCAN-BACKUP', $explain('/dump.sql'));
            same('site.rules:3', $explain('/admin/'));
            same('site.rules:4', $explain('/page', ['REQUEST_METHOD' => 'POST']));
            same('site.rules:6', $explain('/login'));
            same('built-in', $explain('/a/%2e%2e/b'));
            same(null, $explain('/'), 'allowed: no rule');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
        // PHP array settings: the setting and the index.
        $shield = new Shield(['blockedPaths' => ['#^/a#', '#^/b#'], 'budgets' => ['requests' => ['limit' => 1, 'window' => 60]]], new MemoryStore());
        $r = Request::fromServer(['REQUEST_URI' => '/b', 'REMOTE_ADDR' => '198.51.100.7']);
        same('blockedPaths[1]', $shield->explain($shield->decide($r, 1000.0), $r));
    },
    'RSF05-01 bin/request-shield: check, show, reload, trace' => function (): void {
        if (!function_exists('exec')) {
            skip('no exec');
        }
        $bin = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(rsCli());
        $dir = ruleDir(['site.rules' => "block /x/**\nlimit requests 5/min\nrestrict /rs/** to 127.0.0.1 ::1\n", 'ext/a.rules' => "challenge /login\n", 'bad.rules' => "blok /x\n"]);
        try {
            exec("$bin check " . escapeshellarg("$dir/site.rules") . ' --source=' . escapeshellarg("$dir/ext/*.rules") . ' 2>&1', $out, $code);
            same(0, $code, implode("\n", $out));
            truthy(strpos(implode("\n", $out), 'ok: 2 file(s) + built-in rules') !== false, implode("\n", $out));
            $out = [];
            exec("$bin check " . escapeshellarg("$dir/bad.rules") . ' 2>&1', $out, $code);
            same(1, $code);
            same('bad.rules:1: unknown rule "blok" (did you mean "block"?)', $out[0] ?? '');
            $out = [];
            exec("$bin show " . escapeshellarg("$dir/site.rules") . ' --source=' . escapeshellarg("$dir/ext/*.rules") . ' 2>&1', $out, $code);
            $shown = implode("\n", $out);
            truthy(preg_match('~^block regex \^/x\(\?:/\.\*\)\?\$ +# \(site\.rules:1\)$~m', $shown) === 1, $shown);
            truthy(preg_match('~^challenge regex \^/login\$ +# \(ext/a\.rules:1\)$~m', $shown) === 1, 'the extension\'s rule, with its origin');
            truthy(strpos($shown, 'set secret (generated in store-dir)') !== false, 'a secret is never shown');
            touch("$dir/site.rules", time() - 100);
            exec("$bin reload " . escapeshellarg("$dir/site.rules") . ' 2>&1', $out, $code);
            clearstatcache();
            truthy(filemtime("$dir/site.rules") >= time() - 5, 'reload marks the main file changed');
            $out = [];
            exec("$bin trace " . escapeshellarg("$dir/site.rules") . ' ' . escapeshellarg('GET https://www.example.org/x/y') . ' --ip=192.0.2.1 2>&1', $out, $code);
            same(4, $code, 'refused: exit 4');
            truthy(preg_match('~✕ Addresses only attackers ask for\s+refused: /x/\*\*  \[site\.rules:1\]~u', implode("\n", $out)) === 1, implode("\n", $out));
            truthy(strpos(implode("\n", $out), 'This visitor gets "not found" (404)') !== false, 'the verdict');
            chmod("$dir/site.rules", 0666);
            $out = [];
            exec("$bin check " . escapeshellarg("$dir/site.rules") . ' 2>&1', $out, $code);
            same(3, $code, 'a file anyone can change');
            truthy(strpos(implode("\n", $out), 'can be changed by anyone') !== false, implode("\n", $out));
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF02-03 unblock at: blocked paths open at some paths only, for some addresses only; traversal never' => function (): void {
        $s = rulesFrom("unblock at /admin/files/** for 192.0.2.0/24\nunblock [SCAN-HIDDEN] at /public/**\n");
        $from = static fn (string $ip, string $path): string => decideFor($s, $path, ['REMOTE_ADDR' => $ip]);
        same('allow', $from('192.0.2.5', '/admin/files/.env'), 'the admin file reader, from the office');
        same('allow', $from('192.0.2.5', '/admin/files/backup.sql'), 'every block lifted there');
        same('allow', $from('192.0.2.5', '//admin/files/.git/config'), 'as the application routes it');
        same('reject blocked path', $from('198.51.100.7', '/admin/files/.env'), 'from anyone else: blocked');
        same('reject blocked path', $from('192.0.2.5', '/other/.env'), 'elsewhere: blocked');
        same('reject path traversal', $from('192.0.2.5', '/admin/files/%2e%2e/%2e%2e/config.php'), 'the path check is never lifted');
        same('allow', $from('198.51.100.7', '/public/.well-known-ish/.htpasswd'), 'one set, for everyone');
        same('reject blocked path', $from('198.51.100.7', '/public/.well-known-ish/.htaccess'), 'only the set named: another rule\'s file stays refused');
        same('reject blocked path', $from('198.51.100.7', '/public/dump.sql'), 'only that set');
        rulesFail(['site.rules' => "unblock at\n"], 'site.rules:1', 'unblock [<what>] at <paths>');
        rulesFail(['site.rules' => "unblock at /x for\n"], 'site.rules:1', 'unblock [<what>] at <paths>');
        rulesFail(['site.rules' => "unblock /never at /x\n"], 'site.rules:1', 'nothing to unblock');
        rulesFail(['site.rules' => "unblock [SCAN-NOPE] at /x\n"], 'site.rules:1', 'no earlier block has the ID [SCAN-NOPE]');
        rulesFail(['site.rules' => "unblock @joomla at /x\n"], 'site.rules:1', 'unknown set');
        rulesFail(['site.rules' => "unblock at /x for office\n"], 'site.rules:1', 'not an address');
        // PHP array settings
        $a = new Shield(['blockExceptions' => [['paths' => ['#^/files/#'], 'patterns' => null, 'ips' => []]]], new MemoryStore());
        same('allow', $a->decide(Request::fromServer(['REQUEST_URI' => '/files/.env', 'REMOTE_ADDR' => '198.51.100.7']), 1000.0)->action);
    },
    'RSF02-03 unblock at: shown in the check, on the page, and warned about without "for"' => function (): void {
        needsPlugins();         // the shipped plugins' pages (the WAF's, the statistics'): not in the core single file
        $dir = ruleDir(['site.rules' => "unblock at /admin/files/** for 192.0.2.0/24\nunblock [SCAN-BACKUP] at /downloads/**\n"]);
        try {
            $s = Settings::from(RuleFile::read(["$dir/site.rules"])['config']);
            $t = (new \CjwNetwork\RequestShield\Inspector($s, new MemoryStore()))->trace(\CjwNetwork\RequestShield\Inspector::request('GET', '/admin/files/.env', '192.0.2.5'), 1000.0);
            same('pass', step($t, 'Addresses only attackers ask for')['state']);
            same('would be refused (hidden files and folders: .env, .git, .htpasswd, editor settings), but open here for 192.0.2.5 (192.0.2.0/24) — site.rules:1', step($t, 'Addresses only attackers ask for')['text']);
            $html = \CjwNetwork\RequestShield\Waf\RulesPage::render($s, ['store' => new MemoryStore()]);
            truthy(strpos($html, 'Open at /admin/files/**: every block above — only for 192.0.2.0/24') !== false, 'the exception on the page');
            truthy(strpos($html, 'Open at /downloads/**: backups, dumps and archives') !== false && strpos($html, '⚠ for everyone') !== false, 'the open one, with a warning');
            $bin = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(rsCli());
            exec("$bin check " . escapeshellarg("$dir/site.rules") . ' 2>&1', $out, $code);
            same(3, $code, 'a warning');
            truthy(strpos(implode("\n", $out), 'warning: site.rules:2: blocked paths are open there for everyone') !== false, implode("\n", $out));
            $out = [];
            exec("$bin show " . escapeshellarg("$dir/site.rules") . ' 2>&1', $out);
            truthy(preg_match('~^unblock at regex \^/admin/files\(\?:/\.\*\)\?\$ for 192\.0\.2\.0/24 +# \(site\.rules:1\)$~m', implode("\n", $out)) === 1, implode("\n", $out));
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF05-05 IDs: [SITE-10] before a rule names it everywhere; the comment after it describes it' => function (): void {
        needsPlugins();         // the shipped plugins' pages (the WAF's, the statistics'): not in the core single file
        $dir = ruleDir(['site.rules' => "ids SITE\n\n[SITE-10] restrict /admin/** to 192.0.2.0/24   # the admin area: office only\n[SITE-ADMIN-FILES] unblock [SCAN-HIDDEN] at /admin/files/** for 192.0.2.0/24\n block /x/**   # no ID: file and line\n[SITE-20] limit requests 5/min\n"]);
        try {
            $s = Settings::load("$dir/site.rules", "$dir/cache");
            $explain = static function (string $path) use ($s): ?string {
                $shield = new Shield($s, new MemoryStore());
                $r = Request::fromServer(['REQUEST_URI' => $path, 'REMOTE_ADDR' => '198.51.100.7']);
                return $shield->explain($shield->decide($r, 1000.0), $r);
            };
            same('SITE-10', $explain('/admin/'));
            same('site.rules:5', $explain('/x/y'), 'without an ID: file and line');
            same('SCAN-HIDDEN', $explain('/.env'));
            same('site.rules:3', $s->origin('at', 'SITE-10'), 'where it is written');
            same('the admin area: office only', $s->origin('text', 'SITE-10'), 'its description');
            same('no ID: file and line', $s->origin('text', 'site.rules:5'));
            same(shippedAt('SCAN-HIDDEN'), $s->origin('at', 'SCAN-HIDDEN'));
            same('SITE-20', $s->origin('budgets', 'requests'));
            $html = \CjwNetwork\RequestShield\Waf\RulesPage::render($s, ['store' => new MemoryStore()]);
            truthy(strpos($html, 'the admin area: office only<br><code class="rule">/admin/** — only for 192.0.2.0/24</code>') !== false, 'the page: description, then the rule');
            truthy(strpos($html, '<code class="origin">SITE-10</code><br><span class="note">site.rules:3</span>') !== false, 'the page: ID and where');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF05-05 IDs: the namespace of a file, required IDs, no duplicates, and the errors' => function (): void {
        same('SHOP-1', rulesFrom("ids SHOP\n[SHOP-1] block /x\nblock /y\n")->origin('blockedPaths', '#^/x$#'), 'IDs optional by default');
        truthy(rulesFrom("ids SHOP required\nset debug-header on\n[SHOP-1] block /x\n") !== null, 'set and include need no ID');
        rulesFail(['site.rules' => "ids SHOP required\n[SHOP-1] block /x\nblock /y\n"], 'site.rules:3', 'every rule in this file needs an ID');
        rulesFail(['site.rules' => "ids SHOP\n[SITE-1] block /x\n"], 'site.rules:2', 'not in this file\'s namespace -- its IDs start with SHOP-');
        rulesFail(['site.rules' => "include ext/*.rules\n[SHOP-1] block /y\n", 'ext/shop.rules' => "ids SHOP\n[SHOP-1] block /x\n"], 'site.rules:2', '[SHOP-1] is used twice -- already at ext/shop.rules:2');
        rulesFail(['site.rules' => "[SCAN-HIDDEN] block /x\n"], 'site.rules:1', 'used twice -- already at ' . shippedAt('SCAN-HIDDEN'));
        rulesFail(['site.rules' => "[a b] block /x\n"], 'site.rules:1', 'is not an ID');
        rulesFail(['site.rules' => "[X-1]\n"], 'site.rules:1', 'before what?');
        rulesFail(['site.rules' => "[X-1] set debug-header on\n"], 'site.rules:1', 'set takes no ID');
        rulesFail(['site.rules' => "ids SHOP\nids SITE\n"], 'site.rules:2', 'a file has one namespace');
        rulesFail(['site.rules' => "ids 1SHOP\n"], 'site.rules:1', 'ids <NAMESPACE> [required]');
        $dir = ruleDir(['site.rules' => "include ext/*.rules\n[ANY-1] block /a\n", 'ext/shop.rules' => "ids SHOP required\n[SHOP-1] block /x\n"]);
        try {
            same('ANY-1', Settings::from(RuleFile::read(["$dir/site.rules"])['config'])->origin('blockedPaths', '#^/a$#'), 'an included file\'s namespace does not bind the file including it');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF02-02 @devtools: built in -- build files, settings files, debug pages, API consoles, source maps; one rule taken back or opened, or the whole set' => function (): void {
        $cases = ['/package.json' => 'DEV-BUILD', '/app/Dockerfile' => 'DEV-BUILD', '/vite.config.ts' => 'DEV-BUILD',
            '/php.ini' => 'DEV-APPCONFIG', '/appsettings.Production.json' => 'DEV-APPCONFIG', '/config/database.yml' => 'DEV-APPCONFIG',
            '/_profiler/phpinfo' => 'DEV-DEBUG', '/actuator/env' => 'DEV-DEBUG', '/telescope/requests' => 'DEV-DEBUG', '/server-status' => 'DEV-DEBUG',
            '/swagger-ui.html' => 'DEV-APIDOCS', '/v2/api-docs' => 'DEV-APIDOCS', '/openapi.json' => 'DEV-APIDOCS',
            '/assets/main.js.map' => 'DEV-SOURCE', '/@fs/etc/passwd' => 'DEV-SOURCE', '/__vite_ping' => 'DEV-SOURCE'];
        $off = rulesFrom("unblock @devtools\n");
        foreach (array_keys($cases) as $path) {
            same('allow', decideFor($off, $path), "the whole set taken back: $path");
        }
        $s = rulesFrom('');
        same(count(\CjwNetwork\RequestShield\Config::scannerPaths()) + 5, count($s->blockedPaths), 'read by every site: five rules next to the scanner rules');
        same(count($s->blockedPaths), count(rulesFrom("include @devtools\n")->blockedPaths), 'include @devtools changes nothing');
        same(count($s->blockedPaths), count(rulesFrom("block @devtools\n")->blockedPaths), 'block @devtools = include @devtools');
        $shield = new Shield($s, new MemoryStore());
        foreach ($cases as $path => $id) {
            $r = Request::fromServer(['REQUEST_URI' => $path, 'REMOTE_ADDR' => '198.51.100.7', 'HTTP_HOST' => 'www.example.org']);
            $d = $shield->decide($r, 1000.0);
            same(['reject', 404, 'blocked path', $id], [$d->action, $d->status, $d->reason, $shield->explain($d, $r)], "$path: 404 by $id");
        }
        foreach (['/package-tours', '/manifest.json', '/blog/dockerfile-tips', '/account/settings', '/docs/application.html', '/shop/telescope', '/horizon-2030',
            '/actuators-and-valves', '/api-documentation', '/docs/openapi.json', '/sitemap', '/maps/berlin.map.html', '/@alice', '/'] as $path) {
            same('allow', decideFor($s, $path), "a near miss passes: $path");
        }
        same('DEV', array_key_last(array_filter($s->origins['versions'], static fn (string $v): bool => $v === '2026.11.2')), 'the set has a version');
        // A site with an API console takes that one rule back; a team opens the debug pages for its office.
        $api = rulesFrom("include @devtools\nunblock [DEV-APIDOCS@1]\n[SITE-DBG] unblock [DEV-DEBUG@1] at /_profiler/** /_wdt/** for 192.0.2.0/24\n");
        same('allow', decideFor($api, '/swagger-ui.html'), 'taken back');
        same('reject blocked path', decideFor($api, '/package.json'), 'the others stay');
        same('allow', decideFor($api, '/_profiler/latest', ['REMOTE_ADDR' => '192.0.2.5']), 'the profiler, from the office');
        same('reject blocked path', decideFor($api, '/_profiler/latest'), 'from anyone else: refused');
    },
    'RSF02-02 the built-in rules: shipped as rule files, the same as the PHP defaults' => function (): void {
        $mirror = \CjwNetwork\RequestShield\Config::builtIns();
        $defaults = rulesFrom('');
        same(array_merge(\CjwNetwork\RequestShield\Config::scannerPaths(), \CjwNetwork\RequestShield\Config::devtoolsPaths()), $defaults->blockedPaths, 'rules/scanners.rules and rules/devtools.rules = Config::scannerPaths() and devtoolsPaths()');
        $wp = rulesFrom("unblock @scanners\nunblock @devtools\ninclude @wordpress\n");
        same(\CjwNetwork\RequestShield\Config::wordpressPaths(), $wp->blockedPaths, 'rules/wordpress.rules = Config::wordpressPaths()');
        foreach ([$defaults, $wp] as $s) {
            foreach ($s->blockedPaths as $p) {
                $id = (string) $s->origin('blockedPaths', $p);
                same($mirror[$p] ?? null, [$id, $s->origin('text', $id)], "ID and description of $id, in Config::builtIns() and the rule file");
            }
        }
        same(\CjwNetwork\RequestShield\Settings::from([])->blockedPaths, $defaults->blockedPaths, 'PHP array settings get the same blocks');
        same(count(\CjwNetwork\RequestShield\Config::defaults()['blockedPaths']) + 2, count(rulesFrom("block @wordpress\n")->blockedPaths), 'block @wordpress = include @wordpress');
        same(count(rulesFrom("include @wordpress\nblock @wordpress\n")->blockedPaths), count(rulesFrom("include @wordpress\n")->blockedPaths), 'twice is once');
        same(count(\CjwNetwork\RequestShield\Config::defaults()['blockedPaths']) - 1, count(rulesFrom("unblock [SCAN-CGI]\n")->blockedPaths), 'one taken back by its ID');
        same('SCAN-BACKUP', \CjwNetwork\RequestShield\Config::setName(\CjwNetwork\RequestShield\Config::scannerPaths()[1]), 'PHP array settings: the ID too');
    },
    'RSF05-01 versions: one per file, named by its namespace; shown by check' => function (): void {
        needsPlugins();         // the shipped plugins' pages (the WAF's, the statistics'): not in the core single file
        $dir = ruleDir(['site.rules' => "ids SITE\nversion 2026-09-29.2\ninclude ext/*.rules\n", 'ext/shop.rules' => "version 1.4.0\nblock /x\n"]);
        try {
            $s = Settings::from(RuleFile::read(["$dir/site.rules"])['config']);
            same(['SCAN' => '2026.11.1', 'DEV' => '2026.11.2', 'CRAWL' => '2026.10.1', 'ext/shop.rules' => '1.4.0', 'SITE' => '2026-09-29.2'], $s->origins['versions'], 'the built-ins, then in the order read; a file without namespace by its name');
            $bin = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(rsCli());
            exec("$bin check " . escapeshellarg("$dir/site.rules") . ' 2>&1', $out, $code);
            truthy(strpos(implode("\n", $out), 'rule sets SCAN 2026.11.1, DEV 2026.11.2, CRAWL 2026.10.1, ext/shop.rules 1.4.0, SITE 2026-09-29.2') !== false, implode("\n", $out));
            $html = \CjwNetwork\RequestShield\Waf\RulesPage::render($s, ['store' => new MemoryStore()]);
            truthy(strpos($html, '<code>SITE 2026-09-29.2</code>') !== false, 'on the rules page');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
        rulesFail(['site.rules' => "version 1.0\nversion 1.1\n"], 'site.rules:2', 'a file has one version');
        rulesFail(['site.rules' => "version two words\n"], 'site.rules:1', 'version <version>');
        rulesFail(['site.rules' => "[X-1] version 1\n"], 'site.rules:1', 'version <version>');
    },
    'RSF05-01 revisions: [ID@n] defines and pins; a changed rule is a warning, and still applies' => function (): void {
        needsPlugins();         // the shipped plugins' pages (the WAF's, the statistics'): not in the core single file
        same('1', rulesFrom('')->origin('rev', 'SCAN-BACKUP'), 'the built-ins have revisions');
        same([], rulesFrom("unblock [SCAN-BACKUP@1] at /downloads/**\n")->origins['warnings'] ?? [], 'the reviewed revision: no warning');
        same([], rulesFrom("unblock [SCAN-BACKUP] at /downloads/**\n")->origins['warnings'] ?? [], 'no revision named: no warning');
        same([], rulesFrom("[SITE-1@1] block /x\n[SITE-2] unblock [SITE-1@1]\n")->origins['warnings'] ?? [], 'own rules too');
        // A library update: SCAN-BACKUP is revision 2 now (a copy of the shipped file).
        $dir = ruleDir(['site.rules' => "ids SITE\n[SITE-DL] unblock [SCAN-BACKUP@1] at /downloads/**\n[SITE-RS] restrict /rs/** to 127.0.0.1 ::1\n"]);
        $lib = sys_get_temp_dir() . '/rshield-lib-' . getmypid() . '-' . mt_rand();
        try {
            mkdir($lib, 0700, true);
            if (rsSingle() === null) {
                foreach (['src', 'rules', 'bin', 'bootstrap.php'] as $part) {
                    exec('cp -r ' . escapeshellarg(dirname(__DIR__) . "/$part") . ' ' . escapeshellarg($lib));
                }
                $f = "$lib/rules/scanners.rules";
                $tool = "$lib/bin/request-shield";
            } else {
                // The single file: the set is embedded, so the update is a new file.
                $f = $tool = "$lib/request-shield.php";
                copy(rsSingle(), $f);
            }
            // The set only (the single file holds other texts that name the rule): from its start on, once.
            $text = (string) file_get_contents($f);
            $at = rsSingle() === null ? 0 : (int) strpos($text, "'scanners' => <<<'RS_SHIPPED'");
            $hit = strpos($text, '[SCAN-BACKUP@1]', $at);
            truthy($hit !== false && ($at > 0 || rsSingle() === null), 'the shipped rule is there to change');
            file_put_contents($f, substr_replace($text, '[SCAN-BACKUP@2]', (int) $hit, strlen('[SCAN-BACKUP@1]')));
            exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($tool) . ' check ' . escapeshellarg("$dir/site.rules") . ' 2>&1', $out, $code);
            same(3, $code, 'check warns');
            truthy(strpos(implode("\n", $out), 'warning: SITE-DL (site.rules:2) was written for SCAN-BACKUP revision 1; SCAN-BACKUP is now revision 2') !== false, implode("\n", $out));
            exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($tool) . ' trace ' . escapeshellarg("$dir/site.rules") . ' ' . escapeshellarg('GET https://x.example/backup.sql') . ' 2>&1', $out2, $code2);
            same(4, $code2, 'the changed rule still applies elsewhere');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir) . ' ' . escapeshellarg($lib));
        }
        $warned = rulesFrom("[SITE-X] unblock [SCAN-CGI@7]\n");
        truthy(strpos(\CjwNetwork\RequestShield\Waf\RulesPage::render($warned, ['store' => new MemoryStore()]), '<strong>Please check:</strong> SITE-X (site.rules:1) was written for SCAN-CGI revision 7; SCAN-CGI is now revision 1') !== false, 'on the rules page');
        rulesFail(['site.rules' => "[SITE-1@0] block /x\n"], 'site.rules:1', 'is not an ID');
        rulesFail(['site.rules' => "unblock [SCAN-BACKUP@x]\n"], 'site.rules:1', 'is not an ID');
    },
    'RSF05-01 replace: a rule swapped in one line, keeping its ID -- and its count in the log' => function (): void {
        $dir = ruleDir(['site.rules' => "ids SITE\nreplace [SCAN-BACKUP@1] block *.sql *.sql.gz *.bak   # backups, but not archives: this site offers .zip downloads\n"
            . "[SITE-PACE] limit requests 5/min\nreplace [SITE-PACE] limit requests 50/min challenge-at 25\n[SITE-ADM] restrict /admin/** to 192.0.2.1\nreplace [SITE-ADM] restrict /admin/** to 192.0.2.0/24\n"]);
        try {
            $s = Settings::load("$dir/site.rules", "$dir/cache");
            $explain = static function (string $path, string $ip = '198.51.100.7') use ($s): ?string {
                $shield = new Shield($s, new MemoryStore());
                $r = Request::fromServer(['REQUEST_URI' => $path, 'REMOTE_ADDR' => $ip]);
                return $shield->explain($shield->decide($r, 1000.0), $r);
            };
            same('SCAN-BACKUP', $explain('/dump.sql'), 'the same ID');
            same(null, $explain('/download/site.zip'), '.zip is not blocked any more');
            same(null, $explain('/old.log'), 'nor .log: the replacement is all there is');
            same('backups, but not archives: this site offers .zip downloads', $s->origin('text', 'SCAN-BACKUP'), 'the new description');
            truthy(strpos((string) $s->origin('at', 'SCAN-BACKUP'), 'site.rules:2 (replaces ' . shippedAt('SCAN-BACKUP') . ')') === 0, (string) $s->origin('at', 'SCAN-BACKUP'));
            same([50, 25], [$s->budgets['requests']->limit, $s->budgets['requests']->challengeAt], 'a budget replaced');
            same([['paths' => ['#^/admin(?:/.*)?$#i'], 'ips' => ['192.0.2.0/24']]], $s->restricted, 'a restrict replaced, not added');
            same(null, $explain('/admin/', '192.0.2.9'));
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
        // A ban replaced: the new one only -- also where the old one was only watched (monitor ban).
        $dir = ruleDir(['site.rules' => "ids SITE\n[SITE-BAN] ban after 10 refusals in 10m for 1h\nreplace [SITE-BAN] ban after 20 refusals in 10m for 2h\n"
            . "[SITE-WBAN] monitor ban after 5 limits in 1m for 1h\nreplace [SITE-WBAN] ban after 8 limits in 1m for 1h\n"]);
        try {
            $s = Settings::load("$dir/site.rules", "$dir/cache");
            $mine = static fn (array $bans): array => array_values(array_map(static fn (array $b): string => "{$b['rule']} {$b['after']} {$b['signal']}",
                array_filter($bans, static fn (array $b): bool => str_starts_with($b['rule'], 'SITE-'))));
            same(['SITE-BAN 20 refusals', 'SITE-WBAN 8 limits'], $mine($s->bans), 'a ban replaced, not added; the watched one replaced by an enforced one');
            same(['SITE-BAN 20 refusals', 'SITE-WBAN 8 limits'], $mine($s->monitor?->bans ?? $s->bans), 'and the watched rules no longer hold the old thresholds');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
        rulesFail(['site.rules' => "replace [SITE-NOPE] block /x\n"], 'site.rules:1', 'no earlier rule has the ID [SITE-NOPE]');
        rulesFail(['site.rules' => "replace block /x\n"], 'site.rules:1', 'replace [<ID>] <rule>');
        rulesFail(['site.rules' => "[X-1] replace [SCAN-CGI] block /x\n"], 'site.rules:1', 'the ID follows replace');
        rulesFail(['site.rules' => "replace [SCAN-CGI] set debug-header on\n"], 'site.rules:1', 'replace takes a rule');
        rulesFail(['site.rules' => "replace [SCAN-CGI] blok /x\n"], 'site.rules:1', 'unknown rule "blok"');
    },
    'RSF02-06 content rules: block query, header <Name>, headers, anywhere -- regular expressions always' => function (): void {
        $s = rulesFrom('block query \bunion\s+select\b' . "\n"
            . 'block header User-Agent \b(sqlmap|nikto)\b' . "\n"
            . 'block headers \$\{jndi:' . "\n"
            . 'block anywhere \$\{env:' . "\n");
        same([['target' => 'query', 'patterns' => ['#\bunion\s+select\b#i']],
            ['target' => 'header:user-agent', 'patterns' => ['#\b(sqlmap|nikto)\b#i']],
            ['target' => 'headers', 'patterns' => ['#\$\{jndi:#i']],
            ['target' => 'anywhere', 'patterns' => ['#\$\{env:#i']]], $s->contentRules, 'the target and its patterns');
        same(['query' => '#(?:\bunion\s+select\b)#i', 'header:user-agent' => '#(?:\b(sqlmap|nikto)\b)#i',
            'headers' => '#(?:\$\{jndi:)#i', 'anywhere' => '#(?:\$\{env:)#i'], $s->contentIndex, 'one expression per target');
        same('reject attack', decideFor($s, '/?id=1%20union%20select%202'), 'the query');
        same('reject attack', decideFor($s, '/', ['HTTP_USER_AGENT' => 'nikto scan']), 'a named header');
        same('reject attack', decideFor($s, '/', ['HTTP_REFERER' => 'https://e/?${jndi:ldap://x}']), 'every header');
        same('reject attack', decideFor($s, '/${env:x}'), 'anywhere: the path too');
        same('allow', decideFor($s, '/?q=union bank'), 'a near miss passes');
        // "regex" may be written; it changes nothing. Several patterns in one line share the rule.
        same(['#\bunion\s+select\b#i'], rulesFrom('block query regex \bunion\s+select\b' . "\n")->contentRules[0]['patterns'], 'regex is implied');
        same([['target' => 'query', 'patterns' => ['#a#i', '#b#i', '#c#i']]], rulesFrom("block query a b c\n")->contentRules);
        // The refusal is named by the rule's ID, like every other rule.
        $s = rulesFrom("ids X required\n[X-U] block query sqlmap\n");
        $shield = new Shield($s, new MemoryStore());
        $r = Request::fromServer(['REQUEST_URI' => '/?a=sqlmap', 'REMOTE_ADDR' => '198.51.100.7']);
        same('X-U', $shield->explain($shield->decide($r, 1000.0), $r));
        rulesFail(['site.rules' => "block query\n"], 'site.rules:1', 'what to look for');
        rulesFail(['site.rules' => "block headers\n"], 'site.rules:1', 'what to look for');
        rulesFail(['site.rules' => "block anywhere\n"], 'site.rules:1', 'what to look for');
        rulesFail(['site.rules' => "block header\n"], 'site.rules:1', 'block header <Name>');
        rulesFail(['site.rules' => "block header Bad_Name x\n"], 'site.rules:1', 'block header <Name>');
        rulesFail(['site.rules' => "block query [x\n"], 'site.rules:1', 'not a valid regular expression');
        rulesFail(['site.rules' => "block query @scanners\n"], 'site.rules:1', 'expressions, not references');
        rulesFail(['site.rules' => "block query [X-1]\n"], 'site.rules:1', 'expressions, not references');
    },
    'RSF02-06 content rules: unblock takes one back; at some paths, for some addresses; replace keeps the ID' => function (): void {
        same('allow', decideFor(rulesFrom("block query sqlmap\nunblock regex sqlmap\n"), '/?a=sqlmap'), 'the expression as written');
        same('allow', decideFor(rulesFrom("ids X required\n[X-1] block query sqlmap\n[X-2] unblock [X-1]\n"), '/?a=sqlmap'), 'by its ID');
        // A glob is another pattern, not the expression.
        rulesFail(['site.rules' => "block query sqlmap\nunblock sqlmap\n"], 'site.rules:2', 'nothing to unblock');
        rulesFail(['site.rules' => "block query sqlmap\nunblock regex other\n"], 'site.rules:2', 'nothing to unblock');
        // Open at some paths only -- the pattern is then part of the exception.
        $s = rulesFrom("block query sqlmap\nunblock regex sqlmap at /ok/**\n");
        same('allow', decideFor($s, '/ok/x?a=sqlmap'), 'open there');
        same('reject attack', decideFor($s, '/other?a=sqlmap'), 'elsewhere still refused');
        $s = rulesFrom("block query sqlmap\nunblock regex sqlmap at /ok/** for 192.0.2.0/24\n");
        same('allow', decideFor($s, '/ok?a=sqlmap', ['REMOTE_ADDR' => '192.0.2.5']), 'for that range');
        same('reject attack', decideFor($s, '/ok?a=sqlmap'), 'for anyone else: refused');
        same('reject attack', decideFor($s, '/other?a=sqlmap', ['REMOTE_ADDR' => '192.0.2.5']), 'the range alone does not open it');
        $s = rulesFrom("ids X required\n[X-1] block query sqlmap\n[X-2] unblock [X-1] at /ok/**\n");
        same('allow', decideFor($s, '/ok?a=sqlmap'), 'by ID, at a path');
        same('reject attack', decideFor($s, '/x?a=sqlmap'));
        // Without patterns, "unblock at" opens the content rules there too.
        same('allow', decideFor(rulesFrom("block query sqlmap\nunblock at /ok/**\n"), '/ok?a=sqlmap'), 'no pattern: every block open there');
        // replace swaps the pattern and keeps the ID.
        $s = rulesFrom("[X-1] block query sqlmap\nreplace [X-1] block query havij\n");
        same('allow', decideFor($s, '/?a=sqlmap'), 'the old pattern is gone');
        same('reject attack', decideFor($s, '/?a=havij'), 'the replacement applies');
        $shield = new Shield($s, new MemoryStore());
        $r = Request::fromServer(['REQUEST_URI' => '/?a=havij', 'REMOTE_ADDR' => '198.51.100.7']);
        same('X-1', $shield->explain($shield->decide($r, 1000.0), $r), 'the same ID');
        // A back reference would point into the combined expression: refused when checked.
        try {
            rulesFrom("block query (a)\\1\n");
            throw new TestFailure('a back reference was accepted');
        } catch (InvalidArgumentException $e) {
            truthy(strpos($e->getMessage(), 'contentRules') !== false, $e->getMessage());
        }
    },
    'RSF05-01 match blocks: the same settings as the rules written out' => function (): void {
        $blocks = <<<'RULES'
            ids SITE
            match /admin/** {
              [SITE-ADM]   restrict to 192.0.2.0/24        # the admin area: office only
              [SITE-ADM-F] allow POST PUT                  # forms only here
              [SITE-ADM-C] challenge                       # always the browser check
              [SITE-ADM-X] unblock [SCAN-HIDDEN@1] for 192.0.2.0/24
            }
            match /shop {
              match /checkout/** {
                [SITE-PAY] challenge                       # the checkout: always checked
              }
              [SITE-SHOP] cache-path
            }
            match /old/** {
              [SITE-OLD] block
            }
            match regex ^/api/ {
              [SITE-API] challenge-exempt
            }
            RULES;
        $flat = <<<'RULES'
            ids SITE
            [SITE-ADM]   restrict /admin/** to 192.0.2.0/24        # the admin area: office only
            [SITE-ADM-F] allow POST PUT /admin/**                  # forms only here
            [SITE-ADM-C] challenge /admin/**                       # always the browser check
            [SITE-ADM-X] unblock [SCAN-HIDDEN@1] at /admin/** for 192.0.2.0/24
            [SITE-PAY] challenge /shop/checkout/**                 # the checkout: always checked
            [SITE-SHOP] cache-path /shop
            [SITE-OLD] block /old/**
            [SITE-API] challenge-exempt regex ^/api/
            RULES;
        $a = rulesFrom($blocks)->export();
        $b = rulesFrom($flat)->export();
        foreach (['at', 'area'] as $k) {         // where a rule is written, and its area: of course not the same
            unset($a['origins'][$k], $b['origins'][$k]);
        }
        unset($a['storeDir'], $a['listsDir'], $b['storeDir'], $b['listsDir']);     // the store's default is next to each file: two directories here
        same($b, $a);
        $s = rulesFrom($blocks);
        same('/admin/**', $s->origin('area', 'SITE-ADM'), 'each rule knows its area');
        same('/shop/checkout/**', $s->origin('area', 'SITE-PAY'), 'the inner path added to the outer one');
        same('reject restricted', decideFor($s, '/admin/users'));
        same('challenge always', decideFor($s, '/admin/users', ['REMOTE_ADDR' => '192.0.2.9']), 'from the office: into the area, to its browser check');
        same('challenge always', decideFor($s, '/shop/checkout/pay'));
        same('reject blocked path', decideFor($s, '/old/page'));
    },
    'RSF05-01 match blocks: what does not go, with file and line' => function (): void {
        rulesFail(['site.rules' => "match /a/** {\n  restrict /b to 192.0.2.1\n}\n"], 'site.rules:2', 'inside match: restrict to <addresses>');
        rulesFail(['site.rules' => "match /a/** {\n  challenge /b\n}\n"], 'site.rules:2', 'challenge takes no paths');
        rulesFail(['site.rules' => "challenge POST\n"], 'site.rules:1', 'which paths?');
        rulesFail(['site.rules' => "challenge post /x\n"], 'site.rules:1', 'methods are written in capitals');
        $s = rulesFrom("challenge POST PUT **\nchallenge /login\nchallenge DELETE /x/** max-age 5m\nchallenge POST /y\nchallenge /y\nmatch /shop/** {\n  challenge POST\n}\n");
        $c = $s->challenge;
        same(['POST', 'PUT'], $c->alwaysMethods[$c->alwaysPaths[0]] ?? null, 'challenge POST PUT **: the methods, first');
        same(false, isset($c->alwaysMethods[$c->alwaysPaths[1]]), 'challenge /login: every method, as before');
        same([['DELETE'], 300], [$c->alwaysMethods[$c->alwaysPaths[2]] ?? null, $c->alwaysMaxAge[$c->alwaysPaths[2]] ?? null], 'with max-age');
        same(false, isset($c->alwaysMethods[$c->alwaysPaths[3]]), 'the same paths again without methods: every method');
        same(['POST'], $c->alwaysMethods[$c->alwaysPaths[4]] ?? null, 'inside a match block: challenge POST');
        $s = rulesFrom("ids T\n[T-1] challenge POST /x max-age 5m\nreplace [T-1] challenge /y\nchallenge LICENSE\nchallenge POST README\n");
        $c = $s->challenge;
        $onX = static fn (array $map): array => array_values(array_filter(array_keys($map), static fn (string $p): bool => strpos($p, '/x') !== false));
        same([[], []], [$onX($c->alwaysMethods), $onX($c->alwaysMaxAge)], 'replace drops what belonged to the old path: its methods, its max-age (and the settings still compile)');
        same(3, count($c->alwaysPaths), 'the new path, and LICENSE, README: paths, not methods');
        same([['POST']], array_values($c->alwaysMethods), 'challenge POST README: POST is a method, README the path');
        rulesFail(['site.rules' => "match /a/** {\n  allow POST /b\n}\n"], 'site.rules:2', 'inside match: allow <METHODS>');
        rulesFail(['site.rules' => "match /a/** {\n  unblock [SCAN-HIDDEN] at /b\n}\n"], 'site.rules:2', 'the block is where');
        rulesFail(['site.rules' => "match /a/** {\n  host a.example\n}\n"], 'site.rules:2', 'host does not go inside a match block');
        rulesFail(['site.rules' => "match /a/** {\n  cache-query page\n}\n"], 'site.rules:2', 'cache-query per area is not there yet');
        rulesFail(['site.rules' => "match /a/** {\n  limit x 5/min at /b\n}\n"], 'site.rules:2', 'the block is where');
        rulesFail(['site.rules' => "match /a/** {\n  set debug-header on\n}\n"], 'site.rules:2', 'set does not go inside a match block');
        rulesFail(['site.rules' => "match /a/** {\n  challenge\n"], 'site.rules:1', 'match without its }');
        rulesFail(['site.rules' => "challenge /x\n}\n"], 'site.rules:2', '} without a match block');
        rulesFail(['site.rules' => "match /a/** {\n  match /b {\n  }\n}\n"], 'site.rules:2', 'the outer block ends in **');
        rulesFail(['site.rules' => "match /a {\n  match b/** {\n  }\n}\n"], 'site.rules:2', 'an inner block\'s path starts with /');
        rulesFail(['site.rules' => "match regex ^/a {\n  match /b {\n  }\n}\n"], 'site.rules:2', 'a block by regex holds no blocks');
        rulesFail(['site.rules' => "match /a/**\n"], 'site.rules:1', 'match <path> {');
        rulesFail(['site.rules' => "[X-1] match /a/** {\n}\n"], 'site.rules:1', 'IDs go on the rules inside a block');
        rulesFail(['site.rules' => "match regex ^/(a {\n}\n"], 'site.rules:1', 'not a valid regular expression');
        rulesFail(['site.rules' => "include x.rules\n", 'x.rules' => "match /a/** {\n"], 'x.rules:1', 'match without its }');
    },
    'RSF05-01 match blocks: replace inside a block keeps the area' => function (): void {
        $s = rulesFrom("ids SITE\nmatch /admin/** {\n  [SITE-ADM] restrict to 192.0.2.1\n}\nmatch /admin/** {\n  replace [SITE-ADM] restrict to 192.0.2.0/24\n}\n");
        same([['paths' => ['#^/admin(?:/.*)?$#i'], 'ips' => ['192.0.2.0/24']]], $s->restricted);
    },
    'RSF05-01 on-exceeded and api-path in rule files' => function (): void {
        $s = rulesFrom("limit posts 20/min on-exceeded challenge\nlimit calls 5/min on-demand on-exceeded throttle\napi-path /api/**\nmatch /v2/** {\n  api-path\n}\n");
        same([true, false], [$s->budgets['posts']->earnBack, $s->budgets['calls']->earnBack]);
        same(false, $s->budgets['requests']->earnBack, 'the default: a pause');
        same(['#^/api(?:/.*)?$#', '#^/v2(?:/.*)?$#'], $s->challenge->apiPaths);
        rulesFail(['site.rules' => "limit posts 20/min on-exceeded never\n"], 'site.rules:1', 'on-exceeded challenge|throttle');
        try {
            Settings::from(['budgets' => ['x' => ['limit' => 1, 'onExceeded' => 'wait']]]);
            throw new TestFailure('accepted onExceeded wait');
        } catch (InvalidArgumentException $e) {
            truthy(strpos($e->getMessage(), 'budgets.x.onExceeded') !== false, $e->getMessage());
        }
    },
    'RSF02-03 a POST refused (405) is named by the first allow POST line -- not by an area\'s own, written later' => function (): void {
        $dir = ruleDir(['site.rules' => "[SITE-POST] allow POST /contact /search\nmatch /admin/** {\n  [SITE-ADMIN-POST] allow POST\n}\n"]);
        try {
            $s = Settings::load("$dir/site.rules", "$dir/cache");
            $shield = new Shield($s, new MemoryStore());
            $r = Request::fromServer(['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/news/x', 'REMOTE_ADDR' => '198.51.100.7', 'HTTP_HOST' => 'www.example.org']);
            $d = $shield->decide($r, 1000.0);
            same([405, 'SITE-POST'], [$d->status, $shield->explain($d, $r)], 'the site\'s list names it');
            same('allow', $shield->decide(Request::fromServer(['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/admin/x', 'REMOTE_ADDR' => '198.51.100.7', 'HTTP_HOST' => 'www.example.org']), 1000.0)->action === 'reject' ? 'reject' : 'allow', 'the area\'s POST still allowed');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF03-01 limit inside a match block (or limit … at <paths>): only requests in the area count -- everywhere else the budget is not touched' => function (): void {
        $dir = ruleDir(['site.rules' => "exempt none\nno-limit requests\nmatch /search/** {\n  [S-SEARCH] limit searches 3/min   # searches\n}\n[S-API] limit api 2/min challenge-at 1 at /api/** /v2/**\n"]);
        try {
            $s = Settings::load("$dir/site.rules", "$dir/cache");
            same(['#^/search(?:/.*)?$#i'], $s->budgets['searches']->paths, 'the block\'s path, case-insensitive as the other path rules');
            same('S-SEARCH', $s->origin('budgets', 'searches'), 'the rule\'s ID');
            same('/search/**', $s->origin('area', 'S-SEARCH'), 'and its area as written, for the rules page');
            $shield = new Shield($s, new MemoryStore());
            $at = static fn (string $path) => $shield->decide(Request::fromServer(['REQUEST_URI' => $path, 'REMOTE_ADDR' => '198.51.100.7', 'HTTP_HOST' => 'www.example.org']), 1000.0);
            for ($i = 0; $i < 10; $i++) {
                $at('/news/x');                                   // elsewhere: never counted
            }
            for ($i = 1; $i <= 3; $i++) {
                same('allow', $at('/search/q' . $i)->action, "search $i of 3");
            }
            same(['throttle', 'searches'], [$at('/SEARCH/x')->action, $at('/search')->reason], 'the fourth and fifth: past the limit (any case, the area\'s root too)');
            same('allow', $at('/news/y')->action, 'elsewhere still open');
            same('allow', $at('/api/a')->action, 'at: the first call');
            same(['challenge', 'api'], [$at('/v2/b')->action, $at('/v2/b')->reason], 'at <paths>: one budget for both areas -- the second call past challenge-at');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF03-01 an area\'s budget: in a site block, on demand, watched; one name, one budget' => function (): void {
        $dir = ruleDir(['site.rules' => "exempt none\nsite shop.example {\n  match /cart/** {\n    limit carts 2/min on-demand\n  }\n}\n",
            'watch.rules' => "exempt none\nmatch /search/** {\n  monitor limit searches 1/min\n}\n"]);
        try {
            $s = Settings::loadFor("$dir/site.rules", ['SERVER_NAME' => 'shop.example'], "$dir/cache");
            same(['shop.example', ['#^/cart(?:/.*)?$#i']], [$s->budgets['carts']->site, $s->budgets['carts']->paths], 'in a site block and a match block: that website, that area');
            $shield = new Shield($s, new MemoryStore());
            $req = static fn (string $path) => Request::fromServer(['REQUEST_URI' => $path, 'REMOTE_ADDR' => '198.51.100.7', 'HTTP_HOST' => 'shop.example']);
            for ($i = 0; $i < 5; $i++) {
                same('allow', $shield->consume('carts', $req('/news'), 1000.0)->action, 'consume() outside the area: not counted');
            }
            $shield->consume('carts', $req('/cart/a'), 1000.0);
            $shield->consume('carts', $req('/cart/b'), 1000.0);
            same('throttle', $shield->consume('carts', $req('/cart/c'), 1000.0)->action, 'inside: the third is one too many');
            $w = Settings::load("$dir/watch.rules", "$dir/cache");
            truthy(!isset($w->budgets['searches']) && isset($w->monitor) && $w->monitor->budgets['searches']->paths !== [], 'monitor limit inside a block: watched, with its area');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
        rulesFail(['site.rules' => "match /x/** {\n  limit requests 5/min\n}\n"], 'site.rules:2', 'a budget "requests" counts already');
        rulesFail(['site.rules' => "limit s 9/min\nmatch /x/** {\n  limit s 5/min\n}\n"], 'site.rules:3', 'needs a name of its own');
        rulesFail(['site.rules' => "limit s 5/min at /a/**\nlimit s 9/min\n"], 'site.rules:2', 'is an area\'s budget');
        rulesFail(['site.rules' => "limit s 5/min at\n"], 'site.rules:1', 'limit <name>');
    },
];
