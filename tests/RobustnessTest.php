<?php

declare(strict_types=1);

use CjwNetwork\RequestShield\Challenge\Secret;
use CjwNetwork\RequestShield\Decision;
use CjwNetwork\RequestShield\Shield;
use CjwNetwork\RequestShield\Store\FileStore;

/**
 * Fail safe (ADR 0007): whatever breaks inside the shield, the site stays up.
 * The decision path is made to throw through the $known hook (an adapter's
 * URL index), which CacheableRule calls for every GET -- the one place the
 * application can hand the shield code that fails.
 */

/**
 * A site behind the shield on PHP's built-in server, the shield started by a
 * prepend file of this test's own (bootstrap.php stays quiet: no config).
 *
 * @param callable(callable(string): array{status: int, body: string, headers: list<string>}, string): void $body gets a GET function and the directory
 */
function withFailing(string $rules, string $known, callable $body): void
{
    $dir = sys_get_temp_dir() . '/rs-robust-' . getmypid() . '-' . mt_rand();
    mkdir("$dir/docroot", 0700, true);
    file_put_contents("$dir/docroot/index.php", '<?php echo "ok " . ($_SERVER["REQUEST_SHIELD"] ?? "-");');
    // recheck 0: the built-in server has APCu (its SAPI is not "cli" to APCu), and with
    // APCu the shield looks at the rule files only every 10 s -- here every request must.
    file_put_contents("$dir/site.rules", "set recheck 0\n" . str_replace('__DIR__', $dir, $rules));
    file_put_contents("$dir/prepend.php", '<?php require ' . var_export(rsEntry(), true) . ";\n"
        . '\CjwNetwork\RequestShield\Shield::protectFile(' . var_export("$dir/site.rules", true) . ', ' . $known . ', ' . var_export("$dir/cache", true) . ');');
    $port = freePort();
    // OPcache, where it is on (the CI), looks at a changed file at once: the tests change files under it.
    $proc = proc_open(sprintf('REQUEST_SHIELD_CONFIG=/nonexistent exec %s -d opcache.revalidate_freq=0 -d auto_prepend_file=%s -d log_errors=1 -d error_log=%s -S 127.0.0.1:%d -t %s > /dev/null 2>&1',
        serverPhp(), escapeshellarg("$dir/prepend.php"), escapeshellarg("$dir/php-errors.log"), $port, escapeshellarg("$dir/docroot")), [], $pipes);
    for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
        usleep(100000);
    }
    try {
        $body(static function (string $uri) use ($port): array {
            $out = (string) @file_get_contents("http://127.0.0.1:$port$uri", false, stream_context_create(['http' => ['ignore_errors' => true, 'timeout' => 10]]));
            $headers = $http_response_header ?? [];
            return ['status' => (int) substr((string) ($headers[0] ?? ''), 9, 3), 'body' => $out, 'headers' => $headers];
        }, $dir);
    } finally {
        proc_terminate($proc);
        proc_close($proc);
        exec('rm -rf ' . escapeshellarg($dir));
    }
}

return [
    'RSF05-05 an exception in the decision path: the request passes, uncached, as "shield error"' => function (): void {
        $server = $_SERVER;
        $_SERVER = ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/page', 'HTTP_HOST' => 'example.org', 'REMOTE_ADDR' => '198.51.100.7', 'SERVER_PROTOCOL' => 'HTTP/1.1'] + $_SERVER;
        unset($_SERVER['REQUEST_SHIELD']);
        $log = tempnam(sys_get_temp_dir(), 'rs-log-');
        $errorLog = ini_set('error_log', (string) $log);        // the one line goes here, not into the test output
        try {
            $d = Shield::protect(['store' => 'memory'], static function (): ?bool {
                throw new RuntimeException('the adapter\'s index is broken');
            });
            same(Decision::ALLOW_UNCACHED, $d->action, 'let through');
            same('shield error', $d->reason);
            same(false, $d->cacheable(), 'never cached');
            same(Decision::ALLOW_UNCACHED, $_SERVER['REQUEST_SHIELD'] ?? null, 'what the application sees');
            same($d, Shield::current(), 'Shield::current() says the same');
            same(null, Shield::currentRule());
            truthy(strpos((string) file_get_contents((string) $log), 'the shield failed and let the request through: RuntimeException') !== false, 'the error log names the cause');
        } finally {
            $_SERVER = $server;
            ini_set('error_log', (string) $errorLog);
            @unlink((string) $log);
        }
    },
    'RSF05-05 passThrough(): a long-running server\'s exception in place of exit() passes protect() -- no shield error, nothing logged; any other still fails open' => function (): void {
        $server = $_SERVER;
        $_SERVER = ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/page', 'HTTP_HOST' => 'example.org', 'REMOTE_ADDR' => '198.51.100.7', 'SERVER_PROTOCOL' => 'HTTP/1.1'] + $_SERVER;
        unset($_SERVER['REQUEST_SHIELD']);
        $log = tempnam(sys_get_temp_dir(), 'rs-log-');
        $errorLog = ini_set('error_log', (string) $log);
        $signal = new class ('exit') extends RuntimeException {
        };
        $child = new class ('exit') extends LogicException {
        };
        try {
            Shield::passThrough(get_class($signal), LogicException::class);
            foreach (['the class named' => $signal, 'a subclass of one named' => $child] as $what => $thrown) {
                $caught = null;
                try {
                    Shield::protect(['store' => 'memory'], static function () use ($thrown): ?bool {
                        throw $thrown;
                    });
                } catch (\Throwable $e) {
                    $caught = $e;
                }
                same($thrown, $caught, "$what reaches the server unchanged");
            }
            same('', (string) file_get_contents((string) $log), 'and the error log hears nothing: it is no failure');
            $d = Shield::protect(['store' => 'memory'], static function (): ?bool {
                throw new RuntimeException('the adapter\'s index is broken');
            });
            same('shield error', $d->reason, 'an exception not named still fails open');
            Shield::passThrough();
            $d = Shield::protect(['store' => 'memory'], static function () use ($signal): ?bool {
                throw $signal;
            });
            same('shield error', $d->reason, 'an empty list: as before, every exception fails open');
        } finally {
            Shield::passThrough();
            $_SERVER = $server;
            ini_set('error_log', (string) $errorLog);
            @unlink((string) $log);
        }
    },
    'RSF05-05 a plugin\'s rule that throws (RuleProvider, 0031 C.3): through the public API the request passes as if the rule said nothing -- not as a shield error -- and the error log hears it once' => function (): void {
        $server = $_SERVER;
        $_SERVER = ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/forbidden', 'HTTP_HOST' => 'example.org', 'REMOTE_ADDR' => '198.51.100.7', 'SERVER_PROTOCOL' => 'HTTP/1.1'] + $_SERVER;
        unset($_SERVER['REQUEST_SHIELD']);
        $log = tempnam(sys_get_temp_dir(), 'rs-log-');
        $errorLog = ini_set('error_log', (string) $log);
        \CjwNetwork\RequestShield\Rules\Vocabulary::forget();
        try {
            \CjwNetwork\RequestShield\Rules\Vocabulary::offer(\CjwNetwork\RequestShield\Tests\RsTestExtension::class);
            $config = ['store' => 'memory', 'plugins' => [\CjwNetwork\RequestShield\Tests\RulesPlugin::class], 'ext' => ['rs-test' => ['failAt' => 'rules']]];
            $d = Shield::protect($config);
            same(Decision::ALLOW, $d->action, 'let through -- the rule said nothing, nothing else is wrong with the request');
            same(true, $d->cacheable(), 'and cacheable: it is no shield error, the other rules decided as always');
            truthy(strpos((string) file_get_contents((string) $log), 'the rule test-provider failed and said nothing: the provided rule failed, as asked (') !== false, 'the error log names the rule: ' . (string) file_get_contents((string) $log));
        } finally {
            \CjwNetwork\RequestShield\Rules\Vocabulary::reset();
            $_SERVER = $server;
            ini_set('error_log', (string) $errorLog);
            @unlink((string) $log);
        }
    },
    'RSF05-05 the real path: the site answers although the shield throws; its own refusals still stand; the error log hears it once' => function (): void {
        if (!function_exists('proc_open')) {
            skip('no proc_open');
        }
        withFailing("set store file\nset store-dir __DIR__/store\nset debug-header on\nblock /secret/**\n", 'static function () { throw new RuntimeException("boom"); }', function (callable $get, string $dir): void {
            for ($i = 0; $i < 3; $i++) {
                $r = $get('/');
                same(200, $r['status'], 'the site answers');
                same('ok allow-uncached', $r['body'], 'uncached, and the application knows');
                truthy(in_array('X-RS: allow-uncached shield error', $r['headers'], true), 'the debug header names the cause: ' . implode(' | ', $r['headers']));
            }
            $r = $get('/secret/x');
            same(404, $r['status'], 'a blocked path is refused before the failing step runs');
            $log = (string) @file_get_contents("$dir/php-errors.log");
            same(1, preg_match_all('/the shield failed and let the request through: RuntimeException: boom/', $log), "one line for three requests, not three:\n$log");
        });
    },
    'RSF05-05 a store directory nobody can write: nothing is counted, every request passes, no error' => function (): void {
        if (!function_exists('proc_open')) {
            skip('no proc_open');
        }
        $probe = sys_get_temp_dir() . '/rs-ro-' . getmypid();
        mkdir($probe, 0500);
        $root = is_writable($probe);                 // root writes anywhere: the case cannot be made here
        rmdir($probe);
        if ($root) {
            skip('running as root: a read-only directory is still writable');
        }
        withFailing("set store file\nset store-dir __RO__\nlimit requests 2/min\n", 'null', function (callable $get, string $dir): void {
            // The rules are written before the directory exists; point them at it now.
            mkdir("$dir/ro", 0500);
            file_put_contents("$dir/site.rules", str_replace('__RO__', "$dir/ro", (string) file_get_contents("$dir/site.rules")));
            usleep(1100000);                             // a new second: mtime and size tell the rewrite apart
            for ($i = 0; $i < 5; $i++) {
                $r = $get('/');
                same(200, $r['status'], "request $i passes: the limit cannot be counted, so it does not bite");
            }
            same('', trim((string) @file_get_contents("$dir/php-errors.log")), 'no error for the visitor and none in the log');
        });
    },
    'RSF05-05 a rule file broken after a good compile: the last good rules stay in force, one line in the log, the fix is picked up' => function (): void {
        if (!function_exists('proc_open')) {
            skip('no proc_open');
        }
        withFailing("set store file\nset store-dir __DIR__/store\nset debug-header on\nblock /secret/**\n", 'null', function (callable $get, string $dir): void {
            same(404, $get('/secret/x')['status'], 'the good rules compiled and decide');
            file_put_contents("$dir/site.rules", "set recheck 0\nset store file\nset store-dir $dir/store\nset debug-header on\nblock /secret/**\nset mode sideways   # a typo in a deploy\n");
            for ($i = 0; $i < 3; $i++) {
                same(404, $get('/secret/x')['status'], "request $i: the last good rules still refuse");
                same(200, $get('/')['status'], "request $i: the site still answers");
            }
            $log = (string) @file_get_contents("$dir/php-errors.log");
            same(1, preg_match_all('/the rules cannot be compiled -- the last good ones stay in force: .*mode/', $log), "one line, naming the mistake:\n$log");
            truthy(is_file(glob("$dir/cache/settings-*.failed")[0] ?? ''), 'the marker that keeps the next requests from compiling again');
            // The fix: the block is gone, so the path must pass -- proof that the new file was compiled.
            file_put_contents("$dir/site.rules", "set recheck 0\nset store file\nset store-dir $dir/store\nset debug-header on\n");
            same(200, $get('/secret/x')['status'], 'the fixed rules are compiled and in force');
            same([], glob("$dir/cache/settings-*.failed"), 'the marker is gone');
        });
    },
    'RSF05-05 a rule file broken at first install: the shield runs switched off, the site answers, the log says why' => function (): void {
        if (!function_exists('proc_open')) {
            skip('no proc_open');
        }
        withFailing("set store file\nset store-dir __DIR__/store\nhots example.org\n", 'null', function (callable $get, string $dir): void {
            for ($i = 0; $i < 3; $i++) {
                $r = $get('/');
                same(200, $r['status'], "request $i: the site answers");
                same('ok allow', $r['body'], 'switched off: a plain allow');
            }
            $log = (string) @file_get_contents("$dir/php-errors.log");
            same(1, preg_match_all('/the rules cannot be compiled -- the shield runs switched off until they are fixed: .*did you mean "host"/', $log), "one line for the first failure:\n$log");
            same([], glob("$dir/cache/settings-*.php"), 'nothing compiled');
            truthy(glob("$dir/cache/settings-*.failed") !== [], 'the marker');
        });
    },
    'RSF05-05 a compiled settings file cut short: the next request compiles anew, no error reaches the visitor' => function (): void {
        if (!function_exists('proc_open')) {
            skip('no proc_open');
        }
        withFailing("set store file\nset store-dir __DIR__/store\nblock /secret/**\n", 'null', function (callable $get, string $dir): void {
            same(404, $get('/secret/x')['status'], 'compiled');
            $compiled = glob("$dir/cache/settings-*.php")[0] ?? '';
            $whole = (int) filesize($compiled);
            // Cut inside the array, as a full disk would: not even parseable.
            file_put_contents($compiled, substr((string) file_get_contents($compiled), 0, intdiv($whole, 2)));
            touch($compiled, time() + 5);           // changed, as a write that broke off changes it: OPcache sees it (by the second; each cut its own time)
            same(404, $get('/secret/x')['status'], 'decided all the same -- from the rule file');
            same(200, $get('/')['status']);
            same($whole, (int) filesize($compiled), 'the compiled file is whole again');
            // Cut so that it parses, but the array is short: the constructor would not take it.
            $php = (string) file_get_contents($compiled);
            $cut = strrpos($php, "'challenge' =>");
            file_put_contents($compiled, substr($php, 0, (int) $cut) . ");\n");
            touch($compiled, time() + 10);           // changed, as a write that broke off changes it: OPcache sees it (by the second)
            same(404, $get('/secret/x')['status'], 'decided all the same');
            same($whole, (int) filesize($compiled), 'compiled anew');
            // Cut before its last entries only: the constructor would fill them in with defaults
            // and take it -- the end marker says it is not whole.
            $php = (string) file_get_contents($compiled);
            $cut = strrpos($php, "'errorPages' =>");
            file_put_contents($compiled, substr($php, 0, (int) $cut) . "),\n);\n");
            touch($compiled, time() + 15);           // changed, as a write that broke off changes it: OPcache sees it (by the second)
            same(404, $get('/secret/x')['status'], 'decided all the same');
            same($whole, (int) filesize($compiled), 'its end missing: compiled anew');
            same('', trim((string) @file_get_contents("$dir/php-errors.log")), 'nothing for the log: nothing was wrong with the rules');
        });
    },
    'RSF05-05 compiled settings of another format are not taken: compiled anew' => function (): void {
        $dir = sys_get_temp_dir() . '/rs-fmt-' . getmypid() . '-' . mt_rand();
        mkdir($dir, 0700, true);
        try {
            file_put_contents("$dir/site.rules", "set store memory\nhost example.org\n");
            $s = CjwNetwork\RequestShield\Settings::load("$dir/site.rules", "$dir/cache");
            same(['example.org'], $s->hosts);
            $compiled = glob("$dir/cache/settings-*.php")[0] ?? '';
            $php = (string) file_get_contents($compiled);
            truthy(preg_match("/'format' => (\\d+),/", $php, $m) === 1, 'the format is in the file');
            file_put_contents($compiled, str_replace("'format' => {$m[1]},", "'format' => 1,", str_replace("'example.org'", "'stale.example'", $php)));
            $s = CjwNetwork\RequestShield\Settings::load("$dir/site.rules", "$dir/cache");
            same(['example.org'], $s->hosts, 'the stale file of another format was not used');
            truthy(strpos((string) file_get_contents($compiled), "'format' => {$m[1]},") !== false, 'written anew in the current format');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF05-05 the file store and the secret on an unwritable directory do not throw' => function (): void {
        $dir = sys_get_temp_dir() . '/rs-ro-unit-' . getmypid() . '-' . mt_rand();
        mkdir($dir, 0500);
        try {
            if (is_writable($dir)) {
                skip('running as root: a read-only directory is still writable');
            }
            $store = new FileStore($dir);
            same(0.0, $store->hit('k', 60, microtime(true)), 'a hit counts as nothing');
            $store->mark('m', time() + 60, microtime(true));
            same(0, $store->marked('m', microtime(true)), 'a mark is not kept');
            $secret = Secret::resolve(null, $dir);
            truthy(strlen($secret) >= 32, 'a secret for this request all the same');
        } finally {
            @chmod($dir, 0700);
            @rmdir($dir);
        }
    },
];
